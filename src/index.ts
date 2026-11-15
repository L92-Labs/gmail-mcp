#!/usr/bin/env node
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import { createRequire } from "node:module";
import { realpathSync } from "node:fs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  authorize, cachedTokenReader, generateToken, listAccounts, loadAccounts, normalizeEmail,
  readAccountToken, removeAccount, unknownAccountError, writeAccountToken, type LoadedAccount,
} from "./auth.js";
import { describeMode, parseConfig, type Features } from "./config.js";
import { registerTools } from "./tools.js";

const { version } = createRequire(import.meta.url)("../package.json") as { version: string };

// ponytail: fixed sweep; make it configurable if a client legitimately idles longer.
const SESSION_IDLE_MS = 60 * 60_000;

interface Session {
  transport: StreamableHTTPServerTransport;
  lastSeen: number;
  /** The account (or "*" for a shared token) whose bearer opened this session; no other token may use it. */
  email: string;
  /** sha256 hex of the token that opened this session, so a rotation revokes it even for the same email. */
  digest: string;
}

/** Session marker for the unified-token mode, where one bearer may act on every account. */
const SHARED_SESSION = "*";

export interface HandlerOptions {
  accounts: Map<string, LoadedAccount>;
  host: string;
  port: number;
  sessions?: Map<string, Session>;
  /** Looks up the current token for an email; defaults to the in-memory `accounts` entry. */
  tokenFor?: (email: string) => Promise<string | undefined>;
  /**
   * Fork: when set (MCP_BEARER_TOKEN), this one token authenticates every signed-in
   * account and sessions may act across accounts via the `account` argument. When
   * unset, upstream per-account bearer behavior applies unchanged.
   */
  sharedToken?: string;
  /** Fork guardrails handed to the registered tools. Defaults to pull mode. */
  features?: Features;
  /** Fork: account used when `account` is omitted. Defaults to the first signed in. */
  defaultAccount?: string;
  /** Fork: extra Host header values accepted alongside loopback (tunnel/proxy frontends). */
  extraHosts?: string[];
}

const digest = (v: string): Buffer => createHash("sha256").update(v).digest();

/**
 * The email owning the bearer token in `header`, or undefined. Hashing both sides keeps the
 * comparison constant time (timingSafeEqual needs equal lengths) and hides token length.
 * Tokens are resolved via `tokenFor` on every call so a rotated token takes effect immediately.
 */
export const authenticate = async (
  header: string | undefined,
  emails: Iterable<string>,
  tokenFor: (email: string) => Promise<string | undefined>,
  sharedToken?: string
): Promise<{ email: string; digest: string } | undefined> => {
  const match = /^Bearer (\S+)$/i.exec(header ?? "");
  if (!match) return undefined;
  const candidate = digest(match[1]);
  if (sharedToken) {
    // Unified mode: one portal-style token, every account reachable. Per-account
    // token files are not consulted.
    return timingSafeEqual(candidate, digest(sharedToken)) ? { email: SHARED_SESSION, digest: candidate.toString("hex") } : undefined;
  }
  let found: string | undefined;
  for (const email of emails) {
    let token: string | undefined;
    try {
      token = await tokenFor(email);
    } catch (err) {
      // An unreadable token file fails closed for that one account only; every other
      // account's token is still checked.
      console.error(`gmail-mcp: could not read the token for ${email}:`, err);
      continue;
    }
    if (token && timingSafeEqual(candidate, digest(token))) found = email;
  }
  return found ? { email: found, digest: candidate.toString("hex") } : undefined;
};

const rpcError = (res: ServerResponse, status: number, message: string, headers: Record<string, string> = {}): void => {
  res
    .writeHead(status, { "content-type": "application/json", ...headers })
    .end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32001, message }, id: null }));
};

/**
 * Streamable HTTP only, at /mcp. One McpServer per session (the SDK requires 1:1
 * server/transport). Exported so the routing can be exercised without a socket.
 */
export const createRequestHandler = ({
  accounts,
  host,
  port,
  sessions = new Map(),
  tokenFor = async (email) => accounts.get(email)?.token,
  sharedToken,
  features,
  defaultAccount,
  extraHosts = [],
}: HandlerOptions) => {
  // The SDK compares the raw Host header, so list each name with and without the port.
  // Extra hosts serve tunnel/proxy frontends (e.g. a Cloudflare tunnel hostname);
  // anything else is a DNS-rebinding attempt.
  const loopbackAndHost = [...new Set([host, "127.0.0.1", "localhost", "[::1]"])].flatMap((h) => [h, `${h}:${port}`]);
  // A port-bearing extra host matches exactly; a bare hostname also matches the
  // server's own port, mirroring the loopback entries.
  const allowedHosts = [
    ...loopbackAndHost,
    ...extraHosts.flatMap((h) => (/:\d+$/.test(h) ? [h] : [h, `${h}:${port}`])),
  ];

  const handler = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const url = new URL(req.url ?? "/", "http://localhost");
    if (url.pathname !== "/mcp") {
      res.writeHead(404).end();
      return;
    }
    try {
      // Authenticate before the session lookup so an unauthenticated probe cannot tell a live
      // session id from a dead one.
      const auth = req.headers.authorization;
      const authHeader = Array.isArray(auth) ? auth[0] : auth;
      const authResult = await authenticate(authHeader, accounts.keys(), tokenFor, sharedToken);
      if (!authResult) {
        rpcError(res, 401, "Unauthorized", { "www-authenticate": "Bearer" });
        return;
      }
      const { email, digest: tokenDigest } = authResult;
      const header = req.headers["mcp-session-id"];
      const sessionId = Array.isArray(header) ? header[0] : header;
      const existing = sessionId ? sessions.get(sessionId) : undefined;
      if (sessionId && !existing) {
        rpcError(res, 404, "Session not found");
        return;
      }
      if (existing) {
        // A live session id owned by another account must be indistinguishable from a dead
        // one: same 404 both ways.
        if (existing.email !== email) {
          rpcError(res, 404, "Session not found");
          return;
        }
        // Same account, different token: the account's token rotated. Drop the session so any
        // SSE stream opened under the old token is dropped too, and the client re-initializes.
        if (existing.digest !== tokenDigest) {
          sessions.delete(sessionId!);
          existing.transport
            .close()
            .catch((err) => console.error("gmail-mcp: failed to close revoked session transport:", err));
          rpcError(res, 404, "Session not found");
          return;
        }
        existing.lastSeen = Date.now();
        await existing.transport.handleRequest(req, res);
        return;
      }
      if (req.method !== "POST") {
        res.writeHead(400).end("Missing mcp-session-id");
        return;
      }
      const transport: StreamableHTTPServerTransport = new StreamableHTTPServerTransport({
        sessionIdGenerator: randomUUID,
        enableDnsRebindingProtection: true,
        allowedHosts,
        onsessioninitialized: (id: string) => {
          sessions.set(id, { transport, lastSeen: Date.now(), email, digest: tokenDigest });
        },
      });
      transport.onclose = () => transport.sessionId && sessions.delete(transport.sessionId);
      const server = new McpServer({ name: "gmail-mcp", version });
      // The token binds the session to exactly one account (per-account mode) or to the
      // shared token (unified mode, marker email), so that is all the session can see.
      const clients = sharedToken
        ? new Map([...accounts].map(([email, loaded]) => [email, loaded.gmail]))
        : new Map([[email, accounts.get(email)!.gmail]]);
      registerTools(server, {
        clients,
        default: sharedToken ? (defaultAccount ?? [...clients.keys()][0]!) : email,
        ...(features ? { features } : {}),
      });
      await server.connect(transport);
      await transport.handleRequest(req, res);
    } catch (err) {
      console.error("gmail-mcp request failed:", err);
      if (!res.headersSent) res.writeHead(500).end("Internal error");
    }
  };

  // Clients that vanish without DELETE never fire onclose; reap them.
  const sweep = () => {
    const cutoff = Date.now() - SESSION_IDLE_MS;
    for (const [id, s] of sessions) {
      if (s.lastSeen < cutoff) {
        sessions.delete(id);
        s.transport.close().catch(() => {});
      }
    }
  };

  return { handler, sweep, allowedHosts };
};

// All diagnostics go to stderr on purpose: only bearer tokens go to stdout, so
// `gmail-mcp token <email>` can be piped straight into a client config.
export const cli = async (argv: string[]): Promise<boolean> => {
  const [cmd, flag, value] = argv;
  const known = async () => (await listAccounts()).join(", ") || "none";
  if (cmd === "accounts") {
    const all = await listAccounts();
    if (all.length === 0) console.error("No accounts. Run: gmail-mcp auth");
    for (const e of all) console.error(e);
    return true;
  }
  if (cmd === "token") {
    if (!flag) throw new Error("Usage: gmail-mcp token <email> [--rotate]");
    const email = normalizeEmail(flag);
    const all = await listAccounts();
    if (!all.includes(email)) throw unknownAccountError(email, all);
    if (value && value !== "--rotate") throw new Error(`Unknown option ${value}. Usage: gmail-mcp token <email> [--rotate]`);
    const rotate = value === "--rotate";
    const token = (!rotate && (await readAccountToken(email))) || generateToken();
    // Rewriting even the unrotated case is deliberate: it lets writeSecureFile's chmod
    // repair a token file or accounts dir whose permissions have drifted.
    await writeAccountToken(email, token);
    console.error(`Bearer token for ${email}${rotate ? " (rotated; existing clients must be updated)" : ""}:`);
    console.log(token);
    return true;
  }
  if (cmd !== "auth") return false;
  if (flag === "--remove") {
    if (!value) throw new Error("Usage: gmail-mcp auth --remove <email>");
    await removeAccount(value);
    console.error(`Removed ${normalizeEmail(value)}. Signed-in accounts: ${await known()}`);
    return true;
  }
  if (flag) throw new Error(`Unknown option ${flag}. Usage: gmail-mcp auth [--remove <email>]`);
  await authorize();
  return true;
};

const main = async (): Promise<void> => {
  if (await cli(process.argv.slice(2))) return;

  // Guardrails parse before anything binds or loads: a bad deployment dies here.
  const config = parseConfig();

  const loaded = await loadAccounts();
  if (!loaded) {
    console.error("No accounts. Run: gmail-mcp auth");
    process.exit(1);
  }
  const { accounts } = loaded;
  if (config.defaultAccount && !accounts.has(config.defaultAccount)) {
    console.error(`DEFAULT_EMAIL_ACCOUNT "${config.defaultAccount}" is not signed in. Signed in: ${[...accounts.keys()].join(", ")}.`);
    process.exit(1);
  }
  console.error(
    `gmail-mcp accounts: ${[...accounts.keys()].join(", ")}. Mode ${config.mode} (${describeMode(config.mode)}). ` +
    (config.sharedToken
      ? "Every /mcp request needs `Authorization: Bearer <MCP_BEARER_TOKEN>`; tools take `account` to pick a mailbox."
      : "Every /mcp request needs `Authorization: Bearer <token>`; print one with `gmail-mcp token <email>`.") +
    (config.settingsTools ? " Settings tools enabled." : "") +
    (config.dangerousTools ? " DANGEROUS tools (permanent delete, raw send, import) enabled." : "")
  );

  const host = process.env.GMAIL_MCP_HOST || "127.0.0.1";
  const port = Number(process.env.GMAIL_MCP_PORT || process.env.PORT || 3016);
  const { handler, sweep } = createRequestHandler({
    accounts,
    host,
    port,
    tokenFor: cachedTokenReader(),
    sharedToken: config.sharedToken,
    features: { mode: config.mode, allowlist: config.allowlist, settingsTools: config.settingsTools, workspaceTools: config.workspaceTools, dangerousTools: config.dangerousTools },
    defaultAccount: config.defaultAccount,
    extraHosts: config.extraHosts,
  });
  setInterval(sweep, SESSION_IDLE_MS / 4).unref();
  createServer(handler).listen(port, host, () =>
    console.error(`gmail-mcp ${version} listening on http://${host}:${port}/mcp`)
  );
};

// Only run when executed directly, so importing this module for its exports is side-effect free.
const isEntrypoint = (() => {
  try {
    return process.argv[1] && realpathSync(process.argv[1]) === realpathSync(new URL(import.meta.url).pathname);
  } catch {
    return false;
  }
})();
if (isEntrypoint) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
