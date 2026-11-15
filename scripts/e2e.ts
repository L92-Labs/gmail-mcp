#!/usr/bin/env node
/**
 * End-to-end suite for the L92-Labs gmail-mcp fork.
 *
 * Boots the real built server (dist/index.js) against a local fake Gmail REST API and
 * talks to it with a real MCP SDK client over Streamable HTTP — the same path the
 * Cloudflare tunnel and the Perso portal use. No real Google account is involved:
 * fixture accounts carry long-lived fake access tokens, and GMAIL_MCP_API_ROOT points
 * the googleapis client at the fake (the same override k8s deployments never set).
 *
 * Legs:
 *   A  shared bearer + pull          → read/organize tools only, cross-account via `account`
 *   B  shared bearer + draft         → drafting appears, sending stays hidden
 *   C  shared bearer + pull_push     → sending appears and enforces SEND_ALLOWLIST
 *   D  per-account bearers (compat)  → upstream behavior unchanged: one token, one mailbox
 *
 * Run with `pnpm e2e`. Exits non-zero on the first failed expectation.
 */
import { spawn, spawnSync, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from "node:http";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(dirname(fileURLToPath(import.meta.url)), "..");

const ALICE = "alice@l92.test";
const BOB = "bob@l92.test";
const ACCESS = new Map([
  ["at-alice", ALICE],
  ["at-bob", BOB],
]);
const ALICE_FIXTURE = [{ id: "m-alice-1", threadId: "t1" }, { id: "m-alice-2", threadId: "t2" }];
const BOB_FIXTURE = [{ id: "m-bob-1", threadId: "t1" }];

// ---- assertions ----------------------------------------------------------

let failures = 0;
const ok = (label: string, condition: boolean, detail?: unknown): void => {
  if (condition) {
    console.log(`  ok  ${label}`);
  } else {
    failures += 1;
    console.error(`FAIL  ${label}${detail !== undefined ? ` — ${JSON.stringify(detail).slice(0, 400)}` : ""}`);
  }
};

// ---- fake Gmail REST API --------------------------------------------------

interface FakeState { sentTo: string[]; drafts: Map<string, string> }

const startFakeGmail = async (): Promise<{ port: number; close: () => void; state: FakeState }> => {
  const state: FakeState = { sentTo: [], drafts: new Map() };
  const json = (res: ServerResponse, body: unknown, status = 200): void => {
    res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(body));
  };
  const readBody = async (req: IncomingMessage): Promise<Record<string, unknown>> =>
    new Promise((resolve) => {
      let raw = "";
      req.on("data", (chunk) => (raw += chunk));
      req.on("end", () => {
        try { resolve(JSON.parse(raw)); } catch { resolve({}); }
      });
    });
  const server = createHttpServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://fake");
    const email = ACCESS.get((req.headers.authorization ?? "").replace(/^Bearer /i, ""));
    if (!email) return json(res, { error: { code: 401, message: "bad test token" } }, 401);
    const me = url.pathname.match(/^\/gmail\/v1\/users\/[^/]+\/(.+)$/)?.[1] ?? "";
    if (req.method === "GET" && me === "profile") {
      return json(res, { emailAddress: email, messagesTotal: 2, threadsTotal: 1, historyId: "1" });
    }
    if (req.method === "GET" && me === "messages/list" || req.method === "GET" && me === "messages") {
      return json(res, { messages: email === ALICE ? ALICE_FIXTURE : BOB_FIXTURE, resultSizeEstimate: 2 });
    }
    if (req.method === "POST" && me === "messages/send") {
      const body = await readBody(req);
      const raw = Buffer.from(String(body.raw ?? ""), "base64url").toString("utf8");
      const to = [...raw.matchAll(/^To:\s*(.+)$/gim)].flatMap((m) => m[1]!.split(",")).map((a) => a.trim()).filter(Boolean);
      state.sentTo.push(...to);
      return json(res, { id: `sent-${state.sentTo.length}`, labelIds: ["SENT"], threadId: body.threadId ?? undefined });
    }
    if (req.method === "GET" && me === "drafts") {
      return json(res, { drafts: [], resultSizeEstimate: 0 });
    }
    if (req.method === "POST" && me === "drafts") {
      const body = await readBody(req);
      // drafts.create wraps the RFC 822 source in {message:{raw}}; send puts raw at top level.
      const source = (body.message as { raw?: string } | undefined)?.raw ?? body.raw;
      const id = `draft-${state.drafts.size + 1}`;
      // Draft ids are distinct from message ids on purpose, and the stored SOURCE is
      // served back in raw format — the server must bind the send to this snapshot.
      state.drafts.set(id, String(source ?? ""));
      return json(res, { id, message: { id: `m-for-${id}` } });
    }
    const draftGet = me.match(/^drafts\/([^/]+)$/);
    if (req.method === "GET" && draftGet) {
      const source = state.drafts.get(draftGet[1]!);
      if (source === undefined) return json(res, { error: { code: 404, message: "no such draft" } }, 404);
      return json(res, { id: draftGet[1], message: { raw: source, threadId: "t-e2e" } });
    }
    if (req.method === "GET" && me === "labels") {
      return json(res, { labels: [{ id: "INBOX", name: "INBOX", type: "system" }, { id: "Label_1", name: "Receipts", type: "user" }] });
    }
    return json(res, { error: { code: 404, message: `fake has no handler for ${req.method} ${me}` } }, 404);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as { port: number }).port;
  return { port, close: () => server.close(), state };
};

// ---- fixture store --------------------------------------------------------

const writeFixtureStore = (dir: string): void => {
  mkdirSync(path.join(dir, "accounts"), { recursive: true });
  writeFileSync(path.join(dir, "credentials.json"), JSON.stringify({
    installed: {
      client_id: "e2e-client.apps.googleusercontent.com",
      client_secret: "e2e-secret",
      auth_uri: "https://accounts.google.com/o/oauth2/auth",
      token_uri: "https://oauth2.googleapis.com/token",
      redirect_uris: ["http://127.0.0.1/oauth2callback"],
    },
  }));
  const farFuture = Date.now() + 24 * 60 * 60 * 1000;
  const scope = "https://www.googleapis.com/auth/gmail.modify https://www.googleapis.com/auth/gmail.compose";
  for (const [email, token] of [[ALICE, "at-alice"], [BOB, "at-bob"]] as const) {
    writeFileSync(path.join(dir, "accounts", `${email}.json`), JSON.stringify({
      access_token: token, token_type: "Bearer", expiry_date: farFuture, scope,
    }));
  }
  // Pre-minted per-account bearer tokens for the compat leg (leg D).
  writeFileSync(path.join(dir, "accounts", `${ALICE}.token`), "alice-mcp-token-0123456789abcdef");
  writeFileSync(path.join(dir, "accounts", `${BOB}.token`), "bob-mcp-token-0123456789abcdefg");
};

// ---- server process -------------------------------------------------------

const SHARED = "shared-e2e-bearer-0123456789abcdef";

const bootServer = async (fakePort: number, env: Record<string, string>) => {
  const child = spawn(process.execPath, [path.join(ROOT, "dist", "index.js")], {
    cwd: ROOT,
    env: {
      ...process.env,
      PORT: env.PORT,
      GMAIL_MCP_HOST: "127.0.0.1",
      GMAIL_MCP_KEYRING: "file",
      GMAIL_MCP_API_ROOT: `http://127.0.0.1:${fakePort}`,
      ...env,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr!.on("data", (chunk) => (stderr += chunk));
  const port = Number(env.PORT);
  const base = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 50; i++) {
    try {
      const res = await fetch(`${base}/mcp`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
      if (res.status === 401) return { child, base, stderr: () => stderr };
      await res.text();
    } catch { /* not listening yet */ }
    await sleep(100);
  }
  child.kill("SIGKILL");
  throw new Error(`server on :${port} never became ready (401 on unauthenticated probe).\n${stderr}`);
};

// ---- MCP client -----------------------------------------------------------

/** Structural subset of the SDK client; the real Client satisfies it. */
interface McpClient {
  listTools(): Promise<{ tools: { name: string }[] }>;
  callTool(args: { name: string; arguments?: Record<string, unknown> }): Promise<{
    isError?: boolean;
    content?: { type: string; text?: string }[];
  }>;
  connect(transport: unknown): Promise<void>;
  close(): Promise<void>;
}

const { Client } = await import("@modelcontextprotocol/sdk/client/index.js");
const { StreamableHTTPClientTransport } = await import("@modelcontextprotocol/sdk/client/streamableHttp.js");

const connect = async (base: string, token: string): Promise<McpClient> => {
  const client = new Client({ name: "gmail-mcp-e2e", version: "0.0.0" }) as unknown as McpClient;
  const transport = new StreamableHTTPClientTransport(new URL(`${base}/mcp`), {
    requestInit: { headers: { Authorization: `Bearer ${token}` } },
  });
  await client.connect(transport);
  return client;
};

const toolNames = async (client: McpClient): Promise<string[]> =>
  (await client.listTools()).tools.map((t) => t.name).sort();

const call = async (
  client: McpClient,
  name: string,
  args: Record<string, unknown> = {}
): Promise<{ isError: boolean; text: string }> => {
  try {
    const result = await client.callTool({ name, arguments: args });
    const content = (result.content as { type: string; text?: string }[] | undefined) ?? [];
    return { isError: result.isError === true, text: content.map((c) => c.text ?? "").join("\n") };
  } catch (err) {
    // The SDK raises on JSON-RPC tool errors in some paths; treat the message as the result.
    return { isError: true, text: (err as Error).message };
  }
};

// ---- legs -----------------------------------------------------------------

const stop = async (server: { child: { kill: (signal?: NodeJS.Signals) => unknown } }): Promise<void> => {
  server.child.kill("SIGTERM");
  await sleep(150);
  server.child.kill("SIGKILL");
};

const main = async (): Promise<number> => {
  console.log("building dist/ for the e2e (pnpm build already run if invoked via pnpm e2e)...");
  const fake = await startFakeGmail();
  const fixtureDir = mkdtempSync(path.join(tmpdir(), "gmail-mcp-e2e-"));
  writeFixtureStore(fixtureDir);
  const common = {
    GMAIL_MCP_ACCOUNTS_DIR: path.join(fixtureDir, "accounts"),
    GMAIL_MCP_CREDENTIALS: path.join(fixtureDir, "credentials.json"),
  };
  let port = 9361;

  try {
    // ---- Leg A: shared bearer, pull mode --------------------------------
    console.log("\nleg A: shared bearer + pull mode");
    const a = await bootServer(fake.port, { ...common, PORT: String(port++), MAIL_MODE: "pull", MCP_BEARER_TOKEN: SHARED, DEFAULT_EMAIL_ACCOUNT: ALICE });
    try {
      const client = await connect(a.base, SHARED);
      const names = await toolNames(client);
      ok("pull exposes list/get/modify/labels", ["gmail_list_messages", "gmail_get_message", "gmail_modify_message", "gmail_list_labels"].every((n) => names.includes(n)), names);
      ok("pull hides draft and send tools", !names.some((n) => n.includes("send") || n.includes("create_draft")));
      ok("settings tools stay hidden", !names.includes("gmail_update_vacation") && !names.includes("gmail_create_filter"));
      ok("dangerous tools stay hidden", !names.includes("gmail_delete_message") && !names.includes("gmail_send_raw"));

      const accounts = await call(client, "gmail_list_accounts");
      ok("accounts_list shows both mailboxes", accounts.text.includes(ALICE) && accounts.text.includes(BOB) && accounts.text.includes(`"default": "${ALICE}"`), accounts.text);

      const bob = await call(client, "gmail_list_messages", { account: BOB });
      ok("account routes to bob's mailbox", !bob.isError && bob.text.includes("m-bob-1"), bob);
      const alice = await call(client, "gmail_list_messages");
      ok("omitted account uses the default", !alice.isError && alice.text.includes("m-alice-1"), alice);
      const unknown = await call(client, "gmail_list_messages", { account: "zed@l92.test" });
      ok("unknown account fails with the signed-in list", unknown.isError && unknown.text.includes("zed@l92.test"), unknown);
    } finally { await stop(a); }

    // ---- Leg B: shared bearer, draft mode -------------------------------
    console.log("\nleg B: shared bearer + draft mode");
    const b = await bootServer(fake.port, { ...common, PORT: String(port++), MAIL_MODE: "draft", MCP_BEARER_TOKEN: SHARED });
    try {
      const client = await connect(b.base, SHARED);
      const names = await toolNames(client);
      ok("draft mode exposes create_draft", names.includes("gmail_create_draft"));
      ok("draft mode still hides send", !names.includes("gmail_send_message"));
      const draft = await call(client, "gmail_create_draft", { to: ["someone@example.org"], subject: "hi", text: "draft body" });
      ok("create_draft reaches the (fake) Gmail API", !draft.isError && draft.text.includes("draft-1"), draft);
    } finally { await stop(b); }

    // ---- Leg C: shared bearer, pull_push + allowlist --------------------
    console.log("\nleg C: shared bearer + pull_push + allowlist corp.com");
    const c = await bootServer(fake.port, { ...common, PORT: String(port++), MAIL_MODE: "pull_push", SEND_ALLOWLIST: "corp.com", MCP_BEARER_TOKEN: SHARED });
    try {
      const client = await connect(c.base, SHARED);
      const names = await toolNames(client);
      ok("pull_push exposes send and send_draft", names.includes("gmail_send_message") && names.includes("gmail_send_draft"));
      ok("raw send stays hidden without dangerous tools", !names.includes("gmail_send_raw"));

      const allowed = await call(client, "gmail_send_message", { to: ["friend@corp.com"], subject: "s", text: "body" });
      ok("send to an allowlisted domain succeeds", !allowed.isError, allowed);
      ok("fake Gmail received the allowed recipient", fake.state.sentTo.includes("friend@corp.com"), fake.state.sentTo);

      const refused = await call(client, "gmail_send_message", { to: ["friend@corp.com", "stranger@gmail.com"], subject: "s", text: "body" });
      ok("send outside the allowlist is refused at the tool boundary", refused.isError && refused.text.includes("SEND_ALLOWLIST") && refused.text.includes("stranger@gmail.com"), refused);
      ok("refused recipients never reach the API", !fake.state.sentTo.includes("stranger@gmail.com"), fake.state.sentTo);

      const goodDraft = await call(client, "gmail_create_draft", { to: ["corpfriend@corp.com"], subject: "s", text: "b" });
      ok("create_draft reaches the API", !goodDraft.isError, goodDraft);
      const draftId = (JSON.parse(goodDraft.text) as { id?: string }).id ?? "";
      const sentDraft = await call(client, "gmail_send_draft", { id: draftId });
      ok("send_draft resolves the draft and delivers to its stored recipient",
        !sentDraft.isError && fake.state.sentTo.includes("corpfriend@corp.com"), sentDraft);

      const badDraft = await call(client, "gmail_create_draft", { to: ["undercover@gmail.com"], subject: "s", text: "b" });
      const badId = (JSON.parse(badDraft.text) as { id?: string }).id ?? "";
      const refusedDraft = await call(client, "gmail_send_draft", { id: badId });
      ok("send_draft refuses a draft whose stored recipient is outside the allowlist",
        refusedDraft.isError && refusedDraft.text.includes("SEND_ALLOWLIST") && refusedDraft.text.includes("undercover@gmail.com"), refusedDraft);
      ok("refused drafts never reach the API", !fake.state.sentTo.includes("undercover@gmail.com"), fake.state.sentTo);
    } finally { await stop(c); }

    // ---- Leg D: per-account bearers (upstream compat) -------------------
    console.log("\nleg D: per-account bearers (upstream behavior)");
    const d = await bootServer(fake.port, { ...common, PORT: String(port++), MAIL_MODE: "pull" });
    try {
      const alice = await connect(d.base, "alice-mcp-token-0123456789abcdef");
      const accounts = await call(alice, "gmail_list_accounts");
      ok("alice's token binds to alice only", accounts.text.includes(ALICE) && !accounts.text.includes(BOB), accounts.text);
      const cross = await call(alice, "gmail_list_messages", { account: BOB });
      ok("cross-account access fails closed", cross.isError && cross.text.includes("Unknown account"), cross);
      const bobClient = await connect(d.base, "bob-mcp-token-0123456789abcdefg");
      const bobMail = await call(bobClient, "gmail_list_messages");
      ok("bob's token reads bob's mailbox", !bobMail.isError && bobMail.text.includes("m-bob-1"), bobMail);
    } finally { await stop(d); }

    // ---- Boot-time enforcement ------------------------------------------
    console.log("\nboot enforcement");
    const bad = spawnSync(process.execPath, [path.join(ROOT, "dist", "index.js")], {
      cwd: ROOT,
      env: { ...process.env, ...common, PORT: String(port++), MAIL_MODE: "pull_push", SEND_ALLOWLIST: "", GMAIL_MCP_KEYRING: "file" },
      encoding: "utf8",
      timeout: 15000,
    });
    ok("pull_push without SEND_ALLOWLIST refuses to boot", bad.status !== 0 && /SEND_ALLOWLIST/.test(bad.stderr), { status: bad.status, stderr: bad.stderr.slice(0, 200) });

    const short = spawnSync(process.execPath, [path.join(ROOT, "dist", "index.js")], {
      cwd: ROOT,
      env: { ...process.env, ...common, PORT: String(port++), MCP_BEARER_TOKEN: "short", MAIL_MODE: "pull", GMAIL_MCP_KEYRING: "file" },
      encoding: "utf8",
      timeout: 15000,
    });
    ok("a short MCP_BEARER_TOKEN refuses to boot", short.status !== 0 && /at least 32/.test(short.stderr), { status: short.status });
  } finally {
    await fake.close();
    rmSync(fixtureDir, { recursive: true, force: true });
  }

  console.log(failures === 0 ? "\ne2e: all expectations met." : `\ne2e: ${failures} expectation(s) failed.`);
  return failures === 0 ? 0 : 1;
};

main().then(
  (code) => process.exit(code),
  (err) => {
    console.error("e2e crashed:", err);
    process.exit(1);
  }
);
