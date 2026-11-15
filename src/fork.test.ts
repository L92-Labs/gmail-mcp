import { createServer, request } from "node:http";
import { createHash } from "node:crypto";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { gmail_v1 } from "googleapis";
import { authenticate, createRequestHandler, type HandlerOptions } from "./index.js";
import type { Features } from "./config.js";

const gmail = (marker: string, extra: Record<string, unknown> = {}) =>
  ({
    users: {
      settings: {},
      messages: {
        list: async () => ({ data: { messages: [{ id: marker }] } }),
        send: async (args: unknown) => ({ data: { id: "sent-1", ...extra, args } }),
      },
    },
    marker,
  }) as unknown as gmail_v1.Gmail;
const AMY = "amy@example.com";
const BOB = "bob@example.com";

const accounts = (tokens: Record<string, string>): HandlerOptions["accounts"] =>
  new Map(Object.entries(tokens).map(([email, token]) => [email, { gmail: gmail(email), token } as LoadedAccountLite]));

type LoadedAccountLite = { gmail: gmail_v1.Gmail; token: string };

const digestOf = (token: string) => createHash("sha256").update(token).digest("hex");
const SHARED = "s".repeat(48);

describe("authenticate with a shared token", () => {
  const tokenFor = async (email: string) => (email === AMY ? "amy-per-account" : "bob-per-account");
  const signedIn = accounts({ [AMY]: "unused1", [BOB]: "unused2" });

  it("authenticates any account behind the one shared token", async () => {
    const result = await authenticate(`Bearer ${SHARED}`, signedIn.keys(), tokenFor, SHARED);
    expect(result).toEqual({ email: "*", digest: digestOf(SHARED) });
  });

  it("still rejects wrong tokens in shared mode without consulting per-account tokens", async () => {
    expect(await authenticate("Bearer amy-per-account", signedIn.keys(), tokenFor, SHARED)).toBeUndefined();
    expect(await authenticate("Bearer nope", signedIn.keys(), tokenFor, SHARED)).toBeUndefined();
    expect(await authenticate(undefined, signedIn.keys(), tokenFor, SHARED)).toBeUndefined();
  });

  it("keeps per-account behavior when no shared token is configured", async () => {
    expect(await authenticate("Bearer amy-per-account", signedIn.keys(), tokenFor)).toEqual({
      email: AMY,
      digest: digestOf("amy-per-account"),
    });
  });
});

// --- HTTP harness for the unified-token session and tool gating ---
const initialize = { jsonrpc: "2.0", id: 1, method: "initialize",
  params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } } };
const headers = { "content-type": "application/json", accept: "application/json, text/event-stream" };

interface Harness { base: string; close: () => void; allowedHosts: string[] }

const boot = async (options: Omit<HandlerOptions, "host" | "port">): Promise<Harness> => {
  const server = createServer();
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as AddressInfo).port;
  const { handler, allowedHosts } = createRequestHandler({ ...options, host: "127.0.0.1", port });
  server.on("request", handler);
  return { base: `http://127.0.0.1:${port}`, close: () => server.close(), allowedHosts };
};

const openSession = async (base: string, token: string): Promise<string> => {
  const res = await fetch(`${base}/mcp`, { method: "POST", headers: { ...headers, authorization: `Bearer ${token}` }, body: JSON.stringify(initialize) });
  expect(res.status).toBe(200);
  await res.text();
  const sid = res.headers.get("mcp-session-id")!;
  await fetch(`${base}/mcp`, { method: "POST", headers: { ...headers, authorization: `Bearer ${token}`, "mcp-session-id": sid },
    body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) });
  return sid;
};

/** The SDK answers with JSON or SSE depending on negotiation; unwrap `data:` lines. */
const parseMcpResponse = (text: string): any => {
  if (text.startsWith("event:") || text.startsWith("data:")) {
    const data = text.split("\n").find((line) => line.startsWith("data: "));
    return JSON.parse(data!.slice("data: ".length));
  }
  return JSON.parse(text);
};

const rpc = async (base: string, sid: string, token: string, body: unknown): Promise<{ status: number; body: any }> => {
  const res = await fetch(`${base}/mcp`, { method: "POST", headers: { ...headers, authorization: `Bearer ${token}`, "mcp-session-id": sid }, body: JSON.stringify(body) });
  const text = await res.text();
  return { status: res.status, body: text ? parseMcpResponse(text) : undefined };
};

const toolNames = async (h: Harness, token: string): Promise<string[]> => {
  const sid = await openSession(h.base, token);
  const { body } = await rpc(h.base, sid, token, { jsonrpc: "2.0", id: 2, method: "tools/list" });
  return (body.result.tools as { name: string }[]).map((t) => t.name).sort();
};

const callTool = async (h: Harness, token: string, name: string, args: Record<string, unknown> = {}) => {
  const sid = await openSession(h.base, token);
  return rpc(h.base, sid, token, { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name, arguments: args } });
};

describe("unified bearer over HTTP", () => {
  let h: Harness;
  beforeAll(async () => {
    h = await boot({ accounts: accounts({ [AMY]: "unused1", [BOB]: "unused2" }), sharedToken: SHARED });
  });
  afterAll(() => h.close());

  it("accepts the shared token and exposes every signed-in account", async () => {
    const names = await toolNames(h, SHARED);
    expect(names).toContain("gmail_list_accounts");
    const { body } = await callTool(h, SHARED, "gmail_list_accounts");
    const parsed = JSON.parse(body.result.content[0].text);
    expect(parsed.accounts).toEqual([AMY, BOB]);
    expect(parsed.default).toBe(AMY); // first signed in
  });

  it("routes tool calls to the account named in `account`", async () => {
    const { body } = await callTool(h, SHARED, "gmail_list_messages", { account: BOB });
    expect(body.result.isError).toBeFalsy();
    expect(body.result.content[0].text).toContain(BOB);
  });

  it("rejects an unknown account and a wrong shared token", async () => {
    const { body } = await callTool(h, SHARED, "gmail_list_messages", { account: "mallory@example.com" });
    expect(body.result.isError).toBe(true);
    expect(body.result.content[0].text).toMatch(/Unknown account/);
    const sid = await openSession(h.base, SHARED);
    const bad = await rpc(h.base, sid, "w".repeat(48), { jsonrpc: "2.0", id: 9, method: "tools/list" });
    expect(bad.status).toBe(401);
  });

  it("serves multiple accounts across one session", async () => {
    const sid = await openSession(h.base, SHARED);
    const amy = await rpc(h.base, sid, SHARED, { jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "gmail_list_messages", arguments: { account: AMY } } });
    const bob = await rpc(h.base, sid, SHARED, { jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "gmail_list_messages", arguments: { account: BOB } } });
    expect(amy.body.result.content[0].text).toContain(AMY);
    expect(bob.body.result.content[0].text).toContain(BOB);
  });
});

describe("per-account bearers still bind sessions to one mailbox", () => {
  let h: Harness;
  beforeAll(async () => {
    h = await boot({ accounts: accounts({ [AMY]: "amy-token", [BOB]: "bob-token" }) });
  });
  afterAll(() => h.close());

  it("does not let one account's token see the other", async () => {
    const sid = await openSession(h.base, "amy-token");
    const { body } = await rpc(h.base, sid, "amy-token", { jsonrpc: "2.0", id: 6, method: "tools/call", params: { name: "gmail_list_messages", arguments: { account: BOB } } });
    expect(body.result.isError).toBe(true);
    expect(body.result.content[0].text).toMatch(/Unknown account/);
  });
});

describe("tool gating by mode", () => {
  it("pull mode exposes no send or draft tools", async () => {
    const h = await boot({ accounts: accounts({ [AMY]: "t1" }), sharedToken: SHARED, features: { mode: "pull", allowlist: [], settingsTools: false, workspaceTools: false, dangerousTools: false } });
    try {
      const names = await toolNames(h, SHARED);
      expect(names).toContain("gmail_list_messages");
      expect(names).not.toContain("gmail_send_message");
      expect(names).not.toContain("gmail_create_draft");
      expect(names).not.toContain("gmail_send_draft");
      expect(names).not.toContain("gmail_delete_message");
      expect(names).not.toContain("gmail_update_vacation");
      expect(names).not.toContain("gmail_list_delegates");
    } finally { h.close(); }
  });

  it("draft mode adds composing but not sending", async () => {
    const h = await boot({ accounts: accounts({ [AMY]: "t1" }), sharedToken: SHARED, features: { mode: "draft", allowlist: [], settingsTools: false, workspaceTools: false, dangerousTools: false } });
    try {
      const names = await toolNames(h, SHARED);
      expect(names).toContain("gmail_create_draft");
      expect(names).not.toContain("gmail_send_message");
    } finally { h.close(); }
  });

  it("pull_push with an allowlist exposes send and refuses outside recipients", async () => {
    const features: Features = { mode: "pull_push", allowlist: ["corp.com"], settingsTools: false, workspaceTools: false, dangerousTools: false };
    const h = await boot({ accounts: accounts({ [AMY]: "t1" }), sharedToken: SHARED, features });
    try {
      const names = await toolNames(h, SHARED);
      expect(names).toContain("gmail_send_message");
      expect(names).toContain("gmail_send_draft");
      expect(names).not.toContain("gmail_send_raw");

      const ok = await callTool(h, SHARED, "gmail_send_message", { to: ["friend@corp.com"], subject: "hi", text: "hello" });
      expect(ok.body.result.isError).toBeFalsy();

      const refused = await callTool(h, SHARED, "gmail_send_message", { to: ["victim@gmail.com"], subject: "hi", text: "hello" });
      expect(refused.body.result.isError).toBe(true);
      expect(refused.body.result.content[0].text).toMatch(/SEND_ALLOWLIST/);
    } finally { h.close(); }
  });

  it("registers the most restrictive set when features are omitted entirely", async () => {
    const h = await boot({ accounts: accounts({ [AMY]: "t1" }) });
    try {
      const names = await toolNames(h, "t1");
      expect(names).not.toContain("gmail_send_message");
      expect(names).not.toContain("gmail_create_draft");
    } finally { h.close(); }
  });
});

describe("extra hosts enter the rebinding allowlist", () => {
  it("accepts configured tunnel hostnames", async () => {
    const h = await boot({ accounts: accounts({ [AMY]: "t1" }), extraHosts: ["gmail.example.com"] });
    try {
      expect(h.allowedHosts).toContain("gmail.example.com");
      expect(h.allowedHosts.some((entry) => entry.startsWith("gmail.example.com:"))).toBe(true);
    } finally { h.close(); }
  });

  it("keeps port-bearing proxy entries exact instead of rewriting them", async () => {
    const h = await boot({ accounts: accounts({ [AMY]: "t1" }), extraHosts: ["mail.example.com:8443"] });
    try {
      expect(h.allowedHosts).toContain("mail.example.com:8443");
      expect(h.allowedHosts).not.toContain("mail.example.com");
    } finally { h.close(); }
  });
});
