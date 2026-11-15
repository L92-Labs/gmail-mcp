import { describe, expect, it } from "vitest";
import type { McpServer, ToolCallback } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { gmail_v1 } from "googleapis";
import { z } from "zod";
import { registerTools } from "./tools.js";
import type { Accounts } from "./tools.js";
import type { Features } from "./config.js";

// Records `users.messages.send` style paths and the single argument each call received.
const recordingGmail = () => {
  const calls: { path: string; args: unknown }[] = [];
  const make = (trail: string[]): unknown =>
    new Proxy(() => {}, {
      get: (_t, prop) => (typeof prop === "string" ? make([...trail, prop]) : undefined),
      apply: (_t, _this, [args]) => {
        calls.push({ path: trail.join("."), args });
        return Promise.resolve({ data: { ok: true, data: Buffer.from("bytes").toString("base64url") } });
      },
    });
  return { gmail: make([]) as unknown as gmail_v1.Gmail, calls };
};

type Registered = { shape: z.ZodRawShape; handler: ToolCallback<z.ZodRawShape> };
const collect = (accounts: Accounts) => {
  const tools = new Map<string, Registered>();
  const server = {
    registerTool: (name: string, config: { inputSchema: z.ZodRawShape }, handler: ToolCallback<z.ZodRawShape>) =>
      tools.set(name, { shape: config.inputSchema, handler }),
  } as unknown as McpServer;
  registerTools(server, accounts);
  return tools;
};

// Minimal valid input for a zod shape: required fields get a placeholder, optionals are left out.
const sample = (schema: z.ZodType): unknown => {
  const def = (schema as unknown as { _zod: { def: Record<string, unknown> } })._zod.def;
  switch (def.type) {
    case "optional": case "default": return sample(def.innerType as z.ZodType);
    case "string": return "x";
    case "number": return 1;
    case "boolean": return true;
    case "enum": return Object.values(def.entries as Record<string, string>)[0];
    case "array": return [sample(def.element as z.ZodType)];
    case "record": return {};
    case "object": return fill(def.shape as z.ZodRawShape);
    default: throw new Error(`unhandled zod type ${String(def.type)}`);
  }
};
const fill = (shape: z.ZodRawShape) =>
  Object.fromEntries(
    Object.entries(shape)
      .filter(([, s]) => (s as unknown as { _zod: { def: { type: string } } })._zod.def.type !== "optional")
      .map(([k, s]) => [k, sample(s as z.ZodType)])
  );

const invoke = async (t: Registered, args: Record<string, unknown>) =>
  t.handler(z.object(t.shape).parse(args), {} as never);

describe("registerTools", () => {
  const amy = recordingGmail();
  const bob = recordingGmail();
  // Fork: the sweep runs with every gate open (pull_push + all optional families), which
  // registers the same full surface the upstream tests were written against. The gate
  // behavior itself is asserted in the fork describes below.
  const fullFeatures: Features = { mode: "pull_push", allowlist: ["b"], settingsTools: true, workspaceTools: true, dangerousTools: true };
  const accounts: Accounts = {
    clients: new Map([["amy@example.com", amy.gmail], ["bob@example.com", bob.gmail]]),
    default: "amy@example.com",
    features: fullFeatures,
  };
  const tools = collect(accounts);
  // Tools that legitimately contact Google more than once per invocation, plus the
  // account listing tool, are checked in dedicated tests instead of the uniform sweeps.
  // send_message joins them: its allowlist guard rejects empty recipient sets, so the
  // generic fill() sweep cannot drive it; dedicated tests cover it instead.
  const skipUniform = new Set(["gmail_list_accounts", "gmail_send_draft", "gmail_send_message"]);

  it("registers all 80 users.* endpoints plus 1 account tool", () => {
    expect(tools.size).toBe(81);
    expect(tools.has("gmail_set_default_account")).toBe(false);
  });

  it("every tool reaches exactly one googleapis method with its required input and returns JSON text", async () => {
    for (const [name, t] of tools) {
      if (skipUniform.has(name)) continue;
      amy.calls.length = 0;
      const result = await invoke(t, fill(t.shape));
      expect(amy.calls, name).toHaveLength(1);
      expect(amy.calls[0].path, name).toMatch(/^users\./);
      expect(() => JSON.parse((result.content[0] as { text: string }).text), name).not.toThrow();
    }
  });

  it("every Gmail tool accepts an optional account and, when omitted, calls the default account's client", async () => {
    for (const [name, t] of tools) {
      if (skipUniform.has(name)) continue;
      expect(t.shape.account, name).toBeDefined();
      amy.calls.length = 0;
      bob.calls.length = 0;
      await invoke(t, fill(t.shape));
      expect(amy.calls.length, name).toBe(1);
      expect(bob.calls.length, name).toBe(0);
      expect(amy.calls[0].args, name).not.toHaveProperty("account");
    }
  });

  it("routes to the named account, case-insensitively", async () => {
    bob.calls.length = 0;
    await invoke(tools.get("gmail_get_profile")!, { account: "Bob@Example.com" });
    expect(bob.calls.map((c) => c.path)).toEqual(["users.getProfile"]);
  });

  it("treats a blank account as omitted and routes to the default account", async () => {
    amy.calls.length = 0;
    await invoke(tools.get("gmail_get_profile")!, { account: "  " });
    expect(amy.calls.map((c) => c.path)).toEqual(["users.getProfile"]);
  });

  it("rejects an unknown account before touching Google, listing what is signed in", async () => {
    amy.calls.length = 0;
    await expect(invoke(tools.get("gmail_get_profile")!, { account: "zed@example.com" }))
      .rejects.toThrow(/Unknown account "zed@example.com".*amy@example.com, bob@example.com.*gmail-mcp auth/);
    expect(amy.calls.length).toBe(0);
  });

  it("rejects a path-traversal-shaped account before touching Google", async () => {
    amy.calls.length = 0;
    await expect(invoke(tools.get("gmail_get_profile")!, { account: "../amy@example.com" })).rejects.toThrow(/Invalid account/);
    expect(amy.calls.length).toBe(0);
  });

  it.each([
    ["gmail_send_message", { to: ["a@b"], text: "hi" }, "users.messages.send", (a: any) => a.userId === "me" && typeof a.requestBody.raw === "string"],
    ["gmail_insert_message", { text: "hi", labelIds: ["INBOX"], deleted: false }, "users.messages.insert", (a: any) => a.requestBody.labelIds[0] === "INBOX" && a.deleted === false],
    ["gmail_modify_message", { id: "m", addLabelIds: ["STARRED"] }, "users.messages.modify", (a: any) => a.id === "m" && a.requestBody.addLabelIds[0] === "STARRED"],
    ["gmail_batch_delete_messages", { ids: ["a", "b"] }, "users.messages.batchDelete", (a: any) => a.requestBody.ids.length === 2],
    ["gmail_update_draft", { id: "d", userId: "u@x", text: "t" }, "users.drafts.update", (a: any) => a.userId === "u@x" && a.id === "d" && typeof a.requestBody.message.raw === "string"],
    ["gmail_create_filter", { criteria: { from: "x" }, action: { addLabelIds: ["L"] } }, "users.settings.filters.create", (a: any) => a.requestBody.criteria.from === "x"],
    ["gmail_patch_cse_identity", { emailAddress: "e", identity: { primaryKeyPairId: "k" } }, "users.settings.cse.identities.patch", (a: any) => a.emailAddress === "e" && a.requestBody.primaryKeyPairId === "k"],
    ["gmail_enable_cse_keypair", { keyPairId: "k" }, "users.settings.cse.keypairs.enable", (a: any) => a.keyPairId === "k" && typeof a.requestBody === "object"],
    ["gmail_watch", { topicName: "projects/p/topics/t" }, "users.watch", (a: any) => a.requestBody.topicName.endsWith("/t")],
  ])("%s places its parameters where googleapis expects", async (name, args, path, check) => {
    amy.calls.length = 0;
    await invoke(tools.get(name)!, args);
    expect(amy.calls[0].path).toBe(path);
    expect(check(amy.calls[0].args)).toBe(true);
  });

  it("gmail_get_message decodes format=full and passes other formats through", async () => {
    const parsed = await invoke(tools.get("gmail_get_message")!, { id: "m" });
    expect(JSON.parse((parsed.content[0] as { text: string }).text)).toMatchObject({ headers: {}, attachments: [] });
    const raw = await invoke(tools.get("gmail_get_message")!, { id: "m", format: "raw" });
    expect(JSON.parse((raw.content[0] as { text: string }).text)).toMatchObject({ ok: true });
  });

  it("gmail_get_attachment returns standard base64 of the base64url payload", async () => {
    const r = await invoke(tools.get("gmail_get_attachment")!, { messageId: "m", id: "a" });
    expect(JSON.parse((r.content[0] as { text: string }).text)).toEqual({ size: 5, data: Buffer.from("bytes").toString("base64") });
  });

  it("gmail_list_accounts reports the signed-in accounts and the bound one", async () => {
    const list = await invoke(tools.get("gmail_list_accounts")!, {});
    expect(JSON.parse((list.content[0] as { text: string }).text)).toEqual({ accounts: ["amy@example.com", "bob@example.com"], default: "amy@example.com" });
  });

  it("wraps Google auth errors with the account and the command that fixes them", async () => {
    const failing = { users: { getProfile: () => Promise.reject(Object.assign(new Error("invalid_grant"), { code: 400 })), settings: {} } } as unknown as gmail_v1.Gmail;
    const t = collect({ clients: new Map([["amy@example.com", failing]]), default: "amy@example.com" }).get("gmail_get_profile")!;
    await expect(invoke(t, {})).rejects.toThrow(/amy@example\.com.*gmail-mcp auth/);
  });

  it("wraps a 403 insufficient-scope error on gmail_get_profile with the account and the fix", async () => {
    const failing = {
      users: { getProfile: () => Promise.reject(Object.assign(new Error("insufficient scope"), { code: 403 })), settings: {} },
    } as unknown as gmail_v1.Gmail;
    const t = collect({ clients: new Map([["amy@example.com", failing]]), default: "amy@example.com" }).get("gmail_get_profile")!;
    // explain()'s 403-scope message puts the raw Google error last, after the `gmail-mcp auth` fix
    // instruction, so this checks the account + fix + raw error text in the order they actually appear.
    await expect(invoke(t, {})).rejects.toThrow(/amy@example\.com.*gmail-mcp auth.*insufficient scope/);
  });

  it("wraps a failing messages.get on gmail_get_message with the account and the fix", async () => {
    const failing = {
      users: { messages: { get: () => Promise.reject(Object.assign(new Error("invalid_grant"), { code: 400 })) }, settings: {} },
    } as unknown as gmail_v1.Gmail;
    const t = collect({ clients: new Map([["amy@example.com", failing]]), default: "amy@example.com", features: fullFeatures }).get("gmail_get_message")!;
    await expect(invoke(t, { id: "m" })).rejects.toThrow(/amy@example\.com.*gmail-mcp auth/);
  });
});

// ---- Fork: mode gating and the send allowlist ----

// A fake whose drafts.get returns the raw RFC 822 source, so the send_draft guard
// validates and forwards the exact snapshot. The guard must fetch via users.drafts.get
// (draft ids are not message ids) and hand the SAME raw to users.messages.send — the
// fake exposes no drafts.send and no messages.get, so any other path fails.
const draftWithRaw = (rfc822: string, onSend: (raw: string) => void) => {
  const gmail = {
    users: {
      drafts: {
        get: async () => ({
          data: { id: "d", message: { raw: Buffer.from(rfc822, "utf8").toString("base64url"), threadId: "t1" } },
        }),
      },
      messages: {
        send: async (args: { requestBody: { raw?: string } }) => {
          const raw = Buffer.from(args.requestBody.raw ?? "", "base64url").toString("utf8");
          onSend(raw);
          return { data: { id: "sent-1", labelIds: ["SENT"] } };
        },
      },
      settings: {},
    },
  };
  return gmail as unknown as gmail_v1.Gmail;
};

describe("fork gating", () => {
  const pullPush = (allowlist: string[]): Features => ({
    mode: "pull_push",
    allowlist,
    settingsTools: false,
    workspaceTools: false,
    dangerousTools: false,
  });

  it("send_draft validates the stored snapshot and sends those exact bytes", async () => {
    let sentRaw = "";
    const source = "To: friend@corp.com\r\nSubject: hi\r\n\r\nbody";
    const draft = draftWithRaw(source, (raw) => { sentRaw = raw; });
    const tools = collect({ clients: new Map([["amy@example.com", draft]]), default: "amy@example.com", features: pullPush(["corp.com"]) });
    await invoke(tools.get("gmail_send_draft")!, { id: "d" });
    // Bound to the validated snapshot: the outgoing raw is byte-identical to what was
    // checked, so a concurrent update_draft cannot change what goes out.
    expect(sentRaw).toBe(source);
  });

  it("send_draft understands quoted display names and folded recipient headers", async () => {
    let sent = false;
    const source = 'To: "Doe, Jane" <jane@corp.com>\r\nCc: one@corp.com,\r\n two@corp.com\r\n\r\nbody';
    const draft = draftWithRaw(source, () => { sent = true; });
    const tools = collect({ clients: new Map([["amy@example.com", draft]]), default: "amy@example.com", features: pullPush(["corp.com"]) });
    await invoke(tools.get("gmail_send_draft")!, { id: "d" });
    expect(sent).toBe(true);
  });

  it("send_draft refuses stored recipients outside the allowlist, before sending", async () => {
    let sent = false;
    const draft = draftWithRaw("To: friend@corp.com, victim@gmail.com\r\n\r\nbody", () => { sent = true; });
    const tools = collect({ clients: new Map([["amy@example.com", draft]]), default: "amy@example.com", features: pullPush(["corp.com"]) });
    await expect(invoke(tools.get("gmail_send_draft")!, { id: "d" })).rejects.toThrow(/SEND_ALLOWLIST.*victim@gmail\.com/);
    expect(sent).toBe(false);
  });

  it("send_draft ignores a To: line inside the body and refuses Resent-* headers", async () => {
    const trick = "To: friend@corp.com\r\n\r\nignore this line please\r\nTo: victim@gmail.com\r\n";
    let sent = false;
    const draft = draftWithRaw(trick, () => { sent = true; });
    const tools = collect({ clients: new Map([["amy@example.com", draft]]), default: "amy@example.com", features: pullPush(["corp.com"]) });
    await invoke(tools.get("gmail_send_draft")!, { id: "d" });
    expect(sent).toBe(true); // the body line is not a recipient header

    const resent = draftWithRaw("Resent-To: outsider@evil.test\r\nTo: friend@corp.com\r\n\r\nbody", () => { sent = true; });
    const tools2 = collect({ clients: new Map([["amy@example.com", resent]]), default: "amy@example.com", features: pullPush(["corp.com"]) });
    await expect(invoke(tools2.get("gmail_send_draft")!, { id: "d" })).rejects.toThrow(/Resent-/);
    expect(sent).toBe(true); // unchanged by the refused call
  });

  it("send_message refuses recipient headers smuggled through custom headers", async () => {
    const amy = recordingGmail();
    const tools = collect({ clients: new Map([["amy@example.com", amy.gmail]]), default: "amy@example.com", features: pullPush(["corp.com"]) });
    await expect(
      invoke(tools.get("gmail_send_message")!, { to: ["friend@corp.com"], text: "hi", headers: { To: "outsider@evil.test" } })
    ).rejects.toThrow(/headers.*must not carry recipient headers/i);
    expect(amy.calls).toHaveLength(0);
  });

  it("send_message normalizes header names like buildRaw before checking", async () => {
    const amy = recordingGmail();
    const tools = collect({ clients: new Map([["amy@example.com", amy.gmail]]), default: "amy@example.com", features: pullPush(["corp.com"]) });
    // buildRaw strips colons and surrounding whitespace, so "B:cc" serializes as `Bcc`.
    await expect(
      invoke(tools.get("gmail_send_message")!, { to: ["friend@corp.com"], text: "hi", headers: { "B:cc": "outsider@evil.test" } })
    ).rejects.toThrow(/must not carry recipient headers/i);
    await expect(
      invoke(tools.get("gmail_send_message")!, { to: ["friend@corp.com"], text: "hi", headers: { "To :": "outsider@evil.test" } })
    ).rejects.toThrow(/must not carry recipient headers/i);
    expect(amy.calls).toHaveLength(0);
  });

  it("send_message refuses recipient headers even when arrays are absent", async () => {
    const amy = recordingGmail();
    const tools = collect({ clients: new Map([["amy@example.com", amy.gmail]]), default: "amy@example.com", features: pullPush(["corp.com"]) });
    await expect(
      invoke(tools.get("gmail_send_message")!, { text: "hi", headers: { "Resent-To": "boss@corp.com" } })
    ).rejects.toThrow(/resent-to/i);
    expect(amy.calls).toHaveLength(0);
  });

  it("send_message refuses outside recipients before touching Google", async () => {
    const amy = recordingGmail();
    const tools = collect({ clients: new Map([["amy@example.com", amy.gmail]]), default: "amy@example.com", features: pullPush(["corp.com"]) });
    await expect(
      invoke(tools.get("gmail_send_message")!, { to: ["friend@corp.com", "stranger@gmail.com"], text: "hi" })
    ).rejects.toThrow(/SEND_ALLOWLIST.*stranger@gmail\.com/);
    expect(amy.calls).toHaveLength(0);
  });

  it("defaults to pull mode with every optional tool family off when features are omitted", () => {
    const amy = recordingGmail();
    const names = new Set(
      collect({ clients: new Map([["amy@example.com", amy.gmail]]), default: "amy@example.com" }).keys()
    );
    for (const gated of [
      "gmail_send_message", "gmail_send_raw", "gmail_send_draft", "gmail_create_draft", "gmail_update_draft",
      "gmail_delete_message", "gmail_batch_delete_messages", "gmail_delete_thread", "gmail_insert_message",
      "gmail_import_message", "gmail_update_vacation", "gmail_create_filter", "gmail_update_auto_forwarding",
      "gmail_list_delegates", "gmail_insert_smime_info", "gmail_create_cse_keypair",
    ]) {
      expect(names.has(gated), gated).toBe(false);
    }
    for (const open of [
      "gmail_list_messages", "gmail_get_message", "gmail_modify_message", "gmail_batch_modify_messages",
      "gmail_trash_message", "gmail_list_labels", "gmail_create_label", "gmail_get_thread", "gmail_list_history",
      "gmail_list_drafts", "gmail_get_draft", "gmail_get_attachment", "gmail_watch", "gmail_stop",
    ]) {
      expect(names.has(open), open).toBe(true);
    }
  });
});
