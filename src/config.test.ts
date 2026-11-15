import { describe, expect, it } from "vitest";
import { parseConfig, recipientAllowed } from "./config.js";

const base = {
  MAIL_MODE: "pull",
  MCP_BEARER_TOKEN: "x".repeat(40),
  SEND_ALLOWLIST: "",
} as Record<string, string>;

describe("parseConfig", () => {
  it("defaults to pull mode with no shared token and the Google API root", () => {
    const config = parseConfig({ MAIL_MODE: undefined, MCP_BEARER_TOKEN: undefined });
    expect(config.mode).toBe("pull");
    expect(config.sharedToken).toBeUndefined();
    expect(config.allowlist).toEqual([]);
    expect(config.apiRoot).toBe("https://gmail.googleapis.com/");
    expect(config.defaultAccount).toBeUndefined();
  });

  it("keeps the documented mode set", () => {
    expect(parseConfig({ MAIL_MODE: "pull" }).mode).toBe("pull");
    expect(parseConfig({ MAIL_MODE: "draft" }).mode).toBe("draft");
    expect(parseConfig({ MAIL_MODE: "pull_push", SEND_ALLOWLIST: "corp.com" }).mode).toBe("pull_push");
  });

  it("rejects an unknown MAIL_MODE", () => {
    expect(() => parseConfig({ MAIL_MODE: "read_write" })).toThrow(/MAIL_MODE/);
  });

  it("refuses pull_push without an allowlist (prompt-injection guard)", () => {
    expect(() => parseConfig({ MAIL_MODE: "pull_push", SEND_ALLOWLIST: "" })).toThrow(/SEND_ALLOWLIST/);
    expect(() => parseConfig({ MAIL_MODE: "pull_push", SEND_ALLOWLIST: undefined })).toThrow(/SEND_ALLOWLIST/);
    expect(parseConfig({ MAIL_MODE: "pull_push", SEND_ALLOWLIST: "corp.com" }).allowlist).toEqual(["corp.com"]);
  });

  it("refuses an allowlist in pull mode, where no send tools exist", () => {
    expect(() => parseConfig({ MAIL_MODE: "pull", SEND_ALLOWLIST: "corp.com" })).toThrow(/MAIL_MODE=pull/);
  });

  it("rejects a short unified bearer token", () => {
    expect(() => parseConfig({ MCP_BEARER_TOKEN: "short" })).toThrow(/at least 32/);
    const token = "x".repeat(32);
    expect(parseConfig({ MCP_BEARER_TOKEN: token }).sharedToken).toBe(token);
    // Whitespace-only counts as unset, matching mail-mcp's optional-key behavior.
    expect(parseConfig({ MCP_BEARER_TOKEN: "   " }).sharedToken).toBeUndefined();
  });

  it("normalizes the default account", () => {
    expect(parseConfig({ DEFAULT_EMAIL_ACCOUNT: "  Bob@Example.COM " }).defaultAccount).toBe("bob@example.com");
  });

  it("keeps port-bearing proxy hosts exact and lowercases the rest", () => {
    expect(parseConfig({ MCP_ALLOWED_HOSTS: "Mail.Example.com:8443, alt.example.com" }).extraHosts).toEqual([
      "mail.example.com:8443",
      "alt.example.com",
    ]);
    expect(() => parseConfig({ MCP_ALLOWED_HOSTS: " , " })).toThrow(/MCP_ALLOWED_HOSTS/);
  });

  it("normalizes the API root and rejects junk", () => {
    expect(parseConfig({ GMAIL_MCP_API_ROOT: "http://127.0.0.1:9901" }).apiRoot).toBe("http://127.0.0.1:9901/");
    expect(() => parseConfig({ GMAIL_MCP_API_ROOT: "not a url" })).toThrow(/GMAIL_MCP_API_ROOT/);
  });

  it("derives narrow scopes per mode and never requests the full mail scope implicitly", () => {
    const scopes = (env: Record<string, string>) => parseConfig(env).scopes;
    const pull = scopes({ MAIL_MODE: "pull" });
    expect(pull).toContain("https://www.googleapis.com/auth/gmail.modify");
    expect(pull).toContain("https://www.googleapis.com/auth/gmail.labels");
    expect(pull).not.toContain("https://www.googleapis.com/auth/gmail.compose");
    expect(pull).not.toContain("https://mail.google.com/");

    expect(scopes({ MAIL_MODE: "draft" })).toContain("https://www.googleapis.com/auth/gmail.compose");
    expect(scopes({ MAIL_MODE: "pull_push", SEND_ALLOWLIST: "corp.com" })).toContain(
      "https://www.googleapis.com/auth/gmail.compose"
    );

    const withSettings = scopes({ MAIL_MODE: "pull", ENABLE_SETTINGS_TOOLS: "true" });
    expect(withSettings).toContain("https://www.googleapis.com/auth/gmail.settings.basic");
    expect(withSettings).toContain("https://www.googleapis.com/auth/gmail.settings.sharing");
  });

  it("allows dangerous tools only with an explicit full-scope override", () => {
    expect(() =>
      parseConfig({ ENABLE_DANGEROUS_TOOLS: "true" })
    ).toThrow(/mail\.google\.com/);
    const explicit = parseConfig({
      ENABLE_DANGEROUS_TOOLS: "true",
      GMAIL_MCP_SCOPES: "https://mail.google.com/, https://www.googleapis.com/auth/gmail.settings.basic",
    });
    expect(explicit.scopes).toContain("https://mail.google.com/");
    expect(explicit.dangerousTools).toBe(true);
  });

  it("honors a GMAIL_MCP_SCOPES override", () => {
    const config = parseConfig({ GMAIL_MCP_SCOPES: "a b\nhttps://www.googleapis.com/auth/gmail.readonly" });
    expect(config.scopes).toEqual(["a", "b", "https://www.googleapis.com/auth/gmail.readonly"]);
  });

  it("accepts every valid config at once and reports all problems together", () => {
    const config = parseConfig({
      ...base,
      MAIL_MODE: "pull_push",
      SEND_ALLOWLIST: "Corp.com,boss@corp.com",
      DEFAULT_EMAIL_ACCOUNT: "work@corp.com",
      MCP_ALLOWED_HOSTS: "gmail.example.com",
    });
    expect(config.mode).toBe("pull_push");
    expect(config.allowlist).toEqual(["corp.com", "boss@corp.com"]);
    expect(config.defaultAccount).toBe("work@corp.com");
    expect(config.extraHosts).toEqual(["gmail.example.com"]);
  });

  it("collects multiple errors into one message", () => {
    try {
      parseConfig({ MAIL_MODE: "bogus", MCP_BEARER_TOKEN: "tiny" });
      expect.unreachable();
    } catch (err) {
      const message = (err as Error).message;
      expect(message).toMatch(/MAIL_MODE/);
      expect(message).toMatch(/MCP_BEARER_TOKEN/);
    }
  });
});

describe("recipientAllowed", () => {
  const allowlist = ["corp.com", "boss@personal.example", "exact@corp.com"];

  it("validates every mailbox inside one comma-separated string", () => {
    expect(recipientAllowed("friend@corp.com, other@corp.com", allowlist)).toBe(true);
    expect(recipientAllowed("outsider@evil.test, friend@corp.com", allowlist)).toBe(false);
    expect(recipientAllowed("friend@corp.com, exact@corp.com", allowlist)).toBe(true);
  });

  it("validates display-name forms by the address after the last @", () => {
    expect(recipientAllowed("Bob Smith <friend@corp.com>", allowlist)).toBe(true);
    expect(recipientAllowed("Bob <friend@corp.com>, Eve <evil@test.io>", allowlist)).toBe(false);
  });

  it("rejects RFC comment syntax instead of guessing the real recipient", () => {
    // The parenthesized text is a comment; the delivery address sits before it.
    expect(recipientAllowed("outsider@evil.test (friend <friend@corp.com>)", allowlist)).toBe(false);
    expect(recipientAllowed("(comment) friend@corp.com", allowlist)).toBe(false);
  });

  it("validates every bracketed mailbox, not just the first pair", () => {
    expect(recipientAllowed('"Bob" <friend@corp.com>', allowlist)).toBe(true);
    expect(recipientAllowed("a<one@corp.com> b<two@corp.com>", allowlist)).toBe(true);
    expect(recipientAllowed('"<friend@corp.com>" <outsider@evil.test>', allowlist)).toBe(false);
    expect(recipientAllowed("friend@corp.com> <evil@test.io", allowlist)).toBe(false);
    expect(recipientAllowed("evil@test.io Bob <friend@corp.com>", allowlist)).toBe(false);
  });

  it("fails closed on segments without an @", () => {
    expect(recipientAllowed("not-an-address", allowlist)).toBe(false);
    expect(recipientAllowed("friend@corp.com, garbage", allowlist)).toBe(false);
  });

  it("matches exact addresses and domain entries", () => {
    expect(recipientAllowed("boss@personal.example", allowlist)).toBe(true);
    expect(recipientAllowed("anyone@corp.com", allowlist)).toBe(true);
    expect(recipientAllowed("exact@corp.com", allowlist)).toBe(true);
  });

  it("matches subdomains of a domain entry", () => {
    expect(recipientAllowed("a@mail.corp.com", allowlist)).toBe(true);
    expect(recipientAllowed("x@deep.sub.corp.com", allowlist)).toBe(true);
  });

  it("refuses sibling or lookalike domains and unknown addresses", () => {
    expect(recipientAllowed("x@notcorp.com", allowlist)).toBe(false);
    expect(recipientAllowed("x@evil-corp.com", allowlist)).toBe(false);
    expect(recipientAllowed("x@corpanything.com", allowlist)).toBe(false);
    expect(recipientAllowed("stranger@personal.example", allowlist)).toBe(false);
  });

  it("is case-insensitive and trims", () => {
    expect(recipientAllowed("  BOSS@Personal.Example ", allowlist)).toBe(true);
    expect(recipientAllowed("Someone@CORP.COM", allowlist)).toBe(true);
  });

  it("handles recipients without an @ defensively", () => {
    expect(recipientAllowed("corp.com", ["corp.com"])).toBe(false);
    expect(recipientAllowed("nowhere", ["corp.com"])).toBe(false);
  });
});
