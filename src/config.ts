/**
 * L92-Labs fork enforcement layer: parses every guardrail from the environment and
 * fails closed at startup. Modeled on L92-Labs/mail-mcp's plain KEY=value conventions
 * (MAIL_MODE, SEND_ALLOWLIST, MCP_BEARER_TOKEN) so both servers deploy the same way.
 *
 * Nothing here trusts a default the operator did not choose: sending exists only in
 * pull_push AND requires a non-empty allowlist; the full `mail.google.com` scope is
 * never requested implicitly; dangerous and Workspace-only tools are off by default.
 */

export type MailMode = "pull" | "draft" | "pull_push";
const MODES: readonly MailMode[] = ["pull", "draft", "pull_push"];

export interface Features {
  /** pull = read + organize, draft = + save drafts, pull_push = + send (allowlist required). */
  mode: MailMode;
  /** Recipients send may touch: exact addresses or domains (subdomains match). */
  allowlist: string[];
  /** Gmail settings tools (vacation, IMAP/POP, language, filters, forwarding, send-as). */
  settingsTools: boolean;
  /** Workspace-only tools (delegates, S/MIME, CSE). Dead weight on consumer accounts. */
  workspaceTools: boolean;
  /** Permanent delete, raw send, and mailbox import/insert. Needs the full mail scope. */
  dangerousTools: boolean;
}

export interface ServerConfig extends Features {
  /** Unified bearer: one token grants every signed-in account (portal-friendly). */
  sharedToken?: string;
  /** Account used when `account` is omitted. Defaults to the first signed in. */
  defaultAccount?: string;
  /** Extra Host header values accepted alongside loopback (reverse proxies/tunnels). */
  extraHosts: string[];
  /** Gmail REST root; override points at a test double in e2e. */
  apiRoot: string;
  /** OAuth scopes the next `gmail-mcp auth` will request. */
  scopes: string[];
}

export const API_ROOT_DEFAULT = "https://gmail.googleapis.com/";
const FULL_MAIL_SCOPE = "https://mail.google.com/";

const bool = (raw: string | undefined): boolean =>
  raw !== undefined && ["1", "true", "yes"].includes(raw.trim().toLowerCase());

const list = (raw: string | undefined): string[] =>
  (raw ?? "")
    .split(/[,\s]+/)
    .map((entry) => entry.trim().toLowerCase())
    .filter(Boolean);

const mailboxAllowed = (mailbox: string, allowlist: string[]): boolean => {
  const at = mailbox.lastIndexOf("@");
  if (at <= 0) return false;
  const domain = mailbox.slice(at + 1);
  return allowlist.some((entry) => mailbox === entry || domain === entry || domain.endsWith(`.${entry}`));
};

/**
 * One comma-free chunk of a recipient string. Parsing is deliberately structural and
 * rejects anything ambiguous instead of guessing: comment syntax `(...)` and stray `@`
 * outside angle brackets are delivery addresses this guard will not vouch for.
 */
const segmentAllowed = (part: string, allowlist: string[]): boolean => {
  if (/[()]/.test(part)) return false; // RFC comment syntax is not parsed — fail closed.
  const pairs = [...part.matchAll(/<([^<>]*)>/g)].map((m) => m[1]!.trim().toLowerCase()).filter(Boolean);
  if (pairs.length === 0) {
    // Bare mailbox: exactly one @, otherwise the syntax is unsupported.
    if ((part.match(/@/g) ?? []).length !== 1) return false;
    return mailboxAllowed(part, allowlist);
  }
  // Every bracketed mailbox must pass, and no unbracketed @ may remain — a second
  // address outside the brackets would not be the one that was validated.
  const residue = part.replace(/<[^<>]*>/g, "");
  if (residue.includes("@")) return false;
  return pairs.every((mailbox) => mailboxAllowed(mailbox, allowlist));
};

/**
 * Every mailbox represented by `recipient` must pass: one string may carry several
 * addresses ("a@x.test, b@y.test" or several <addr> forms) and display names are fine
 * as long as no @ sits outside the brackets. Allowlist entry forms: exact address, or
 * bare domain (subdomains match).
 */
export const recipientAllowed = (recipient: string, allowlist: string[]): boolean => {
  const parts = recipient.split(",").map((part) => part.trim().toLowerCase()).filter(Boolean);
  if (parts.length === 0) return false;
  return parts.every((part) => segmentAllowed(part, allowlist));
};

export const recipientAllowedBy = (allowlist: string[]) => (recipient: string): boolean =>
  recipientAllowed(recipient, allowlist);

const normalizeRoot = (raw: string): string => (/^https?:\/\/\S+/.test(raw) ? (raw.endsWith("/") ? raw : `${raw}/`) : "");

const deriveScopes = (f: Features): string[] => {
  const base = ["https://www.googleapis.com/auth/gmail.modify", "https://www.googleapis.com/auth/gmail.labels"];
  const scopes = [...base];
  if (f.mode !== "pull") scopes.push("https://www.googleapis.com/auth/gmail.compose");
  if (f.settingsTools || f.workspaceTools) {
    scopes.push(
      "https://www.googleapis.com/auth/gmail.settings.basic",
      "https://www.googleapis.com/auth/gmail.settings.sharing"
    );
  }
  return scopes;
};

const describeMode = (mode: MailMode): string =>
  mode === "pull"
    ? "read and organize only"
    : mode === "draft"
      ? "read, organize and save drafts"
      : "read, organize, save drafts and send (allowlist enforced)";
export { describeMode };

/**
 * Parses `env` and throws with every problem it found, so a bad deployment fails at
 * boot instead of at first tool call. `errors` let tests assert individual messages.
 */
export const parseConfig = (
  env: Record<string, string | undefined> = process.env
): ServerConfig => {
  const errors: string[] = [];

  const rawMode = (env.MAIL_MODE ?? "pull").trim().toLowerCase();
  if (!MODES.includes(rawMode as MailMode)) {
    errors.push(`Set MAIL_MODE to one of: ${MODES.join(", ")} (got "${rawMode}")`);
  }
  const mode = rawMode as MailMode;

  const allowlist = list(env.SEND_ALLOWLIST);
  if (mode === "pull_push" && allowlist.length === 0) {
    errors.push("MAIL_MODE=pull_push requires a non-empty SEND_ALLOWLIST (prompt-injection guard; empty is not accepted in this fork)");
  }
  if (allowlist.length > 0 && mode === "pull") {
    errors.push("SEND_ALLOWLIST is set but MAIL_MODE=pull exposes no send tools; set MAIL_MODE=draft or pull_push");
  }

  const rawToken = env.MCP_BEARER_TOKEN?.trim();
  if (rawToken !== undefined && rawToken !== "" && rawToken.length < 32) {
    errors.push("MCP_BEARER_TOKEN must have at least 32 characters (openssl rand -hex 32)");
  }

  // Port-bearing entries stay exact ("example.com:8443"); bare hostnames are widened
  // with the server's listening port by the request handler.
  const extraHosts = list(env.MCP_ALLOWED_HOSTS);
  if (env.MCP_ALLOWED_HOSTS && extraHosts.length === 0) {
    errors.push('MCP_ALLOWED_HOSTS is set but parsed to nothing; use comma-separated hostnames like "mail.example.com"');
  }

  const apiRoot = normalizeRoot(env.GMAIL_MCP_API_ROOT?.trim() || API_ROOT_DEFAULT);
  if (!apiRoot) errors.push(`GMAIL_MCP_API_ROOT must be an http(s) URL (got "${env.GMAIL_MCP_API_ROOT}")`);

  const settingsTools = bool(env.ENABLE_SETTINGS_TOOLS);
  const workspaceTools = bool(env.ENABLE_WORKSPACE_TOOLS);
  const dangerousTools = bool(env.ENABLE_DANGEROUS_TOOLS);

  const override = list(env.GMAIL_MCP_SCOPES);
  const scopes = override.length > 0 ? override : deriveScopes({ mode, allowlist, settingsTools, workspaceTools, dangerousTools });
  // The full mail scope is the only path to permanent delete and raw send. It is never
  // derived implicitly, so enabling dangerous tools demands it be granted on purpose.
  if (dangerousTools && !scopes.includes(FULL_MAIL_SCOPE)) {
    errors.push(
      "ENABLE_DANGEROUS_TOOLS=true needs the full mail scope; add https://mail.google.com/ to GMAIL_MCP_SCOPES explicitly"
    );
  }

  if (errors.length > 0) throw new Error(`Invalid gmail-mcp settings:\n- ${errors.join("\n- ")}`);

  return {
    mode,
    allowlist,
    settingsTools,
    workspaceTools,
    dangerousTools,
    sharedToken: rawToken || undefined,
    defaultAccount: env.DEFAULT_EMAIL_ACCOUNT?.trim().toLowerCase() || undefined,
    extraHosts,
    apiRoot,
    scopes,
  };
};
