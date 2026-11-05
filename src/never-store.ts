/**
 * The never-store write policy (founder decision D-07, docs/never-store.md).
 *
 * Every write path into shared memory passes through `enforceNeverStore`
 * before anything is stored: remember, supersede_memory, upload and link,
 * and graph rows written by extraction. A refusal names the field and the
 * kind of item, never the matched text, and is logged the same way.
 *
 * It fails closed. The checks are part of the server, with no setting that
 * turns them off, and if a check itself throws, the write is refused.
 *
 * What it can and can't catch, said plainly (D-07 follow-on decision 9):
 *   - secrets with a known shape (keys, tokens, private keys, connection
 *     strings with a password, password and door-code statements) and links
 *     that carry a token or a signature;
 *   - email addresses, US-style phone numbers, social security numbers, card
 *     numbers that pass the Luhn check, and account or routing numbers named
 *     as such;
 *   - transcripts with timestamps or speaker labels, and transcript files;
 *   - metadata keys that name a never-store field, and metadata nested more
 *     than one level;
 *   - links that aren't plain https.
 * It can't recognise a name, a home address or a dollar figure in free text
 * reliably. Those rest on the agents' instructions and the owner's review,
 * and neither is a guarantee.
 */

/** What kind of never-store item a refusal is about. */
export type NeverStoreRule =
  | "secret"
  | "token_link"
  | "contact_detail"
  | "id_number"
  | "financial_number"
  | "transcript"
  | "field"
  | "unavailable";

const RULE_TEXT: Record<NeverStoreRule, string> = {
  secret: "looks like a secret (a key, token, password or code)",
  token_link: "has a link that carries a token or a signature",
  contact_detail: "has contact details (an email address or a phone number)",
  id_number: "has what looks like an ID number",
  financial_number: "has what looks like a card, bank account or routing number",
  transcript: "looks like a meeting transcript",
  field: "isn't a field shared memory may hold",
  unavailable: "couldn't be checked, so it was refused",
};

/** A write the policy refused. Its message never repeats the refused text. */
export class NeverStoreRefusal extends Error {
  constructor(readonly rule: NeverStoreRule, readonly field: string) {
    super(
      `Refused by the never-store policy (docs/never-store.md): ${field} ${RULE_TEXT[rule]}. ` +
        "Nothing was stored. Store a paraphrase, or a reference to where the item lives, instead.",
    );
    this.name = "NeverStoreRefusal";
  }
}

/** The short rule agents see in tool descriptions. */
export const NEVER_STORE_RULES =
  "Never store secrets (keys, tokens, passwords, codes), links that carry a token, contact details, " +
  "ID, card or account numbers, names of transaction parties, transaction figures, or meeting " +
  "transcripts or verbatim quotes; paraphrase and link to the source instead. The server refuses " +
  "what it can detect (docs/never-store.md).";

// ─── text checks ─────────────────────────────────────────────────────────────
// Every pattern here is linear: bounded quantifiers, no nested repetition, so a
// long input can't make a check slow.

const SECRET_PATTERNS: RegExp[] = [
  /-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----/,
  /\bep_live_[A-Za-z0-9]{8,}/, // EngramPort's own keys
  /\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/, // AWS access key ids
  /\baws_secret_access_key\s{0,3}[:=]\s{0,3}\S{16,}/i,
  /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}/, // GitHub tokens
  /\bgithub_pat_[A-Za-z0-9_]{20,}/,
  /\bglpat-[A-Za-z0-9_-]{20,}/, // GitLab
  /\bxox[abposr]-[A-Za-z0-9-]{10,}/, // Slack tokens
  /\bhooks\.slack\.com\/services\/[A-Za-z0-9/]{10,}/,
  /\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}/, // OpenAI, Anthropic
  /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}/, // Stripe secret and restricted keys
  /\bwhsec_[A-Za-z0-9]{16,}/,
  /\bAIza[0-9A-Za-z_-]{35}/, // Google API keys
  /\bGOCSPX-[A-Za-z0-9_-]{20,}/, // Google OAuth client secrets
  /\bya29\.[A-Za-z0-9_-]{20,}/, // Google access tokens
  /\bsb_secret_[A-Za-z0-9_-]{16,}/, // Supabase secret keys
  /\bnpm_[A-Za-z0-9]{30,}/,
  /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/, // JWTs
  /\bbearer\s{1,3}[A-Za-z0-9._~+/-]{20,}/i,
  // A URL with a password in it: scheme://user:password@host
  /\b[a-z][a-z0-9+.-]{1,20}:\/\/[^\s:/@]{1,256}:[^\s@/]{1,256}@/i,
  // "password: x7!k", "door code is 4471": a statement of a secret's value
  /\b(?:password|passwd|passphrase|passcode|pin\s{0,3}code|door\s{0,3}code|gate\s{0,3}code|alarm\s{0,3}code|lockbox\s{0,3}code|access\s{0,3}code|combination)\s{0,3}(?:[:=]|\bis\b)\s{0,3}["'`]?[^\s"'`]{0,40}[0-9!@#$%^&*][^\s"'`]{0,40}/i,
];

/** Query parameters that make a link a credential by itself. */
const TOKEN_PARAMS = new Set([
  "token", "access_token", "id_token", "refresh_token", "auth", "authkey", "auth_token", "apikey", "api_key",
  "key", "sig", "signature", "code", "password", "pwd", "secret", "client_secret", "session", "sessionid",
  "x-amz-signature", "x-amz-credential", "x-amz-security-token", "x-goog-signature", "x-goog-credential",
  "googleaccessid", "se", "sv", "sp", "jwt", "otp", "magic", "invite",
]);

/** A link carries a token if it has a password in it or a token-bearing parameter. */
export function linkCarriesToken(raw: string): boolean {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  if (url.password || url.username) return true;
  for (const name of url.searchParams.keys()) {
    if (TOKEN_PARAMS.has(name.toLowerCase())) return true;
  }
  // Some sign-in and share links carry the token in the fragment.
  if (/(?:^|[#&])(?:access_token|id_token|token|code)=/i.test(url.hash)) return true;
  return false;
}

const URL_IN_TEXT = /\bhttps?:\/\/[^\s<>"'`)\]]{1,2048}/gi;
const EMAIL = /^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,8}\.[A-Za-z]{2,24}$/;
const PHONE = /(?:\+?1[\s.-]{0,2})?(?:\(\s{0,2}[2-9]\d{2}\s{0,2}\)\s{0,2}|\b[2-9]\d{2}[\s.-]{1,2})[2-9]\d{2}[\s.-]{1,2}\d{4}\b/;
const SSN = /\b\d{3}-\d{2}-\d{4}\b/;
const CARD_CANDIDATE = /\b\d(?:[ -]?\d){12,18}\b/g;
// Named bank details only: an AWS account id, which the policy lets agents
// store as a location, is not a bank account.
const ACCOUNT = /\b(?:routing|aba|iban|(?:bank|checking|savings)\s{1,3}(?:account|acct))\s{0,3}(?:number|no\.?|#)?\s{0,3}[:#]?\s{0,3}[0-9][0-9 -]{5,30}[0-9]\b/i;

function luhn(digits: string): boolean {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

// Transcripts: subtitle files, or several lines that start with a timestamp
// or a numbered speaker label.
const VTT_OR_SRT = /^\uFEFF?WEBVTT\b|\d{2}:\d{2}:\d{2}[,.]\d{3}\s{0,3}-->\s{0,3}\d{2}:\d{2}:\d{2}/m;
// A bracketed time, or one with seconds, then a speaker: "[00:12] Sam: ..." or
// "00:01:23 Sam: ...". A plain "9:00 Kickoff:" agenda line doesn't count.
const TIMESTAMPED_TURN = /^\s{0,8}(?:[[(]\d{1,2}:\d{2}(?::\d{2})?(?:[.,]\d{1,3})?[\])]|\d{1,2}:\d{2}:\d{2}(?:[.,]\d{1,3})?)\s{0,4}[-–—]?\s{0,4}[A-Za-z][^:\n]{0,40}:\s{0,4}\S/;
const SPEAKER_LABEL = /^\s{0,8}(?:speaker|participant|caller|interviewer|interviewee)\s{0,2}[0-9A-Z]{0,3}\s{0,2}:\s{0,4}\S/i;
const TRANSCRIPT_TURNS = 3;

function looksLikeTranscript(text: string): boolean {
  if (VTT_OR_SRT.test(text)) return true;
  let turns = 0;
  for (const line of text.split("\n")) {
    if (line.length > 2000) continue;
    if (TIMESTAMPED_TURN.test(line) || SPEAKER_LABEL.test(line)) {
      turns += 1;
      if (turns >= TRANSCRIPT_TURNS) return true;
    }
  }
  return false;
}

/** The first never-store item found in one piece of text, or null. */
export function scanText(text: string): NeverStoreRule | null {
  for (const p of SECRET_PATTERNS) if (p.test(text)) return "secret";
  for (const m of text.matchAll(URL_IN_TEXT)) {
    if (linkCarriesToken(m[0].replace(/[.,;:!?]+$/, ""))) return "token_link";
  }
  for (const word of text.split(/[\s,;<>()[\]{}"'`]+/)) {
    if (word.length > 320 || !word.includes("@")) continue;
    const trimmed = word.replace(/^[^A-Za-z0-9]+|[^A-Za-z0-9]+$/g, "").replace(/^mailto:/i, "");
    if (EMAIL.test(trimmed)) return "contact_detail";
  }
  if (PHONE.test(text)) return "contact_detail";
  if (SSN.test(text)) return "id_number";
  if (ACCOUNT.test(text)) return "financial_number";
  for (const m of text.matchAll(CARD_CANDIDATE)) {
    const digits = m[0].replace(/[ -]/g, "");
    if (digits.length >= 13 && digits.length <= 19 && luhn(digits)) return "financial_number";
  }
  if (looksLikeTranscript(text)) return "transcript";
  return null;
}

// ─── structured fields ───────────────────────────────────────────────────────

const META_KEY = /^[a-z][a-z0-9_]{0,47}$/;
const META_MAX_KEYS = 32;
const META_MAX_STRING = 1000;
const META_MAX_ARRAY = 50;

/** Parts of a metadata key that name a never-store field (D-07 sections 1 to 3). */
const DENIED_KEY_PARTS = new Set([
  // secrets
  "password", "passwd", "pwd", "passcode", "secret", "token", "credential", "credentials", "apikey", "bearer",
  "cookie", "otp", "pin",
  // contact details and identity
  "email", "phone", "mobile", "fax", "address", "street", "zip", "zipcode", "postal", "postcode", "ssn", "dob",
  "birthday", "birthdate", "passport", "license", "licence",
  // financial
  "routing", "iban", "card", "cvv", "cvc", "commission", "fee", "fees", "split", "payment", "payments", "price",
  "amount", "salary", "income", "balance",
  // transaction parties and meetings
  "buyer", "buyers", "seller", "sellers", "tenant", "landlord", "transcript", "quote", "verbatim",
]);

function deniedKey(key: string): boolean {
  return key.split("_").some((part) => DENIED_KEY_PARTS.has(part));
}

type Field = [path: string, value: unknown];

function metadataFields(metadata: unknown): Field[] {
  if (metadata === undefined || metadata === null) return [];
  if (typeof metadata !== "object" || Array.isArray(metadata)) throw new NeverStoreRefusal("field", "metadata");
  const entries = Object.entries(metadata as Record<string, unknown>);
  if (entries.length > META_MAX_KEYS) throw new NeverStoreRefusal("field", "metadata");
  const out: Field[] = [];
  for (const [key, value] of entries) {
    const path = `metadata.${META_KEY.test(key) ? key : "<key>"}`;
    if (!META_KEY.test(key) || deniedKey(key)) throw new NeverStoreRefusal("field", path);
    const values = Array.isArray(value) ? value : [value];
    if (Array.isArray(value) && value.length > META_MAX_ARRAY) throw new NeverStoreRefusal("field", path);
    for (const v of values) {
      if (v === null || typeof v === "boolean" || (typeof v === "number" && Number.isFinite(v))) continue;
      if (typeof v === "string" && v.length <= META_MAX_STRING) {
        out.push([path, v]);
        continue;
      }
      // Nested objects, long strings and anything else: not a shape shared memory takes.
      throw new NeverStoreRefusal("field", path);
    }
  }
  return out;
}

/** A source link: plain https, no password, no token. */
function checkSourceUrl(raw: unknown, path: string): Field[] {
  if (raw === undefined || raw === null || raw === "") return [];
  if (typeof raw !== "string" || raw.length > 2048) throw new NeverStoreRefusal("field", path);
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new NeverStoreRefusal("field", path);
  }
  if (url.protocol !== "https:") throw new NeverStoreRefusal("field", path);
  if (linkCarriesToken(raw)) throw new NeverStoreRefusal("token_link", path);
  return [[path, raw]];
}

const TRANSCRIPT_FILE = /\.(?:vtt|srt|sbv|ttml|dfxp)$|transcript/i;

// ─── the entry point ─────────────────────────────────────────────────────────

/** What a write carries, by the field it came in. */
export interface WriteFields {
  /** Free text: content, reason, dedup key, entity names, evidence and the like. */
  text?: Array<[path: string, value: unknown]>;
  metadata?: unknown;
  sourceUrl?: unknown;
  filename?: unknown;
}

export type TextScanner = (text: string) => NeverStoreRule | null;

/**
 * Refuses the write if anything in it is a never-store item. Throws
 * NeverStoreRefusal; returns nothing when the write may go ahead.
 */
export function enforceNeverStore(fields: WriteFields, scan: TextScanner = scanText): void {
  try {
    const all: Field[] = [...(fields.text ?? [])];
    all.push(...metadataFields(fields.metadata));
    all.push(...checkSourceUrl(fields.sourceUrl, "source_url"));
    if (fields.filename !== undefined && fields.filename !== null) {
      if (typeof fields.filename !== "string") throw new NeverStoreRefusal("field", "filename");
      if (TRANSCRIPT_FILE.test(fields.filename)) throw new NeverStoreRefusal("transcript", "filename");
      all.push(["filename", fields.filename]);
    }
    for (const [path, value] of all) {
      if (value === undefined || value === null) continue;
      if (typeof value !== "string") continue; // shape is checked where the field is parsed
      const rule = scan(value);
      if (rule) throw new NeverStoreRefusal(rule, path);
    }
  } catch (err) {
    const refusal = err instanceof NeverStoreRefusal ? err : new NeverStoreRefusal("unavailable", "the write");
    logRefusal(refusal);
    throw refusal;
  }
}

/** One line per refusal: which rule and field, never the text. */
function logRefusal(r: NeverStoreRefusal): void {
  console.log(JSON.stringify({ event: "write_refused", policy: "never_store", rule: r.rule, field: r.field }));
}
