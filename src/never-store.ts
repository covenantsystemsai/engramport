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
  /\bep[ar]_[A-Za-z0-9_-]{40,}/, // EngramPort's OAuth codes (epa_) and refresh tokens (epr_)
  /\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/, // AWS access key ids
  /\baws_secret_access_key\s{0,3}[:=]\s{0,3}\S{16,}/i,
  /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}/, // GitHub tokens
  /\bgithub_pat_[A-Za-z0-9_]{20,}/,
  /\bglpat-[A-Za-z0-9_-]{20,}/, // GitLab
  /\bxox[abposr]-[A-Za-z0-9-]{10,}/, // Slack tokens
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
  // "password: x7!kQ", "door code is 4471". An assignment (colon or equals)
  // counts whatever the value; with "is", the value must have a digit or a
  // symbol, so "the password is stored in the vault" reads as prose.
  /\b(?:password|passwd|passphrase|passcode|pin\s{0,3}code|door\s{0,3}code|gate\s{0,3}code|alarm\s{0,3}code|lockbox\s{0,3}code|access\s{0,3}code|combination)\s{0,3}[:=]\s{0,3}["'`]?[^\s"'`]{4,}/i,
  /\b(?:password|passwd|passphrase|passcode|pin\s{0,3}code|door\s{0,3}code|gate\s{0,3}code|alarm\s{0,3}code|lockbox\s{0,3}code|access\s{0,3}code|combination)\s{0,3}\bis\b\s{0,3}["'`]?[^\s"'`]{0,40}[0-9!@#$%^&*][^\s"'`]{0,40}/i,
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
    // Not parseable as a whole: read its parameter names by hand, so a broken
    // link is never a way past the check.
    const q = raw.search(/[?#]/);
    if (q < 0) return false;
    return raw.slice(q + 1).split(/[&#;]/).some((pair) => {
      const name = pair.split("=")[0];
      return TOKEN_PARAMS.has(name.toLowerCase());
    });
  }
  if (url.password || url.username) return true;
  for (const name of url.searchParams.keys()) {
    if (TOKEN_PARAMS.has(name.toLowerCase())) return true;
  }
  // Some sign-in and share links carry the token in the fragment: the same
  // names count there as in the query string.
  for (const name of new URLSearchParams(url.hash.slice(1)).keys()) {
    if (TOKEN_PARAMS.has(name.toLowerCase())) return true;
  }
  return false;
}

// The whole link up to whitespace or a quote, brackets included, with no
// length cutoff, so a token later in a long link is still seen.
const URL_IN_TEXT = /\bhttps?:\/\/[^\s<>"'`]+/gi;
const EMAIL = /^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,8}\.[A-Za-z]{2,24}$/;
const PHONE = /(?:\+?1[\s.-]{0,2})?(?:\(\s{0,2}[2-9]\d{2}\s{0,2}\)\s{0,2}|\b[2-9]\d{2}[\s.-]{1,2})[2-9]\d{2}[\s.-]{1,2}\d{4}\b/;
const SSN = /\b\d{3}-\d{2}-\d{4}\b/;
const CARD_CANDIDATE = /\b\d(?:[ -]?\d){12,18}\b/g;
// Named bank details only: an AWS account id, which the policy lets agents
// store as a location, is not a bank account.
// An IBAN: two letters, two check digits, then 11 to 30 letters or digits,
// confirmed by its mod-97 check so ordinary codes don't match.
const IBAN_CANDIDATE = /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b/g;

function ibanValid(raw: string): boolean {
  const s = raw.replace(/ /g, "");
  if (s.length < 15 || s.length > 34) return false;
  const moved = s.slice(4) + s.slice(0, 4);
  let rem = 0;
  for (const ch of moved) {
    const c = ch.charCodeAt(0);
    const v = c >= 65 ? String(c - 55) : ch;
    for (const d of v) rem = (rem * 10 + (d.charCodeAt(0) - 48)) % 97;
  }
  return rem === 1;
}

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
/** A webhook URL that posts by itself, with no other credential. */
function isWebhook(raw: string): boolean {
  try {
    const url = new URL(raw);
    return url.hostname === "hooks.slack.com" && url.pathname.startsWith("/services/");
  } catch {
    return false;
  }
}

const isAlnum = (c: number) => (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122);
const TRAILING_PUNCTUATION = new Set([".", ",", ";", ":", "!", "?"]);

const isLocalChar = (c: number) => isAlnum(c) || c === 46 || c === 95 || c === 37 || c === 43 || c === 45; // . _ % + -
const isDomainChar = (c: number) => isAlnum(c) || c === 46 || c === 45; // . -

/**
 * Whether the text holds an email address, wherever it sits: after a label
 * ("Email:x@y.com", "email=x@y.com"), in brackets or mid-sentence. Each "@"
 * is read at most 64 characters back and 253 forward, so the scan stays
 * linear. "git@github.com:org/repo" (an SSH remote, a host followed by a
 * colon and a path) is not an address.
 */
function hasEmail(text: string): boolean {
  for (let at = text.indexOf("@"); at >= 0; at = text.indexOf("@", at + 1)) {
    let start = at;
    while (start > 0 && at - start < 64 && isLocalChar(text.charCodeAt(start - 1))) start -= 1;
    let end = at + 1;
    while (end < text.length && end - at <= 253 && isDomainChar(text.charCodeAt(end))) end += 1;
    const local = trimEnds(text.slice(start, at), (ch) => ch === ".");
    const domain = trimEnds(text.slice(at + 1, end), (ch) => ch === "." || ch === "-");
    if (!local || !domain) continue;
    const after = text.charCodeAt(at + 1 + domain.length);
    const next = text.charCodeAt(at + 2 + domain.length);
    // host:path, as in an SSH remote
    if (after === 58 && !Number.isNaN(next) && next !== 32 && next !== 10) continue;
    if (EMAIL.test(`${local}@${domain}`)) return true;
  }
  return false;
}

/** Strips characters from both ends while `junk` says so, in one pass each way. */
function trimEnds(s: string, junk: (ch: string) => boolean): string {
  let start = 0;
  let end = s.length;
  while (start < end && junk(s[start])) start += 1;
  while (end > start && junk(s[end - 1])) end -= 1;
  return s.slice(start, end);
}

export function scanText(text: string): NeverStoreRule | null {
  for (const p of SECRET_PATTERNS) if (p.test(text)) return "secret";
  for (const m of text.matchAll(URL_IN_TEXT)) {
    let end = m[0].length;
    while (end > 0 && TRAILING_PUNCTUATION.has(m[0][end - 1])) end -= 1;
    const url = m[0].slice(0, end);
    if (isWebhook(url)) return "secret";
    if (linkCarriesToken(url)) return "token_link";
  }
  if (hasEmail(text)) return "contact_detail";
  if (PHONE.test(text)) return "contact_detail";
  if (SSN.test(text)) return "id_number";
  if (ACCOUNT.test(text)) return "financial_number";
  for (const m of text.matchAll(IBAN_CANDIDATE)) {
    if (ibanValid(m[0])) return "financial_number";
  }
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
    // A key is checked like text before it is named anywhere, so a refusal or
    // a log line never repeats a secret that was put in a key.
    if (!META_KEY.test(key)) throw new NeverStoreRefusal("field", "metadata.<key>");
    const keyRule = scanText(key);
    if (keyRule) throw new NeverStoreRefusal(keyRule, "metadata.<key>");
    const path = `metadata.${key}`;
    if (deniedKey(key)) throw new NeverStoreRefusal("field", path);
    const values = Array.isArray(value) ? value : [value];
    if (Array.isArray(value) && value.length > META_MAX_ARRAY) throw new NeverStoreRefusal("field", path);
    for (const v of values) {
      if (v === null || typeof v === "boolean") continue;
      if (typeof v === "number" && Number.isFinite(v)) {
        // A card or account number sent as a JSON number is read like text.
        out.push([path, Number.isInteger(v) ? BigInt(v).toString() : String(v)]);
        continue;
      }
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
