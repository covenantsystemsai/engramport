/**
 * The never-store write policy (D-07, docs/never-store.md), without a
 * database: what it refuses, what it lets through, that a refusal never
 * repeats the refused text, and that it fails closed.
 *
 * Secret-shaped samples are built at run time, so no real-looking credential
 * sits in this file for a secret scanner to trip on.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { enforceNeverStore, linkCarriesToken, NEVER_STORE_RULES, NeverStoreRefusal, scanText } from "../src/never-store.ts";
import { forPostgresStore } from "../src/tools/store-definitions.ts";
import { allToolDefinitions } from "../src/tools/index.ts";

const rep = (c: string, n: number) => c.repeat(n);
const SAMPLES = {
  secret: [
    `-----BEGIN ${"RSA "}PRIVATE KEY-----\nMIIB`,
    `ep_live_${rep("A", 22)}.${rep("b", 43)}`,
    `ep${"a"}_${rep("c", 43)}`,
    `ep${"r"}_${rep("d", 41)}-_`,
    `${"AK"}IA${rep("Q", 16)}`,
    `aws_secret_access_key = ${rep("x", 40)}`,
    `${"gh"}p_${rep("a", 36)}`,
    `github_pat_${rep("B", 30)}`,
    `${"xo"}xb-${rep("1", 12)}-abc`,
    `${"sk"}-ant-${rep("z", 30)}`,
    `${"sk"}-proj-${rep("z", 30)}`,
    `${"sk"}_live_${rep("Z", 24)}`,
    `${"AI"}za${rep("y", 35)}`,
    `GOCSPX-${rep("q", 28)}`,
    `sb_secret_${rep("s", 24)}`,
    `eyJ${rep("a", 12)}.eyJ${rep("b", 12)}.${rep("c", 20)}`,
    `Authorization: Bearer ${rep("t", 32)}`,
    "postgres://app:hunter2@db.example.com:5432/memory",
    "https://user:pw@files.example.com/report",
    "The lockbox code is 4471.",
    "password: x7!kQ",
    "Front door code: 1234#",
    "password: correcthorsebatterystaple",
    `Posts to https://hooks.${"slack"}.com/services/T0${"0".repeat(8)}/B0${"0".repeat(8)}/${"x".repeat(24)}.`,
  ],
  token_link: [
    "See https://drive.example.com/file/d/abc?token=deadbeef",
    "https://bucket.s3.amazonaws.com/a.pdf?X-Amz-Signature=abc&X-Amz-Credential=def",
    "Report at https://example.com/report(2026).pdf?token=opaque-value",
    `Long link https://example.com/${rep("a", 5000)}?sig=abc`,
    "Broken https://exa mple.com is not one link but https://[bad?token=abc is checked anyway",
    "Signed in at https://app.example.com/callback#access_token=abc",
    "https://example.com/callback#refresh_token=opaque-value",
    "https://example.com/cb#state=1&sig=abc",
  ],
  contact_detail: [
    "Reach the seller at jane.doe@example.com before Friday.",
    "Call (252) 555-0143 about the listing.",
    "Their cell is 919.555.0199.",
    "mailto:owner@example.org",
    "Email:alice@example.com",
    "email=alice@example.com&next",
    "<alice@example.com>",
    "Write to alice@example.com: she replies fast.",
  ],
  id_number: ["SSN 123-45-6789 on the form."],
  financial_number: [
    "Card 4111 1111 1111 1111 on file.",
    "Routing number 021000021 for the wire.",
    "Bank account #12345678 at the credit union.",
    "IBAN: GB82 WEST 1234 5698 7654 32",
    "Wire to DE89370400440532013000 today.",
    "IBAN: GB82 WEST 1234 5698 7654 32 FOR RENT",
    "IBAN: DE89370400440532013000 EUR",
  ],
  transcript: [
    "WEBVTT\n\n00:00:01.000 --> 00:00:04.000\nHello",
    "1\n00:00:01,000 --> 00:00:04,000\nHello",
    "[00:01] Sam: let's start\n[00:02] Lee: ok\n[00:05] Sam: first item",
    "00:00:12 Sam: hi\n00:00:15 Lee: hello\n00:00:20 Sam: agenda",
    "Speaker 1: hello\nSpeaker 2: hi\nSpeaker 1: let's go",
  ],
} as const;

const ALLOWED = [
  "Decision (Nov 3 meeting, owner role): task cards show the closing date first.",
  "Team: the account owners handle approvals; one assistant handles commissions workflow; one member is read-only.",
  "The key pepper lives in AWS Secrets Manager as engramport/pilot/key-pepper in AWS account 123456789012.",
  "Property PROP-2026-0042 (residential) closes 2026-12-01; inspection task open.",
  "Live version v2.2.1 from commit c15cbd1; see https://github.com/example/repo/pull/63.",
  "Agenda:\n9:00 Kickoff: intro\n9:30 Review: open items\n10:00 Wrap-up: next steps",
  "Status: waiting on the founder since Nov 4. Owner: build agent.",
  "Clone with git@github.com:example/repo.git",
  "The connector registered as client epc_abcdefghijklmnopqrstuvwx.",
  "The password is stored in the vault, never here.",
  "Ticket AB12 CDEF GHIJ KLMN 0 is a made-up code, not an IBAN.",
  "Town ordinance 7-12 checked 2026-11-01; source https://example.gov/ordinances?chapter=7",
];

for (const [rule, samples] of Object.entries(SAMPLES)) {
  test(`${rule}: each sample is refused`, () => {
    for (const s of samples) assert.equal(scanText(s), rule, s.slice(0, 40));
  });
}

test("ordinary memory text is let through", () => {
  for (const s of ALLOWED) assert.equal(scanText(s), null, s);
});

test("a refusal names the field and the kind, never the text", () => {
  const secret = `${"gh"}p_${rep("a", 36)}`;
  const logged: string[] = [];
  const orig = console.log;
  console.log = (...a: unknown[]) => void logged.push(a.join(" "));
  try {
    assert.throws(
      () => enforceNeverStore({ text: [["content", `token ${secret}`]] }),
      (err: unknown) => err instanceof NeverStoreRefusal && err.rule === "secret" && err.field === "content" &&
        !err.message.includes(secret) && /Nothing was stored/.test(err.message),
    );
  } finally {
    console.log = orig;
  }
  assert.equal(logged.length, 1);
  assert.ok(!logged[0].includes(secret));
  assert.deepEqual(JSON.parse(logged[0]), { event: "write_refused", policy: "never_store", rule: "secret", field: "content" });
});

test("metadata takes only flat, named fields that aren't never-store fields", () => {
  const ok = { topic: "billing", stage: "under_contract", tags: ["a", "b"], count: 3, done: false, note: null };
  enforceNeverStore({ metadata: ok });
  const refusedField = (metadata: unknown, field: string) =>
    assert.throws(() => enforceNeverStore({ metadata }), (e: unknown) => e instanceof NeverStoreRefusal && e.field === field);
  refusedField({ seller_email: "x" }, "metadata.seller_email");
  refusedField({ buyer_name: "x" }, "metadata.buyer_name");
  refusedField({ commission_rate: 3 }, "metadata.commission_rate");
  refusedField({ door_pin: "1" }, "metadata.door_pin");
  refusedField({ transcript: "x" }, "metadata.transcript");
  refusedField({ nested: { a: 1 } }, "metadata.nested");
  refusedField({ "Bad Key": 1 }, "metadata.<key>");
  refusedField({ long: rep("x", 1001) }, "metadata.long");
  refusedField({ list: Array(51).fill("a") }, "metadata.list");
  refusedField(["a"], "metadata");
  // A value is read as text too.
  assert.throws(() => enforceNeverStore({ metadata: { contact: "x@example.com" } }),
    (e: unknown) => e instanceof NeverStoreRefusal && e.rule === "contact_detail" && e.field === "metadata.contact");
  // A number is read like text: a card number sent as a JSON number is refused.
  assert.throws(() => enforceNeverStore({ metadata: { reference: 4111111111111111 } }),
    (e: unknown) => e instanceof NeverStoreRefusal && e.rule === "financial_number" && e.field === "metadata.reference");
  assert.throws(() => enforceNeverStore({ metadata: { refs: [1, 4111111111111111] } }),
    (e: unknown) => e instanceof NeverStoreRefusal && e.rule === "financial_number");
  enforceNeverStore({ metadata: { count: 42, ratio: 0.5, year: 2026 } });
  // A secret in a key is refused, and the key is never named in the answer or the log.
  const keySecret = `${"gh"}p_${"a".repeat(36)}`;
  const logged: string[] = [];
  const orig = console.log;
  console.log = (...a: unknown[]) => void logged.push(a.join(" "));
  try {
    for (const value of ["fine", "x@example.com"]) {
      assert.throws(() => enforceNeverStore({ metadata: { [keySecret]: value } }),
        (e: unknown) => e instanceof NeverStoreRefusal && e.rule === "secret" && e.field === "metadata.<key>" &&
          !e.message.includes(keySecret));
    }
  } finally {
    console.log = orig;
  }
  assert.ok(logged.length === 2 && logged.every((l) => !l.includes(keySecret)));
  // "fee" is a key part; "feedback" isn't.
  enforceNeverStore({ metadata: { feedback: "fine" } });
});

test("a source link is plain https with no password or token", () => {
  enforceNeverStore({ sourceUrl: "https://github.com/example/repo/issues/75" });
  for (const [url, rule] of [
    ["http://example.com/meeting", "field"],
    ["not a url", "field"],
    ["https://u:p@example.com/x", "token_link"],
    ["https://example.com/x?sig=abc", "token_link"],
    ["https://example.com/x?Signature=abc", "token_link"],
  ] as const) {
    assert.throws(() => enforceNeverStore({ sourceUrl: url }), (e: unknown) => e instanceof NeverStoreRefusal && e.rule === rule, url);
  }
  assert.equal(linkCarriesToken("https://example.com/a?chapter=7&page=2"), false);
});

test("transcript files are refused by name", () => {
  for (const f of ["meeting.vtt", "call.srt", "Nov 3 transcript.txt", "x.SBV"]) {
    assert.throws(() => enforceNeverStore({ filename: f }), (e: unknown) => e instanceof NeverStoreRefusal && e.rule === "transcript", f);
  }
  enforceNeverStore({ filename: "ordinance-ch7.pdf.txt", text: [["content", "Section 7.1 Setbacks."]] });
});

test("it fails closed: a check that breaks refuses the write", () => {
  const orig = console.log;
  console.log = () => {};
  try {
    assert.throws(
      () => enforceNeverStore({ text: [["content", "fine"]] }, () => { throw new Error("boom"); }),
      (e: unknown) => e instanceof NeverStoreRefusal && e.rule === "unavailable",
    );
  } finally {
    console.log = orig;
  }
});

test("long hostile inputs are checked quickly", () => {
  const inputs = [
    `https://${rep("a", 2000)}:${rep("b", 20000)}`,
    rep("a@", 10000),
    rep("1-", 10000),
    rep("password is ", 2000),
    rep("[00:01] x", 3000),
    `${rep("x", 19990)}@example.com`,
    `https://example.com/${rep("!", 2000)}x`,
    rep("!", 300) + "@" + rep("!", 19),
  ];
  for (const s of inputs) {
    const t = performance.now();
    scanText(s);
    assert.ok(performance.now() - t < 500, `took too long on ${s.slice(0, 20)}`);
  }
});

test("every write tool states the rules; read tools don't", () => {
  const defs = forPostgresStore(allToolDefinitions) as Array<{ name: string; description?: string }>;
  for (const name of ["remember", "upload", "link", "supersede_memory"]) {
    const d = defs.find((x) => x.name === name);
    assert.ok(d?.description?.includes(NEVER_STORE_RULES), name);
  }
  assert.ok(!defs.find((x) => x.name === "recall")?.description?.includes(NEVER_STORE_RULES));
});
