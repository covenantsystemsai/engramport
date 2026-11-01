import { test } from "node:test";
import assert from "node:assert/strict";
import { AdminClient, adminUrlProblems, parseDuration, runAdmin } from "../src/admin.ts";

function capture() {
  const out: string[] = [];
  const err: string[] = [];
  return { io: { out: (l: string) => out.push(l), err: (l: string) => err.push(l) }, out, err };
}

const noDb = (): AdminClient => {
  throw new Error("this command must not open the database");
};

test("durations take d, h or m, and 0", () => {
  assert.equal(parseDuration("90d"), 90 * 86_400_000);
  assert.equal(parseDuration("24h"), 86_400_000);
  assert.equal(parseDuration("30m"), 1_800_000);
  assert.equal(parseDuration("0"), 0);
  for (const bad of ["", "5", "1w", "-1d", "1.5h", "99999d"]) assert.throws(() => parseDuration(bad), bad);
});

test("the admin URL must be postgres and must not weaken TLS", () => {
  assert.equal(adminUrlProblems(undefined).length, 1);
  assert.equal(adminUrlProblems("not a url").length, 1);
  assert.equal(adminUrlProblems("https://db.example.com/x").length, 1);
  assert.equal(adminUrlProblems("postgres://ops@db.example.com:5432/postgres?sslmode=disable").length, 1);
  assert.deepEqual(adminUrlProblems("postgres://ops@db.example.com:5432/postgres"), []);
  assert.deepEqual(adminUrlProblems("postgres://postgres@127.0.0.1:5432/x?sslmode=disable"), []);
});

test("usage errors exit 2 without touching the database", async () => {
  for (const argv of [[], ["key"], ["key", "explode"], ["key", "mint", "--namespace"], ["key", "mint", "--bogus", "x"], ["namespace", "create"]]) {
    const c = capture();
    assert.equal(await runAdmin(argv, noDb, c.io), 2, argv.join(" "));
    assert.match(c.err.join("\n"), /Usage: engramport admin/);
  }
});

test("help prints usage and exits 0", async () => {
  const c = capture();
  assert.equal(await runAdmin(["help"], noDb, c.io), 0);
  assert.match(c.out.join("\n"), /key mint/);
});

test("revoke refuses a whole key, so keys stay out of shell history", async () => {
  const c = capture();
  const code = await runAdmin(["key", "revoke", `ep_live_${"a".repeat(12)}.${"b".repeat(43)}`], noDb, c.io);
  assert.equal(code, 1);
  assert.match(c.err.join("\n"), /prefix/);
  assert.equal(c.out.length, 0);
});

test("a bad namespace path is refused before any database work", async () => {
  const c = capture();
  assert.equal(await runAdmin(["namespace", "create", "City/Tower"], noDb, c.io), 1);
  assert.equal(await runAdmin(["namespace", "create", "a/b/c/d"], noDb, c.io), 1);
});
