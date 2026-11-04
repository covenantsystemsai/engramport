# Erasure (founder decision D-02)

Agents ask. People erase. Nothing of the text is left anywhere it can be found.

This page is the deletion contract: what erasure removes, what it keeps, who can
order it, and what happens after a restore from a backup. The database side is
`db/migrations/0022_erasure.sql`; its tests are `db/test/erasure_test.sql` and
`db/test/erasure_race_test.sh`.

## The decision

Founder decision D-02, decided Nov 4:

- **Authority.** Only an authenticated namespace owner, or a delegate given that
  power explicitly, orders an erasure. Agents can propose one and never carry it
  out. The content-blind admin can't do either.
- **Scope.** One request names at most 100 memories. Larger jobs go in separately
  authorized batches or through whole-cell erasure.
- **Whole-cell erasure.** The owner starts it; a different authenticated person
  with AN2B governance authority confirms after seeing the impact preview. The
  person who started it can't be the second. Decided Nov 4 (D-02.1a): that
  authority is a dedicated cell-erasure-confirmer role, explicitly assigned to
  a named person who accepts it with their own sign-in, scoped, expiring or
  revocable, and separate from approving memories. The confirmer sees no
  memory content and can't start or confirm their own request.
- **Retraction is not erasure.** Retracting takes a memory out of retrieval and
  authority at once. Only an authorized person can restore it within 30 days,
  after which the retraction is final. Retraction never triggers erasure, and
  erasure has no recovery window.
- **No fingerprints.** The tombstone holds no content-derived data, not even a
  keyed fingerprint. Identical text stored later is a new submission, not the
  erased memory coming back.
- **Backups.** No claim that backups are erased until the backup lifecycle can
  show it. A restored database is reconciled against the erasure records before
  it serves any memory.
- **Export.** Owners, and people given a separate export grant they accept with
  their own sign-in, export authorized namespace data. Archives are never stored
  on the server; temporary processing is bounded, protected and cleaned up.

## What is built so far

| Part | State |
| --- | --- |
| Erasure core: request, review, confirm, erase, verify, record | Built (this page) |
| An agent asks: `request_erasure` | Built |
| Admin ledger: `engramport admin erasure list` | Built |
| The owner's page to review and confirm: `/erase/<request id>` | Built, off unless `ENGRAMPORT_ERASURE_PAGE=true` |
| Export by an owner: `/export` | Built, off unless `ENGRAMPORT_EXPORT_PAGE=true`; see Export below |
| Delegated erase and export grants | Built in the database (`0024_data_grants.sql`); the page where owners give them and holders accept them is next |
| Whole-cell erasure with a cell-erasure-confirmer (D-02.1a) | Built in the database (`0026_cell_erasure.sql`) with the admin commands `confirmer` and `cell-erasure`; the pages for starting, confirming and accepting the role are next. See Whole-cell erasure below |
| 30-day retraction restore window | Built in the database (`0025_retraction_restore.sql`) with the admin ledger `engramport admin restore list`; the restore page is next. See Retraction and restoring below |

## The page

The owner opens `<public URL>/erase/<request id>`: the request id comes back to
the agent from `request_erasure` and shows in `engramport admin erasure list`.
The page asks for a fresh Google sign-in, shows every memory the request names
with its text and how much would go with it, then asks for a second, explicit
confirmation. Each visit uses its own sign-in once. The page carries no scripts,
can't be framed, and keeps its secret only in an encrypted cookie of its own,
which the approval page's cookie can't stand in for. A failed confirmation
erases nothing and records only its error class.

The page is off unless `ENGRAMPORT_ERASURE_PAGE=true`, which needs OAuth set up
and `<public URL>/erase/callback` in Supabase's redirect URLs (see
`docs/oauth-setup.md`). It is separate from the approval page's setting, so
turning on approvals doesn't turn on erasure.

## What an erasure removes

For every version of each memory named: the whole supersession chain, earlier
and later versions and pending proposals included.

- the text, metadata and dedup key, and the text's digest;
- its embeddings, and so its place in vector search;
- its keyword index entry, which is generated from the text and empties with it;
- graph rows that cite it: entity mentions, memory links in either direction,
  relations it is evidence for, and extracted entities nothing else points at
  (with their aliases). Entities an agent asserted are its own claims and stay;
- its provenance's source link, client claims and digest;
- the digest held in approval decisions and approval challenges about it.

There are no caches or derived summaries yet. Anything added later that holds or
derives from memory text must be added to `memory.erase_chain` and to
`memory.erasure_verified`.

## What it keeps

- The memory row as a content-free tombstone: id, namespace, kind, claim type,
  approval state, times, status `erased`. Empty text, no digest, no metadata.
- A row in `memory.erasures`: memory id, namespace, request, when, and whether it
  came from a request or a restore.
- The request: who asked, the reason category (owner request, stored in error,
  legal), which memories, who decided under which authority, and the evidence:
  counts of what was removed and whether verification found nothing left.
- Failed attempts: request, time and error class only.
- Approval and audit records, which hold no text.

## How it is decided

1. An agent calls `request_erasure` (or `memory.request_erasure`) with up to 100
   ids in its own namespace and a reason. Nothing changes.
2. The person signs in and reviews: `memory.erasure_review` shows each memory
   named, its text, and how many versions, embeddings, mentions, links and
   relations would go. Someone without authority gets the same answer whether or
   not the request exists.
3. The person confirms: `memory.issue_erasure_challenge` takes the digest of the
   request they were shown and returns a single-use secret.
4. `memory.decide_erasure_challenge` spends the sign-in and the challenge,
   re-checks the authority under lock, erases every version, verifies nothing is
   left, and completes the request. All of it or none of it.

Erasing in this first version needs a grant made to the person directly (an
owner, not a delegate), covering the claim type of every version named.

## What stops it going wrong

- Only `memory.erase_chain` can change a memory's text, and only after writing
  its tombstone in the same transaction. An erased memory stays erased, even for
  the database owner.
- Nothing attaches to an erased memory afterwards: embeddings, mentions, links,
  evidence and new versions are refused. Each such write takes a share lock on the
  memory, so one racing an erasure waits for it and is then refused; one that
  started first is erased with it.
- The chain is locked whole, and locked again if a version arrived while the
  erasure waited, so a revision proposed or approved at the same moment is erased
  too.
- A revoked or expired authority, an expired challenge, a replayed challenge and a
  changed request are all refused, and nothing changes.
- Requests, items, challenges, tombstones and failures are records: no role
  changes or deletes them.

## Restoring from a backup

A database restored from a backup taken before an erasure brings the erased text
back. Before the restored database serves anyone:

1. Export the erasure ledger from the database being replaced, or from the last
   copy of it you hold: every `memory_id` in `memory.erasures`. Keep this ledger
   outside the database; it holds ids only.
2. Restore, with the app's connections still off.
3. As the database owner (not the app, not the admin role), run
   `SELECT memory.reapply_erasures($1::uuid[])` with every id from the ledger. It
   erases each again, writes a restore tombstone, and is safe to run twice.
4. Check the result counts, then turn the app back on.

A whole-cell erasure also removes graph rows that no memory id names. For each
completed one in the ledger (`engramport admin cell-erasure list`: the cell and
when it completed), also run, as the database owner,
`SELECT memory.reapply_cell_erasure($1::uuid, $2::timestamptz)` with the cell's
id and that time. It erases again everything that was in the cell at that time,
leaves what was written after, and is safe to run twice.

Supabase keeps daily backups for 7 days on the Pro plan, and single rows can't be
removed from them. So erased text can remain in a backup for up to 7 days after
the erasure. Say that plainly; don't claim more until the backup lifecycle can
show it.

## Export

A person with an owner's grant over a namespace downloads everything in it from
`<public URL>/export`, with a fresh Google sign-in (D-02.4). The database side is
`db/migrations/0023_export.sql`; its tests are `db/test/export_test.sql`.

What the file holds, for that one namespace and nothing above or below it, as
JSON lines (one object per line, `type` says which):

- a header: the namespace, who exported it, when, and counts;
- every memory and every version, with its text, status, claim type, approval
  and verification state, and who wrote it through which tool and client;
  erased memories come as tombstones with no text;
- entities, aliases, relations, entity mentions and memory links;
- the approval trail: requests and decisions, with who made them;
- the erasure records.

Embeddings are left out: they are derived from the text and rebuilt from it.

How it runs, and why nothing is kept:

1. The person signs in and is offered only the namespaces they hold a direct,
   unrestricted owner's grant over. A grant limited to some claim types, or a
   delegation, exports nothing until delegated export grants are built.
2. They pick one and see what the file will hold; a single-use secret is kept
   only in the page's own encrypted cookie.
3. On confirming, `memory.start_export` spends the sign-in and the secret,
   re-checks the grant under lock, and records the start. That record is
   committed on its own, so an attempt stays on record even if the download
   then fails.
4. `memory.export_rows` streams the rows from the database straight to the
   browser in small batches, in one transaction that records the export as
   delivered, with counts. If the browser goes away first, the transaction rolls
   back: the export shows as started but not delivered, and the file the
   browser got is cut off rather than passed off as whole. The same happens if
   the browser stops taking the file for a minute, or the whole download runs
   past ten minutes, so a stalled download never holds a database connection.
   To try again, the person signs in again for a new export.

EngramPort writes no file and keeps no copy. Postgres may use its own temporary
work space while the query runs, released when it ends. The admin sees who
exported which namespace, when, and how much (`engramport admin export list`),
never what was in it, and can't export.

The page is off unless `ENGRAMPORT_EXPORT_PAGE=true`, which needs OAuth set up
and `<public URL>/export/callback` in Supabase's redirect URLs.

## Delegated grants

An owner can give one other person the power to erase in, or to export, one
namespace (D-02 item 2 and D-02.4). The database side is
`db/migrations/0024_data_grants.sql`; its tests are `db/test/grants_test.sql` and
`db/test/grants_race_test.sh`.

- **Who gives one.** A person holding a direct, unrestricted owner's grant over
  the namespace that allows delegation, with a fresh sign-in
  (`memory.grant_data_power`). Approval delegates, owners limited to some claim
  types, agents and the admin can't.
- **To whom.** Another enabled person who is a member of that namespace. One
  power, one namespace (not those under it), ending within 90 days.
- **Accepting.** The person sees the grant's exact terms and accepts or rejects
  them with their own fresh sign-in, against a fingerprint of those terms
  (`memory.pending_data_grants`, `memory.decide_data_grant`). Until then it
  counts for nothing.
- **When it stops counting.** At once when revoked (by the owner who gave it,
  another owner who could give it, or the admin with `engramport admin grant
  revoke`), when it expires, when the owner's own authority stops being valid,
  or when the person is disabled or leaves the namespace. A decision already
  under way is refused if the grant stops counting before it completes: an
  erasure decision holds the grant, its holder and their membership until it
  is recorded, so a change made first is seen. An export holds the authority it rests on until its download ends (at most 10
  minutes), so a revocation, a disabled account or a lost membership made
  during it waits for it; a revocation made first stops it; and a grant that
  runs out by the clock while the rows are gathered stops the whole export,
  which is then not recorded as delivered (`db/test/grants_race_test.sh`).
- **The record.** An erasure or export done under a grant records both the
  grant and the owner's authority it rests on, and who decided.

The page where owners give grants and holders accept them is the next step;
until then these are database functions only, like approval delegation.

## Retraction and restoring

Founder decision D-02.3. The database side is
`db/migrations/0025_retraction_restore.sql`; its tests are
`db/test/restore_test.sql` and `db/test/restore_race_test.sh`.

- **Retracting** (an agent's `delete_memory`, withdrawing a revision) takes a
  memory out of recall and authority at once and keeps its text. The database
  stamps when it happened and what the memory was before. No role can set or
  move that stamp, so the window can't be stretched. Nothing is erased.
- **Who restores.** A person holding approval authority over the memory's
  namespace and claim type, the same people who may approve it, with their own
  fresh sign-in, in three steps like approving: review
  (`memory.restore_review`), a single-use challenge bound to the person, the
  memory, that exact retraction and the authority
  (`memory.issue_restore_challenge`), and the decision, which spends the
  sign-in and the challenge together (`memory.decide_restore_challenge`). No
  agent, key or admin can restore: the database lets a retracted memory change
  back only when the decision has written its restoration record in the same
  transaction, and no other role can write one.
- **The window.** 30 days from the retraction by the wall clock, checked when
  the challenge is issued and again when the decision is written, after it
  holds the memory and the authority. After that,
  and for memories retracted before this existed, the retraction is final.
- **What comes back.** The memory returns to what it was, with its approval
  state unchanged: a current memory comes back current unless another current
  memory now holds its key; a withdrawn revision comes back as a proposal only
  while the version it revises is still the current approved one. A version
  that was already replaced when it was retracted is not restored. An erased
  memory is never restored.
- **The record.** Each restoration names the memory, the person, the
  authority, the challenge and the retraction it reversed. Challenges and
  restorations are never changed or deleted and hold no text or digest of it,
  so a later erasure leaves no fingerprint there. The admin sees them with
  `engramport admin restore list`, never the text.

The page where a person reviews a retracted memory and restores it is next;
until then these are database functions only.

## Whole-cell erasure

Founder decisions D-02.1 and D-02.1a. The database side is
`db/migrations/0026_cell_erasure.sql`; its tests are
`db/test/cell_erasure_test.sql`.

- **The confirmer role.** The admin assigns the cell-erasure-confirmer role to
  one named person who belongs to AN2B (an enabled person with a sign-in
  membership of a company namespace), over a scope (it covers the cells at or
  under that namespace), for at most a year: `engramport admin confirmer assign
  <actor> --scope <path> --expires-in 90d`. It counts only once that person
  accepts its exact terms with their own fresh sign-in
  (`memory.pending_confirmer_roles`, `memory.decide_confirmer_role`), and only
  while it is unrevoked, unexpired and they still belong to AN2B. It grants
  nothing else: no approval and no reading of memories.
- **Starting.** Only the cell's owner (a direct, unrestricted, valid approval
  authority over the cell) starts one, with their own fresh sign-in, after a
  preview of counts (`memory.cell_erasure_preview`,
  `memory.request_cell_erasure`). Delegates, grant holders, agents and the admin
  can't. One open request per cell; it lapses after 7 days, and the admin can
  cancel it (`engramport admin cell-erasure cancel`).
- **The cell is frozen** while a request is open: nothing new is written to it
  (memories, revisions, embeddings, graph rows), so what is confirmed is what
  was previewed.
- **Confirming.** A different person whose confirmer role covers the cell sees
  the open requests (`memory.pending_cell_erasures`), reviews fresh counts and a
  digest of the ids of everything that will go, never content
  (`memory.cell_erasure_review`), takes a single-use challenge bound to that
  digest (`memory.issue_cell_erasure_challenge`), and confirms with their own
  fresh sign-in (`memory.decide_cell_erasure_challenge`). The owner who started
  it can't confirm it, even holding the role.
- **The decision** spends the sign-in and the challenge, holds the role, the
  confirmer and their AN2B membership, the owner's authority chain and the cell
  still, checks each again by the wall clock, and refuses if the cell changed.
  Then it erases every memory version (each with a content-free tombstone naming
  the request), every embedding and every graph row in the cell, asserted ones
  included, scrubs the cell's provenance of anything content-derived, verifies
  nothing is left, and records the counts. All of it, or none of it. The cell
  stays, and takes new writes again as new submissions.
- **The record.** The request names who started it, under which authority, who
  confirmed it, under which role, the digest confirmed and what was removed.
  Requests, challenges and roles are records. None holds text or a digest of
  text. The admin sees them (`engramport admin cell-erasure list`,
  `engramport admin confirmer list`), never content or secrets, and can't start
  or confirm one.

The pages where an owner starts one, a confirmer confirms one, and a person
accepts the role are next; until then these are database functions only.
