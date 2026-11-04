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
  person who started it can't be the second.
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
| The owner's page to review and confirm | Next |
| Delegated erasure; export grants | To build |
| Export | To build |
| Whole-cell erasure with a second confirmer | To build |
| 30-day retraction recovery window | To build |

Until the page exists, an erasure can be decided only through the database
functions below, by a person's own sign-in.

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

Supabase keeps daily backups for 7 days on the Pro plan, and single rows can't be
removed from them. So erased text can remain in a backup for up to 7 days after
the erasure. Say that plainly; don't claim more until the backup lifecycle can
show it.
