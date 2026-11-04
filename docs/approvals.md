# Memory approvals

Founder decision D-03 picked who may approve a memory: the founder within
assigned company governance scopes, plus each client namespace's authorized
owner within their own cell. This page says how EngramPort implements that and
how far the build has got.

## The one idea

An approval is a person doing something, checked by the database. It is never
a memory, a field or a tool argument that a writer sets. So:

- No write can set `approval_state` or `verification_state` (0014). Every new
  memory starts at `none` / `unverified`, whatever its text says.
- Approval authority belongs only to a **human actor** (0015), and only once
  that person has **accepted the exact grant** with their own sign-in (0017).
- That person proves it is them with a **fresh Google sign-in** that the
  database checks against Supabase Auth itself (`memory.oauth_signed_in_email`
  from 0009): signed in with Google, within the last 15 minutes, on an email that
  maps to exactly one enabled human actor through an unrevoked membership.
- Each sign-in does **one** authority act (accept, approve, delegate or revoke), then
  is recorded as spent. For a decision on a memory, the sign-in is also bound
  to one challenge for one named action on one exact version (0018). A second act needs a new sign-in. A sign-in used to
  connect a client (the OAuth flow) is spent for authority acts too, and one
  already spent on an authority act can't connect a client. The sign-in is
  recorded by a hash of its session id, never the id itself.
- A person is **one email**. If a second email can sign in as the same actor
  (an assistant added to connect as the owner, say), that actor can't use any
  authority until one of the two memberships is revoked.
- No function takes an API key or an OAuth access token as proof of a person.
  An agent that holds a person's MCP connection can read and write as that
  person, but it cannot approve: approving is not an MCP tool.

## The ten rules and where each lives

| # | Rule | Where |
|---|------|-------|
| 1 | The founder approves within explicitly assigned company scopes | `company_governance` authority, granted per company namespace (0015) |
| 2 | Each client namespace owner approves within their own cell | `cell_knowledge` authority, granted on one client cell (0015) |
| 3 | Owners delegate limited authority through an explicit, auditable grant | `memory.delegate_approval_authority`: fresh sign-in, same namespace and scope, same or fewer claim types, no later expiry, no re-delegation (0015). The delegate must accept it too (0017) |
| 4 | Agents propose and recommend, never approve or impersonate a person | Authority is human-only; a decision needs a human sign-in; agents can only ask; the trust guard refuses every other change (0014, 0015, 0016) |
| 5 | Tower and city promotion needs separate AN2B governance approval | `promotion` authority, only on a tower or city; every tower or city memory needs it, and it approves nothing in a cell (0015, 0016) |
| 6 | Engineering, security, financial and deployment approvals stay separate | EngramPort records memory approvals only. No scope here covers anything else |
| 7 | Approval binds to the exact memory id, version, content digest, action and namespace | A single-use challenge bound to the approver, namespace, action, memory id, version, digest, authority, sign-in and expiry, consumed with the decision (0018) |
| 8 | A changed or superseded memory needs fresh approval | A change is a new version with a new id and digest, which starts at `none` (0014). A challenge dies if the memory is superseded, retracted, re-versioned or decided by someone else before it is used (0018). A revision of an approved memory is a proposal, and the approved version stays current until a person approves it (0020, D-04) |
| 9 | Revoked authority invalidates future approvals and stops reuse | Validity is checked up the whole chain at the moment of use: unrevoked, unexpired, accepted, enabled humans. Revoking an owner ends every delegation from it. An unused challenge dies with its authority, and a revocation racing a decision is seen (0015, 0017, 0018) |
| 10 | Full audit provenance, no content for content-blind admins | Authorities, requests and decisions carry ids, actors, namespaces, scopes and times. The admin reads those, never memory text, digest or sign-in (0015, 0016) |

## What is built

**PR 41 (migration 0015, approval authority)**

- `memory.approval_authorities`: holder, namespace, scope, optional claim types,
  whether it may delegate, parent and grantor for a delegation, expiry and
  revocation. Rows are never edited or deleted, only revoked once.
- `memory.approval_authority_valid(id)`: true only while the row and every row
  above it is unrevoked and unexpired and each holder is an enabled human.
- `memory.consume_human_sign_in`: the single-use sign-in check, callable only
  from the functions below.
- `memory.delegate_approval_authority` and `memory.revoke_delegated_authority`:
  what the server calls for an owner, each with the owner's own fresh sign-in.
- The admin role grants and revokes top-level authority and lists it. It can't
  write, revoke or otherwise touch a delegation, it can't say a revocation came
  from a grantor, and a revocation is stamped with the moment it happens, so it
  can't be backdated. Nothing here shows it memory content.
- No role deletes or truncates the authority table or the spent sign-ins, the
  table owner included.
- Admin commands:

  ```
  engramport admin authority grant <actor> --namespace <path> --scope cell_knowledge|company_governance|promotion [--claim-types decision,fact] [--can-delegate] [--expires-in 365d]
  engramport admin authority list [--namespace <path>] [--actor <name>] [--all]
  engramport admin authority revoke <id> --reason <code>
  ```

**PR 42 (migration 0016, approval events)**

- `memory.request_approval(memory_id)`: a writer, usually an agent, asks for
  approval of an active memory in its key's own namespace. The memory becomes
  `pending`. Asking again returns the same request. Agents reach it through the
  `request_approval` tool, which asks and nothing more.
- `memory.record_approval(user, session, memory_id, approve|reject, sha256)`:
  a person decided on one memory version. 0018 replaces it with the challenge
  steps below; the checks it made are kept along that path. It takes their fresh, single-use
  sign-in and the digest of the text they were shown. Someone with no authority
  gets the same answer whether or not the memory exists. Then the memory must
  still be the active version, not decided yet, and match the digest.
- The scope comes from where the memory lives:

  | Memory lives in | Needs | Granted on |
  |---|---|---|
  | a client cell | `cell_knowledge` | that cell |
  | a company cell | `company_governance` | that cell or a namespace above it |
  | any tower or city | `promotion` | that tower or city, or the city above it |

  So company governance alone never approves tower or city knowledge.
- `memory.approval_requests` and `memory.approvals` are append-only, for every
  role. There is one request and one decision per memory version.
- The trust guard from 0014 now lets `approval_state` move only to match a
  request or decision recorded for that memory in the same transaction. Claim
  type and verification still never change in place.
- `fetch_memory` shows the trail: who asked and when, and who decided, what,
  when and under which scope. It never shows the digest or the sign-in.
- The admin reads who asked and who decided, where and under which authority:
  `engramport admin approval list [--namespace <path>] [--since 7d]`. It never
  sees the text, the digest or the sign-in, and it cannot decide.
- Decisions made before an authority was revoked stay on the record, with the
  authority they used. Nothing approved is held back to be applied later, so
  there is no unused approval to replay.

**Migration 0017 (D-03A, approver acceptance)**

Founder decision D-03A: a newly granted approver must personally accept the
authority with an authenticated sign-in before it becomes active, bound to the
precise grant. Pending, rejected, expired or revoked grants confer nothing.

- Granting, by the admin or by an owner's delegation, now only **offers**
  authority. `memory.approval_authority_valid` is false until the holder has
  accepted, and that holds at every link of a delegation chain.
- `memory.pending_authority_grants(user, session)`: what the signed-in person
  has been offered and not yet decided, with every term (namespace, scope,
  claim types, whether it may be delegated, expiry, the authority it came from)
  and the grant's fingerprint. Looking does not spend the sign-in.
- `memory.decide_approval_authority(user, session, authority, accept|reject, sha256)`:
  the holder accepts or rejects one grant with a fresh, single-use sign-in and
  the fingerprint of what they were shown. The fingerprint covers every term
  above plus who granted it, so the acceptance binds to that exact grant.
  Someone else's grant and no grant give the same answer. A revoked or expired
  grant, a parent that is no longer valid, or a fingerprint that doesn't match
  are refused.
- A decision is made once and is final. A rejected grant stays rejected; a new
  offer is a new grant. A pending grant can't be delegated from.
- `memory.approval_authority_decisions` is append-only for every role. The
  admin sees whether and when each grant was decided, never the sign-in, and
  cannot decide for anyone. The server cannot read it directly.
- `engramport admin authority grant` says the grant counts only once accepted,
  and `authority list` shows "waiting for the holder to accept", "rejected by
  the holder" or "valid, accepted".

This closes I7: the admin can still create a person and offer them authority,
but nothing counts until that person signs in with their own Google account and
accepts it. The acceptance page itself is part of the approval page below.

**Migration 0018 (D-03B, approval challenges)**

Founder decision D-03B: each decision binds to an exact, single-use
authorization challenge, with fresh human authentication and explicit review.
A decision takes three calls, all with the approver's same fresh sign-in:

1. `memory.approval_review(user, session, memory_id)` shows the memory the
   approver may decide on: its text, digest, version, namespace and scope.
   Nothing is spent or recorded. Someone with no authority gets the same answer
   whether or not the memory exists.
2. `memory.issue_approval_challenge(user, session, memory_id, action, sha256, version)`
   takes the digest and version the approver was shown and the action they
   picked. It records a challenge bound to the approver, namespace, action,
   memory id, version, digest, the authority it is issued under, the sign-in
   and a ten-minute expiry, and returns a 256-bit secret once. Only the
   secret's hash is kept. One sign-in takes one challenge.
3. `memory.decide_approval_challenge(user, session, challenge_id, secret)`
   spends the sign-in and the challenge together, once. Someone else, another
   sign-in of the same person, a wrong secret and no challenge all get the
   same answer. It is refused if the challenge expired or was used, if the
   memory was superseded, retracted, given a new version or already decided,
   or if the authority, any authority above it, or a holder is no longer
   valid. The authority chain and its holders are held still while it
   decides, so a revocation racing the decision is seen. Once everything is
   locked, the challenge's expiry and the authorities' expiry are checked again
   against the wall clock, so neither a long transaction nor a wait for a lock
   lets a challenge or an authority be used after its deadline.

`memory.record_approval` is removed, so there is no other way to decide.
Challenges are records that no role changes or deletes. The admin sees who took
which challenge, for which memory and action, under which authority, when it
expires and whether it was used, never the text, digest, secret or sign-in.
The server can only call the three steps. This closes L6: a sign-in used for a
decision is tied to one named act.

**The approval page (D-03B, `src/approve.ts`)**

Off unless `ENGRAMPORT_APPROVAL_PAGE=true`, which needs OAuth. Not deployed
anywhere. It is deliberately a page and not an MCP tool, so an agent holding a
person's connection can ask for approval but can't approve.

1. `GET /approve/<memory id>` starts a fresh Google sign-in for this visit.
2. Back from Supabase Auth, the page runs `approval_review` and shows the
   memory: namespace, kind and claim type, version, when it was written and
   asked about, its fingerprint and its full text. It offers Approve, Reject
   or Not now. A memory already decided or no longer active shows why, with no
   buttons. Someone with no authority sees the same page as for a memory that
   doesn't exist.
3. Picking an action takes the challenge for that action on that exact
   version, and shows the memory again with "Approve it" or "Reject it" and
   "Go back without deciding".
4. Confirming spends the challenge and the sign-in. The page then ends the
   Supabase session.

The visit is carried in an encrypted, signed, ten-minute `__Host-` cookie
(HttpOnly, Secure, SameSite=Lax) under a key of its own. The challenge's secret
is only ever in that cookie, never in the page. Each form carries a token tied
to the cookie. The page loads no scripts, can't be framed, posts only to itself
and is never cached. A refusal shows the database's own words, so a changed
memory, a revoked authority or a replayed confirmation says what happened and
records nothing.

### D-04: revising an approved memory (0019, 0020)

Founder decision D-04: agents propose, people approve, EngramPort preserves history.

**The defect this fixes.** Until 0020 an agent could displace a memory a person
had approved: new text under its dedup key, `supersede_memory` or
`delete_memory` all worked, and recall then showed only the unapproved text, so
the approved decision quietly dropped out of view. An agent-written revision
must never silently displace a human-approved decision.

**What happens now.**

- An approved memory stays current. An agent's revision of it, through
  `supersede_memory` or `remember` under its dedup key, is stored as its own row
  with status `proposed`, its own id, provenance, text and digest, pointing at
  the approved version it would replace. It is put up for approval at once.
- Recall and search return only active memories, so a pending, rejected or
  withdrawn proposal never comes back by default. `memory_history` and
  `fetch_memory` show proposals, marked as such, to keys that can read the
  namespace; another cell sees nothing of them.
- Competing revisions stay separate proposals until each is decided.
- The person reviews the proposal on the approval page, which shows the proposed
  text next to the approved text it would replace, with both fingerprints. The
  challenge also binds the approved version it would replace, and the
  approver's authority must cover the claim types of both, so a grant limited
  to some claim types can't replace a memory of another type.
- Approving makes the proposal active and approved and the old version
  superseded, in the decision's own transaction. The old version keeps its
  approval on record.
- If the approved version was replaced meanwhile, for example by a competing
  proposal that won, the decision is refused as stale and needs a fresh review.
  Two competing approvals at the same moment are decided one after the other:
  one wins and the other is refused.
- Rejecting changes nothing else; the proposal stays on record as proposed and
  rejected. Its writer can withdraw an undecided or rejected proposal with
  `delete_memory`, which retracts it and keeps the text. Rejected and withdrawn
  proposals are kept until the retention policy (D-02) says otherwise.
- An agent can't retract an approved memory. No person's retraction path exists
  yet; it would go through the same approval page.

**How it's enforced.** A lifecycle guard on `memory.memories` holds for every
role except the decision function:

- Superseded and retracted versions stay that way, and a superseded approved
  version can't be retracted.
- The version a memory follows never changes, and a new active version can only
  follow one that is already superseded.
- An approved memory leaves `active` only when a person's approval of a revision
  of it is recorded in the same transaction.
- A proposal becomes active only when its own approval is, and nothing becomes a
  proposal after it is written.

**Tests.** `db/test/revision_test.sql` covers an agent's direct attempts, other
cells, competing proposals, a stale base, replayed challenges, rejection and
withdrawal, a revoked approver, another cell's approver, a decision rolled back
after it succeeded, and a failure in its last step. `revision_race_test.sh`
races two approvals of competing proposals and fails if the approved version's
lock is removed. Store and page tests cover the same flow through the tools and
the approval page.

**Not built.** A safety-critical correction would need its own authorized hold
process; nothing here lets a proposal replace approved knowledge without a
person's approval.

## The first pilot owner's scope, not yet provisioned

Nothing below has been done. Each step that touches the live project is its own
yes from the founder.

1. Create the pilot owner as a human actor: `engramport admin actor create <name> --kind human --display "<display name>"`.
2. Add the owner's Google email as a member of the first memory pilot cell as that actor, so the database can map their sign-in to them: `engramport admin member add <email> --namespace <pilot cell> --actor <name>`.
3. Grant the owner `cell_knowledge` authority on the pilot cell, with `--can-delegate` if they will hand some approval to staff. Narrow it with `--claim-types` if only some kinds of claim should need their approval, and give it an expiry that matches the pilot.
4. If the owner delegates, they do it themselves through their own sign-in; the admin cannot do it for them.

Until then the pilot cell can be written to and read as usual, and agents can
ask for approval. Nothing in it can be approved, because no one there holds
authority yet.

The founder's own `company_governance` authority, on the company namespace, is
provisioned the same way and is also left for its own yes. So is any
`promotion` authority on a tower or city.

## Review and verification record

**PR 41, independent security review (reviewed head `bba4e24`).** The review
covered approval authority, delegation chains, Google sign-in binding,
namespace scope and revocation. It found two medium and three low issues,
which were fixed on the PR before any merge, and two design points that stay
open for the founder.

| # | Finding | Severity | Outcome |
|---|---------|----------|---------|
| M1 | The admin role could revoke a delegation, mark a revocation as the grantor's, and backdate a revocation | Medium | Fixed. The admin policy covers top-level rows only; only a delegation may carry `revoked_by_grantor`; `revoked_at` is set to the time of the change |
| M2 | A sign-in used to connect a client could then be used once more for an authority act | Medium | Fixed. Connecting records the sign-in as spent for authority acts, and a sign-in spent on an authority act can't connect |
| L3 | Two emails mapped to one human actor could each act as that person | Low | Fixed. An actor reachable from more than one email can't use authority |
| L4 | A claim type list could hold a blank, or be empty | Low | Fixed by a check on the column |
| L5 | The table owner could delete or truncate authority and sign-in records | Low | Fixed. Delete and truncate are refused for every role |
| L6 | A sign-in isn't tied to the act it was taken for, and a refused act doesn't spend it | Low | Closed for decisions by D-03B (0018): a decision's sign-in is bound to one challenge for one named act. A refused decision still doesn't spend it, but the challenge can't be retried with another act |
| C1 | Codex on `7fb145e`: the M2 fix had a race. A connect and an authority act using the same sign-in at the same moment could both succeed | Medium | Fixed. Connecting now records the sign-in first and then checks how it was used, so the second of two racing uses always fails. A two-session test proves it, and fails on the earlier code |
| I7 | The admin role can create a human actor, give it a membership and grant it authority, so the admin can make an approver | Info | Founder decided D-03A: the grantee must accept with their own sign-in. Built in 0017 |

Tests added for each fix: the admin can't revoke, relabel or backdate a
delegation's revocation; a revoked authority stays revoked for every role;
delete and truncate are refused; blank or empty claim type lists are refused;
a connect sign-in can't delegate and a spent sign-in can't connect; two emails
on one actor are refused; a spent revoke sign-in can't revoke again; an expired
authority is not valid; a fresh password sign-in and a mismatched user and
session are refused; and the API roles and the server hold no direct rights on
these tables. The non-delegable test now uses the holder's own sign-in, so it
tests the flag and not the holder check.

Local verification on the fixed revision: database suite 436 checks plus the
two race checks passed, unit tests 76 passed, store and database tests 88
passed, typecheck clean. The
commit, check runs and second review of the fixed head are recorded on PR 41.

A second independent review of `7fb145e` confirmed M1, L3, L4 and L5 closed,
found the same race as C1 independently, and confirmed the C1 fix. Each fix was
switched off in turn and at least one test failed every time. Its notes, kept
here so they are known:

- While a second email is on an actor, that person also can't revoke their own
  delegations. The admin can still revoke the parent authority, which ends
  them. The same lockout happens if one person is added under two addresses,
  such as a Gmail alias.
- The record triggers stop changes and deletes through SQL statements. A
  database owner could still switch a trigger off with a schema change. That is
  outside what a migration can prevent, and is covered by who holds the owner
  role.
- Every client connection now leaves a permanent spent sign-in row.
- 0015 was edited in place after review. That is safe only because it has never
  been applied to any real database.

**PR 42 (0016).** Codex reviewed head `8ef38ec` and raised no findings. PR 42
now carries PR 41's fixes, and in line with L5 its approval records also refuse
truncation by any role. Local verification on that revision: database suite
484 checks plus the two race checks passed, unit tests 77 passed, store and database tests 90 passed,
typecheck clean. After PR 41 merged it was retargeted to main, with
final head `9419f07`. On that head every GitHub check passed (test, db,
gte-small, secrets, analyze, CodeQL), GitHub reports it mergeable and clean,
and there are no review comments. A security review was requested from Codex on
`9419f07`, naming approval requests and decisions, the trust guard, sign-in
binding, namespace scope and the admin view. Codex reviewed `9419f07` and
reported no major issues. Codex's separate security-review record stays empty
on every PR in this repository, so this rests on its review of that head after
the security request. PR 42 is held for the founder's merge decision.

**Merge decisions.** The review found issues on PR 41's first version, so the
fixes went back to the founder before any merge. On the founder's yes, PR 41
was merged at its verified head `2107f91` (all checks green, no open findings)
as `038c206` on main. PR 42 was then retargeted to main and stays open for its
own review and decision. Neither migration is applied to the live project, no
owner is provisioned and no live authority is granted. The founder has
since decided D-03A (acceptance, built in 0017) and D-03B (single-use approval
challenges on the approval page, next).
