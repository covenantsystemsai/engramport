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
  is recorded as spent. A second act needs a new sign-in. A sign-in used to
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
| 7 | Approval binds to the exact memory id, version, content digest, action and namespace | `memory.approvals` (0016). Each version is its own memory row, so the id pins the version |
| 8 | A changed or superseded memory needs fresh approval | A change is a new version with a new id and digest, which starts at `none` (0014). Deciding checks it is still the active version and the digest matches (0016) |
| 9 | Revoked authority invalidates future approvals and stops reuse | Validity is checked up the whole chain at the moment of use: unrevoked, unexpired, accepted, enabled humans. Revoking an owner ends every delegation from it (0015, 0017) |
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
  a person decides on one memory version. It takes their fresh, single-use
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

**Next: the approval page.** A small page where the person signs in with
Google in their own browser, sees the memory, and approves or rejects it. It
calls `record_approval` with that sign-in and the digest of what it showed. It
is deliberately a page and not an MCP tool, so an agent holding the person's
connection still can't approve.

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
| L6 | A sign-in isn't tied to the act it was taken for, and a refused act doesn't spend it | Low | Open, by design for now. Any act still needs the holder's own fresh Google sign-in and valid authority. The approval page should take one sign-in for one named act |
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
typecheck clean. It needs a fresh review on its new head, and is held until
PR 41 merges before it is retargeted to main.

**Merge decisions.** The review found issues on PR 41's first version, so the
fixes went back to the founder before any merge. On the founder's yes, PR 41
was merged at its verified head `2107f91` (all checks green, no open findings)
as `038c206` on main. PR 42 was then retargeted to main and stays open for its
own review and decision. Neither migration is applied to the live project, no
owner is provisioned and no live authority is granted. The founder has
since decided D-03A (acceptance, built in 0017) and D-03B (single-use approval
challenges on the approval page, next).
