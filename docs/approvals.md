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
- Approval authority belongs only to a **human actor** (0015).
- That person proves it is them with a **fresh Google sign-in** that the
  database checks against Supabase Auth itself (`memory.oauth_signed_in_email`
  from 0009): signed in with Google, within the last 15 minutes, on an email that
  maps to exactly one enabled human actor through an unrevoked membership.
- Each sign-in does **one** authority act (approve, delegate or revoke), then
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
| 3 | Owners delegate limited authority through an explicit, auditable grant | `memory.delegate_approval_authority`: fresh sign-in, same namespace and scope, same or fewer claim types, no later expiry, no re-delegation (0015) |
| 4 | Agents propose and recommend, never approve or impersonate a person | Authority is human-only; approval needs a human sign-in; the trust guard refuses every other change (0014, 0015, next PR) |
| 5 | Tower and city promotion needs separate AN2B governance approval | `promotion` authority, only on a tower or city, never usable for an ordinary memory (0015) |
| 6 | Engineering, security, financial and deployment approvals stay separate | EngramPort records memory approvals only. No scope here covers anything else |
| 7 | Approval binds to the exact memory id, version, content digest, action and namespace | Approval events (next PR). Each version is its own memory row, so the id pins the version |
| 8 | A changed or superseded memory needs fresh approval | A change is a new version with a new id and digest, which starts at `none` (0014). Approving checks the memory is still active (next PR) |
| 9 | Revoked authority invalidates future approvals and stops reuse | Validity is checked up the whole chain at the moment of use: unrevoked, unexpired, enabled humans. Revoking an owner ends every delegation from it (0015) |
| 10 | Full audit provenance, no content for content-blind admins | Authorities and approval events carry ids, actors, namespaces, scopes and times. The admin reads those, never memory text or its digest (0015, next PR) |

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

**Next: approval events (0016).** An agent can ask for approval, which marks a
memory `pending`. A person approves or rejects through a function that takes
their fresh sign-in, the memory id, the action and the content digest they were
shown. It checks the memory is active, its digest still matches, and a valid
authority covers its namespace, scope and claim type. Only that function can
move `approval_state`. The admin sees who decided what and when, not the text.

**After that: the approval page.** A small page where the person signs in with
Google in their own browser, sees the memory, and approves or rejects it. It is
deliberately a page and not an MCP tool.

## The first pilot owner's scope, not yet provisioned

Nothing below has been done. Each step that touches the live project is its own
yes from the founder.

1. Create the pilot owner as a human actor: `engramport admin actor create <name> --kind human --display "<display name>"`.
2. Add the owner's Google email as a member of the first memory pilot cell as that actor, so the database can map their sign-in to them: `engramport admin member add <email> --namespace <pilot cell> --actor <name>`.
3. Grant the owner `cell_knowledge` authority on the pilot cell, with `--can-delegate` if they will hand some approval to staff. Narrow it with `--claim-types` if only some kinds of claim should need their approval, and give it an expiry that matches the pilot.
4. If the owner delegates, they do it themselves through their own sign-in; the admin cannot do it for them.

Until then the pilot cell can be written to and read as usual. Nothing in it
can be approved, because no one there holds authority yet.

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
| I7 | The admin role can create a human actor, give it a membership and grant it authority, so the admin can make an approver | Info | Open, founder decision. Options: a second person confirms each top-level grant, or the grantee accepts it with their own sign-in |

Tests added for each fix: the admin can't revoke, relabel or backdate a
delegation's revocation; a revoked authority stays revoked for every role;
delete and truncate are refused; blank or empty claim type lists are refused;
a connect sign-in can't delegate and a spent sign-in can't connect; two emails
on one actor are refused; a spent revoke sign-in can't revoke again; an expired
authority is not valid; a fresh password sign-in and a mismatched user and
session are refused; and the API roles and the server hold no direct rights on
these tables. The non-delegable test now uses the holder's own sign-in, so it
tests the flag and not the holder check.

Local verification on the fixed revision: database suite 436 checks passed,
unit tests 76 passed, store and database tests 88 passed, typecheck clean. The
commit, check runs and second review of the fixed head are recorded on PR 41.

**PR 42 (0016).** Codex reviewed head `8ef38ec` and raised no findings. PR 42
is held until PR 41 merges; it then takes PR 41's fixes, is verified again, and
is reviewed again on its new head before it is retargeted to main.

**Merge decisions.** PR 41 is not merged yet: the review found issues, so the
fixes go back to the founder before the merge. PR 42 stays open. Neither
migration is applied to the live project, no owner is provisioned and no live
authority is granted.
