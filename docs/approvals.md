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
- Each sign-in is used **once**, then recorded as spent. A second approval or
  delegation needs a new sign-in, so an earlier sign-in can't be replayed.
- No function takes an API key or an OAuth access token as proof of a person.
  An agent that holds a person's MCP connection can read and write as that
  person, but it cannot approve: approving is not an MCP tool.

## The ten rules and where each lives

| # | Rule | Where |
|---|------|-------|
| 1 | The founder approves within explicitly assigned company scopes | `company_governance` authority, granted per company namespace (0015) |
| 2 | Each client namespace owner approves within their own cell | `cell_knowledge` authority, granted on one client cell (0015) |
| 3 | Owners delegate limited authority through an explicit, auditable grant | `memory.delegate_approval_authority`: fresh sign-in, same namespace and scope, same or fewer claim types, no later expiry, no re-delegation (0015) |
| 4 | Agents propose and recommend, never approve or impersonate a person | Authority is human-only; a decision needs a human sign-in; agents can only ask; the trust guard refuses every other change (0014, 0015, 0016) |
| 5 | Tower and city promotion needs separate AN2B governance approval | `promotion` authority, only on a tower or city; every tower or city memory needs it, and it approves nothing in a cell (0015, 0016) |
| 6 | Engineering, security, financial and deployment approvals stay separate | EngramPort records memory approvals only. No scope here covers anything else |
| 7 | Approval binds to the exact memory id, version, content digest, action and namespace | `memory.approvals` (0016). Each version is its own memory row, so the id pins the version |
| 8 | A changed or superseded memory needs fresh approval | A change is a new version with a new id and digest, which starts at `none` (0014). Deciding checks it is still the active version and the digest matches (0016) |
| 9 | Revoked authority invalidates future approvals and stops reuse | Validity is checked up the whole chain at the moment of use: unrevoked, unexpired, enabled humans. Revoking an owner ends every delegation from it (0015) |
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
  write a delegation, and nothing here shows it memory content.
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
