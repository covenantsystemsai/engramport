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
  write a delegation, and nothing here shows it memory content.
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
