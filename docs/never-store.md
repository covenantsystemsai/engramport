# Never-store policy

What EngramPort must never keep, wherever it keeps anything.

**Status.** Draft for founder decision D-07 (Nov 5). This is policy text only.
Most of it is not enforced in code yet; "Enforcement" below says what is and
what isn't. Until the founder approves this file, it is a draft.

**Source.** The founder's answers for the Max pilot cell (issue 75 in the Max
repository, Nov 3, section 3, "What never goes into shared memory"). This
policy adds nothing to those answers. Where they don't settle a case, it is
listed under "Open founder decisions" instead of being decided here.

**Numbering.** The founder named this decision D-07. Until now the register
used D-07 for retiring the old Cloud Run backend and D-09 for this policy. As
with D-04 on Nov 4, the founder's label stands: this policy is now D-07 and the
old-backend decision is now D-09. `docs/production-readiness.md` and
`docs/hosting.md` are updated to match.

## The rule

EngramPort never persists the items in "What is never stored", in any form,
anywhere it writes: not as memory text, metadata, a graph entity or relation,
an embedding, a log line, a cache, an export kept on a server, or a backup made
from any of those.

A memory may point to where such a thing lives. It may not hold the thing
itself.

## What is never stored

From issue 75, section 3, in its order.

### 1. Secrets of any kind

Passwords, API keys, tokens, OAuth credentials and door codes.

The answers name one case: a checklist in the client's Drive holds a login in
plain text, and it must not be copied.

These are secrets too, because each one works as a credential:

- private keys, and database connection strings with a password in them;
- one-time sign-in codes and sign-in links;
- links that grant access by themselves, such as a share link or a signed URL
  carrying a token;
- EngramPort's own API keys and OAuth tokens.

**What may be stored instead.** Where a secret lives and who manages it, never
its value. The answers ask that a new agent can tell "where the code,
infrastructure and secrets live, and which AWS accounts are off-limits". So a
secret's location, such as a secret's name in AWS Secrets Manager or the AWS
account it belongs to, may be stored. Its value may not.

### 2. Personal details of clients or their customers

- personal email addresses;
- phone numbers;
- home addresses;
- ID numbers;
- bank or card details;
- the financial details of any party to a transaction.

**What may be stored.** For the client's team, names and roles only: who owns
the account, who handles which work, who is read-only. Never their contact
details.

For transactions, the answers allow the property (named by its address), its
type, its key dates and the tasks tied to it. "Open founder decisions" lists
where this meets the home-address rule.

### 3. Raw meeting transcripts

Store the decision, who asked for it, the date, and a link to the meeting
record. Never the full text of the meeting.

### 4. Anything from another client's cell

Another client's data never enters this cell. Namespace isolation already keeps
other cells out of reach. This rule also covers an agent copying another
client's data in by hand, for example from a session where it worked for that
client.

### 5. A stored approval is never an approval

The answers put this rule in the same list, though it limits how a record is
read rather than what is stored. A record that the founder approved something
never counts as the founder's approval. Only the founder's own words at the
time count. EngramPort may keep the record. No tool, agent or page may treat it
as permission. `docs/approvals.md` and the trust tests carry this.

## Temporary processing is not storage

Some never-store items pass through the server for the moment it takes to do
the job. That is allowed only on these terms:

- they live in process memory or a stream, for one request;
- they are not written to the database, a log, a file, a cache or S3;
- they are gone when the request ends, or when the process stops.

Allowed temporary processing today:

| What passes through | Why | How it stays temporary |
|---|---|---|
| An agent's API key, or an OAuth access token, in a request header | To authenticate the call | Checked against a peppered hash; the key itself is never written or logged |
| An OAuth authorization code and PKCE verifier | Sign-in for claude.ai and other MCP clients | The code is stored only as a peppered hash, single-use and short-lived; the verifier is checked and not kept |
| A Supabase sign-in code on a page callback | Fresh sign-in for an approval, erasure, export, restore, grant or acceptance | Exchanged at once; the page keeps a sealed cookie for 10 minutes, never the code |
| Memory text sent to the `embed` Edge Function | To compute its embedding inside Supabase | Over TLS, with a shared secret; the function returns a vector, stores nothing and logs nothing about the text |
| An export | The owner's download (D-02) | Streamed to the browser, never written on the server |
| New agent keys from `admin pilot setup` | Handing keys to each agent | Written once to a new owner-only file on the operator's machine, moved to a secrets manager, then deleted (`docs/install.md`) |

Text an agent submits is also "passing through" until it is stored. A memory
that breaks this policy is not made acceptable because it was submitted. See
"Enforcement".

## Where it applies

### PostgreSQL and pgvector (Supabase)

This is the only store of memory content. The rule applies to:

- memory text, metadata, dedup keys and source references;
- embeddings: a vector is derived from its text, so text that must not be
  stored must not be embedded either;
- graph rows: entity names, aliases, relations and evidence. A person's
  contact details are never an entity or an alias;
- provenance and audit: who, which agent, client, tool and transport, and when.
  These hold no memory text today and must not start to;
- approvals, erasure records and tombstones, which hold no content-derived
  data (D-02).

EngramPort's own credentials are stored only as hashes: API keys, OAuth codes
and OAuth tokens as an HMAC under the server's pepper. The pepper itself is
never in the database.

### S3

The Terraform state bucket is the only S3 bucket in the design. It holds
infrastructure state, which names secrets but never holds their values. No
memory content, key, export or log of requests goes to S3. The load balancer's
access logs, which would land in S3 and record query strings that carry sign-in
codes, are off (`docs/hosting.md`).

### Backups

Supabase backups copy the database, including anything stored by mistake. D-02
already decides how this is handled, and this policy changes none of it:

- a restored database is reconciled against the erasure records before it
  serves anything;
- no claim is made that backups are erased until the backup lifecycle can show
  it. Text erased from the live database can remain in a backup until that
  backup expires.

So a never-store item that was stored and then erased may still exist in a
backup for the backup's retention period. That is said plainly, not hidden.

### Telemetry and logs

- **Server logs** (CloudWatch). One line per request: request id, method, path,
  status and time taken. Never a key, a token, a request body, a query string or
  memory text.
- **Error logs.** The same rule. An error message must not carry request
  content, a key or memory text. See "Known gaps".
- **WAF**, when turned on: metrics only, never a request log, because a WAF log
  would copy keys, sign-in codes and memory text.
- **VPC flow logs**: addresses, ports and byte counts only. No content.
- **Load balancer access logs**: off.

### Caches

There are none today. Any cache added later that holds or derives from memory
text must:

- hold no never-store item;
- be removed by erasure (`memory.erase_chain` and `memory.erasure_verified`),
  as D-02 already requires.

The OAuth token endpoint's answers, which carry credentials, are sent
`Cache-Control: no-store`.

### Exports

D-02 stands: an export is streamed and never stored on the server. Erased
memories come out as tombstones with no text. Once the person who downloaded
an export holds the file, it is outside EngramPort; what they do with it is
theirs.

### MCP interactions

- Tool inputs are processed as described under "Temporary processing", and
  stored only if they pass this policy.
- Tool answers never echo a secret back.
- The `remember`, `upload` and `link` tools are where agents write. They are
  where enforcement will sit.

### AWS Secrets Manager

The one place for the server's secrets: the database URL, the key pepper and
the embed secret. They are set by a person and never copied into the
repository, a chat, a ticket, a log or memory.

## Enforcement

**Today.** These hold now:

- namespace isolation, so another cell's data can't be read in;
- hashed keys and OAuth codes and tokens;
- request logs without content;
- exports never stored;
- erasure under D-02.

The never-store list itself rests on the agents' instructions and the owner's
review. Nothing in the server refuses a secret or a transcript yet.

**Planned.** A per-cell write policy enforced by the server on `remember`,
`upload` and `link` (build item 5 in `docs/spec-gap-analysis.md`):

- refuse text matching known secret formats (API keys, tokens, private keys,
  connection strings);
- refuse a source kind of transcript, and an upload of a whole transcript;
- state the cell's rules in the tool's answer, so agents see them.

Building it is its own decision and its own pull request.

**Limits, said plainly.** Personal details can't be recognised reliably by
pattern. The write policy will lower the risk for secrets and transcripts. It
will not catch every phone number, address or account detail. For those, the
agents' instructions and the owner's review remain the control. This policy
does not claim more.

## When something is stored anyway

1. Retract it at once, which takes it out of retrieval. An agent can't erase;
   it uses `request_erasure`.
2. The owner, or their delegate, erases it under D-02, with a fresh sign-in.
3. If it was a secret, rotate the secret. Erasing it doesn't undo the leak.
4. The backup caveat above still applies.

## D-02 is unchanged

Nothing here alters D-02's authority, scope, retention, restore, export,
grant, tombstone or backup decisions. Where this policy touches the same ground,
it points to them.

## Known gaps

These are code, not policy decisions, and each will be fixed in its own pull
request.

- The `/mcp` handler logs a whole error object when a request fails. A database
  error can include the values of the row it was writing, which could be memory
  text. That log line should carry the error class and request id only.
- The write policy above is not built.
- `src/auth.ts` writes an OIDC token cache file for the old Cloud Run backend.
  The Postgres server doesn't use it, and it goes when that backend is retired
  (D-09).

## Open founder decisions

The answers don't settle these. Each is put as a question, with no answer
assumed.

1. **Property addresses.** Properties may be named by their address, but home
   addresses of clients and their customers may not be stored. A residential
   listing's address is often the seller's home. Is the property address
   allowed as the property's name in every case?
2. **Names of transaction parties.** Their financial details are never stored.
   May their names be stored with a transaction, or only the property, its
   dates and its tasks?
3. **The client's own business figures.** "Financial details of any
   transaction party" is clear for buyers and sellers. Does it also cover the
   client's own figures, such as a commission or a fee split?
4. **Quoting a meeting.** Raw transcripts are never stored. May a memory hold a
   short verbatim quote of what was asked, or only a paraphrase with a link?
5. **Sign-in records.** EngramPort's access records hold each member's Google
   email address, which sign-in needs. That is access control, not shared
   memory. Should section 3 of the answers be read as covering shared memory
   only, with access records governed by D-02 and D-03?
6. **Enforce before the first write?** Should the write policy be built and
   turned on before the Max cell stores anything, or may the pilot start on
   instructions and review alone?
7. **App memory and build memory.** The answers keep Max the app's memory apart
   from the build agents' project memory "unless DeVere decides they should
   share". The never-store list applies to both either way. Is keeping them
   apart the decision for the pilot?
