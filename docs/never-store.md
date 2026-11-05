# Never-store policy

What EngramPort must never keep, wherever it keeps anything.

**Status.** Approved by the founder as decision D-07 on Nov 5, at the reviewed
text of pull request 63, with two follow-on decisions recorded below. This is
policy text. Most of it is not enforced in code yet, and approving it does not
count as enforcing it; "Enforcement" below says what is and what isn't.

**Sources.** Two, both the founder's:

- the answers for the Max pilot cell (issue 75 in the Max repository, Nov 3,
  section 3, "What never goes into shared memory");
- the founder's decisions on this draft's seven open questions, with two
  corrections (pull request 63, Nov 5).

This policy adds nothing to those two. A case neither settles is listed under
"Open founder decisions" rather than decided here.

**Numbering.** The founder named this decision D-07. Until now the register
used D-07 for retiring the old Cloud Run backend and D-09 for this policy. As
with D-04 on Nov 4, the founder's label stands: this policy is now D-07 and the
old-backend decision is now D-09. `docs/production-readiness.md` and
`docs/hosting.md` are updated to match.

## What the policy covers

**Shared memory**, also called institutional memory, is everything agents and
people store and retrieve through EngramPort: memory text and metadata,
embeddings, graph rows, provenance, approvals and their records. This policy is
about shared memory and every copy of it: logs, caches, exports, S3 and
backups.

Two things are **not** shared memory, and each is allowed only as described:

- **Sign-in and membership records.** EngramPort keeps the minimum email
  identifier each member signs in with, only as sign-in and access control
  need it. These records are kept in their own tables, apart from memories,
  under D-02 and D-03's scope, access, retention, export and deletion
  controls. They never appear in search, the graph, embeddings or agent memory
  (founder decision 5).
- **Managed credential storage.** AWS Secrets Manager holds the server's own
  secrets. It is an explicitly authorized security service, not EngramPort
  memory. The rule that memories never hold secrets does not mean the service
  runs without secured credential storage (founder correction 2).

## The rule

EngramPort never persists the items in "What is never stored", in any form,
anywhere it writes: not as memory text, metadata, a graph entity or relation,
an embedding, a log line, a cache, an export kept on a server, or a backup made
from any of those.

A memory may point to where such a thing lives. It may not hold the thing
itself.

## What is never stored

From issue 75, section 3, in its order, with the founder's decisions of Nov 5
added where they apply.

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

Links that carry an access token or a signature are never copied into memory,
even when they point to an allowed source (founder decisions 1 and 4).

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

The founder's decisions of Nov 5 add, for transactions:

- **No property address that is, or may be, someone's home.** A property is
  named by an opaque transaction or property reference, with a link to the
  authorized system that holds the address. An address that is demonstrably a
  non-residential business location, and not anyone's home, may be stored when
  it is needed and authorized (decision 1). For the Max pilot, only the cell's
  owner or a delegate the owner has explicitly authorized may approve storing
  one. An agent can't authorize it, and the default stays the opaque reference
  (follow-on decision 8).
- **No names of buyers, sellers or other parties to a transaction.** Names
  needed to carry out a transaction stay in the client's authorized system of
  record (decision 2).
- **No transaction-level money,** including the client's own: commissions,
  fee splits, payments and related amounts. Financial processing stays in the
  authorized system of record (decision 3).

**What may be stored.**

- For the client's team: names and roles only, as issue 75 decided. Who owns
  the account, who handles which work, who is read-only. Never their contact
  details.
- For a transaction: the opaque property or transaction reference, a
  non-sensitive property type, key dates, tasks and their status, and
  references to the authorized source system (decisions 1 and 2).
- For money: workflow status, policy references and calculation-rule
  identifiers. Never the figures (decision 3).

### 3. Raw meeting transcripts, and verbatim quotes

Never the full text of a meeting, and never a verbatim quote from it (founder
decision 4).

Store instead:

- the decision or requirement, paraphrased;
- the date and the role of whoever asked for it;
- a non-secret reference to the meeting record, never a link that carries an
  access token.

### 4. Anything from another client's cell, or another memory

Another client's data never enters this cell. Namespace isolation already keeps
other cells out of reach. This rule also covers an agent copying another
client's data in by hand, for example from a session where it worked for that
client.

The same holds inside the Max pilot (founder decision 7):

- Max the customer-facing app and Max's build agents use separately authorized
  namespaces and separate credentials.
- Neither reads the other's memory, and nothing is shared between them
  automatically.
- Promoting an approved, non-sensitive lesson from one to the other later
  needs its own separately authorized process.

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

The Terraform state bucket is the only S3 bucket in the design. No memory
content, export or log of requests goes to S3.

Terraform state can hold sensitive values, so this policy makes no promise
that it never will (founder correction 1). The rules are:

- don't write credentials into Terraform. The design names the server's
  secrets in Terraform and leaves their values to Secrets Manager, set by a
  person;
- keep the state secured: the bucket is private, KMS-encrypted, versioned and
  TLS-only (`deploy/terraform/bootstrap`);
- treat any state that already exists as sensitive. The load balancer's
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
- Every tool that writes is a write path: `remember`, `upload`, `link` and
  `supersede_memory` (which also carries revision proposals), and any tool
  that writes later. Enforcement covers all of them.

### AWS Secrets Manager

An explicitly authorized security service, not EngramPort memory (founder
correction 2). It is the one place for the server's own secrets: the database
URL, the key pepper and the embed secret. They are set by a person and never
copied into the repository, a chat, a ticket, a log or memory.

## Enforcement

**Today.** These hold now:

- namespace isolation, so another cell's data can't be read in;
- hashed keys and OAuth codes and tokens;
- request logs without content;
- exports never stored;
- erasure under D-02.

**Built, not yet enabled for real customer writes.** `src/never-store.ts` runs
on every write path before anything is stored: `remember`, `supersede_memory`,
`upload` and `link`, and graph rows from extraction. It refuses:

- secrets with a known shape: private keys, EngramPort, AWS, GitHub, GitLab,
  Slack, OpenAI, Anthropic, Stripe, Google, Supabase and npm keys and tokens,
  JWTs, bearer tokens, URLs with a password, and statements of a password or
  door, gate, alarm or lockbox code;
- links that carry a token or a signature, in text or as `source_url`;
- email addresses, US phone numbers, social security numbers, card numbers
  that pass the Luhn check, IBANs that pass their check digits, and bank and
  routing numbers named as such;
- transcripts: subtitle formats, transcript file names, and three or more
  lines with a timestamp or a speaker label;
- structured fields (follow-on decision 9): metadata is flat, with lower-case
  keys checked like text, numbers read like text, short values and no key
  that names a never-store field (such as
  `email`, `address`, `buyer`, `seller`, `commission`, `fee`, `password`); a
  `source_url` must be plain https; entity types and relation predicates were
  already limited to lower-case names.

A refusal answers with code `refused`, names the field and the kind of item,
never repeats the text, and is logged as one line with the rule and field
only. There is no setting that turns the checks off, and if a check fails the
write is refused. The `/mcp` error log and the unhandled-error log now carry
an error's class only.

The founder's own review and independent review of this enforcement come
before any real customer write (decision 6).

**Required before real customer memory** (founder decision 6). The Max cell
stores no real customer memory until a write policy is enforced by the server.
Offline testing with synthetic data only may go ahead before then. The
enforcement must have:

- **every write path covered,** server-side: memory text, metadata, source
  references and graph rows, through every tool that writes;
- **fail-closed configuration:** if the policy is missing or can't load, writes
  are refused, not let through;
- **sanitized logs and errors:** no rejected content in a log line or an error
  message;
- **negative tests** that show each kind of item is refused;
- **its limits stated,** as below.

At the least it refuses text matching known secret formats (API keys, tokens,
private keys, connection strings), a source kind of transcript and an upload of
a whole transcript, and states the cell's rules in the tool's answer so agents
see them (build item 5 in `docs/spec-gap-analysis.md`).

It also restricts structured fields wherever practical (follow-on decision 9):
where a field's shape is known, such as metadata keys, source kinds and graph
relation types, only the expected values are accepted, so a never-store item
can't ride in through a field that isn't checked as text.

Approving this policy does not approve that enforcement. Building it is its own
pull request, with independent review and negative tests, before real customer
writes are turned on.

**Limits, said plainly.** Personal details can't be recognised reliably by
pattern. The write policy will lower the risk for secrets and transcripts. It
will not catch every phone number, address or account detail. For those, the
agents' instructions, the owner's review and the structured field
restrictions are the controls, and none of them is a guarantee against
sensitive data leaking in (follow-on decision 9). This policy does not claim
more.

## When something is stored anyway

1. Retract it at once, which takes it out of retrieval. An agent can't erase;
   it uses `request_erasure`.
2. The owner, or their delegate, erases it under D-02, with a fresh sign-in.
3. If it was a secret, rotate the secret. Erasing it doesn't undo the leak.
4. The backup caveat above still applies.

## D-02, D-03 and D-04 are unchanged

Nothing here alters:

- D-02's erasure, export, retention, delegation, restore, tombstone or backup
  decisions;
- D-03's approval authority: only the people it names approve, agents never do;
- D-04's supersession: an agent's revision of an approved memory is a proposal
  that a person approves.

Where this policy touches the same ground, it points to them. Erasing a
never-store item that slipped in goes through D-02, as above.

## Known gaps

These are code, not policy decisions.

- Names, home addresses and dollar figures in free text can't be detected
  reliably, so they aren't refused by pattern. Metadata keys for them are.
- Phone numbers are recognised in US formats only.
- `src/auth.ts` writes an OIDC token cache file for the old Cloud Run backend.
  The Postgres server doesn't use it, and it goes when that backend is retired
  (D-09).

## Founder decisions on this draft

The founder answered the first draft's seven open questions on Nov 5. Each is
applied in the sections above.

| # | Question | Decision |
|---|---|---|
| 1 | A property address that is also a seller's home | Not stored. An opaque property or transaction reference and a link to the authorized system instead. A demonstrably non-residential business address may be stored when needed and authorized. No token-bearing or signed links |
| 2 | Names of transaction parties | Not stored. Property reference, non-sensitive type, dates, tasks and status, and source references only. The client's internal team's names and roles stay allowed |
| 3 | The client's own transaction figures | Not stored: commissions, fee splits, payments and related amounts. Workflow status, policy references and calculation-rule identifiers instead |
| 4 | Quoting a meeting | Paraphrase only, no verbatim quotes. Source, date, the requester's role and a non-secret reference to the meeting |
| 5 | Sign-in emails | The policy covers shared memory. Minimum email identifiers stay in separate sign-in and membership records under D-02 and D-03, never in search, the graph, embeddings or agent memory |
| 6 | Enforce before the first write | Yes, before the Max cell stores real customer memory. Synthetic-only offline testing may go ahead. Policy approval alone doesn't qualify the enforcement |
| 7 | App memory and build memory | Separate namespaces and credentials, no cross-access or automatic sharing. Promoting lessons later needs its own authorized process |

The two corrections, on Terraform state and on AWS Secrets Manager, are applied
under "S3" and "What the policy covers".

## Follow-on decisions at approval

Recorded by the founder when approving D-07 on Nov 5.

| # | Decision |
|---|---|
| 8 | For the Max pilot, only the customer cell's owner or an explicitly authorized delegate may approve storing a demonstrably non-residential business address. Agents can't authorize it themselves. The default remains an opaque property reference |
| 9 | The documented limits of pattern matching are accepted, but agent instructions and human review are not a guarantee against sensitive-data leakage. The enforcement pull request adds structured field restrictions wherever practical, as well as secret detection and fail-closed writes |

## Open founder decisions

None from the seven questions or the two follow-on decisions. A case none of the decisions above settles will
be listed here, as a question, rather than decided in this file.
