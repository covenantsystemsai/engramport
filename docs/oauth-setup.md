# Setting up Sign in with Google

This is how a hosted EngramPort server lets claude.ai and other MCP clients connect without a pasted key. It takes four parts: a Google OAuth client, the Google provider in your Supabase project's Auth, the server's settings, and the members you allow. Each part is a change to a live system, so do it on a development project first.

Nothing here goes in the repository. The Google client secret lives in Supabase Auth, and the server's settings live in your secrets manager.

## What you need first

- A Supabase project with EngramPort's migrations applied through `0009_oauth`. `select to_regclass('memory.oauth_members');` in the SQL editor returns the table's name once 0009 is in, and null before. `db/migrate.sh` records each file it applied in `engramport_meta.schema_migrations`.
- The public https origin the server will run on, like `https://mcp.example.com`. Below it is called the public URL.
- Your project's ref, the part before `.supabase.co` in its URL.

## 1. Create the Google OAuth client

In the Google Cloud Console, in a project you own:

1. Go to **APIs & Services** > **OAuth consent screen** and set up an **External** app. Use your company's name and support email. Ask for no scopes beyond `openid`, `email` and `profile`, which are the defaults.
2. While the app is in testing, only the test users you list can sign in. List the people you plan to add as members, or publish the app once you're ready.
3. Go to **APIs & Services** > **Credentials** > **Create credentials** > **OAuth client ID**, with application type **Web application**.
4. Under **Authorized redirect URIs**, add `https://<project ref>.supabase.co/auth/v1/callback`. This is Supabase's callback, not EngramPort's.
5. Copy the client ID and secret straight into the next step. Don't save the secret anywhere else.

## 2. Turn on Google in Supabase Auth

In the Supabase dashboard for the project:

1. **Authentication** > **Sign In / Providers** > **Google**: turn it on and paste the client ID and secret.
2. **Authentication** > **URL Configuration** > **Redirect URLs**: add `<public URL>/oauth/callback`, written out in full with no wildcard. Supabase sends people back only to URLs on this list. The server asks for exactly this one. If the approval page is on (`ENGRAMPORT_APPROVAL_PAGE=true`), add `<public URL>/approve/callback` the same way. If the erasure page is on (`ENGRAMPORT_ERASURE_PAGE=true`), add `<public URL>/erase/callback` too, for the export page (`ENGRAMPORT_EXPORT_PAGE=true`), `<public URL>/export/callback`, for the restore page (`ENGRAMPORT_RESTORE_PAGE=true`), `<public URL>/restore/callback`, for the whole-cell erasure pages (`ENGRAMPORT_CELL_ERASURE_PAGE=true`), `<public URL>/cell-erasure/callback`, and for the acceptance page (`ENGRAMPORT_ACCEPT_PAGE=true`), `<public URL>/accept/callback`.
3. Optional but tidy: turn off sign-in providers you don't use, such as email. EngramPort ignores them anyway. It issues a key only for a session that signed in with Google in the last 15 minutes, with a verified Google email that is an active member.

Anyone with a Google account can create a Supabase Auth user this way. That user gets nothing from EngramPort until you add their email as a member.

## 3. Set the server's settings

Put these in your secrets manager, next to the database URL and key pepper the server already uses:

| Variable | Value |
|---|---|
| `ENGRAMPORT_OAUTH` | `true` |
| `ENGRAMPORT_PUBLIC_URL` | The public URL, https and nothing after the host |
| `ENGRAMPORT_SUPABASE_URL` | `https://<project ref>.supabase.co` |
| `ENGRAMPORT_SUPABASE_PUBLISHABLE_KEY` | The project's publishable key, from **Project Settings** > **API Keys** |
| `ENGRAMPORT_OAUTH_REDIRECT_HOSTS` | Leave unset for `claude.ai,claude.com` |

The server must run in HTTP mode with `ENGRAMPORT_STORE=postgres`. It refuses to start with OAuth on if any of these is missing or wrong, and says which.

Once it's running, `<public URL>/.well-known/oauth-authorization-server` should return the server's endpoints, and a request to `<public URL>/mcp` with no key should get a 401 that names `<public URL>/.well-known/oauth-protected-resource/mcp`.

## 4. Add members

A member is one Google email, allowed into one namespace as one actor. The namespace and actor must exist already.

```bash
engramport admin member add person@example.com --namespace acme/ops/pilot --actor claude
engramport admin member add reviewer@example.com --namespace acme/ops/pilot --actor claude --read-only
engramport admin member list --namespace acme
```

## 5. Connect from claude.ai

In claude.ai, add a custom connector with the URL `<public URL>/mcp`. claude.ai registers itself and sends the person to Google. After they sign in, EngramPort shows the namespaces their email is a member of. The person picks one and approves, and claude.ai gets a key for that namespace only. The key lasts an hour and renews itself.

## Check the first sign-in

Do this once on a development project before going live:

1. Add yourself as a member, connect, and sign in.
2. Run `engramport admin connection list --email <your email>`. One active connection should show, with the client's name.
3. If you see "No access yet" though `member list` shows you, either the email Google reported isn't the one you added, or Supabase Auth didn't record the session the way the database check expects. That check needs a session less than 15 minutes old, a verified Google identity that signed in as the session started, and the session's sign-in method recorded as OAuth. Don't loosen the check; compare your rows in `auth.sessions`, `auth.identities` and `auth.mfa_amr_claims` against `memory.oauth_signed_in_email` in `0009_oauth.sql` first.

## Taking access away

- `engramport admin connection revoke <id>` ends one client's connection and its tokens. The person can connect again.
- `engramport admin member revoke <email> --namespace <path>` ends the membership and every connection and token made through it.
- Either takes effect on the client's next request. Setting `ENGRAMPORT_OAUTH=false` turns sign-in off for everyone. Keys already issued keep working until they expire within the hour, unless you revoke their members too.
