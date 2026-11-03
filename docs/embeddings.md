# Embeddings that stay in Supabase

EngramPort embeds memory text so recall can search by meaning. Each namespace names the one model its text may go to, and the server and the database both hold to it.

| Model | Size | Where the text goes | Setting |
|---|---|---|---|
| `gte-small` (default) | 384 | Supabase's built-in model, run by the `embed` Edge Function in the same Supabase project. Nothing leaves Supabase. | `ENGRAMPORT_EMBED_URL`, `ENGRAMPORT_EMBED_SECRET` |
| `text-embedding-3-small` | 1536 | OpenAI's embeddings API | `OPENAI_API_KEY` |
| none | | Nowhere. Recall uses keyword and graph search only. | |

A new city uses `gte-small`, and a new tower or cell takes its parent's model unless you name another. A server can hold both providers: a namespace on `gte-small` is never sent to OpenAI, even when the server has an OpenAI key. If the server has no provider for a namespace's model, that namespace's memories are stored without embeddings and its recall says so. It never falls back to another provider.

`gte-small` reads about the first 512 tokens of a text, roughly 2,000 characters. Uploads are already cut into chunks of that size. A longer single memory is found by meaning from its opening, and by keyword and graph search in full.

Every step below is a change to a live system. Do it on a development project first. Nothing here goes in the repository: the shared secret lives in Supabase's function secrets and in your secrets manager.

## 1. Make the shared secret

Generate one random value of at least 32 characters, for example with `openssl rand -base64 48`. It is the only thing that lets a caller use the function, so keep it in your secrets manager and nowhere else.

## 2. Deploy the function

From the repository root, with the Supabase CLI signed in to the project:

```bash
supabase secrets set ENGRAMPORT_EMBED_SECRET=<the secret> --project-ref <project ref>
supabase functions deploy embed --project-ref <project ref>
```

`supabase/config.toml` deploys `embed` with JWT verification off. That is on purpose: the publishable key that would pass that check is public, so the function checks the shared secret itself, and refuses every request without it. The function logs nothing about the text it embeds.

## 3. Set the server's settings

Next to the database URL and key pepper in your secrets manager:

| Variable | Value |
|---|---|
| `ENGRAMPORT_EMBED_URL` | `https://<project ref>.supabase.co/functions/v1/embed` |
| `ENGRAMPORT_EMBED_SECRET` | The same secret |

Leave `OPENAI_API_KEY` unset unless some namespace is meant to use OpenAI. `engramport doctor` lists the providers the server has.

## 4. Check each namespace's model

```bash
engramport admin embedding models
engramport admin namespace list
engramport admin namespace embedding acme/ops/pilot gte-small
```

Changing a namespace's model takes effect on its next write. Embeddings it already has stay stored and are no longer searched by meaning until they are made again with the new model.
