# Pilot configs

`pilot.example.json` shows every field `engramport admin pilot setup` reads,
with made-up names. Copy it to a new file here (ignored by git, because it
holds the owner's email), fill it in, and follow `docs/install.md`.

| Field | What it is |
|---|---|
| `namespace` | `city/tower/cell`. The cell must be new; a city or tower that exists must be a client one |
| `embedding_model` | `gte-small` keeps text inside Supabase |
| `owner.actor`, `owner.display` | The cell owner's name in EngramPort, and how it reads |
| `owner.email` | The Google address the owner signs in with |
| `owner.authority` | Approval authority over the cell's knowledge: `cell_knowledge` only, whether the owner may delegate it, and for how long. It counts only once the owner accepts it with their own sign-in |
| `agents[]` | 1 to 8 agents, each with its own actor name and one key, read-only or not, expiring within a year |

Actor names are global: every name in the file must be unused anywhere in the
store. Anything the tool doesn't expect, such as an unknown field, is refused.
