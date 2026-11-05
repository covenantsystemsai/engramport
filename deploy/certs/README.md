# Database CA certificate

The server verifies the database's TLS certificate. Supabase signs it with its
own certificate authority, so the image carries that CA's certificate.

Before building an image for a real deployment, a person downloads it from the
Supabase project: **Project Settings** > **Database** > **SSL Configuration** >
**Download certificate**, and saves it here as `supabase-ca.crt`. It is a
public certificate, not a secret, so it can be committed.

The container finds it through `ENGRAMPORT_DATABASE_CA_FILE=/app/certs/supabase-ca.crt`.
If the file is missing or wrong, the server can't connect and doesn't start:
it fails closed rather than trusting an unverified database.
