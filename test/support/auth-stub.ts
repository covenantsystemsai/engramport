/**
 * A stand-in for the Supabase Auth tables that migration 0009 reads, for
 * THROWAWAY test databases only. signInWithGoogle makes what a fresh Google
 * sign-in leaves behind: a user, a verified Google identity, a session and
 * its 'oauth' AMR claim.
 */
import { randomUUID } from "node:crypto";
import type pg from "pg";

export async function createAuthStub(admin: pg.Pool): Promise<void> {
  await admin.query(`
    CREATE SCHEMA IF NOT EXISTS auth;
    CREATE TABLE IF NOT EXISTS auth.users (
      id uuid PRIMARY KEY, email text, email_confirmed_at timestamptz, banned_until timestamptz,
      deleted_at timestamptz, is_anonymous boolean NOT NULL DEFAULT false);
    CREATE TABLE IF NOT EXISTS auth.identities (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL, provider text NOT NULL,
      provider_id text, identity_data jsonb NOT NULL, last_sign_in_at timestamptz);
    CREATE TABLE IF NOT EXISTS auth.sessions (
      id uuid PRIMARY KEY, user_id uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
      not_after timestamptz);
    CREATE TABLE IF NOT EXISTS auth.mfa_amr_claims (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(), session_id uuid NOT NULL,
      authentication_method text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());`);
}

export async function signInWithGoogle(admin: pg.Pool, email: string): Promise<{ userId: string; sessionId: string }> {
  const userId = randomUUID();
  const sessionId = randomUUID();
  await admin.query("INSERT INTO auth.users (id, email) VALUES ($1, $2)", [userId, email]);
  await admin.query(
    `INSERT INTO auth.identities (user_id, provider, identity_data, last_sign_in_at)
     VALUES ($1, 'google', jsonb_build_object('email', $2::text, 'email_verified', true), now())`,
    [userId, email],
  );
  await admin.query("INSERT INTO auth.sessions (id, user_id) VALUES ($1, $2)", [sessionId, userId]);
  await admin.query("INSERT INTO auth.mfa_amr_claims (session_id, authentication_method) VALUES ($1, 'oauth')", [sessionId]);
  return { userId, sessionId };
}
