-- ─────────────────────────────────────────────────────────────────────────────
-- RentManager · Supabase / PostgreSQL lockdown
--
-- WHY: Supabase automatically exposes every table in the `public` schema through
-- a REST API (PostgREST) that anyone holding the project's *public* anon key can
-- call. Without Row Level Security (RLS) that means the whole database is
-- readable/writable from the internet without ever touching this app.
--
-- The app connects with a direct Postgres connection as the table OWNER, which
-- bypasses RLS, so enabling RLS with NO policies denies the REST API everything
-- and changes nothing for the app. Safe to run repeatedly.
--
-- The app runs this automatically at start-up (disable with DB_ENABLE_RLS=0);
-- run it by hand in the Supabase SQL editor if you prefer, or if start-up logs
-- "Could not enable RLS".
-- ─────────────────────────────────────────────────────────────────────────────
DO $$
DECLARE
  t text;
  tbls text[] := ARRAY['admin','tenants','rent_records','common_expenses','building_expenses',
                       'reminder_logs','vacate_settlements','rent_amount_history','deposit_payments'];
BEGIN
  FOREACH t IN ARRAY tbls LOOP
    IF to_regclass(format('public.%I', t)) IS NOT NULL THEN
      EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
        EXECUTE format('REVOKE ALL ON TABLE public.%I FROM anon', t);
      END IF;
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        EXECUTE format('REVOKE ALL ON TABLE public.%I FROM authenticated', t);
      END IF;
    END IF;
  END LOOP;
END $$;

-- Verify (every row should show rowsecurity = true):
-- SELECT tablename, rowsecurity FROM pg_tables WHERE schemaname = 'public';

-- Storage: make the uploads bucket PRIVATE (Dashboard → Storage → uploads → Edit → Public: off).
-- The app now serves files through short-lived signed URLs after an ownership check.
