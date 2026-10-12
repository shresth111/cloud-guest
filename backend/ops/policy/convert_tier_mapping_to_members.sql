-- One-off, reviewed, per-row. NOT run by any deploy or migration.
--
-- Converts ONE Access Tier's old location mapping (an untargeted assignment,
-- which made the tier the location's default and applied it to every guest
-- there) into the new members-only mapping (target_type = 'members'), so the
-- tier reaches only the guests mapped into it.
--
-- This changes what non-members at that location get: they fall back to the
-- location's own Guest WiFi Limits, or to the platform defaults if there are
-- none. So it refuses unless the location has another active untargeted
-- assignment of the same policy type to fall back to. Read the "before" row
-- it prints, and run it only for a tier the venue has confirmed.
--
-- Usage (inside the postgres container):
--   psql -U <user> -d <db> -v ON_ERROR_STOP=1 \
--        -v assignment_id="'<policy_assignments.id>'" \
--        -f convert_tier_mapping_to_members.sql
--
-- The same change is made from the dashboard without this script: unmap the
-- tier from the location and map it again.

BEGIN;

-- psql does not expand :variables inside a $$ body, so hand the id to the
-- block through a transaction-local setting.
SELECT set_config('tiers.assignment_id', :assignment_id, true);

SELECT 'before' AS state, pa.id, pa.policy_id, p.policy_type, p.name AS policy_name,
       pa.scope_type, pa.scope_id, pa.target_type, pa.is_active
FROM policy_assignments pa JOIN policies p ON p.id = pa.policy_id
WHERE pa.id = :assignment_id;

DO $$
DECLARE
  v_id uuid := current_setting('tiers.assignment_id')::uuid;
  v_row policy_assignments%ROWTYPE;
  v_type text;
  v_fallbacks int;
  v_n int;
BEGIN
  SELECT * INTO v_row FROM policy_assignments WHERE id = v_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'no such assignment %', v_id; END IF;
  IF NOT v_row.is_active OR v_row.is_deleted THEN RAISE EXCEPTION 'assignment % is not active', v_id; END IF;
  IF v_row.scope_type <> 'location' OR v_row.target_type <> 'none' THEN
    RAISE EXCEPTION 'assignment % is %/% -- only an untargeted location mapping can be converted',
      v_id, v_row.scope_type, v_row.target_type;
  END IF;
  SELECT policy_type INTO v_type FROM policies WHERE id = v_row.policy_id;

  SELECT count(*) INTO v_fallbacks
  FROM policy_assignments pa JOIN policies p ON p.id = pa.policy_id
  WHERE pa.id <> v_id AND pa.is_active AND NOT pa.is_deleted
    AND pa.scope_type = 'location' AND pa.scope_id = v_row.scope_id AND pa.target_type = 'none'
    AND p.is_active AND NOT p.is_deleted AND p.policy_type = v_type AND p.current_version_id IS NOT NULL;
  IF v_fallbacks = 0 THEN
    RAISE EXCEPTION 'location % has no other active % default -- converting would leave every non-member on the platform default. Save Guest WiFi Limits for the location first.',
      v_row.scope_id, v_type;
  END IF;

  UPDATE policy_assignments SET target_type = 'members', updated_at = now()
  WHERE id = v_id AND target_type = 'none';
  GET DIAGNOSTICS v_n = ROW_COUNT;
  IF v_n <> 1 THEN RAISE EXCEPTION 'expected to convert 1 row, converted %', v_n; END IF;
  RAISE NOTICE 'converted % (% policy %) at location %; % other default(s) remain there',
    v_id, v_type, v_row.policy_id, v_row.scope_id, v_fallbacks;
END $$;

SELECT 'after' AS state, pa.id, pa.target_type, pa.is_active,
       (SELECT count(*) FROM policy_assignments m
         WHERE m.policy_id = pa.policy_id AND m.scope_id = pa.scope_id
           AND m.target_type = 'guest' AND m.is_active AND NOT m.is_deleted) AS members_here
FROM policy_assignments pa WHERE pa.id = :assignment_id;

COMMIT;
