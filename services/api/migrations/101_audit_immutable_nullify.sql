-- 101b: fix the jsonb null test (jsonb 'null' is not SQL NULL).
CREATE OR REPLACE FUNCTION public.audit_log_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $fn$
DECLARE
    key text;
    old_row jsonb := to_jsonb(OLD);
    new_row jsonb := to_jsonb(NEW);
BEGIN
    FOR key IN SELECT jsonb_object_keys(new_row) LOOP
        IF old_row -> key IS DISTINCT FROM new_row -> key THEN
            -- The ONE legal mutation, pinned to its column: only actor_id
            -- carries ON DELETE SET NULL. audit_log has ten nullable columns
            -- (actor_email, actor_ip, resource, resource_id, changes,
            -- metadata, prev_hash, entry_hash, chain_index); a blanket
            -- value->NULL exemption would let one UPDATE strip every fact an
            -- auditor reads while the trigger stayed silent. Review #1231
            -- reproduced exactly that on Postgres 16; this guard refuses it.
            IF key = 'actor_id'
               AND jsonb_typeof(old_row -> key) <> 'null'
               AND jsonb_typeof(new_row -> key) = 'null'
            THEN
                CONTINUE;
            END IF;
            RAISE EXCEPTION 'audit_log rows are immutable (attempted UPDATE of %)', key;
        END IF;
    END LOOP;
    RETURN NEW;
END;
$fn$;
