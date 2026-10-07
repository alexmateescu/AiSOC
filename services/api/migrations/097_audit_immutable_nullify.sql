-- 097b: fix the jsonb null test (jsonb 'null' is not SQL NULL).
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
            -- the one legal mutation: attribution nulled by ON DELETE SET NULL
            IF jsonb_typeof(old_row -> key) <> 'null'
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
