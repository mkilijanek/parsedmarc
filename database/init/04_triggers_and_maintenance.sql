SET search_path = ti, public;

-- updated_at auto-maintenance
CREATE OR REPLACE FUNCTION trg_set_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS t_set_updated_at_indicators ON indicators;
CREATE TRIGGER t_set_updated_at_indicators
BEFORE UPDATE ON indicators
FOR EACH ROW
EXECUTE FUNCTION trg_set_updated_at();

-- feed_stats recomputation (safe to call from app/worker too; trigger gives best-effort)
CREATE OR REPLACE FUNCTION refresh_feed_stats(p_source TEXT, p_source_ref TEXT)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
  INSERT INTO feed_stats (source, source_ref, total_indicators, active_indicators, inactive_indicators, last_update)
  SELECT
      p_source,
      p_source_ref,
      COUNT(*),
      COUNT(*) FILTER (WHERE is_active),
      COUNT(*) FILTER (WHERE NOT is_active),
      now()
  FROM indicators
  WHERE source = p_source AND (source_ref IS NOT DISTINCT FROM p_source_ref)
  ON CONFLICT (source, source_ref) DO UPDATE SET
      total_indicators = EXCLUDED.total_indicators,
      active_indicators = EXCLUDED.active_indicators,
      inactive_indicators = EXCLUDED.inactive_indicators,
      last_update = EXCLUDED.last_update;
END;
$$;

-- Best-effort trigger to update stats on insert/update/delete
CREATE OR REPLACE FUNCTION trg_indicators_refresh_stats()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
  s TEXT;
  r TEXT;
BEGIN
  IF TG_OP = 'DELETE' THEN
    s := OLD.source;
    r := OLD.source_ref;
  ELSE
    s := NEW.source;
    r := NEW.source_ref;
  END IF;

  PERFORM refresh_feed_stats(s, r);
  RETURN COALESCE(NEW, OLD);
END;
$$;

DROP TRIGGER IF EXISTS t_indicators_refresh_stats_ins ON indicators;
DROP TRIGGER IF EXISTS t_indicators_refresh_stats_upd ON indicators;
DROP TRIGGER IF EXISTS t_indicators_refresh_stats_del ON indicators;

CREATE TRIGGER t_indicators_refresh_stats_ins
AFTER INSERT ON indicators
FOR EACH ROW EXECUTE FUNCTION trg_indicators_refresh_stats();

CREATE TRIGGER t_indicators_refresh_stats_upd
AFTER UPDATE OF is_active, source, source_ref ON indicators
FOR EACH ROW EXECUTE FUNCTION trg_indicators_refresh_stats();

CREATE TRIGGER t_indicators_refresh_stats_del
AFTER DELETE ON indicators
FOR EACH ROW EXECUTE FUNCTION trg_indicators_refresh_stats();

-- Mobile permission normalization helper trigger (optional)
CREATE OR REPLACE FUNCTION trg_mobile_permissions_sync()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  -- wipe and repopulate normalized table
  DELETE FROM mobile_permissions WHERE indicator_id = NEW.indicator_id;

  INSERT INTO mobile_permissions(indicator_id, platform, permission)
  SELECT NEW.indicator_id, NEW.platform, p
  FROM unnest(NEW.permissions) AS p
  WHERE p IS NOT NULL AND length(btrim(p)) > 0;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS t_mobile_permissions_sync ON mobile_app_iocs;
CREATE TRIGGER t_mobile_permissions_sync
AFTER INSERT OR UPDATE OF permissions, platform ON mobile_app_iocs
FOR EACH ROW
EXECUTE FUNCTION trg_mobile_permissions_sync();
