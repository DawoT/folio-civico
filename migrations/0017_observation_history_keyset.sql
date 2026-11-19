-- Keyset history uses commission + created_at + deterministic tie-breaker id.
-- Keeps page fetches indexed without sorting all statuses for a commission.
CREATE INDEX IF NOT EXISTS idx_observations_history_keyset
  ON observations(commission_id,created_at DESC,id DESC);
