/**
 * Honest duration from a run record: the old hand-copied frontend
 * interfaces declared duration_ms, which never existed on run records —
 * every duration cell rendered "—". Derive it from the timestamps.
 */
export function runDuration(run: {
  started_at?: string | null;
  finished_at?: string | null;
}): number | null {
  if (!run.started_at || !run.finished_at) return null;
  const ms =
    new Date(run.finished_at).getTime() - new Date(run.started_at).getTime();
  return Number.isFinite(ms) && ms >= 0 ? Math.round(ms / 1000) : null;
}
