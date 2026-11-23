import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import Pipeline from './Pipeline';

vi.mock('../lib/api', () => ({
  apiFetch: vi.fn(),
}));

const runFull = {
  run_id: 'phase1001-rest',
  started_at: '2026-11-20T05:00:00Z',
  finished_at: '2026-11-20T05:01:00Z',
  source: 'file',
  operator: 'test',
  watchlist_groups: null,
  log_types: 'all',
  log_count: 50,
  anomaly_count: 2,
  findings_count: 1,
  step_durations: { ingestion: 30.0, anomaly: 5.0 },
  success: true,
  error: null,
  anomalies: [
    {
      anomaly_id: 'a1', entity: 'helpdeskone', entity_type: 'user',
      severity: 'high', timestamp: '2026-11-20T05:00:30Z',
      detection_method: 'entity_z_score', details: 'z 2.02',
      categories: [], mitre_attack: [],
      raw_score: 2.021, event_ids: ['e1', 'e2'], threshold_in_effect: 2.0,
    },
  ],
  findings: [],
  degradations: ['risk_scores'],
  layer_counts: { base: 2, gcn_lof: 0, provenance: 0, temporal: 0, exfiltration: 0 },
  temporal_stats: {},
  supervisor_narrative: 'Narrative.',
  ingest_chunks: null, ingest_siem_data: null, ingest_frozen_baseline: null,
};

const runClean = {
  ...runFull,
  run_id: 'clean0001-rest',
  degradations: [],
};

async function mockApi() {
  const { apiFetch } = await import('../lib/api');
  (apiFetch as ReturnType<typeof vi.fn>).mockImplementation((url: string) => {
    if (url.includes('/status')) {
      return Promise.resolve({ running: false, run_id: null, started_at: null, current_step: null, last_run: null });
    }
    if (url.includes('/history')) {
      return Promise.resolve({ runs: [runFull, runClean], total: 2, limit: 20, offset: 0 });
    }
    if (url.includes(`/runs/${runFull.run_id.slice(0, 8)}`)) {
      return Promise.resolve(runFull);
    }
    if (url.includes(`/runs/${runClean.run_id.slice(0, 8)}`)) {
      return Promise.resolve(runClean);
    }
    return Promise.reject(new Error(`unmocked: ${url}`));
  });
}

async function setupMock() {
  await mockApi();
}

function runIdCell(idPrefix: string) {
  // The run-id cell renders "▸ <id>" as two text nodes — match on the
  // td's full textContent instead of a single text node.
  return screen.getByText(
    (_content, element) =>
      element?.tagName === 'TD' && !!element.textContent?.includes(idPrefix)
  );
}

function renderPipeline() {
  return render(
    <MemoryRouter>
      <Pipeline />
    </MemoryRouter>
  );
}

describe('Pipeline page — Phase 1 run detail (A3/A4/N7)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('shows a degradation badge on the degraded run in history', async () => {
    await setupMock();
    renderPipeline();
    await waitFor(() => {
      expect(screen.getByText('⚠ 1')).toBeInTheDocument();
    });
  });

  it('expands the run detail with the degradations panel and fallback copy', async () => {
    await setupMock();
    renderPipeline();
    await waitFor(() => {
      expect(screen.getByText('⚠ 1')).toBeInTheDocument();
    });
    fireEvent.click(runIdCell('phase100'));
    await waitFor(() => {
      expect(screen.getByText(/Degraded steps \(1\)/)).toBeInTheDocument();
      expect(screen.getByText(/scores retained from previous run/i)).toBeInTheDocument();
    });
  });

  it('renders raw score, threshold, and events columns in the anomaly table', async () => {
    await setupMock();
    renderPipeline();
    await waitFor(() => {
      expect(screen.getByText('⚠ 1')).toBeInTheDocument();
    });
    fireEvent.click(runIdCell('phase100'));
    await waitFor(() => {
      expect(screen.getByText('2.021')).toBeInTheDocument();
      expect(screen.getByText('2.00')).toBeInTheDocument();
      expect(screen.getByText('Raw score')).toBeInTheDocument();
      expect(screen.getByText('Threshold')).toBeInTheDocument();
      expect(screen.getByText('Events')).toBeInTheDocument();
    });
  });

  it('shows DEGRADATIONS: NONE for a clean run', async () => {
    await setupMock();
    renderPipeline();
    await waitFor(() => {
      expect(runIdCell('clean000')).toBeInTheDocument();
    });
    fireEvent.click(runIdCell('clean000'));
    await waitFor(() => {
      expect(screen.getByText('DEGRADATIONS: NONE')).toBeInTheDocument();
    });
  });

  it('computes duration honestly from started_at/finished_at', async () => {
    await setupMock();
    renderPipeline();
    await waitFor(() => {
      // 60s run — the old duration_ms lie rendered "—" for every run
      expect(screen.getAllByText('60s').length).toBeGreaterThan(0);
    });
  });
});
