import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import Config from './Config';

vi.mock('../lib/api', () => ({
  apiFetch: vi.fn(),
}));

const { apiFetch } = await import('../lib/api');

const rlResponse = {
  feedback_labels: 47,
  min_labels: 30,
  thresholds: {
    entity_event_count_sigma: {
      name: 'entity_event_count_sigma', current: 2.25, default: 2.0, changed: true,
      pinned: false, state: 'calibratable', evidence: 'calibrated 2026-11-23',
      label_count: 35, tp_count: 27, fp_count: 8, min_labels: 30,
      methods: ['entity_z_score'], reason: null,
    },
    z_score_sigma: {
      name: 'z_score_sigma', current: 3.0, default: 3.0, changed: false,
      pinned: true, state: 'calibratable', evidence: null,
      label_count: 0, tp_count: 0, fp_count: 0, min_labels: 30,
      methods: ['z_score'], reason: null,
    },
    brute_force_ratio: {
      name: 'brute_force_ratio', current: 0.5, default: 0.5, changed: false,
      pinned: false, state: 'held', evidence: null,
      label_count: 12, tp_count: 8, fp_count: 4, min_labels: 30,
      methods: ['failed_login_ratio'], reason: 'below min_labels (12/30); accumulating',
    },
    lolbin_sensitivity: {
      name: 'lolbin_sensitivity', current: 0.7, default: 0.7, changed: false,
      pinned: false, state: 'not_calibratable', evidence: null,
      label_count: 0, tp_count: 0, fp_count: 0, min_labels: 30,
      methods: [], reason: 'no calibratable method feeds this threshold',
    },
  },
  effectiveness: {},
};

function mockAll() {
  (apiFetch as ReturnType<typeof vi.fn>).mockImplementation((path: string) => {
    if (path === '/api/system/rl') return Promise.resolve(rlResponse);
    if (path === '/api/system/schedule') return Promise.resolve({ running: false, next_run: null, interval: 15, log_types: 'all', log_count: 20 });
    if (path === '/api/system/health') return Promise.resolve({ letta: { healthy: true }, ollama: { healthy: true }, data_dir: { path: '/data', writable: true, exists: true } });
    return Promise.resolve({});
  });
}

async function openRL() {
  mockAll();
  render(<Config />);
  fireEvent.click(screen.getByText('RL State'));
  await waitFor(() => expect(screen.getByText('ADAPTIVE THRESHOLDS — HONEST STATES')).toBeInTheDocument());
}

describe('Config calibration states (Phase 4, L6/L12 — mockup 03)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders all four honest states with label evidence', async () => {
    await openRL();
    // MOVED with the arc
    expect(screen.getByText('MOVED 2 → 2.25')).toBeInTheDocument();
    expect(screen.getByText('35 labels · 8 FP / 27 TP')).toBeInTheDocument();
    // PINNED guardrail
    expect(screen.getAllByText('PINNED').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('operator guardrail — never tuned')).toBeInTheDocument();
    // HELD with counts
    expect(screen.getByText('HELD — 12/30 LABELS')).toBeInTheDocument();
    expect(screen.getByText(/below min_labels \(12\/30\); accumulating/)).toBeInTheDocument();
    // NOT CALIBRATABLE
    expect(screen.getAllByText('NOT CALIBRATABLE').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText(/no calibratable method feeds this threshold/)).toBeInTheDocument();
  });

  it('serves real stats, not the phantom totals the old interface invented', async () => {
    await openRL();
    expect(screen.getByText('FEEDBACK LABELS')).toBeInTheDocument();
    expect(screen.getByText('47')).toBeInTheDocument();
    expect(screen.getByText('MIN LABELS / METHOD')).toBeInTheDocument();
    expect(screen.getByText('30')).toBeInTheDocument();
  });

  it('L13: export copy no longer implies a watchlist UI', async () => {
    mockAll();
    render(<Config />);
    fireEvent.click(screen.getByText('Export/Import'));
    await waitFor(() => expect(screen.getByText('EXPORT STATE')).toBeInTheDocument());
    const copy = screen.getByText(/Download all learned state/);
    expect(copy.textContent).not.toMatch(/watchlist/i);
  });
});
