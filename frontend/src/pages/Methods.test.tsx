import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import Methods from './Methods';
import { DETECTION_METHODS, SUPPLEMENTARY } from '../lib/detectionMethods';

vi.mock('../lib/api', () => ({
  apiFetch: vi.fn(),
}));

const { apiFetch } = await import('../lib/api');

vi.mock('../hooks/useAuth', () => ({
  useAuth: () => ({ isAuthenticated: true, username: 'test', role: 'admin', loading: false, refreshAuth: async () => {}, logout: vi.fn() }),
}));

// A representative slice of the real /api/system/methods response —
// one prose-backed method (join by type string), one joined by method
// key, one uncatalogued (no prose anywhere).
const METHODS_SLICE = [
  { method: 'multi_ip', types: ['multiple_source_ips'], threshold: 'multi_ip_count', default: 3, calibratable: true, state: 'calibratable', bandit_arm: true },
  { method: 'off_hours', types: ['off_hours_activity'], threshold: 'off_hours_count', default: 3, calibratable: true, state: 'calibratable', bandit_arm: true },
  { method: 'attack_script', types: ['attack_script_execution'], threshold: null, default: null, calibratable: false, state: 'static', bandit_arm: false },
];

function renderMethods() {
  return render(
    <MemoryRouter initialEntries={['/methods']}>
      <Methods />
    </MemoryRouter>
  );
}

describe('Methods data integrity', () => {
  it('has exactly 29 numbered methods, contiguous 1-29', () => {
    expect(DETECTION_METHODS).toHaveLength(29);
    const numbers = DETECTION_METHODS.map((m) => m.number).sort((a, b) => a - b);
    expect(numbers).toEqual(Array.from({ length: 29 }, (_, i) => i + 1));
  });

  it('category split is 6/5/9/9 (README canon)', () => {
    const count = (c: string) => DETECTION_METHODS.filter((m) => m.category === c).length;
    expect(count('statistical')).toBe(6);
    expect(count('endpoint')).toBe(5);
    expect(count('advanced')).toBe(9);
    expect(count('entity')).toBe(9);
  });

  it('every method has required fields (typeLabel non-empty, how non-empty)', () => {
    for (const m of DETECTION_METHODS) {
      expect(m.typeLabel.length).toBeGreaterThan(0);
      expect(m.how.length).toBeGreaterThan(0);
      expect(m.catches.length).toBeGreaterThan(0);
      expect(m.fp.length).toBeGreaterThan(0);
      expect(m.fn.length).toBeGreaterThan(0);
    }
  });

  it('supplementary has 7 layers (README 3 + 4 exfil sub-detectors)', () => {
    expect(SUPPLEMENTARY).toHaveLength(7);
    expect(SUPPLEMENTARY.filter((s) => s.name.startsWith('Exfil') || s.name.startsWith('DNS'))).toHaveLength(4);
  });

  it('baseline suppression count is 16 methods / 17 detectors', () => {
    const suppressed = DETECTION_METHODS.filter((m) => !m.baseline);
    expect(suppressed).toHaveLength(16);
    // #20 counts as two detectors (EWMA + CUSUM)
    expect(suppressed.some((m) => m.number === 20)).toBe(true);
    const active = DETECTION_METHODS.filter((m) => m.baseline);
    expect(active).toHaveLength(13);
  });
});

describe('Methods page', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (apiFetch as ReturnType<typeof vi.fn>).mockResolvedValue({ methods: METHODS_SLICE });
  });

  it('renders the generated list: every served method appears', async () => {
    renderMethods();
    expect(screen.getByText('METHODS')).toBeInTheDocument();
    // join by type string: multi_ip serves multiple_source_ips
    expect(await screen.findByText('Impossible travel')).toBeInTheDocument();
    // join by method key: off_hours prose entry carries typeLabel
    // 'off_hours' (the method key), not the emitted type
    expect(screen.getByText('Off-hours activity')).toBeInTheDocument();
    // the count line reads from the served list
    expect(screen.getByText(/3 \/ 3/)).toBeInTheDocument();
  });

  it('renders the supplementary layers', () => {
    renderMethods();
    expect(screen.getByText(/Provenance communities/i)).toBeInTheDocument();
    expect(screen.getByText(/Temporal chains/i)).toBeInTheDocument();
  });

  it('uncatalogued methods render flagged, never silently missing', async () => {
    renderMethods();
    expect(
      await screen.findByText(/Emitted — No Reference Entry/i)
    ).toBeInTheDocument();
    expect(screen.getAllByText(/attack_script/).length).toBeGreaterThanOrEqual(1);
    expect(
      screen.getByText(/No authored reference entry for this method yet/i)
    ).toBeInTheDocument();
  });

  it('stale prose entries surface in their own section', async () => {
    renderMethods();
    expect(await screen.findByText(/Stale Reference Entries/i)).toBeInTheDocument();
    // the L11 slash-triple is the canonical stale entry
    expect(
      screen.getByText(/ewma_drift \/ cusum_shift \/ cusum_drop/)
    ).toBeInTheDocument();
  });

  it('searches across method keys and type strings', async () => {
    renderMethods();
    await screen.findByText(/3 \/ 3/);
    const search = screen.getByPlaceholderText(/Search methods/);
    fireEvent.change(search, { target: { value: 'multiple_source_ips' } });
    expect(screen.getByText(/1 \/ 3/)).toBeInTheDocument();
  });
});
