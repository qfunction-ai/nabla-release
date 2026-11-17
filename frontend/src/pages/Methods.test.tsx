import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import Methods from './Methods';
import { DETECTION_METHODS, SUPPLEMENTARY } from '../lib/detectionMethods';

vi.mock('../hooks/useAuth', () => ({
  useAuth: () => ({ isAuthenticated: true, username: 'test', role: 'admin', loading: false, refreshAuth: async () => {}, logout: vi.fn() }),
}));

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
  });

  it('renders the title and all 29 cards', () => {
    renderMethods();
    expect(screen.getByText('METHODS')).toBeInTheDocument();
    for (const m of DETECTION_METHODS) {
      expect(screen.getByText(`#${m.number}`)).toBeInTheDocument();
    }
  });

  it('renders the supplementary layers', () => {
    renderMethods();
    expect(screen.getByText(/Provenance communities/i)).toBeInTheDocument();
    expect(screen.getByText(/Temporal chains/i)).toBeInTheDocument();
  });

  it('filters by category', () => {
    renderMethods();
    const before = screen.getByText(/29 \/ 29/);
    expect(before).toBeInTheDocument();
    const catSelect = screen.getAllByDisplayValue('All categories')[0];
    fireEvent.change(catSelect, { target: { value: 'entity' } });
    expect(screen.getByText(/9 \/ 29/)).toBeInTheDocument();
  });

  it('searches by name and type label', () => {
    renderMethods();
    const search = screen.getByPlaceholderText(/Search methods/);
    fireEvent.change(search, { target: { value: 'brute_force' } });
    expect(screen.getByText(/1 \/ 29/)).toBeInTheDocument();
    expect(screen.getByText('Brute force')).toBeInTheDocument();
  });

  it('filters by baseline availability', () => {
    renderMethods();
    const select = screen.getAllByDisplayValue('Baseline: any')[0];
    fireEvent.change(select, { target: { value: 'active' } });
    expect(screen.getByText(/13 \/ 29/)).toBeInTheDocument();
  });
});
