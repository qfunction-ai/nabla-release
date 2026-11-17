import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import Incidents from './Incidents';
import Entities from './Entities';

vi.mock('../lib/api', () => ({
  apiFetch: vi.fn(),
}));

const { apiFetch } = await import('../lib/api');

describe('UI-1: navigation query params', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (apiFetch as ReturnType<typeof vi.fn>).mockResolvedValue({
      incidents: [],
      total: 0,
    });
  });

  it('Incidents consumes severity param on mount', async () => {
    render(
      <MemoryRouter initialEntries={['/incidents?severity=critical']}>
        <Incidents />
      </MemoryRouter>
    );
    // Mount fetch fires with empty filters, then the param effect re-triggers
    // a filtered fetch — assert the filtered call occurs.
    await waitFor(() => {
      const calls = (apiFetch as ReturnType<typeof vi.fn>).mock.calls.map((c) => c[0]);
      expect(calls.some((c) => c.includes('severity=critical'))).toBe(true);
    });
  });

  it('Incidents ignores invalid severity values', async () => {
    render(
      <MemoryRouter initialEntries={['/incidents?severity=bogus']}>
        <Incidents />
      </MemoryRouter>
    );
    await waitFor(() => expect(apiFetch).toHaveBeenCalled());
    await new Promise((r) => setTimeout(r, 50));
    const calls = (apiFetch as ReturnType<typeof vi.fn>).mock.calls.map((c) => c[0]);
    expect(calls.some((c) => c.includes('severity='))).toBe(false);
  });

  it('Entities consumes entity param and fetches its detail', async () => {
    (apiFetch as ReturnType<typeof vi.fn>).mockReset();
    (apiFetch as ReturnType<typeof vi.fn>).mockResolvedValue({});

    render(
      <MemoryRouter initialEntries={['/entities?entity=jsmith_corp']}>
        <Entities />
      </MemoryRouter>
    );
    await waitFor(() => {
      const calls = (apiFetch as ReturnType<typeof vi.fn>).mock.calls.map((c) => c[0]);
      expect(calls.some((c) => c === '/api/entities/jsmith_corp')).toBe(true);
    });
  });
});
