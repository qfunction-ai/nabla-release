import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import Entities from './Entities';

vi.mock('../lib/api', () => ({
  apiFetch: vi.fn(),
}));

const entitiesPage = {
  entities: [
    {
      id: 'helpdeskone', type: 'user', observation_count: 40,
      first_seen: '2026-08-01T00:00:00Z', last_seen: '2026-08-16T00:00:00Z',
      warm: true, risk_score: 68, account_created_at: null,
      is_machine: false,
      quarantine: {
        held: true, since: '2026-08-15T00:00:00Z', days_left: 13, tp_hold: true,
        batches_held: 2, held_batches: 2, held_events: 20, released_at: null,
      },
    },
    {
      id: 'smith', type: 'user', observation_count: 40,
      first_seen: '2026-08-01T00:00:00Z', last_seen: '2026-08-16T00:00:00Z',
      warm: true, risk_score: 12, account_created_at: null,
      is_machine: false, quarantine: null,
    },
    {
      id: 'svc-jenkins', type: 'user', observation_count: 500,
      first_seen: '2026-08-01T00:00:00Z', last_seen: '2026-08-16T00:00:00Z',
      warm: true, risk_score: 0, account_created_at: null,
      is_machine: true, quarantine: null,
    },
  ],
  total: 3, limit: 50, offset: 0,
};

const detail = (isMachine: boolean) => ({
  type: 'user', warm: true, observation_count: 40,
  first_seen: '2026-08-01T00:00:00Z', last_seen: '2026-08-16T00:00:00Z',
  environment_facts: [], ewma: {}, typical_ips: [],
  peer_group: null, is_machine: isMachine,
  quarantine: isMachine ? null : entitiesPage.entities[0].quarantine,
});

async function setupMock() {
  const { apiFetch } = await import('../lib/api');
  (apiFetch as ReturnType<typeof vi.fn>).mockImplementation((url: string) => {
    if (url.startsWith('/api/entities?')) {
      return Promise.resolve(entitiesPage);
    }
    if (url.includes('/svc-jenkins') && !url.includes('attribution')) {
      return Promise.resolve(detail(true));
    }
    if (url.includes('/helpdeskone') && !url.includes('attribution')) {
      return Promise.resolve(detail(false));
    }
    if (url.includes('attribution')) {
      return Promise.resolve({
        entity_id: 'x', anomalies: [], incidents: [],
        risk: null, runs_scanned: 0,
      });
    }
    return Promise.resolve({ events: [], total: 0 });
  });
}

function renderEntities() {
  return render(
    <MemoryRouter>
      <Entities />
    </MemoryRouter>
  );
}

describe('Entities page — Phase 2 states (mockup 04)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('shows QUARANTINE HOLD with days left on the held entity', async () => {
    await setupMock();
    renderEntities();
    await waitFor(() => {
      expect(screen.getByText('QUARANTINE HOLD — 13d LEFT')).toBeInTheDocument();
    });
  });

  it('shows ACTIVE on the unheld entity', async () => {
    await setupMock();
    renderEntities();
    await waitFor(() => {
      expect(screen.getByText('ACTIVE')).toBeInTheDocument();
    });
  });

  it('tags machine accounts and shows EXCLUDED state', async () => {
    await setupMock();
    renderEntities();
    await waitFor(() => {
      expect(screen.getByText('MACHINE')).toBeInTheDocument();
      expect(screen.getByText('EXCLUDED FROM BASELINE & RISK')).toBeInTheDocument();
    });
  });

  it('shows the quarantine panel in the held entity detail', async () => {
    await setupMock();
    renderEntities();
    await waitFor(() => {
      expect(screen.getByText('QUARANTINE HOLD — 13d LEFT')).toBeInTheDocument();
    });
    fireEvent.click(screen.getByText('helpdeskone'));
    await waitFor(() => {
      expect(screen.getByText('BASELINE DATA HELD')).toBeInTheDocument();
      expect(screen.getByText(/20 events across 2 batches/i)).toBeInTheDocument();
    });
  });

  it('shows the machine-account panel with the blind-spot warning', async () => {
    await setupMock();
    renderEntities();
    await waitFor(() => {
      expect(screen.getByText('svc-jenkins')).toBeInTheDocument();
    });
    fireEvent.click(screen.getByText('svc-jenkins'));
    await waitFor(() => {
      expect(screen.getByText('MACHINE ACCOUNT')).toBeInTheDocument();
      expect(screen.getByText(/Documented blind spot/i)).toBeInTheDocument();
    });
  });
});
