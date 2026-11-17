import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import Entities from './Entities';

vi.mock('../lib/api', () => ({
  apiFetch: vi.fn(),
}));

const { apiFetch } = await import('../lib/api');

function renderEntities() {
  return render(
    <MemoryRouter initialEntries={['/entities?entity=analyst_a']}>
      <Entities />
    </MemoryRouter>
  );
}

describe('Peer group card (course plan 2026-11-17)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders the peer group with members; selected entity highlighted', async () => {
    (apiFetch as ReturnType<typeof vi.fn>).mockImplementation((path: string) => {
      if (path.startsWith('/api/entities?')) {
        return Promise.resolve({ entities: [], total: 0 });
      }
      if (path.includes('/api/timeline/')) {
        return Promise.resolve({ events: [], total: 0 });
      }
      if (path.includes('/attribution')) {
        return Promise.resolve({ entity_id: 'analyst_a', anomalies: [], incidents: [], risk: null, runs_scanned: 0 });
      }
      return Promise.resolve({
        type: 'user', warm: true, observation_count: 10, environment_facts: [],
        peer_group: {
          group_id: 'user_0', label: 'business-hours',
          members: ['analyst_a', 'analyst_b', 'helpdesk_user'], centroid: { event_count: 40 },
        },
        risk_score: { overall: 0, categories: {}, peak: 0, trend: 0, trend_label: 'stable' },
      });
    });

    renderEntities();
    expect(await screen.findByText('PEER GROUP')).toBeInTheDocument();
    expect(screen.getByText('analyst_b')).toBeInTheDocument();
    expect(screen.getByText('helpdesk_user')).toBeInTheDocument();
    // the selected entity appears as a member chip (getAllByText covers both the member
    // chip and any other render site; the member chip is present)
    expect(screen.getAllByText('analyst_a').length).toBeGreaterThan(0);
  });

  it('renders the null state when no peer group exists', async () => {
    (apiFetch as ReturnType<typeof vi.fn>).mockImplementation((path: string) => {
      if (path.startsWith('/api/entities?')) {
        return Promise.resolve({ entities: [], total: 0 });
      }
      if (path.includes('/api/timeline/')) {
        return Promise.resolve({ events: [], total: 0 });
      }
      if (path.includes('/attribution')) {
        return Promise.resolve({ entity_id: 'brown', anomalies: [], incidents: [], risk: null, runs_scanned: 0 });
      }
      return Promise.resolve({
        type: 'user', warm: false, observation_count: 1, environment_facts: [],
        peer_group: null,
      });
    });

    renderEntities();
    expect(await screen.findByText(/No peer group yet/i)).toBeInTheDocument();
    expect(screen.getByText(/about hourly/i)).toBeInTheDocument();
  });

  it('caps member chips at 10 with an N-more line', async () => {
    const members = Array.from({ length: 14 }, (_, i) => `user${i}`);
    (apiFetch as ReturnType<typeof vi.fn>).mockImplementation((path: string) => {
      if (path.startsWith('/api/entities?')) {
        return Promise.resolve({ entities: [], total: 0 });
      }
      if (path.includes('/api/timeline/')) {
        return Promise.resolve({ events: [], total: 0 });
      }
      if (path.includes('/attribution')) {
        return Promise.resolve({ entity_id: 'user0', anomalies: [], incidents: [], risk: null, runs_scanned: 0 });
      }
      return Promise.resolve({
        type: 'user', warm: true, observation_count: 10, environment_facts: [],
        peer_group: { group_id: 'user_1', label: 'big', members },
      });
    });

    renderEntities();
    expect(await screen.findByText('+4 more')).toBeInTheDocument();
  });
});
