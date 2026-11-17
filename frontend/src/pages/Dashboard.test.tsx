import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import Dashboard from './Dashboard';

vi.mock('../lib/api', () => ({
  apiFetch: vi.fn(),
}));

function renderDashboard() {
  return render(
    <MemoryRouter>
      <Dashboard />
    </MemoryRouter>
  );
}

const mockDashboardData = {
  phase: 'detection',
  days_remaining: null,
  warm_up: {
    users: { total: 10, warm: 8, pct: 80 },
    hosts: { total: 5, warm: 3, pct: 60 },
    ips: { total: 20, warm: 15, pct: 75 },
    min_observations: 5,
  },
  entity_counts: { users: 10, hosts: 5, ips: 20 },
  health: {
    letta: { healthy: true },
    ollama: { healthy: false },
  },
  incident_stats: {
    total: 7,
    by_status: { new: 3, investigating: 2, resolved: 1, false_positive: 1 },
    by_severity: { critical: 1, high: 2, medium: 3, low: 1 },
  },
  recent_runs: [],
  recent_incidents: [],
};

describe('Dashboard', () => {
  beforeEach(async () => {
    const { apiFetch } = await import('../lib/api');
    (apiFetch as ReturnType<typeof vi.fn>).mockResolvedValue(mockDashboardData);
  });

  it('renders loading state initially', () => {
    renderDashboard();
    expect(screen.getByText(/loading/i)).toBeInTheDocument();
  });

  it('renders dashboard data after fetch', async () => {
    renderDashboard();
    await waitFor(() => {
      expect(screen.getByText(/detection phase/i)).toBeInTheDocument();
    });
  });

  it('shows Letta connected status', async () => {
    renderDashboard();
    await waitFor(() => {
      expect(screen.getByText('Connected')).toBeInTheDocument();
    });
  });

  it('shows Ollama down status', async () => {
    renderDashboard();
    await waitFor(() => {
      expect(screen.getByText('Down')).toBeInTheDocument();
    });
  });

  it('renders incident count', async () => {
    renderDashboard();
    await waitFor(() => {
      expect(screen.getAllByText('7').length).toBeGreaterThan(0);
    });
  });

  it('renders severity counts', async () => {
    renderDashboard();
    await waitFor(() => {
      expect(screen.getByText('critical')).toBeInTheDocument();
      expect(screen.getByText('high')).toBeInTheDocument();
    });
  });

  it('shows empty state for recent runs', async () => {
    renderDashboard();
    await waitFor(() => {
      expect(screen.getByText('No runs yet')).toBeInTheDocument();
    });
  });

  it('shows empty state for incidents', async () => {
    renderDashboard();
    await waitFor(() => {
      expect(screen.getByText('No incidents')).toBeInTheDocument();
    });
  });
});

describe('Dashboard with error', () => {
  it('shows error state on fetch failure', async () => {
    const { apiFetch } = await import('../lib/api');
    (apiFetch as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error('Network error'));

    renderDashboard();
    await waitFor(() => {
      expect(screen.getByText(/Network error/i)).toBeInTheDocument();
    });
  });
});

describe('Dashboard baseline phase', () => {
  it('shows baseline phase indicator', async () => {
    const { apiFetch } = await import('../lib/api');
    (apiFetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ...mockDashboardData,
      phase: 'baseline',
      days_remaining: 5,
    });

    renderDashboard();
    await waitFor(() => {
      expect(screen.getByText(/baseline phase/i)).toBeInTheDocument();
    });
  });
});
