import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import Timeline from './Timeline';

vi.mock('../lib/api', () => ({
  apiFetch: vi.fn(),
}));

const { apiFetch } = await import('../lib/api');
const mockFetch = apiFetch as ReturnType<typeof vi.fn>;

function event(overrides: Record<string, unknown> = {}) {
  return {
    timestamp: '2026-08-09T10:00:00Z',
    event_type: 'anomaly',
    severity: 'medium',
    entity: 'alice',
    entity_type: 'user',
    title: 'Off-hours activity',
    details: '',
    detection_method: 'off_hours',
    categories: [],
    risk_score: 40,
    source: 'auth',
    mitre_attack: [],
    ...overrides,
  };
}

describe('Timeline', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders events from the response', async () => {
    mockFetch.mockResolvedValue({ events: [event()], total: 1 });
    render(<Timeline entityId="alice" />);
    await waitFor(() => expect(screen.getByText(/1 events/)).toBeInTheDocument());
  });

  it('survives a response with no events key (F6)', async () => {
    // Regression: `setEvents(data.events)` with no validation, then
    // `[...filtered].sort(...)` — an absent `events` threw
    // "TypeError: filtered is not iterable" and took the whole view down.
    mockFetch.mockResolvedValue({});
    render(<Timeline entityId="alice" />);
    await waitFor(() =>
      expect(screen.getByText(/No events found for alice/)).toBeInTheDocument()
    );
  });

  it('survives a null events value', async () => {
    mockFetch.mockResolvedValue({ events: null });
    render(<Timeline entityId="alice" />);
    await waitFor(() =>
      expect(screen.getByText(/No events found for alice/)).toBeInTheDocument()
    );
  });

  it('survives a non-array events value', async () => {
    mockFetch.mockResolvedValue({ events: { unexpected: 'shape' } });
    render(<Timeline entityId="alice" />);
    await waitFor(() =>
      expect(screen.getByText(/No events found for alice/)).toBeInTheDocument()
    );
  });

  it('prompts when no entity is selected', () => {
    render(<Timeline entityId="" />);
    expect(screen.getByText(/Select an entity to view timeline/)).toBeInTheDocument();
  });
});
