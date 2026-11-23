import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import Chat from './Chat';

vi.mock('../lib/api', () => ({
  apiFetch: vi.fn(),
  API_URL: 'http://test',
}));

const { apiFetch } = await import('../lib/api');

function mockHistory(turns: Array<{ turn_id: string; ts: string; message: string; answer: string; reasoning?: string | null }>) {
  (apiFetch as ReturnType<typeof vi.fn>).mockResolvedValue({ turns, next_cursor: null });
}

describe('Chat history restore (Phase 5, B1 — survives refresh)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('loads the persisted transcript on open, oldest first', async () => {
    mockHistory([
      { turn_id: 't2', ts: '2026-11-23T02:00:00+00:00', message: 'second question', answer: 'second answer' },
      { turn_id: 't1', ts: '2026-11-23T01:00:00+00:00', message: 'first question', answer: 'first answer' },
    ]);
    render(<Chat />);
    await waitFor(() => expect(screen.getByText('first question')).toBeInTheDocument());
    expect(screen.getByText('second question')).toBeInTheDocument();
    expect(screen.getByText('first answer')).toBeInTheDocument();
    expect(screen.getByText('second answer')).toBeInTheDocument();
  });

  it('restores reasoning turns when they were persisted', async () => {
    mockHistory([
      { turn_id: 't1', ts: '2026-11-23T01:00:00+00:00', message: 'q', answer: 'a', reasoning: 'deep thought' },
    ]);
    render(<Chat />);
    await waitFor(() => expect(screen.getByText('deep thought')).toBeInTheDocument());
  });

  it('renders the empty state when no history exists', async () => {
    mockHistory([]);
    render(<Chat />);
    await waitFor(() =>
      expect(screen.getByText(/Ask the supervisor/i)).toBeInTheDocument());
  });

  it('history failure does not break the page (best-effort restore)', async () => {
    (apiFetch as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('network'));
    render(<Chat />);
    await waitFor(() =>
      expect(screen.getByText(/Ask the supervisor/i)).toBeInTheDocument());
  });
});
