import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import Help from './Help';

vi.mock('../hooks/useAuth', () => ({
  useAuth: () => ({ isAuthenticated: true, username: 'test', role: 'admin', loading: false, refreshAuth: async () => {}, logout: vi.fn() }),
}));

function renderHelp(path = '/help') {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Help />
    </MemoryRouter>
  );
}

describe('Help page', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders the page title and subtitle', () => {
    renderHelp();
    expect(screen.getByText('HELP')).toBeInTheDocument();
    expect(screen.getByText(/divergence-free/i)).toBeInTheDocument();
  });

  it('renders all ten section titles in the TOC', () => {
    renderHelp();
    for (const title of [
      'Getting Started', 'How It Works', 'Dashboard', 'Entities', 'Incidents',
      'Pipeline', 'Chat', 'Config', 'Detection Methods', 'FAQ',
    ]) {
      expect(screen.getAllByText(title).length).toBeGreaterThan(0);
    }
  });

  it('renders section content headings', () => {
    renderHelp();
    expect(screen.getByText('Prerequisites')).toBeInTheDocument();
    expect(screen.getByText(/The two-phase lifecycle/i)).toBeInTheDocument();
  });

  it('highlights the first section initially', () => {
    renderHelp();
    const first = screen.getAllByText('Getting Started')[0].closest('button');
    expect(first?.className).toContain('doc-toc-active');
  });

  it('navigates sections on TOC click', () => {
    renderHelp();
    const faqBtn = screen.getAllByText('FAQ')[0].closest('button');
    fireEvent.click(faqBtn!);
    const faqActive = screen.getAllByText('FAQ')[0].closest('button');
    expect(faqActive?.className).toContain('doc-toc-active');
  });

  it('links to the Methods page from the detection section', () => {
    renderHelp();
    const link = screen.getByText(/Open the full Methods reference/i).closest('a');
    expect(link).toHaveAttribute('href', '/methods');
  });

  it('documents the FAQ sharp edges from real incidents', () => {
    renderHelp();
    expect(screen.getByText(/stale-image gotcha/i)).toBeInTheDocument();
    expect(screen.getByText(/docker compose down -v/i)).toBeInTheDocument();
  });
});
