import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import Layout from './Layout';

const mockLogout = vi.fn();

vi.mock('../hooks/useAuth', () => ({
  useAuth: () => ({
    isAuthenticated: true,
    requiresToken: false,
    token: 'test-token',
    setToken: vi.fn(),
    logout: mockLogout,
  }),
}));

function renderWithRouter(ui: React.ReactNode, path = '/') {
  return render(
    <MemoryRouter initialEntries={[path]}>
      {ui}
    </MemoryRouter>
  );
}

describe('Layout', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders navigation links', () => {
    renderWithRouter(
      <Layout><div>Content</div></Layout>
    );
    expect(screen.getByText('Dashboard')).toBeInTheDocument();
    expect(screen.getByText('Entities')).toBeInTheDocument();
    expect(screen.getByText('Pipeline')).toBeInTheDocument();
    expect(screen.getByText('Incidents')).toBeInTheDocument();
    expect(screen.getByText('Chat')).toBeInTheDocument();
    expect(screen.getByText('Config')).toBeInTheDocument();
    expect(screen.getByText('Methods')).toBeInTheDocument();
    expect(screen.getByText('Help')).toBeInTheDocument();
    // Environment merged into Config (redesign plan Phase 2a) — no nav item
    expect(screen.queryByText('Environment')).not.toBeInTheDocument();
  });

  it('renders children content', () => {
    renderWithRouter(
      <Layout><div>Test content</div></Layout>
    );
    expect(screen.getByText('Test content')).toBeInTheDocument();
  });

  it('renders the logo', () => {
    renderWithRouter(
      <Layout><div>Content</div></Layout>
    );
    expect(screen.getByText('NABLA')).toBeInTheDocument();
    expect(screen.getByText('QFunction')).toBeInTheDocument();
  });

  it('calls logout on logout button click', () => {
    renderWithRouter(
      <Layout><div>Content</div></Layout>
    );
    fireEvent.click(screen.getByRole('button', { name: /logout/i }));
    expect(mockLogout).toHaveBeenCalledOnce();
  });

  it('applies active class to current route', () => {
    renderWithRouter(
      <Layout><div>Content</div></Layout>,
      '/'
    );
    const dashboardLink = screen.getByText('Dashboard').closest('a');
    expect(dashboardLink?.className).toContain('active');
  });

  it('does not apply active class to non-current routes', () => {
    renderWithRouter(
      <Layout><div>Content</div></Layout>,
      '/'
    );
    const entitiesLink = screen.getByText('Entities').closest('a');
    expect(entitiesLink?.className).not.toContain('active');
  });
});
