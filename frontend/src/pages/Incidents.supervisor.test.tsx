import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import Incidents from './Incidents';
import type { components } from '../types/api';

vi.mock('../lib/api', () => ({
  apiFetch: vi.fn(),
}));

const { apiFetch } = await import('../lib/api');
type Incident = components['schemas']['IncidentResponse'];

const baseIncident: Incident = {
  incident_id: 'a1b2c3d4-0000-0000-0000-000000000001',
  run_id: 'run-1',
  entity: 'helpdeskone',
  entity_type: 'user',
  finding_type: 'lolbin',
  severity: 'high',
  status: 'new',
  confidence: 0.9,
  description: 'certutil with download flags',
  evidence: '',
  created_at: '2026-11-23T00:00:00Z',
  updated_at: '2026-11-23T00:00:00Z',
  log_types: ['endpoint'],
  cross_type: 'single-type',
  mitre_attack: [{ id: 'T1105', name: 'Ingress Tool Transfer', tactic: 'Defense Evasion' }],
  contributing_anomaly_ids: ['4d8ea52907a0310e'],
  contributing_anomaly_details: [],
  operator_notes: '',
  supervisor_review: '[]',
};

const okReport: Incident = {
  ...baseIncident,
  review_status: 'ok',
  supervisor_report: {
    entity: 'helpdeskone',
    summary: 'True positive: certutil downloaded payloads.',
    severity: 'high',
    entities: ['helpdeskone', 'WKSTN-04'],
    attack_techniques: [
      { id: 'T1105', known: true },
      { id: 'T9999', known: false },
    ],
    recommended_actions: ['Isolate the host'],
    claims: [
      {
        text: 'certutil downloaded payloads',
        evidence: [
          { ref: '4d8ea52907a0310e', resolved: true, kind: 'anomaly_id', method: 'lolbin', raw_score: 16, threshold_in_effect: 3.0 },
          { ref: 'deadbeefdeadbeef', resolved: false, kind: 'unknown' },
        ],
      },
    ],
  },
  supervisor_report_meta: { invalid_elements: 1, parse_error: null, reason: null },
};

function mockIncidents(detail: Incident) {
  (apiFetch as ReturnType<typeof vi.fn>).mockImplementation((path: string) => {
    if (path.startsWith('/api/incidents?')) {
      return Promise.resolve({ incidents: [detail], total: 1, limit: 50, offset: 0 });
    }
    if (path.startsWith('/api/incidents/')) {
      return Promise.resolve(detail);
    }
    return Promise.resolve({ incidents: [], total: 0 });
  });
}

async function openDetail(detail: Incident) {
  mockIncidents(detail);
  render(
    <MemoryRouter initialEntries={['/incidents']}>
      <Incidents />
    </MemoryRouter>,
  );
  await waitFor(() => expect(screen.getByText(detail.entity)).toBeInTheDocument());
  fireEvent.click(screen.getByText(detail.entity));
  await waitFor(() => expect(screen.getByText('SUPERVISOR ANALYSIS')).toBeInTheDocument());
}

describe('SupervisorReportCard (Phase 3, R-1/FR-1/D-10)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('round 8 (N-4/N-6)', () => {
    it('claims without evidence carry a visible NO EVIDENCE CITED chip; heading asserts nothing', async () => {
      await openDetail({
        ...okReport,
        supervisor_report: {
          ...okReport.supervisor_report!,
          claims: [{ text: 'an unsupported assertion', evidence: [] }],
        },
      });
      expect(screen.getByText('CLAIMS AND CITED EVIDENCE')).toBeInTheDocument();
      expect(screen.queryByText(/EVERY CLAIM TRACES/)).not.toBeInTheDocument();
      expect(screen.getByText('NO EVIDENCE CITED')).toBeInTheDocument();
    });

    it('safeguard_note renders as a banner; the summary is untouched', async () => {
      await openDetail({
        ...okReport,
        supervisor_report: {
          ...okReport.supervisor_report!,
          safeguard_note: 'DETERMINISTIC NOTE: the pipeline confirmed 3 threat(s).',
        },
      });
      expect(screen.getByText(/DETERMINISTIC NOTE/)).toBeInTheDocument();
      expect(screen.getByText('True positive: certutil downloaded payloads.')).toBeInTheDocument();
    });

    it('resolved entity and anomaly chips click through (N-4 links)', async () => {
      await openDetail({
        ...okReport,
        supervisor_report: {
          ...okReport.supervisor_report!,
          claims: [
            {
              text: 'both cited',
              evidence: [
                { ref: '4d8ea52907a0310e', resolved: true, kind: 'anomaly_id', method: 'lolbin', raw_score: 16, threshold_in_effect: 3.0 },
                { ref: 'helpdeskone', resolved: true, kind: 'entity_id' },
              ],
            },
          ],
        },
      });
      const anomalyChip = screen.getByText(/lolbin · 4d8ea529/);
      expect(anomalyChip.getAttribute('role')).toBe('link');
      fireEvent.click(anomalyChip);
      expect(screen.getByText(/lolbin · 4d8ea529/)).toBeInTheDocument(); // still rendered
      const entityChip = screen.getByText(/entity_id · helpdeskone/);
      expect(entityChip.getAttribute('role')).toBe('link');
    });
  });

  it('renders the structured report: summary, claims, evidence chips with scores', async () => {
    await openDetail(okReport);
    expect(screen.getByText('True positive: certutil downloaded payloads.')).toBeInTheDocument();
    expect(screen.getByText('certutil downloaded payloads')).toBeInTheDocument();
    // resolved evidence chip carries method + raw/thr
    expect(screen.getByText(/lolbin · 4d8ea529/)).toBeInTheDocument();
    expect(screen.getByText(/raw 16 \/ thr 3/)).toBeInTheDocument();
    // unresolved evidence is flagged, never dropped
    expect(screen.getByText(/UNRESOLVED · deadbeef/)).toBeInTheDocument();
    // unknown ATT&CK flagged
    expect(screen.getByText('T9999 · UNVERIFIED')).toBeInTheDocument();
    // per-element validation honesty
    expect(screen.getByText(/1 malformed report element/)).toBeInTheDocument();
  });

  it('invalid: banner + deterministic description is authoritative', async () => {
    await openDetail({
      ...baseIncident,
      review_status: 'invalid',
      supervisor_report_meta: { invalid_elements: 0, parse_error: 'no complete JSON array', reason: 'no valid report matched this incident' },
    });
    expect(screen.getByText('REPORT INVALID')).toBeInTheDocument();
    expect(screen.getByText(/no valid report matched this incident/)).toBeInTheDocument();
    expect(screen.getByText(/authoritative summary/i)).toBeInTheDocument();
  });

  it('absent: honest banner, no fabricated report', async () => {
    await openDetail({ ...baseIncident, review_status: 'absent' });
    expect(screen.getByText('NO REPORT')).toBeInTheDocument();
    expect(screen.getByText(/No supervisor analysis was generated/)).toBeInTheDocument();
  });

  it('legacy incidents (no review_status) render no supervisor section', async () => {
    mockIncidents(baseIncident);
    render(
      <MemoryRouter initialEntries={['/incidents']}>
        <Incidents />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText('helpdeskone')).toBeInTheDocument());
    fireEvent.click(screen.getByText('helpdeskone'));
    await waitFor(() => expect(screen.getByText('INCIDENT DETAIL')).toBeInTheDocument());
    expect(screen.queryByText('SUPERVISOR ANALYSIS')).not.toBeInTheDocument();
  });

  it('R-2: hostile text in the report renders as literal text, never markup', async () => {
    // The injection clip quotes attacker command lines — a markdown or
    // HTML render path is a stored-XSS path. React text nodes render
    // literal by construction; this witness pins that contract.
    const hostile = {
      ...baseIncident,
      review_status: 'ok',
      supervisor_report: {
        entity: 'helpdeskone',
        summary: '<script>alert(1)</script> **bold** [link](http://evil)',
        severity: 'high',
        entities: ['<img src=x onerror=alert(2)>'],
        attack_techniques: [{ id: 'T1059', known: true }],
        recommended_actions: ['# Heading', '```code```'],
        claims: [],
      },
    };
    await openDetail(hostile);
    // the literal strings are present as TEXT
    expect(screen.getByText(/<script>alert\(1\)<\/script>/)).toBeInTheDocument();
    expect(screen.getByText(/\*\*bold\*\*/)).toBeInTheDocument();
    // and no script/img element was created from them
    expect(document.querySelector('script')).toBeNull();
    expect(document.querySelector('img')).toBeNull();
  });
});
