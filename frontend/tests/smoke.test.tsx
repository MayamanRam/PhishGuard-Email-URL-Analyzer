import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import App from '../src/App';
import { SeverityBadge } from '../src/components/SeverityBadge';
import { ScoreGauge } from '../src/components/ScoreGauge';
import { RoutingHopsVisualizer } from '../src/components/RoutingHopsVisualizer';

// Mock the API client
vi.mock('../src/services/api', () => ({
  fetchHealth: vi.fn().mockResolvedValue({
    status: 'healthy',
    app_name: 'PhishGuard',
    version: '1.0.0',
    timestamp: '2026-11-13T10:00:00Z',
    database: { status: 'connected', error: null },
    environment: 'test',
  }),
  fetchDashboardStats: vi.fn().mockResolvedValue({
    total_analyses: 42,
    email_analyses: 24,
    url_analyses: 18,
    open_cases: 5,
    total_findings: 112,
    severity_distribution: {
      low: 10,
      moderate: 14,
      high: 12,
      critical: 6,
    },
    recent_analyses: [
      {
        id: 'test-run-1',
        target_type: 'email',
        target_identifier: 'Account Verification Notice',
        risk_score: 88.5,
        severity: 'critical',
        created_at: '2026-11-13T10:00:00Z',
      },
    ],
  }),
  fetchCases: vi.fn().mockResolvedValue({
    items: [],
    total: 0,
  }),
  fetchRuleCatalog: vi.fn().mockResolvedValue([]),
  fetchReports: vi.fn().mockResolvedValue({
    items: [],
    total: 0,
  }),
  fetchAuditLogs: vi.fn().mockResolvedValue({
    items: [],
    total: 0,
  }),
  createCase: vi.fn().mockResolvedValue({
    id: 'case-mock-id',
    case_number: 'CASE-20261113-0001',
    title: 'Mock Case',
    status: 'open',
    severity: 'high',
    created_at: '2026-11-13T10:00:00Z',
    updated_at: '2026-11-13T10:00:00Z',
  }),
  associateArtifactToCase: vi.fn().mockResolvedValue({ success: true }),
}));

describe('PhishGuard Frontend Smoke & Component Tests', () => {
  it('renders application brand, header, and dashboard console', async () => {
    render(<App />);
    expect(screen.getAllByText(/PhishGuard/i).length).toBeGreaterThan(0);
    expect(
      await screen.findByText(/Security Operations Center \(SOC\) Console/i)
    ).toBeInTheDocument();
  });

  it('renders tactical severity badges correctly', () => {
    const { rerender } = render(<SeverityBadge severity="critical" />);
    expect(screen.getByText(/CRITICAL/i)).toBeInTheDocument();

    rerender(<SeverityBadge severity="low" />);
    expect(screen.getByText(/LOW/i)).toBeInTheDocument();

    rerender(<SeverityBadge severity="moderate" />);
    expect(screen.getByText(/MODERATE/i)).toBeInTheDocument();
  });

  it('renders risk score gauge with score and tier', () => {
    render(<ScoreGauge score={82.4} severity="high" />);
    expect(screen.getByText(/82/)).toBeInTheDocument();
    expect(screen.getByText(/HIGH/i)).toBeInTheDocument();
  });

  it('renders routing hops chronological timeline', () => {
    render(
      <RoutingHopsVisualizer
        hops={[
          {
            hop_number: 1,
            raw_header: 'Received: from client.local by mx.example.com',
            from_host: 'client.local',
            by_host: 'mx.example.com',
            with_protocol: 'ESMTPS',
            ip_address: '198.51.100.20',
            is_private_ip: false,
            timestamp_raw: 'Thu, 12 Nov 2026 12:00:00 +0000',
            delay_seconds: 2.5,
            anomalies: [],
          },
        ]}
      />
    );
    expect(screen.getByText(/Originating Relay/i)).toBeInTheDocument();
    expect(screen.getByText(/198.51.100.20/)).toBeInTheDocument();
  });

  it('switches navigation tabs upon user click', async () => {
    render(<App />);
    const emailNav = screen.getAllByText(/Email Analyzer/i)[0];
    fireEvent.click(emailNav);
    expect(
      await screen.findByText(/Defensive Email Threat Analyzer/i)
    ).toBeInTheDocument();

    const urlNav = screen.getAllByText(/URL Analyzer/i)[0];
    fireEvent.click(urlNav);
    expect(
      await screen.findByText(/Defensive URL Threat Analyzer/i)
    ).toBeInTheDocument();
  });
});
