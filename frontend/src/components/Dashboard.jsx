import React, { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  } from 'recharts';
import api, { getApiErrorMessage } from '../services/api';
import { useAuth } from '../contexts/AuthContext';
import InfoHint from './soc/InfoHint';
import '../styles/globals.css';

const SOURCE_LABELS = {
  demo_seed: 'Demo Simulation',
  manual_analysis: 'Manual Analysis',
  bulk_ingest: 'Bulk Ingest',
  correlation_engine: 'Correlation Engine',
  real_windows_event_log: 'Windows Event Log',
  webhook: 'Webhook',
  asset_website: 'Website Asset',
  asset_github: 'GitHub Asset',
  asset_api: 'API Asset',
  asset_cloud: 'Cloud Asset',
  asset_server: 'Server Asset',
  asset_saas: 'SaaS Asset',
  other: 'Other',
};

const CountUp = ({ value }) => {
  const [display, setDisplay] = useState(0);
  const prev = useRef(0);

  useEffect(() => {
    if (value == null) {
      return;
    }

    const target = Number(value);
    let current = prev.current;
    const step = Math.max(1, Math.ceil(Math.abs(target - current) / 28));

    const interval = setInterval(() => {
      current = target > current ? Math.min(current + step, target) : Math.max(current - step, target);
      setDisplay(current);
      if (current === target) {
        clearInterval(interval);
        prev.current = target;
      }
    }, 18);

    return () => clearInterval(interval);
  }, [value]);

  return <>{display}</>;
};

function MetricCard({ label, hint, value, sub, tone = 'default', delay = 0 }) {
  return (
    <motion.div
      className={`soc-metric-card soc-metric-${tone}`}
      initial={{ opacity: 0, y: 18 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.45, delay }}
    >
      <div className="soc-metric-label">{label}{hint ? <InfoHint text={hint} /> : null}</div>
      <div className="soc-metric-value"><CountUp value={value} /></div>
      <div className="soc-metric-sub">{sub}</div>
    </motion.div>
  );
}

function MiniBar({ label, value, total, color }) {
  const width = total > 0 ? Math.max(4, (value / total) * 100) : 0;
  return (
    <div className="mini-bar-row">
      <div className="mini-bar-label">{label}</div>
      <div className="mini-bar-track">
        <motion.div
          className="mini-bar-fill"
          style={{ background: color }}
          initial={{ width: 0 }}
          animate={{ width: `${width}%` }}
          transition={{ duration: 0.7, ease: 'easeOut' }}
        />
      </div>
      <div className="mini-bar-value">{value}</div>
    </div>
  );
}

// ── Incident Trend Chart (real activity from /dashboard/stats) ─────────────
function IncidentTrendChart({ stats, range = '7d' }) {
  const series = range === '24h' ? (stats?.activity_24h || []) : (stats?.activity_7d || []);
  const rawData = series.map((point) => {
    const stamp = new Date(`${(point.hour || point.day)}${point.hour ? 'Z' : 'T00:00:00Z'}`);
    return {
      day: range === '24h'
        ? stamp.toLocaleTimeString([], { hour: '2-digit' })
        : stamp.toLocaleDateString([], { weekday: 'short', timeZone: 'UTC' }),
      critical: point.critical || 0,
      high: point.high || 0,
      medium: (point.medium || 0) + (point.low || 0),
    };
  });

  const CustomTooltip = ({ active, payload, label }) => {
    if (!active || !payload?.length) return null;
    return (
      <div style={{
        background: '#141210', border: '1px solid rgba(215,163,90,0.18)',
        borderRadius: 8, padding: '10px 14px', fontFamily: 'JetBrains Mono, monospace',
      }}>
        <div style={{ color: '#8A7F72', fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6 }}>{label}</div>
        {payload.map((p) => (
          <div key={p.dataKey} style={{ display: 'flex', justifyContent: 'space-between', gap: 16, marginBottom: 3 }}>
            <span style={{ color: p.color, fontSize: 10, textTransform: 'uppercase' }}>{p.dataKey}</span>
            <span style={{ color: '#F5F0E8', fontSize: 11, fontWeight: 700 }}>{p.value}</span>
          </div>
        ))}
      </div>
    );
  };

  return (
    <div style={{ height: 160, width: '100%' }}>
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={rawData} margin={{ top: 8, right: 4, left: -28, bottom: 0 }}>
          <defs>
            <linearGradient id="purpleGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%"  stopColor="var(--accent-primary)" stopOpacity={0.4} />
              <stop offset="95%" stopColor="var(--accent-primary)" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="critGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%"  stopColor="#EF4444" stopOpacity={0.35} />
              <stop offset="95%" stopColor="#EF4444" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(215,163,90,0.06)" />
          <XAxis dataKey="day" tick={{ fill: '#564E44', fontSize: 9, fontFamily: 'JetBrains Mono' }} axisLine={false} tickLine={false} />
          <YAxis tick={{ fill: '#564E44', fontSize: 9, fontFamily: 'JetBrains Mono' }} axisLine={false} tickLine={false} />
          <Tooltip content={<CustomTooltip />} />
          <Area type="monotone" dataKey="critical" stroke="#EF4444" strokeWidth={1.5} fill="url(#critGrad)" />
          <Area type="monotone" dataKey="high" stroke="var(--accent-primary)" strokeWidth={2.5} fill="url(#purpleGrad)" />
          <Area type="monotone" dataKey="medium" stroke="var(--accent-blue)" strokeWidth={1.5} fill="transparent" />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

function QueueItem({ incident, active, onSelect, index }) {
  const severityClass = incident.risk_level?.toLowerCase() || 'low';
  const sourceLabel = SOURCE_LABELS[incident.source] || SOURCE_LABELS.other;
  return (
    <motion.button
      type="button"
      className={`queue-item ${active ? 'queue-item-active' : ''}`}
      onClick={() => onSelect(incident)}
      initial={{ opacity: 0, x: -12 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.35, delay: index * 0.04 }}
    >
      <div className="queue-item-top">
        <span className={`severity-chip ${severityClass}`}>{incident.risk_level || 'LOW'}</span>
        <span className="queue-item-status">{incident.status || 'Open'}</span>
      </div>
      <div className="queue-item-title">{incident.threat_type || 'Unknown Threat'}</div>
      <div className="queue-item-meta">
        <span>{incident.source_ip || 'No source IP'}</span>
        <span>{sourceLabel}</span>
      </div>
      <div className="queue-item-foot">
        <span>{incident.mitre_technique || 'No ATT&CK tag'}</span>
        <span>Risk {incident.risk_score ?? 0}</span>
      </div>
    </motion.button>
  );
}

function Panel({ title, hint, action, children, className = '' }) {
  return (
    <section className={`soc-panel ${className}`.trim()}>
      <div className="soc-panel-header">
        <div>
          <div className="soc-panel-kicker">Analyst View</div>
          <h3>{title}{hint ? <InfoHint text={hint} /> : null}</h3>
        </div>
        {action}
      </div>
      <div className="soc-panel-body">{children}</div>
    </section>
  );
}

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [trendRange, setTrendRange] = useState('7d');
  const navigate = useNavigate();
  const { user } = useAuth();

  const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

  const fetchStats = async () => {
    try {
      const [statsRes, incidentsRes] = await Promise.all([
        api.get('/dashboard/stats'),
        api.get('/dashboard/incidents?limit=15'),
      ]);

      const sortedIncidents = (incidentsRes.data.incidents || []).sort((a, b) => {
        return (severityOrder[a.risk_level] ?? 9) - (severityOrder[b.risk_level] ?? 9);
      });

      setStats(statsRes.data);
      setIncidents(sortedIncidents);
      setSelectedIncident((current) => {
        if (!sortedIncidents.length) {
          return null;
        }
        if (!current) {
          return sortedIncidents[0];
        }
        return sortedIncidents.find((item) => item.id === current.id) || sortedIncidents[0];
      });
      setError(null);
    } catch (err) {
      setError(getApiErrorMessage(err, 'Failed to load SOC workspace data. Check that the backend is running.'));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 30000);
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);


  if (loading) {
    return (
      <div className="page-loading">
        <div className="loading-spinner" />
        <span>Loading SOC workspace</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="empty-state" style={{ padding: '88px 24px' }}>
        <span className="empty-title">{error}</span>
        <button className="btn-primary" onClick={() => window.location.reload()}>Retry</button>
      </div>
    );
  }

  const totalLogs = stats?.total_logs_ingested || 0;
  const totalIncidents = stats?.total_incidents || 0;
  const hasIncidents = incidents.length > 0;
  const topIps = (stats?.top_source_ips || []).slice(0, 5);

  return (
    <div className="soc-dashboard nazday-layout" style={{ padding: '32px' }}>
      {/* Top Header */}
      <motion.div
        className="nazday-header"
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.45 }}
        style={{ padding: '24px 0', marginBottom: '16px' }}
      >
        <h1 style={{ fontSize: '28px', fontWeight: 800, color: 'var(--text-primary)', letterSpacing: '-0.02em', margin: 0 }}>
          Welcome back, {user?.full_name || user?.username || 'Analyst'}
        </h1>
        <p style={{ color: 'var(--text-secondary)', fontSize: '15px', marginTop: '6px', fontWeight: 500 }}>
          {stats?.open_incidents || 0} open cases · {stats?.sla_breaches || 0} SLA breaches · {stats?.incidents_last_24h || 0} incidents active in the last 24h
        </p>
      </motion.div>

      {/* Main Grid: Left 70%, Right 30% */}
      <div className="dashboard-main-grid">
        
        {/* LEFT COLUMN */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
          
          {/* Trend Chart (Acts like Revenue) */}
          <section className="card" style={{ padding: '24px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '24px', alignItems: 'center' }}>
              <h3 style={{ margin: 0, fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)' }}>Incident Trend</h3>
              <div style={{ display: 'flex', gap: '16px', alignItems: 'center', flexWrap: 'wrap' }}>
                {['7d', '24h'].map((range) => (
                  <button
                    key={range}
                    type="button"
                    onClick={() => setTrendRange(range)}
                    className={`filter-btn-sm ${trendRange === range ? 'fbsm-active' : ''}`}
                  >
                    {range === '7d' ? '7 days' : '24 hours'}
                  </button>
                ))}
                <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--accent-blue)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <span style={{ width: 8, height: 8, borderRadius: 2, background: 'var(--accent-blue)' }} /> Medium/Low
                </span>
                <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--accent-primary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <span style={{ width: 8, height: 8, borderRadius: 2, background: 'var(--accent-primary)' }} /> High
                </span>
                <span style={{ fontSize: '12px', fontWeight: 600, color: '#EF4444', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <span style={{ width: 8, height: 8, borderRadius: 2, background: '#EF4444' }} /> Critical
                </span>
              </div>
            </div>
            <IncidentTrendChart stats={stats} range={trendRange} />
          </section>

          {/* Metrics Grid */}
          <section style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px' }}>
            <MetricCard label="Open Cases" value={stats?.open_incidents || 0} sub="needs analyst review" tone="critical" delay={0.04} />
            <MetricCard label="In Review" value={stats?.investigating_incidents || 0} sub="active workload" tone="info" delay={0.08} />
            <MetricCard label="Assets" value={stats?.monitored_assets || 0} sub="signal sources" tone="default" delay={0.12} />
          </section>

          {/* Activity / Case Queue */}
          <Panel
            title="Recent Activity"
            hint="Grouped analyst queue for triage."
            action={<button className="btn-ghost" onClick={() => navigate('/investigate')} style={{ color: 'var(--accent-primary)' }}>See All</button>}
          >
            <div className="queue-list" style={{ marginTop: '16px' }}>
              {hasIncidents ? incidents.slice(0, 5).map((incident, index) => (
                <QueueItem
                  key={incident.id}
                  incident={incident}
                  active={selectedIncident?.id === incident.id}
                  onSelect={setSelectedIncident}
                  index={index}
                />
              )) : (
                <div className="empty-state" style={{ padding: '40px 20px' }}>
                  <span className="empty-title">No recent activity</span>
                  <span className="empty-sub">Analyze a log in Threat Studio or forward logs to the webhook to populate cases.</span>
                </div>
              )}
            </div>
          </Panel>

        </div>

        {/* RIGHT COLUMN */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
          
          {/* Gradient Status Card (Like "Your Card") */}
          <div>
            <h3 style={{ margin: '0 0 16px 0', fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)' }}>System Status</h3>
            <div style={{
              background: 'linear-gradient(135deg, var(--accent-primary) 0%, #A78BFA 100%)',
              borderRadius: '24px',
              padding: '24px',
              color: '#FFFFFF',
              boxShadow: '0 20px 40px -10px var(--accent-primary-glow)',
              position: 'relative',
              overflow: 'hidden'
            }}>
              {/* Glass circles decoration */}
              <div style={{ position: 'absolute', top: '-20px', right: '-20px', width: '100px', height: '100px', borderRadius: '50%', background: 'rgba(255,255,255,0.1)' }} />
              <div style={{ position: 'absolute', bottom: '-40px', right: '40px', width: '120px', height: '120px', borderRadius: '50%', background: 'rgba(255,255,255,0.1)' }} />
              
              <div style={{ fontWeight: 600, fontSize: '15px', marginBottom: '32px' }}>ThreatLens Engine</div>
              
              <div style={{ display: 'flex', gap: '16px', fontSize: '16px', fontFamily: 'var(--font-mono)', opacity: 0.9, marginBottom: '32px' }}>
                <span>****</span><span>****</span><span>****</span><span>LIVE</span>
              </div>
              
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', fontSize: '12px', opacity: 0.8 }}>
                <div>
                  <div style={{ marginBottom: '4px' }}>Total Logs</div>
                  <div style={{ fontSize: '18px', fontWeight: 700, opacity: 1 }}>{totalLogs.toLocaleString()}</div>
                </div>
                <div>
                  <div style={{ marginBottom: '4px' }}>Uptime</div>
                  <div style={{ fontSize: '14px', fontWeight: 700, opacity: 1 }}>99.9%</div>
                </div>
              </div>
            </div>
          </div>

          {/* Top Source IPs (Acts like Exchange Rate) */}
          <Panel title="Top Source IPs" action={<button className="btn-ghost" style={{ color: 'var(--accent-primary)' }} onClick={() => navigate('/investigate')}>See All</button>}>
            <div className="rank-list" style={{ marginTop: '12px' }}>
              {topIps.map((item, index) => (
                <div key={`${item.ip}-${index}`} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 0', borderBottom: '1px solid var(--border-subtle)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <span style={{ color: 'var(--text-muted)', fontSize: '12px', width: '20px' }}>{index + 1}</span>
                    <div style={{ width: '24px', height: '24px', borderRadius: '50%', background: 'var(--accent-primary-dim)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--accent-primary)', fontSize: '10px', fontWeight: 'bold' }}>IP</div>
                    <strong style={{ fontSize: '14px', color: 'var(--text-primary)' }}>{item.ip}</strong>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                    <span style={{ fontSize: '13px', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>{item.incident_count} alerts</span>
                    <span style={{ color: '#EF4444', fontSize: '14px' }}>↑</span>
                  </div>
                </div>
              ))}
            </div>
          </Panel>

          {/* Source Breakdown (Acts like Features Tool) */}
          <Panel title="Telemetry Sources">
            <div className="stacked-bars" style={{ marginTop: '12px' }}>
              {Object.entries(stats?.incident_sources || {})
                .sort((a, b) => b[1] - a[1])
                .map(([key, value], idx) => (
                  <MiniBar
                    key={key}
                    label={SOURCE_LABELS[key] || key.replace(/_/g, ' ')}
                    value={value}
                    total={totalIncidents}
                    color={['var(--accent-warm)', 'var(--accent-blue)', 'var(--accent-primary)', 'var(--success)', 'var(--warning)', 'var(--info)'][idx % 6]}
                  />
                ))}
              {!Object.keys(stats?.incident_sources || {}).length && (
                <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>No incidents yet.</span>
              )}
            </div>
          </Panel>
          
        </div>
      </div>
    </div>
  );
}
