// Executive View — board-level security KPIs computed from real case data.
import React, { useCallback, useEffect, useState } from 'react';
import { Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import api, { getApiErrorMessage } from '../services/api';
import { useLiveRefresh } from '../contexts/LiveEventsContext';
import { LivePill } from './live/LiveToasts';

const WINDOWS = [{ h: 24, label: '24 hours' }, { h: 168, label: '7 days' }, { h: 720, label: '30 days' }];
const SEV_COLORS = { CRITICAL: '#EF4444', HIGH: '#F59E0B', MEDIUM: '#60A5FA', LOW: '#34D399' };

const fmtMinutes = (m) => {
  if (m === null || m === undefined) return '—';
  if (m < 1) return `${Math.round(m * 60)} s`;
  if (m < 120) return `${m.toFixed(1)} min`;
  return `${(m / 60).toFixed(1)} h`;
};
const pct = (v) => (v === null || v === undefined ? '—' : `${v}%`);

function Kpi({ label, value, sub, tone }) {
  return (
    <div className={`exec-kpi ${tone ? `ek-${tone}` : ''}`}>
      <span className="exec-kpi-label">{label}</span>
      <strong className="exec-kpi-value">{value}</strong>
      {sub && <span className="exec-kpi-sub">{sub}</span>}
    </div>
  );
}

function narrative(d, windowLabel) {
  if (!d) return '';
  const parts = [
    `In the last ${windowLabel}, ThreatLens analysed ${d.logs_ingested.toLocaleString()} log events and raised ${d.alerts.toLocaleString()} alerts,`,
    `which it grouped into ${d.incidents.toLocaleString()} cases — ${d.noise_reduction_pct}% less noise for analysts.`,
  ];
  if (d.critical_open) parts.push(`${d.critical_open} critical case${d.critical_open === 1 ? ' is' : 's are'} still open.`);
  if (d.automation_rate_pct) parts.push(`Automated response acted on ${d.automation_rate_pct}% of cases and blocked ${d.auto_blocked_ips} IP${d.auto_blocked_ips === 1 ? '' : 's'} without human intervention.`);
  if (d.performance?.pipeline_latency_ms?.samples) parts.push(`Median detection latency is ${d.performance.pipeline_latency_ms.p50} ms per event.`);
  return parts.join(' ');
}

export default function Executive() {
  const [hours, setHours] = useState(168);
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  const load = useCallback(async () => {
    try {
      const res = await api.get(`/dashboard/executive?hours=${hours}`);
      setData(res.data);
      setError(null);
    } catch (err) {
      setError(getApiErrorMessage(err, 'Failed to load executive metrics.'));
    }
  }, [hours]);

  useEffect(() => { load(); }, [load]);
  useLiveRefresh(() => load(), ['incident', 'soar'], 3000);

  const windowLabel = WINDOWS.find((w) => w.h === hours)?.label || `${hours} hours`;
  const perf = data?.performance;
  const epm = (perf?.events_per_minute || []).map((v, i, arr) => ({ t: `-${arr.length - 1 - i}m`, events: v }));
  const severityTotal = data ? Object.values(data.severity).reduce((a, b) => a + b, 0) : 0;

  return (
    <div className="exec-page">
      <div className="page-header">
        <div>
          <div className="soc-header-kicker">Security posture report</div>
          <h1 className="page-header-title">Executive View</h1>
          <p className="page-header-sub">Outcome metrics for leadership — every number is computed from live case data.</p>
        </div>
        <div className="no-print" style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <LivePill />
          {WINDOWS.map((w) => (
            <button key={w.h} className={`filter-btn-sm ${hours === w.h ? 'fbsm-active' : ''}`} onClick={() => setHours(w.h)}>{w.label}</button>
          ))}
          <button className="btn-outline" onClick={() => window.print()}>Print / PDF</button>
        </div>
      </div>

      <div className="page-body">
        {error && <div className="auth-error">{error}</div>}
        {!data && !error && <div className="page-loading"><div className="loading-spinner" /><span>Computing metrics…</span></div>}
        {data && (
          <>
            <div className="card exec-summary">{narrative(data, windowLabel)}</div>

            <div className="exec-kpis">
              <Kpi label="Alerts → cases" value={`${data.alerts.toLocaleString()} → ${data.incidents.toLocaleString()}`} sub={`${data.noise_reduction_pct}% noise reduction`} tone="accent" />
              <Kpi label="Critical open" value={data.critical_open} sub={`${data.open_cases} open cases total`} tone={data.critical_open ? 'danger' : 'success'} />
              <Kpi label="Mean time to triage" value={fmtMinutes(data.mtta_minutes)} sub={data.mtta_minutes === null ? 'no analyst actions yet — triage a case' : 'open → first analyst action'} />
              <Kpi label="Mean time to resolve" value={fmtMinutes(data.mttr_minutes)} sub={data.resolved_cases ? `${data.resolved_cases} resolved cases` : 'no cases resolved yet'} />
              <Kpi label="SLA compliance" value={pct(data.sla_compliance_pct)} sub="resolved or within SLA" tone={data.sla_compliance_pct >= 90 ? 'success' : 'warning'} />
              <Kpi label="Automated response" value={pct(data.automation_rate_pct)} sub={`${data.auto_blocked_ips} IPs auto-blocked`} tone="accent" />
              <Kpi label="Detection latency" value={perf?.pipeline_latency_ms?.samples ? `${perf.pipeline_latency_ms.p50} ms` : '—'} sub={perf?.pipeline_latency_ms?.samples ? `p95 ${perf.pipeline_latency_ms.p95} ms · measured` : 'no events measured yet'} />
              <Kpi label="Active campaigns" value={data.active_campaigns} sub="multi-stage attacks tracked" tone={data.active_campaigns ? 'warning' : undefined} />
            </div>

            <div className="exec-charts">
              <div className="card">
                <div className="card-header"><span className="card-title">Cases per day</span></div>
                <div style={{ height: 230, padding: '8px 12px 12px' }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={data.trend.map((t) => ({ ...t, label: new Date(`${t.day}T00:00:00Z`).toLocaleDateString([], { month: 'short', day: 'numeric', timeZone: 'UTC' }) }))}>
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(215,163,90,0.08)" />
                      <XAxis dataKey="label" tick={{ fill: '#8A7F72', fontSize: 10 }} axisLine={false} tickLine={false} />
                      <YAxis allowDecimals={false} tick={{ fill: '#8A7F72', fontSize: 10 }} axisLine={false} tickLine={false} width={28} />
                      <Tooltip contentStyle={{ background: '#141210', border: '1px solid rgba(215,163,90,0.2)', borderRadius: 8 }} />
                      <Bar dataKey="incidents" name="All cases" fill="#D97706" radius={[4, 4, 0, 0]} />
                      <Bar dataKey="critical" name="Critical" fill="#EF4444" radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>

              <div className="card">
                <div className="card-header"><span className="card-title">Pipeline throughput (events / minute, last 30 min)</span></div>
                <div style={{ height: 230, padding: '8px 12px 12px' }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={epm}>
                      <defs>
                        <linearGradient id="epmGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#F59E0B" stopOpacity={0.45} />
                          <stop offset="95%" stopColor="#F59E0B" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(215,163,90,0.08)" />
                      <XAxis dataKey="t" tick={{ fill: '#8A7F72', fontSize: 10 }} axisLine={false} tickLine={false} interval={4} />
                      <YAxis allowDecimals={false} tick={{ fill: '#8A7F72', fontSize: 10 }} axisLine={false} tickLine={false} width={28} />
                      <Tooltip contentStyle={{ background: '#141210', border: '1px solid rgba(215,163,90,0.2)', borderRadius: 8 }} />
                      <Area type="monotone" dataKey="events" stroke="#F59E0B" strokeWidth={2} fill="url(#epmGrad)" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>

              <div className="card">
                <div className="card-header"><span className="card-title">Cases by severity</span></div>
                <div className="card-body">
                  {Object.entries(data.severity).map(([level, count]) => (
                    <div key={level} className="tm-country-row">
                      <span style={{ color: SEV_COLORS[level], fontWeight: 700 }}>{level}</span>
                      <div className="tm-bar"><div style={{ width: `${severityTotal ? (count / severityTotal) * 100 : 0}%`, background: SEV_COLORS[level] }} /></div>
                      <b>{count}</b>
                    </div>
                  ))}
                </div>
              </div>

              <div className="card">
                <div className="card-header"><span className="card-title">Most frequent ATT&amp;CK techniques</span></div>
                <div className="card-body">
                  {data.top_techniques.length === 0 && <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>No techniques observed yet.</span>}
                  {data.top_techniques.map((t) => (
                    <div key={t.technique} className="tm-country-row">
                      <span className="technique-id">{t.technique}</span>
                      <div className="tm-bar"><div style={{ width: `${(t.count / data.top_techniques[0].count) * 100}%` }} /></div>
                      <b>{t.count}</b>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
