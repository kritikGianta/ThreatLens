// src/components/ThreatIntel.jsx — threat-intelligence feeds and IOC browser
import React, { useCallback, useEffect, useState } from 'react';
import api, { getApiErrorMessage, LONG_TIMEOUT } from '../services/api';
import { useAuth } from '../contexts/AuthContext';

const FEED_INFO = {
  CISA_KEV: { icon: '🐛', color: 'var(--danger)', desc: 'Known Exploited Vulnerabilities — CVEs actively exploited in the wild (CISA).' },
  FEODO_TRACKER: { icon: '🕸️', color: 'var(--warning)', desc: 'abuse.ch Feodo Tracker — botnet command-and-control servers.' },
  IPSUM: { icon: '🛰️', color: 'var(--info)', desc: 'IPsum — IPs listed on 5+ independent public blocklists.' },
  URLHAUS: { icon: '🔗', color: 'var(--accent-primary, #f97316)', desc: 'abuse.ch URLhaus — URLs distributing malware.' },
  THREATFOX: { icon: '🦊', color: 'var(--success)', desc: 'abuse.ch ThreatFox — fresh IOCs with malware attribution.' },
};
const PAGE_SIZE = 50;

function formatTime(value) {
  if (!value) return 'never';
  return new Date(value.endsWith('Z') ? value : `${value}Z`).toLocaleString();
}

export default function ThreatIntel() {
  const { canWrite } = useAuth();
  const [tab, setTab] = useState('overview');
  const [stats, setStats] = useState(null);
  const [iocs, setIocs] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [search, setSearch] = useState('');
  const [query, setQuery] = useState('');
  const [source, setSource] = useState('');
  const [iocType, setIocType] = useState('');
  const [loading, setLoading] = useState(true);
  const [ingesting, setIngesting] = useState(false);
  const [notice, setNotice] = useState(null);

  const loadStats = useCallback(async () => {
    try {
      const res = await api.get('/alerts/intel/stats');
      setStats(res.data);
    } catch (err) {
      setNotice({ type: 'error', text: getApiErrorMessage(err, 'Failed to load feed statistics.') });
    }
  }, []);

  const loadIocs = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(page * PAGE_SIZE) });
      if (query) params.set('search', query);
      if (source) params.set('source', source);
      if (iocType) params.set('ioc_type', iocType);
      const res = await api.get(`/alerts/intel/iocs?${params.toString()}`);
      setIocs(res.data.iocs || []);
      setTotal(res.data.total || 0);
    } catch (err) {
      setNotice({ type: 'error', text: getApiErrorMessage(err, 'Failed to load IOCs.') });
    } finally {
      setLoading(false);
    }
  }, [page, query, source, iocType]);

  useEffect(() => { loadStats(); }, [loadStats]);
  useEffect(() => { loadIocs(); }, [loadIocs]);

  const ingest = async () => {
    setIngesting(true);
    setNotice(null);
    try {
      const res = await api.post('/alerts/intel/ingest', null, { timeout: LONG_TIMEOUT });
      const feeds = res.data.results?.feeds || {};
      const added = Object.values(feeds).reduce((sum, f) => sum + (f.new_entries || 0), 0);
      const failed = Object.entries(feeds).filter(([, f]) => f.status === 'error').map(([k]) => k);
      setNotice({
        type: failed.length ? 'warning' : 'success',
        text: `Ingestion complete — ${added} new indicators.${failed.length ? ` Failed: ${failed.join(', ')}.` : ''}`,
      });
      setStats(res.data.stats);
      setPage(0);
      loadIocs();
    } catch (err) {
      setNotice({ type: 'error', text: getApiErrorMessage(err, 'Ingestion failed.') });
    } finally {
      setIngesting(false);
    }
  };

  const applySearch = (e) => {
    e.preventDefault();
    setPage(0);
    setQuery(search.trim());
  };

  const feeds = stats?.feeds || [];
  const totalIocs = stats?.total_entries || 0;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const noticeColor = { success: 'var(--success)', warning: 'var(--warning)', error: 'var(--danger)' }[notice?.type];

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-header-title">Threat Intelligence</h1>
          <p className="page-header-sub">
            {totalIocs.toLocaleString()} indicators from {feeds.filter((f) => f.count > 0).length} live feeds · last refresh {formatTime(stats?.last_ingested_at)}
          </p>
        </div>
        {canWrite && (
          <button className="btn-primary" onClick={ingest} disabled={ingesting}>
            {ingesting ? <><span className="btn-spinner" />Ingesting feeds…</> : '↓ Ingest Latest Feeds'}
          </button>
        )}
      </div>

      <div className="page-body">
        {notice && (
          <div className="card" style={{ marginBottom: 16, padding: '12px 16px', borderLeft: `3px solid ${noticeColor}` }}>
            <span style={{ fontSize: 13, color: 'var(--text-primary)' }}>{notice.text}</span>
          </div>
        )}

        <div className="filter-tabs">
          <button className={`filter-tab ${tab === 'overview' ? 'ft-active' : ''}`} onClick={() => setTab('overview')}>📊 Feed Overview</button>
          <button className={`filter-tab ${tab === 'iocs' ? 'ft-active' : ''}`} onClick={() => setTab('iocs')}>
            🔍 IOC Browser <span className="ft-count">{totalIocs.toLocaleString()}</span>
          </button>
        </div>

        {tab === 'overview' && (
          <div>
            <div className="feed-cards">
              {feeds.map((feed) => {
                const info = FEED_INFO[feed.source] || { icon: '📡', color: 'var(--info)', desc: '' };
                const result = feed.last_result;
                return (
                  <div key={feed.source} className="feed-card" style={{ '--feed-color': info.color, opacity: feed.enabled ? 1 : 0.6 }}>
                    <div className="feed-card-top">
                      <span className="feed-icon">{info.icon}</span>
                      <span className="feed-count">{feed.count.toLocaleString()}</span>
                    </div>
                    <div className="feed-label">{feed.label}</div>
                    <div className="feed-desc">{info.desc}</div>
                    <div className="feed-desc" style={{ marginTop: 6, fontSize: 11 }}>
                      {!feed.enabled
                        ? '🔑 Requires ABUSECH_AUTH_KEY in .env'
                        : result?.status === 'error'
                          ? `⚠️ Last run failed: ${result.message}`
                          : result?.status === 'ok'
                            ? `✓ Last run: +${result.new_entries} new`
                            : '✓ Enabled'}
                    </div>
                    <div className="feed-bar">
                      <div className="feed-bar-fill" style={{ width: `${Math.min(100, (feed.count / Math.max(1, totalIocs)) * 100)}%`, background: info.color }} />
                    </div>
                  </div>
                );
              })}
            </div>

            {totalIocs === 0 && !loading && (
              <div className="empty-state" style={{ paddingTop: 40 }}>
                <span className="empty-icon">📡</span>
                <span className="empty-title">No indicators loaded yet</span>
                <span className="empty-sub">Feeds refresh automatically every hour{canWrite ? ' — or ingest them now.' : '.'}</span>
                {canWrite && <button className="btn-primary" onClick={ingest} disabled={ingesting}>↓ Ingest Now</button>}
              </div>
            )}

            {stats?.by_type && Object.keys(stats.by_type).length > 0 && (
              <div className="card" style={{ marginTop: 16 }}>
                <div className="card-header"><span className="card-title">Indicators by type</span></div>
                <div className="card-body" style={{ display: 'flex', gap: 24, flexWrap: 'wrap' }}>
                  {Object.entries(stats.by_type).map(([type, count]) => (
                    <div key={type}>
                      <div style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-primary)' }}>{count.toLocaleString()}</div>
                      <div style={{ fontSize: 12, color: 'var(--text-muted)', textTransform: 'uppercase' }}>{type}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {tab === 'iocs' && (
          <div>
            <form className="ioc-search-bar" onSubmit={applySearch}>
              <input
                className="ip-search-input"
                placeholder="Search by IP, CVE, URL, malware or description… (Enter)"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
              <div className="ioc-filters">
                <select className="field-input" value={source} onChange={(e) => { setSource(e.target.value); setPage(0); }}>
                  <option value="">All feeds</option>
                  {feeds.map((f) => <option key={f.source} value={f.source}>{f.label}</option>)}
                </select>
                <select className="field-input" value={iocType} onChange={(e) => { setIocType(e.target.value); setPage(0); }}>
                  <option value="">All types</option>
                  {Object.keys(stats?.by_type || {}).map((t) => <option key={t} value={t}>{t}</option>)}
                </select>
                <button className="btn-primary" type="submit">Search</button>
              </div>
            </form>

            {loading ? (
              <div className="page-loading"><div className="loading-spinner" /><span>Loading indicators…</span></div>
            ) : iocs.length === 0 ? (
              <div className="empty-state"><span className="empty-title">No indicators match your filters</span></div>
            ) : (
              <div className="card">
                <table className="data-table">
                  <thead>
                    <tr><th>Indicator</th><th>Type</th><th>Threat</th><th>Severity</th><th>Feed</th><th>Ingested</th></tr>
                  </thead>
                  <tbody>
                    {iocs.map((ioc) => (
                      <tr key={ioc.id} title={ioc.description || ''}>
                        <td><span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-primary)', wordBreak: 'break-all' }}>{ioc.ioc_value}</span></td>
                        <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{ioc.ioc_type}</td>
                        <td style={{ fontSize: 13, color: 'var(--text-secondary)' }}>{ioc.threat_name || '—'}</td>
                        <td><span className={`severity-chip ${ioc.severity?.toLowerCase()}`}>{ioc.severity || '—'}</span></td>
                        <td><span className="rule-chip" style={{ color: FEED_INFO[ioc.source]?.color }}>{ioc.source}</span></td>
                        <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{formatTime(ioc.ingested_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px 16px', fontSize: 12, color: 'var(--text-muted)' }}>
                  <span>{total.toLocaleString()} results · page {page + 1} of {pages}</span>
                  <span style={{ display: 'flex', gap: 8 }}>
                    <button className="btn-outline" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>← Prev</button>
                    <button className="btn-outline" disabled={page + 1 >= pages} onClick={() => setPage((p) => p + 1)}>Next →</button>
                  </span>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
