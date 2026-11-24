// src/components/Campaigns.jsx — multi-stage attack campaigns and their kill chains
import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import api, { getApiErrorMessage } from '../services/api';
import { useAuth } from '../contexts/AuthContext';
import { useLiveRefresh } from '../contexts/LiveEventsContext';

const KILL_CHAIN = [
  'Reconnaissance', 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion',
  'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Command and Control', 'Exfiltration', 'Impact',
];
const fmtDuration = (c) => {
  const s = c.duration_seconds ?? Math.round((c.duration_hours || 0) * 3600);
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${Math.round(s / 60)} min`;
  if (s < 172800) return `${(s / 3600).toFixed(1).replace(/\.0$/, '')} h`;
  return `${Math.round(s / 86400)} d`;
};
const fmt = (iso) => (iso ? new Date(iso.endsWith('Z') ? iso : `${iso}Z`).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—');

function KillChain({ progression }) {
  const byStage = {};
  (progression || []).forEach((entry) => {
    const s = byStage[entry.stage] || (byStage[entry.stage] = { count: 0, first: entry.timestamp });
    s.count += 1;
    if (entry.timestamp < s.first) s.first = entry.timestamp;
  });
  const extra = Object.keys(byStage).filter((s) => !KILL_CHAIN.includes(s));
  return (
    <div className="killchain">
      {[...KILL_CHAIN, ...extra].map((stage) => (
        <div key={stage} className={`kc-stage ${byStage[stage] ? 'kc-hit' : ''}`} title={stage}>
          <div className="kc-name">{stage}</div>
          <div className="kc-count">{byStage[stage]?.count || '·'}</div>
          {byStage[stage] && <div className="kc-time">{fmt(byStage[stage].first).split(', ').pop()}</div>}
        </div>
      ))}
    </div>
  );
}




const STATUS_COLORS = { Active: 'var(--danger)', Dormant: 'var(--warning)', Closed: 'var(--text-muted)' };

function StageChain({ stages }) {
  if (!stages?.length) return <span className="no-stages">No stages yet</span>;
  const unique = [...new Set(stages)];
  return (
    <div className="stage-chain">
      {unique.map((s, i) => (
        <React.Fragment key={i}>
          <span className="stage-pill">{s}</span>
          {i < unique.length - 1 && <span className="stage-arrow">→</span>}
        </React.Fragment>
      ))}
    </div>
  );
}

function CampaignDetail({ campaign, onClose, onCloseCampaign, canWrite }) {
  const navigate = useNavigate();
  const [detail, setDetail] = useState(null);

  useEffect(() => {
    api.get(`/dashboard/campaigns/${campaign.id}`).then((res) => setDetail(res.data)).catch(() => setDetail(null));
  }, [campaign.id]);

  const progression = [...(detail?.stages_progression || [])].sort((a, b) => (a.timestamp < b.timestamp ? -1 : 1));
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal modal-wide modal-campaign" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <div>
            <span className="modal-title">{campaign.name}</span>
            <span className={`severity-chip ${campaign.risk_level?.toLowerCase()}`} style={{ marginLeft: 10 }}>
              {campaign.risk_level}
            </span>
          </div>
          <button className="modal-close" onClick={onClose}>✖</button>
        </div>
        <div className="modal-body">
          <div className="detail-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)' }}>
            <div className="detail-item"><span className="detail-label">Status</span>
              <span style={{ color: STATUS_COLORS[campaign.status], fontWeight: 700, fontSize: 14 }}>{campaign.status}</span>
            </div>
            <div className="detail-item"><span className="detail-label">Risk Score</span>
              <span className="detail-value">{campaign.risk_score ?? '—'}/100</span>
            </div>
            <div className="detail-item"><span className="detail-label">Duration</span>
              <span className="detail-value">{fmtDuration(campaign)}</span>
            </div>
            <div className="detail-item"><span className="detail-label">Stage events</span>
              <span className="detail-value">{campaign.event_count ?? progression.length}</span>
            </div>
          </div>

          <div style={{ marginTop: 20 }}>
            <span className="detail-label">Kill chain (MITRE ATT&amp;CK tactics)</span>
            <KillChain progression={progression} />
          </div>

          {progression.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <span className="detail-label">Timeline</span>
              <div className="kc-timeline">
                {progression.slice(-40).map((entry, i) => (
                  <div key={i} className="kc-event">
                    <span>{fmt(entry.timestamp)}</span>
                    <strong style={{ color: 'var(--text-primary)' }}>{entry.stage}</strong>
                    <span>{entry.ip}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {detail?.incidents?.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <span className="detail-label">Linked cases ({detail.incidents.length})</span>
              <div style={{ marginTop: 6, display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {detail.incidents.map((inc) => (
                  <button key={inc.id} className="dsp-det" onClick={() => navigate(`/incidents/${inc.id}`)}>
                    #{inc.id} · {inc.risk_level} · {inc.threat_type}
                  </button>
                ))}
              </div>
            </div>
          )}

          <div style={{ marginTop: 16, display: 'flex', gap: 24, flexWrap: 'wrap' }}>
            {campaign.source_ips?.length > 0 && (
              <div>
                <span className="detail-label">Source IPs</span>
                <div style={{ marginTop: 6, display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {campaign.source_ips.map((ip, i) => (
                    <button key={i} className="ip-tag" onClick={() => navigate(`/investigate?ip=${encodeURIComponent(ip)}`)}>{ip}</button>
                  ))}
                </div>
              </div>
            )}
            {campaign.mitre_techniques?.length > 0 && (
              <div>
                <span className="detail-label">MITRE Techniques</span>
                <div style={{ marginTop: 6, display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {campaign.mitre_techniques.map((t, i) => (
                    <button key={i} className="mitre-tag" onClick={() => navigate(`/mitre?id=${t}`)}>{t}</button>
                  ))}
                </div>
              </div>
            )}
          </div>

          {campaign.status !== 'Closed' && canWrite && (
            <div style={{ marginTop: 20, paddingTop: 16, borderTop: '1px solid var(--border-subtle)' }}>
              <button
                className="btn-outline"
                style={{ color: 'var(--danger)', borderColor: 'var(--danger-dim)' }}
                onClick={() => onCloseCampaign(campaign.id)}
              >
                Close Campaign
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default function Campaigns() {
  const [campaigns, setCampaigns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState('All');
  const [selected, setSelected] = useState(null);
  const { canWrite } = useAuth();

  const load = async () => {
    try {
      const res = await api.get('/dashboard/campaigns');
      setCampaigns(res.data.campaigns || []);
    } catch { setError('Failed to load campaigns.'); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);
  useLiveRefresh(() => load(), ['incident'], 2500);

  const handleClose = async (id) => {
    try {
      await api.put(`/dashboard/campaigns/${id}/close`);
      setSelected(null);
      load();
    } catch (err) { alert(getApiErrorMessage(err, 'Failed to close campaign.')); }
  };

  const triggerCorrelation = async () => {
    try {
      const res = await api.post('/dashboard/correlate');
      alert(`Correlation sweep done. ${res.data.total} findings.`);
      load();
    } catch (err) { alert(getApiErrorMessage(err, 'Correlation sweep failed.')); }
  };

  const filtered = filter === 'All' ? campaigns : campaigns.filter(c => c.status === filter);

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-header-title">Campaign Manager</h1>
          <p className="page-header-sub">Multi-stage attack campaigns tracked across days and weeks</p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn-outline" onClick={triggerCorrelation} title="Run the background correlation engine manually">
            ⟲ Run Correlation
          </button>
        </div>
      </div>

      <div className="page-body">
        {/* Filter tabs */}
        <div className="filter-tabs">
          {['All', 'Active', 'Dormant', 'Closed'].map(f => (
            <button key={f} className={`filter-tab ${filter === f ? 'ft-active' : ''}`} onClick={() => setFilter(f)}>
              {f}
              <span className="ft-count">
                {f === 'All' ? campaigns.length : campaigns.filter(c => c.status === f).length}
              </span>
            </button>
          ))}
        </div>

        {loading ? (
          <div className="page-loading"><div className="loading-spinner" /><span>Loading campaigns…</span></div>
        ) : error ? (
          <div className="empty-state"><span className="empty-icon">⚠️</span><span className="empty-title">{error}</span></div>
        ) : filtered.length === 0 ? (
          <div className="empty-state" style={{ paddingTop: 60 }}>
            <span className="empty-icon">🕸️</span>
            <span className="empty-title">No {filter !== 'All' ? filter.toLowerCase() : ''} campaigns yet</span>
            <span className="empty-sub">Campaign tracking activates automatically when multi-stage attacks are detected. Run the correlation engine to check.</span>
            <button className="btn-primary" onClick={triggerCorrelation}>⟲ Run Correlation Now</button>
          </div>
        ) : (
          <div className="campaigns-list">
            {filtered.map(c => (
              <div key={c.id} className="campaign-row" onClick={() => setSelected(c)}>
                <div className="campaign-row-left">
                  <div className="campaign-status-dot" style={{ background: STATUS_COLORS[c.status] }} title={c.status} />
                  <div>
                    <div className="campaign-name">{c.name}</div>
                    <div className="campaign-meta">
                      {c.source_ips?.slice(0, 2).join(', ')}{c.source_ips?.length > 2 ? ` +${c.source_ips.length - 2}` : ''}
                    </div>
                  </div>
                </div>
                <div className="campaign-row-center">
                  <StageChain stages={c.stages} />
                </div>
                <div className="campaign-row-right">
                  <span className={`severity-chip ${c.risk_level?.toLowerCase()}`}>{c.risk_level}</span>
                  <span className="campaign-duration">{fmtDuration(c)}</span>
                  <span className="campaign-status-label" style={{ color: STATUS_COLORS[c.status] }}>{c.status}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {selected && (
        <CampaignDetail
          campaign={selected}
          onClose={() => setSelected(null)}
          onCloseCampaign={handleClose}
          canWrite={canWrite}
        />
      )}
    </div>
  );
}
