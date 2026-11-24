// src/components/MitreExplorer.js — New design, no MUI
import React, { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { getApiErrorMessage, getMitreTechnique, searchMitre } from '../services/api';
import AttackMatrix from './AttackMatrix';

const TECHNIQUE_ID = /^T\d{4}(\.\d{3})?$/i;




const COMMON_TECHNIQUES = [
  { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access', severity: 'HIGH' },
  { id: 'T1059', name: 'Command & Scripting Interpreter', tactic: 'Execution', severity: 'CRITICAL' },
  { id: 'T1003', name: 'OS Credential Dumping', tactic: 'Credential Access', severity: 'CRITICAL' },
  { id: 'T1566', name: 'Phishing', tactic: 'Initial Access', severity: 'HIGH' },
  { id: 'T1021', name: 'Remote Services', tactic: 'Lateral Movement', severity: 'HIGH' },
  { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact', severity: 'CRITICAL' },
  { id: 'T1078', name: 'Valid Accounts', tactic: 'Defense Evasion', severity: 'MEDIUM' },
  { id: 'T1071', name: 'Application Layer Protocol', tactic: 'Command and Control', severity: 'MEDIUM' },
];

export default function MitreExplorer() {
  const [query, setQuery] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [saved, setSaved] = useState([]);
  const [view, setView] = useState('matrix');
  const [recent, setRecent] = useState([]);
  const [copied, setCopied] = useState(false);
  const [matches, setMatches] = useState([]);
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  const search = async (id) => {
    const term = (id || query).trim();
    if (!term) return;
    setLoading(true); setError(null);
    try {
      if (TECHNIQUE_ID.test(term)) {
        const tid = term.toUpperCase();
        const data = await getMitreTechnique(tid);
        setResult(data);
        setRecent(r => [tid, ...r.filter(t => t !== tid)].slice(0, 5));
      } else {
        const data = await searchMitre(term);
        setMatches(data.results || []);
        if (!data.results?.length) setError(`No techniques match "${term}".`);
      }
    } catch (err) {
      setError(getApiErrorMessage(err, 'Failed to fetch technique.'));
    } finally { setLoading(false); }
  };

  useEffect(() => {
    const id = searchParams.get('id');
    if (id) { setView('explore'); setQuery(id); search(id); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams]);

  const toggleSave = (technique) => {
    setSaved(s => s.find(t => t.id === technique.id) ? s.filter(t => t.id !== technique.id) : [...s, technique]);
  };
  const isSaved = (id) => saved.some(t => t.id === id);

  const copy = (text) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-header-title">MITRE ATT&amp;CK Explorer</h1>
          <p className="page-header-sub">Explore adversary tactics, techniques, and procedures</p>
        </div>
        {saved.length > 0 && (
          <div className="saved-badge">
            🔖 {saved.length} saved technique{saved.length > 1 ? 's' : ''}
          </div>
        )}
      </div>

      <div className="page-body">
        <div className="filter-tabs">
          <button className={`filter-tab ${view === 'matrix' ? 'ft-active' : ''}`} onClick={() => setView('matrix')}>🗺️ Coverage heatmap</button>
          <button className={`filter-tab ${view === 'explore' ? 'ft-active' : ''}`} onClick={() => setView('explore')}>🔍 Technique explorer</button>
        </div>
        {view === 'matrix' && <AttackMatrix onSelect={(id) => { setView('explore'); setQuery(id); search(id); }} />}
        <div className="mitre-layout" style={{ display: view === 'matrix' ? 'none' : undefined }}>
          {/* Left panel */}
          <div className="mitre-left">
            {/* Search */}
            <div className="card" style={{ marginBottom: 12 }}>
              <div className="card-header"><span className="card-title">Search Technique</span></div>
              <div className="card-body">
                <div className="mitre-search">
                  <input
                    className="field-input"
                    placeholder="Technique ID (T1110) or keyword (phishing)"
                    value={query}
                    onChange={e => setQuery(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && search()}
                  />
                  <button className="btn-primary" onClick={() => search()} disabled={loading || !query.trim()}>
                    {loading ? <span className="btn-spinner" /> : 'Search'}
                  </button>
                </div>

                {recent.length > 0 && (
                  <div className="recent-searches">
                    <span className="recent-label">Recent</span>
                    {recent.map(t => (
                      <button key={t} className="recent-pill" onClick={() => { setQuery(t); search(t); }}>{t}</button>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {matches.length > 0 && (
              <div className="card" style={{ marginBottom: 12 }}>
                <div className="card-header">
                  <span className="card-title">Search results</span>
                  <button className="rule-delete-btn" onClick={() => setMatches([])} title="Clear results">✖</button>
                </div>
                <div style={{ maxHeight: 360, overflowY: 'auto' }}>
                  {matches.map(t => (
                    <div key={t.id} className="technique-row" onClick={() => search(t.id)}>
                      <div>
                        <span className="technique-id">{t.id}</span>
                        <span className="technique-name">{t.name}</span>
                        <span className="technique-tactic">{(t.tactics || []).join(' · ')}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Common Techniques */}
            <div className="card">
              <div className="card-header"><span className="card-title">Common Techniques</span></div>
              <div>
                {COMMON_TECHNIQUES.map(t => (
                  <div
                    key={t.id}
                    className="technique-row"
                    onClick={() => { setQuery(t.id); search(t.id); }}
                  >
                    <div>
                      <span className="technique-id">{t.id}</span>
                      <span className="technique-name">{t.name}</span>
                      <span className="technique-tactic">{t.tactic}</span>
                    </div>
                    <span className={`severity-chip ${t.severity.toLowerCase()}`}>{t.severity}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Saved */}
            {saved.length > 0 && (
              <div className="card" style={{ marginTop: 12 }}>
                <div className="card-header"><span className="card-title">🔖 Saved Techniques</span></div>
                <div>
                  {saved.map(t => (
                    <div key={t.id} className="technique-row" onClick={() => { setQuery(t.id); search(t.id); }}>
                      <div>
                        <span className="technique-id">{t.id}</span>
                        <span className="technique-name">{t.name || t.id}</span>
                      </div>
                      <button className="rule-delete-btn" onClick={e => { e.stopPropagation(); toggleSave(t); }}>✖</button>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Right panel */}
          <div className="mitre-right">
            {error && <div className="auth-error"><span>⚠️</span> {error}</div>}

            {!result && !loading && !error && (
              <div className="empty-state" style={{ padding: '80px 24px', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-lg)', background: 'var(--bg-surface)' }}>
                <span className="empty-icon">📋</span>
                <span className="empty-title">No technique selected</span>
                <span className="empty-sub">Search by technique ID or keyword, or pick a common technique</span>
              </div>
            )}

            {loading && (
              <div className="page-loading" style={{ height: 300, border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-lg)' }}>
                <div className="loading-spinner" />
                <span>Fetching technique…</span>
              </div>
            )}

            {result && (
              <div className="mitre-result">
                <div className="mitre-result-header">
                  <div>
                    <div className="mitre-result-id">{result.id}</div>
                    <div className="mitre-result-name">{result.name}</div>
                  </div>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button
                      className={`mitre-action-btn ${isSaved(result.id) ? 'mab-saved' : ''}`}
                      onClick={() => toggleSave(result)}
                      title={isSaved(result.id) ? 'Unsave' : 'Save technique'}
                    >
                      {isSaved(result.id) ? '🔖 Saved' : '🔖 Save'}
                    </button>
                    <button
                      className="mitre-action-btn"
                      onClick={() => copy(result.id)}
                      title="Copy ID"
                    >
                      {copied ? '✓ Copied' : '📋 Copy ID'}
                    </button>
                    {result.url && (
                      <a className="mitre-action-btn" href={result.url} target="_blank" rel="noreferrer" title="Open on attack.mitre.org">
                        ↗ ATT&amp;CK
                      </a>
                    )}
                  </div>
                </div>

                {result.description && (
                  <div className="mitre-desc">
                    <div className="detail-label">Description</div>
                    <p>{result.description}</p>
                  </div>
                )}

                <div className="mitre-meta-grid">
                  {result.tactics?.length > 0 && (
                    <div className="mitre-meta-card">
                      <div className="detail-label">Tactics</div>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 6 }}>
                        {result.tactics.map((t, i) => <span key={i} className="rule-chip" style={{ color: 'var(--info)' }}>{t}</span>)}
                      </div>
                    </div>
                  )}
                  {result.platforms?.length > 0 && (
                    <div className="mitre-meta-card">
                      <div className="detail-label">Platforms</div>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 6 }}>
                        {result.platforms.map((p, i) => <span key={i} className="rule-chip" style={{ color: 'var(--warning)' }}>{p}</span>)}
                      </div>
                    </div>
                  )}
                  {result.detection && (
                    <div className="mitre-meta-card" style={{ gridColumn: '1 / -1' }}>
                      <div className="detail-label">Detection</div>
                      <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6, marginTop: 6 }}>{result.detection}</p>
                    </div>
                  )}
                </div>

                {(result.observed_incidents > 0 || result.sub_techniques?.length > 0) && (
                  <div className="mitre-meta-grid" style={{ marginTop: 12 }}>
                    <div className="mitre-meta-card">
                      <div className="detail-label">Observed in your environment</div>
                      <div style={{ fontSize: 22, fontWeight: 700, marginTop: 6, color: result.observed_incidents ? 'var(--danger)' : 'var(--text-secondary)' }}>
                        {result.observed_incidents} incident{result.observed_incidents === 1 ? '' : 's'}
                      </div>
                      {(result.recent_incidents || []).map(inc => (
                        <div key={inc.id} className="technique-row" style={{ padding: '6px 0' }} onClick={() => navigate(`/incidents/${inc.id}`)}>
                          <div>
                            <span className="technique-id">#{inc.id}</span>
                            <span className="technique-name">{inc.threat_type}</span>
                          </div>
                          <span className={`severity-chip ${(inc.risk_level || '').toLowerCase()}`}>{inc.risk_level}</span>
                        </div>
                      ))}
                    </div>
                    {result.sub_techniques?.length > 0 && (
                      <div className="mitre-meta-card">
                        <div className="detail-label">Sub-techniques</div>
                        {result.sub_techniques.map(st => (
                          <div key={st.id} className="technique-row" style={{ padding: '6px 0' }} onClick={() => search(st.id)}>
                            <div>
                              <span className="technique-id">{st.id}</span>
                              <span className="technique-name">{st.name}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {result.mitigations?.length > 0 && (
                  <div className="mitre-mitigations">
                    <div className="detail-label" style={{ marginBottom: 8 }}>Mitigations</div>
                    {result.mitigations.map((m, i) => (
                      <div key={i} className="mitigation-item">
                        <span className="mitigation-id">{m.id}</span>
                        <span className="mitigation-name">{m.name}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
