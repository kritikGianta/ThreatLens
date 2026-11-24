import React, { useCallback, useEffect, useState } from 'react';
import api, { getApiErrorMessage } from '../services/api';
import { useLiveRefresh } from '../contexts/LiveEventsContext';

function heat(observed, max) {
  if (!observed) return undefined;
  const t = Math.min(1, Math.log2(observed + 1) / Math.log2(max + 1));
  // amber → red as the technique is seen more often
  const r = Math.round(217 + (220 - 217) * t);
  const g = Math.round(119 - (119 - 38) * t);
  const b = Math.round(6 + (38 - 6) * t);
  return `rgba(${r}, ${g}, ${b}, ${0.45 + 0.5 * t})`;
}

/** MITRE ATT&CK coverage heatmap: detectable techniques by tactic, coloured by observed incidents. */
export default function AttackMatrix({ onSelect }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  const load = useCallback(async () => {
    try {
      setData((await api.get('/mitre/matrix')).data);
    } catch (err) {
      setError(getApiErrorMessage(err, 'Failed to load the ATT&CK matrix.'));
    }
  }, []);
  useEffect(() => { load(); }, [load]);
  useLiveRefresh(() => load(), ['incident'], 4000);

  if (error) return <div className="auth-error">{error}</div>;
  if (!data) return <div className="page-loading"><div className="loading-spinner" /><span>Building coverage matrix…</span></div>;
  const max = Math.max(1, ...data.matrix.flatMap((c) => c.techniques.map((t) => t.observed)));

  return (
    <div className="card" style={{ padding: 16 }}>
      <div style={{ display: 'flex', gap: 28, flexWrap: 'wrap', marginBottom: 4 }}>
        {[
          [data.rules, 'detection rules'],
          [data.detectable_techniques, 'techniques detectable'],
          [data.tactics_covered, 'tactics covered'],
          [data.observed_techniques, 'techniques observed'],
        ].map(([value, label]) => (
          <div key={label} className="demo-metrics" style={{ marginTop: 0 }}>
            <div><strong>{value}</strong><span>{label}</span></div>
          </div>
        ))}
      </div>
      <div className="am-legend">
        <span><i style={{ background: 'var(--bg-surface)', border: '1px solid rgba(52,211,153,0.5)' }} />Detectable, not yet seen</span>
        <span><i style={{ background: heat(1, max) }} />Observed</span>
        <span><i style={{ background: heat(max, max) }} />Most observed</span>
        <span>Click a technique for details</span>
      </div>
      <div className="attack-matrix">
        {data.matrix.map((col) => (
          <div key={col.tactic} className="am-col">
            <div className="am-tactic">{col.tactic}</div>
            {col.techniques.map((t) => (
              <button
                key={`${col.tactic}-${t.id}`}
                className={`am-cell ${t.detectable ? 'am-detect' : ''} ${t.observed ? 'am-hit' : ''}`}
                style={{ background: heat(t.observed, max) }}
                title={`${t.id} ${t.name}\n${t.rules.length ? `Rules: ${t.rules.join(', ')}` : 'Observed via correlation'}\nIncidents: ${t.observed}`}
                onClick={() => onSelect?.(t.id)}
              >
                <b>{t.id}{t.observed ? ` · ${t.observed}` : ''}</b>
                {t.name}
              </button>
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}
