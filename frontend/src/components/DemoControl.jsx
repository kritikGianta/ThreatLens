// Live Demo — presenter controls for background traffic, attack scenarios and the attack lab.
import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api, { getApiErrorMessage, LONG_TIMEOUT } from '../services/api';
import { useAuth } from '../contexts/AuthContext';
import { useLive } from '../contexts/LiveEventsContext';
import { LivePill } from './live/LiveToasts';
import LiveEventFeed from './live/LiveEventFeed';

const LAB_SOURCES = ['lab-ssh', 'lab-web', 'lab-shell'];
const STAGE_COLORS = {
  Reconnaissance: '#60A5FA', 'Initial Access': '#F59E0B', Execution: '#F97316', Persistence: '#A78BFA',
  'Privilege Escalation': '#E879F9', 'Defense Evasion': '#94A3B8', 'Credential Access': '#F43F5E',
  'Lateral Movement': '#FB7185', 'Command and Control': '#22D3EE', Exfiltration: '#EF4444', Impact: '#DC2626',
};

function CopyCommand({ command }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="demo-cmd">
      <code>{command}</code>
      <button className="btn-ghost" onClick={() => { navigator.clipboard?.writeText(command); setCopied(true); setTimeout(() => setCopied(false), 1500); }}>
        {copied ? '✓ Copied' : 'Copy'}
      </button>
    </div>
  );
}

export default function DemoControl() {
  const { canWrite, isAdmin } = useAuth();
  const live = useLive();
  const navigate = useNavigate();
  const [status, setStatus] = useState(null);
  const [rate, setRate] = useState('normal');
  const [speed, setSpeed] = useState(1);
  const [busy, setBusy] = useState(null);
  const [notice, setNotice] = useState(null);
  const [labSources, setLabSources] = useState([]);

  const load = useCallback(async () => {
    try {
      const [demoRes, healthRes] = await Promise.all([api.get('/demo/status'), api.get('/dashboard/ingestion-health')]);
      setStatus(demoRes.data);
      setRate(demoRes.data.traffic.rate);
      setLabSources((healthRes.data.sources || []).filter((s) => LAB_SOURCES.includes(s.source_key)));
    } catch (err) {
      setNotice({ type: 'error', text: getApiErrorMessage(err, 'Failed to load demo status.') });
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  // Scenario progress and traffic changes arrive over the real-time stream.
  useEffect(() => {
    if (!live) return undefined;
    return live.subscribe((event) => {
      if (event.type === 'scenario') {
        setStatus((s) => (s ? { ...s, scenario: event.data.scenario, scenario_running: event.data.event !== 'finished' } : s));
        if (event.data.event === 'finished') load();
      }
      if (event.type === 'simulator') load();
    });
  }, [live, load]);

  const act = async (key, fn, success) => {
    setBusy(key);
    setNotice(null);
    try {
      const res = await fn();
      if (success) setNotice({ type: 'success', text: typeof success === 'function' ? success(res.data) : success });
      await load();
    } catch (err) {
      setNotice({ type: 'error', text: getApiErrorMessage(err, 'Action failed.') });
    } finally {
      setBusy(null);
    }
  };

  const traffic = status?.traffic;
  const scenario = status?.scenario;
  const running = status?.scenario_running;
  const labLast = labSources.reduce((latest, s) => (s.last_event_at && (!latest || s.last_event_at > latest) ? s.last_event_at : latest), null);
  const labEvents = labSources.reduce((sum, s) => sum + (s.events_ingested || 0), 0);

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="soc-header-kicker">Presenter controls</div>
          <h1 className="page-header-title">Live Demo</h1>
          <p className="page-header-sub">Generate realistic network activity, launch multi-stage attacks, or run real tools in the attack lab — and watch ThreatLens respond.</p>
        </div>
        <LivePill />
      </div>

      <div className="page-body">
        {!canWrite && <div className="card" style={{ padding: '12px 16px', marginBottom: 16, fontSize: 13 }}>🔒 You are signed in with a read-only account — controls are disabled, but you can watch everything update live.</div>}
        {notice && (
          <div className="card" style={{ padding: '12px 16px', marginBottom: 16, borderLeft: `3px solid ${notice.type === 'error' ? 'var(--danger)' : 'var(--success)'}`, fontSize: 13 }}>
            {notice.text}
          </div>
        )}

        <div className="demo-grid">
          {/* Background traffic */}
          <section className="card demo-section">
            <div className="card-header"><span className="card-title">1 · Background network traffic</span>
              <span className={`demo-state ${traffic?.running ? 'ds-on' : ''}`}>{traffic?.running ? '● Running' : '○ Stopped'}</span>
            </div>
            <div className="card-body">
              <p className="demo-text">
                A steady stream of everyday activity from a fictional company (logons, web requests, DNS, firewall, backups),
                plus the background internet noise every company sees — port scans and SSH brute force from IP addresses that
                are on <strong>real public blocklists</strong>. Every event goes through the real detection pipeline.
              </p>
              <div className="demo-row">
                {(traffic?.rates || ['low', 'normal', 'high']).map((r) => (
                  <button key={r} className={`filter-btn-sm ${rate === r ? 'fbsm-active' : ''}`} disabled={!canWrite}
                          onClick={() => { setRate(r); if (traffic?.running) act('traffic', () => api.post('/demo/traffic/start', { rate: r })); }}>
                    {r}
                  </button>
                ))}
                {traffic?.running
                  ? <button className="btn-outline" disabled={!canWrite || busy === 'traffic'} onClick={() => act('traffic', () => api.post('/demo/traffic/stop'), 'Background traffic stopped.')}>Stop traffic</button>
                  : <button className="btn-primary" disabled={!canWrite || busy === 'traffic'} onClick={() => act('traffic', () => api.post('/demo/traffic/start', { rate }), 'Background traffic started.')}>Start traffic</button>}
              </div>
              <div className="demo-metrics">
                <div><strong>{live?.rate ?? 0}</strong><span>events / min (live)</span></div>
                <div><strong>{(status?.events_generated || 0).toLocaleString()}</strong><span>generated this session</span></div>
              </div>
            </div>
          </section>

          {/* Real attack lab */}
          <section className="card demo-section">
            <div className="card-header"><span className="card-title">2 · Real attack lab</span>
              <span className={`demo-state ${labLast ? 'ds-on' : ''}`}>{labLast ? `● Connected · ${labEvents.toLocaleString()} real log lines` : '○ Not running'}</span>
            </div>
            <div className="card-body">
              <p className="demo-text">
                A real Linux server (OpenSSH + nginx) and an attacker container running <strong>nmap, sqlmap and hydra</strong>.
                A log shipper forwards the server's genuine logs to ThreatLens over the authenticated webhook — nothing here is simulated.
              </p>
              <CopyCommand command="docker compose --profile lab up -d --build" />
              <CopyCommand command="docker compose --profile lab run --rm attacker all" />
              <p className="demo-hint">Run the second command in a terminal next to the browser: each stage prints what to watch for in ThreatLens.</p>
            </div>
          </section>

          {/* Scenarios */}
          <section className="card demo-section demo-span">
            <div className="card-header">
              <span className="card-title">3 · Attack scenarios</span>
              <span style={{ display: 'flex', gap: 6, alignItems: 'center', fontSize: 12, color: 'var(--text-muted)' }}>
                speed
                {[1, 2, 4].map((s) => <button key={s} className={`filter-btn-sm ${speed === s ? 'fbsm-active' : ''}`} onClick={() => setSpeed(s)}>{s}×</button>)}
              </span>
            </div>
            <div className="demo-scenarios">
              {(status?.catalog || []).map((item) => (
                <div key={item.id} className={`demo-scenario ${scenario?.id === item.id && running ? 'dsc-active' : ''}`}>
                  <div className="dsc-title">{item.name}</div>
                  <p>{item.summary}</p>
                  <div className="dsc-tags">{item.techniques.map((t) => <span key={t} className="mitre-tag">{t}</span>)}</div>
                  <div className="dsc-foot">
                    <span>{item.steps} stages · ~{Math.round((item.steps * 8) / speed)}s</span>
                    <button className="btn-primary" disabled={!canWrite || running || busy === item.id}
                            onClick={() => act(item.id, () => api.post(`/demo/scenarios/${item.id}/launch?speed=${speed}`), (d) => `Launched "${d.name}" from ${d.attacker_ip}.`)}>
                      {scenario?.id === item.id && running ? 'Running…' : 'Launch'}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </section>

          {/* Scenario progress */}
          <section className="card demo-section">
            <div className="card-header">
              <span className="card-title">Scenario progress</span>
              {running && <button className="btn-ghost" disabled={!canWrite} onClick={() => act('stop', () => api.post('/demo/scenarios/stop'))}>Stop</button>}
            </div>
            <div className="card-body">
              {!scenario && <div className="live-feed-empty">Launch a scenario to watch each stage get detected.</div>}
              {scenario && (
                <>
                  <div className="dsp-head">
                    <strong>{scenario.name}</strong>
                    <span>attacker <code>{scenario.attacker_ip}</code> · {scenario.status}</span>
                  </div>
                  <ol className="dsp-steps">
                    {scenario.steps.map((step, i) => (
                      <li key={i} className={`dsp-step dsp-${step.status}`}>
                        <span className="dsp-icon">{step.status === 'done' ? '✓' : step.status === 'running' ? '◉' : '○'}</span>
                        <div>
                          <div className="dsp-label">
                            {step.label}
                            <span className="dsp-stage" style={{ color: STAGE_COLORS[step.stage] || 'var(--text-muted)' }}>{step.stage}</span>
                          </div>
                          {step.detections?.length > 0 && (
                            <div className="dsp-detections">
                              {[...new Map(step.detections.map((d) => [d.threat, d])).values()].map((d) => (
                                <button key={d.threat} className={`dsp-det sev-${(d.risk_level || '').toLowerCase()}`}
                                        onClick={() => d.incident_id && navigate(`/incidents/${d.incident_id}`)}>
                                  {d.risk_level} · {d.threat}{d.multi_stage ? ` · ${d.multi_stage}` : ''}
                                </button>
                              ))}
                            </div>
                          )}
                        </div>
                      </li>
                    ))}
                  </ol>
                  {scenario.status !== 'running' && (
                    <div className="demo-row" style={{ marginTop: 12 }}>
                      <button className="btn-outline" onClick={() => navigate('/campaigns')}>Open campaign kill chain →</button>
                      <button className="btn-outline" onClick={() => navigate('/copilot')}>Ask the Copilot →</button>
                    </div>
                  )}
                </>
              )}
            </div>
          </section>

          {/* Live feed */}
          <section className="card demo-section">
            <div className="card-header"><span className="card-title">Live event stream</span></div>
            <div className="card-body"><LiveEventFeed limit={14} /></div>
          </section>

          {isAdmin && (
            <section className="card demo-section demo-span">
              <div className="card-header"><span className="card-title">Before you present</span></div>
              <div className="card-body demo-row" style={{ flexWrap: 'wrap' }}>
                <button className="btn-outline" disabled={busy === 'reset'}
                        onClick={() => window.confirm('Wipe incidents, logs and campaigns and replay the baseline scenario?')
                          && act('reset', () => api.post('/dashboard/reset', null, { timeout: LONG_TIMEOUT }), 'Demo data reset — clean slate with the baseline scenario.')}>
                  Reset demo data
                </button>
                <button className="btn-outline" disabled={busy === 'intel'}
                        onClick={() => act('intel', () => api.post('/alerts/intel/ingest', null, { timeout: LONG_TIMEOUT }), 'Threat-intel feeds refreshed.')}>
                  Refresh threat-intel feeds
                </button>
                <span className="demo-hint">Reset first so the judges see a clean dashboard fill up in real time.</span>
              </div>
            </section>
          )}
        </div>
      </div>
    </div>
  );
}
