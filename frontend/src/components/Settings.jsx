import React, { useCallback, useEffect, useState } from 'react';
import api, { getApiErrorMessage } from '../services/api';
import { useAuth } from '../contexts/AuthContext';
import InfoHint from './soc/InfoHint';

const TABS = [
  { id: 'platform', label: '⚙️ Platform' },
  { id: 'integrations', label: '🔌 Integrations' },
  { id: 'users', label: '👥 Users', admin: true },
  { id: 'audit', label: '📜 Audit Log', admin: true },
  { id: 'account', label: '👤 My Account' },
];

const fmt = (value) => (value ? new Date(value.endsWith('Z') ? value : `${value}Z`).toLocaleString() : 'Never');

function Banner({ notice, onClose }) {
  if (!notice) return null;
  const color = notice.type === 'error' ? 'var(--danger)' : 'var(--success)';
  return (
    <div className="card" style={{ marginBottom: 16, padding: '12px 16px', borderLeft: `3px solid ${color}`, display: 'flex', justifyContent: 'space-between', gap: 12 }}>
      <span style={{ fontSize: 13, color: 'var(--text-primary)' }}>{notice.text}</span>
      <button className="rule-delete-btn" onClick={onClose} aria-label="Dismiss">✖</button>
    </div>
  );
}

// ── Platform settings ───────────────────────────────────────────────────────
function PlatformTab({ isAdmin, notify }) {
  const [settings, setSettings] = useState(null);
  const [health, setHealth] = useState(null);
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    try {
      const [settingsRes, healthRes] = await Promise.all([api.get('/dashboard/settings'), api.get('/dashboard/ingestion-health')]);
      setSettings(settingsRes.data);
      setHealth(healthRes.data);
    } catch (err) {
      notify('error', getApiErrorMessage(err, 'Failed to load settings.'));
    }
  }, [notify]);

  useEffect(() => { load(); }, [load]);

  if (!settings) return <div className="page-loading"><div className="loading-spinner" /><span>Loading settings…</span></div>;

  const set = (section, key, value) => setSettings((cur) => ({ ...cur, [section]: { ...cur[section], [key]: value } }));
  const setDeep = (section, group, key, value) => setSettings((cur) => ({
    ...cur, [section]: { ...cur[section], [group]: { ...cur[section][group], [key]: value } },
  }));
  const num = (fn) => (e) => fn(Number(e.target.value));

  const save = async () => {
    setSaving(true);
    try {
      await api.put('/dashboard/settings', settings);
      notify('success', 'Settings saved.');
      await load();
    } catch (err) {
      notify('error', getApiErrorMessage(err, 'Failed to save settings.'));
    } finally {
      setSaving(false);
    }
  };

  const field = (label, value, onChange, type = 'number') => (
    <label key={label}><span className="field-label">{label}</span>
      <input className="field-input" type={type} value={value} onChange={onChange} disabled={!isAdmin} />
    </label>
  );

  return (
    <div className="settings-grid">
      {!isAdmin && (
        <div className="card settings-span-two" style={{ padding: '12px 16px', fontSize: 13, color: 'var(--text-secondary)' }}>
          🔒 Read-only — only administrators can change platform settings.
        </div>
      )}
      <section className="card settings-section">
        <div className="card-header"><span className="card-title">Collector &amp; Demo <InfoHint text="The Windows Event Log collector only works when the backend runs natively on Windows. Demo mode replays a realistic attack scenario into an empty database." /></span></div>
        <div className="card-body settings-form-grid">
          <label><span className="field-label">Demo Mode</span>
            <select className="field-input" disabled={!isAdmin} value={String(settings.demo_mode)} onChange={(e) => setSettings({ ...settings, demo_mode: e.target.value === 'true' })}>
              <option value="true">Enabled</option><option value="false">Disabled</option>
            </select>
          </label>
          <label><span className="field-label">Windows Collector</span>
            <select className="field-input" disabled={!isAdmin} value={String(settings.collector.enabled)} onChange={(e) => set('collector', 'enabled', e.target.value === 'true')}>
              <option value="true">Enabled</option><option value="false">Disabled</option>
            </select>
          </label>
          {field('Interval Seconds', settings.collector.interval_seconds, num((v) => set('collector', 'interval_seconds', v)))}
          {field('Max Events / Sweep', settings.collector.max_events_per_sweep, num((v) => set('collector', 'max_events_per_sweep', v)))}
        </div>
      </section>

      <section className="card settings-section">
        <div className="card-header"><span className="card-title">Retention <InfoHint text="Oldest records beyond these limits are pruned every 30 minutes." /></span></div>
        <div className="card-body settings-form-grid">
          {field('Max Logs', settings.retention.max_logs, num((v) => set('retention', 'max_logs', v)))}
          {field('Max Incidents', settings.retention.max_incidents, num((v) => set('retention', 'max_incidents', v)))}
          {field('Max Chat Messages', settings.retention.max_chats, num((v) => set('retention', 'max_chats', v)))}
        </div>
      </section>

      <section className="card settings-section">
        <div className="card-header"><span className="card-title">Detection Thresholds <InfoHint text="Grouping windows control how repeat alerts merge into one case; thresholds map the 0-100 risk score to severity." /></span></div>
        <div className="card-body settings-form-grid">
          {field('Group Window (hours)', settings.detection.group_window_hours, num((v) => set('detection', 'group_window_hours', v)))}
          {field('Reopen Window (hours)', settings.detection.reopen_window_hours, num((v) => set('detection', 'reopen_window_hours', v)))}
          {field('Critical ≥', settings.detection.risk_thresholds.critical, num((v) => setDeep('detection', 'risk_thresholds', 'critical', v)))}
          {field('High ≥', settings.detection.risk_thresholds.high, num((v) => setDeep('detection', 'risk_thresholds', 'high', v)))}
          {field('Medium ≥', settings.detection.risk_thresholds.medium, num((v) => setDeep('detection', 'risk_thresholds', 'medium', v)))}
        </div>
      </section>

      <section className="card settings-section">
        <div className="card-header"><span className="card-title">SLA &amp; Auto-Close <InfoHint text="SLA targets per severity, and how long inactive LOW/MEDIUM cases stay open before auto-resolving." /></span></div>
        <div className="card-body settings-form-grid">
          {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((lvl) => field(`${lvl} SLA (min)`, settings.detection.sla_minutes[lvl], num((v) => setDeep('detection', 'sla_minutes', lvl, v))))}
          {field('LOW auto-close (h)', settings.detection.auto_close_hours.LOW, num((v) => setDeep('detection', 'auto_close_hours', 'LOW', v)))}
          {field('MEDIUM auto-close (h)', settings.detection.auto_close_hours.MEDIUM, num((v) => setDeep('detection', 'auto_close_hours', 'MEDIUM', v)))}
        </div>
      </section>

      <section className="card settings-section">
        <div className="card-header"><span className="card-title">Threat-Intel Feeds</span></div>
        <div className="card-body settings-form-grid">
          <label><span className="field-label">Auto Refresh</span>
            <select className="field-input" disabled={!isAdmin} value={String(settings.feeds.threat_intel_auto_refresh)} onChange={(e) => set('feeds', 'threat_intel_auto_refresh', e.target.value === 'true')}>
              <option value="true">Enabled</option><option value="false">Disabled</option>
            </select>
          </label>
          {field('Refresh Interval (min)', settings.feeds.refresh_interval_minutes, num((v) => set('feeds', 'refresh_interval_minutes', v)))}
        </div>
      </section>

      <section className="card settings-section settings-span-two">
        <div className="card-header"><span className="card-title">Ingestion Health <InfoHint text="Per-source event volume, incidents created, parse failures and dropped low-signal events." /></span></div>
        <div className="card-body ingestion-health-list">
          {(health?.sources || []).length === 0 && <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>No ingestion sources have reported yet.</span>}
          {(health?.sources || []).map((source) => (
            <div key={source.source_key} className="ingestion-health-item">
              <div>
                <strong>{source.display_name}</strong>
                <span>Last event: {fmt(source.last_event_at)}{source.last_error ? ` · last error: ${source.last_error}` : ''}</span>
              </div>
              <div className="ingestion-health-metrics">
                <span>{source.events_ingested} events</span>
                <span>{source.incidents_created} incidents</span>
                <span>{source.parse_failures} parse failures</span>
                <span>{source.dropped_events} dropped</span>
              </div>
            </div>
          ))}
        </div>
      </section>

      {isAdmin && (
        <div className="settings-save-row settings-span-two">
          <button className="btn-primary" onClick={save} disabled={saving}>{saving ? 'Saving…' : 'Save Settings'}</button>
        </div>
      )}
    </div>
  );
}

// ── Integrations (which API keys are configured) ────────────────────────────
function IntegrationsTab({ notify }) {
  const [status, setStatus] = useState(null);
  useEffect(() => {
    api.get('/system/status').then((res) => setStatus(res.data)).catch((err) => notify('error', getApiErrorMessage(err, 'Failed to load system status.')));
  }, [notify]);
  if (!status) return <div className="page-loading"><div className="loading-spinner" /><span>Checking integrations…</span></div>;
  return (
    <div className="settings-grid">
      <section className="card settings-section settings-span-two">
        <div className="card-header"><span className="card-title">Platform</span></div>
        <div className="card-body ingestion-health-list">
          <div className="ingestion-health-item"><div><strong>Version</strong><span>ThreatLens {status.version} · {status.environment}</span></div></div>
          <div className="ingestion-health-item"><div><strong>Database</strong><span>{status.database.engine} · {status.database.reachable ? 'reachable' : 'UNREACHABLE'}</span></div></div>
          <div className="ingestion-health-item"><div><strong>AI model</strong><span>{status.llm.enabled ? `Groq · ${status.llm.model}` : 'Not configured — summaries and Copilot use the built-in rule engine'}</span></div></div>
          <div className="ingestion-health-item"><div><strong>MITRE ATT&amp;CK</strong><span>{status.mitre_techniques_loaded} techniques loaded</span></div></div>
          {status.security_warnings?.map((w) => (
            <div key={w} className="ingestion-health-item"><div><strong style={{ color: 'var(--danger)' }}>⚠️ Security</strong><span>{w}</span></div></div>
          ))}
        </div>
      </section>
      <section className="card settings-section settings-span-two">
        <div className="card-header"><span className="card-title">Integrations <InfoHint text="API keys are read from the .env file at the repository root. See .env.example for where to obtain each key, then restart the backend." /></span></div>
        <div className="card-body ingestion-health-list">
          {status.integrations.map((item) => (
            <div key={item.key} className="ingestion-health-item">
              <div>
                <strong>{item.name}</strong>
                <span>{item.purpose}</span>
              </div>
              <div className="ingestion-health-metrics">
                <span style={{ fontFamily: 'var(--font-mono)' }}>{item.env_var}</span>
                <span style={{ color: item.configured ? 'var(--success)' : 'var(--text-muted)', fontWeight: 700 }}>
                  {item.configured ? '● Configured' : '○ Not set'}
                </span>
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

// ── Users (admin) ───────────────────────────────────────────────────────────
function UsersTab({ currentUserId, notify }) {
  const [users, setUsers] = useState([]);
  const [form, setForm] = useState({ username: '', email: '', password: '', role: 'analyst', full_name: '' });
  const load = useCallback(async () => {
    try { setUsers((await api.get('/auth/users')).data.users); }
    catch (err) { notify('error', getApiErrorMessage(err, 'Failed to load users.')); }
  }, [notify]);
  useEffect(() => { load(); }, [load]);

  const act = async (fn, message) => {
    try { await fn(); notify('success', message); await load(); }
    catch (err) { notify('error', getApiErrorMessage(err, 'Action failed.')); }
  };

  const create = (e) => {
    e.preventDefault();
    act(() => api.post('/auth/users', { ...form, full_name: form.full_name || undefined }), `User ${form.username} created.`)
      .then(() => setForm({ username: '', email: '', password: '', role: 'analyst', full_name: '' }));
  };

  return (
    <div className="settings-grid">
      <section className="card settings-section settings-span-two">
        <div className="card-header"><span className="card-title">Team members</span></div>
        <table className="data-table">
          <thead><tr><th>User</th><th>Email</th><th>Role</th><th>Status</th><th>Last login</th><th /></tr></thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id}>
                <td><strong>{u.username}</strong>{u.full_name ? <span style={{ color: 'var(--text-muted)' }}> · {u.full_name}</span> : null}</td>
                <td style={{ fontSize: 13 }}>{u.email}</td>
                <td>
                  <select className="field-input" value={u.role} disabled={u.id === currentUserId}
                    onChange={(e) => act(() => api.put(`/auth/users/${u.id}/role`, { role: e.target.value }), `Role updated for ${u.username}.`)}>
                    <option value="admin">admin</option><option value="analyst">analyst</option><option value="viewer">viewer</option>
                  </select>
                </td>
                <td style={{ color: u.is_active ? 'var(--success)' : 'var(--danger)', fontSize: 13 }}>{u.is_active ? 'Active' : 'Deactivated'}</td>
                <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{fmt(u.last_login)}</td>
                <td>
                  {u.id !== currentUserId && (
                    <button className="btn-outline" onClick={() => act(() => api.put(`/auth/users/${u.id}/deactivate`), `${u.username} ${u.is_active ? 'deactivated' : 'activated'}.`)}>
                      {u.is_active ? 'Deactivate' : 'Activate'}
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
      <section className="card settings-section settings-span-two">
        <div className="card-header"><span className="card-title">Add a user</span></div>
        <form className="card-body settings-form-grid" onSubmit={create}>
          <label><span className="field-label">Username</span><input className="field-input" required value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} /></label>
          <label><span className="field-label">Email</span><input className="field-input" type="email" required value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></label>
          <label><span className="field-label">Full name</span><input className="field-input" value={form.full_name} onChange={(e) => setForm({ ...form, full_name: e.target.value })} /></label>
          <label><span className="field-label">Temporary password</span><input className="field-input" type="password" required autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></label>
          <label><span className="field-label">Role</span>
            <select className="field-input" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
              <option value="analyst">analyst</option><option value="viewer">viewer</option><option value="admin">admin</option>
            </select>
          </label>
          <div style={{ display: 'flex', alignItems: 'flex-end' }}><button className="btn-primary" type="submit">Create user</button></div>
        </form>
      </section>
    </div>
  );
}

// ── Audit log (admin) ───────────────────────────────────────────────────────
function AuditTab({ notify }) {
  const [entries, setEntries] = useState([]);
  const [filter, setFilter] = useState('');
  const load = useCallback(async (action) => {
    try {
      const params = new URLSearchParams({ limit: '200' });
      if (action) params.set('action', action);
      setEntries((await api.get(`/dashboard/audit-logs?${params.toString()}`)).data.entries);
    } catch (err) { notify('error', getApiErrorMessage(err, 'Failed to load audit log.')); }
  }, [notify]);
  useEffect(() => { load(); }, [load]);
  return (
    <section className="card">
      <div className="card-header">
        <span className="card-title">Audit trail</span>
        <form onSubmit={(e) => { e.preventDefault(); load(filter); }} style={{ display: 'flex', gap: 8 }}>
          <input className="field-input" placeholder="Filter by action (e.g. incident, auth)" value={filter} onChange={(e) => setFilter(e.target.value)} />
          <button className="btn-outline" type="submit">Filter</button>
        </form>
      </div>
      <table className="data-table">
        <thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Details</th><th>IP</th></tr></thead>
        <tbody>
          {entries.map((e) => (
            <tr key={e.id}>
              <td style={{ fontSize: 12, whiteSpace: 'nowrap' }}>{fmt(e.timestamp)}</td>
              <td style={{ fontSize: 13 }}>{e.actor}{e.actor_role ? <span style={{ color: 'var(--text-muted)' }}> ({e.actor_role})</span> : null}</td>
              <td><span className="rule-chip">{e.action}</span></td>
              <td style={{ fontSize: 12 }}>{e.target_type ? `${e.target_type} ${e.target_id || ''}` : '—'}</td>
              <td style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', maxWidth: 360, wordBreak: 'break-word' }}>
                {Object.keys(e.details || {}).length ? JSON.stringify(e.details) : '—'}
              </td>
              <td style={{ fontSize: 12, fontFamily: 'var(--font-mono)' }}>{e.ip_address || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

// ── My account ──────────────────────────────────────────────────────────────
function AccountTab({ user, refreshProfile, notify }) {
  const [profile, setProfile] = useState({ full_name: user?.full_name || '', organization: user?.organization || '' });
  const [pw, setPw] = useState({ current_password: '', new_password: '', confirm: '' });

  const saveProfile = async (e) => {
    e.preventDefault();
    try { await api.put('/auth/me', profile); await refreshProfile(); notify('success', 'Profile updated.'); }
    catch (err) { notify('error', getApiErrorMessage(err, 'Failed to update profile.')); }
  };
  const changePassword = async (e) => {
    e.preventDefault();
    if (pw.new_password !== pw.confirm) { notify('error', 'New passwords do not match.'); return; }
    try {
      await api.put('/auth/me/password', { current_password: pw.current_password, new_password: pw.new_password });
      setPw({ current_password: '', new_password: '', confirm: '' });
      notify('success', 'Password changed.');
    } catch (err) { notify('error', getApiErrorMessage(err, 'Failed to change password.')); }
  };

  return (
    <div className="settings-grid">
      <section className="card settings-section">
        <div className="card-header"><span className="card-title">Profile</span></div>
        <form className="card-body settings-form-grid" onSubmit={saveProfile}>
          <label><span className="field-label">Username</span><input className="field-input" value={user?.username || ''} disabled /></label>
          <label><span className="field-label">Role</span><input className="field-input" value={user?.role || ''} disabled /></label>
          <label><span className="field-label">Full name</span><input className="field-input" value={profile.full_name} onChange={(e) => setProfile({ ...profile, full_name: e.target.value })} /></label>
          <label><span className="field-label">Organization</span><input className="field-input" value={profile.organization} onChange={(e) => setProfile({ ...profile, organization: e.target.value })} /></label>
          <div style={{ display: 'flex', alignItems: 'flex-end' }}><button className="btn-primary" type="submit">Save profile</button></div>
        </form>
      </section>
      <section className="card settings-section">
        <div className="card-header"><span className="card-title">Change password</span></div>
        <form className="card-body settings-form-grid" onSubmit={changePassword}>
          <label><span className="field-label">Current password</span><input className="field-input" type="password" autoComplete="current-password" required value={pw.current_password} onChange={(e) => setPw({ ...pw, current_password: e.target.value })} /></label>
          <label><span className="field-label">New password</span><input className="field-input" type="password" autoComplete="new-password" required value={pw.new_password} onChange={(e) => setPw({ ...pw, new_password: e.target.value })} /></label>
          <label><span className="field-label">Confirm new password</span><input className="field-input" type="password" autoComplete="new-password" required value={pw.confirm} onChange={(e) => setPw({ ...pw, confirm: e.target.value })} /></label>
          <div style={{ display: 'flex', alignItems: 'flex-end' }}><button className="btn-primary" type="submit">Update password</button></div>
        </form>
      </section>
    </div>
  );
}

export default function Settings() {
  const { user, isAdmin, refreshProfile } = useAuth();
  const [tab, setTab] = useState('platform');
  const [notice, setNotice] = useState(null);
  const notify = useCallback((type, text) => setNotice({ type, text }), []);

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="soc-header-kicker">{isAdmin ? 'Admin Workspace' : 'Workspace'}</div>
          <h1 className="page-header-title">Settings</h1>
          <p className="page-header-sub">Platform configuration, integrations, team access, audit trail and your account.</p>
        </div>
      </div>
      <div className="page-body">
        <Banner notice={notice} onClose={() => setNotice(null)} />
        <div className="filter-tabs">
          {TABS.filter((t) => !t.admin || isAdmin).map((t) => (
            <button key={t.id} className={`filter-tab ${tab === t.id ? 'ft-active' : ''}`} onClick={() => { setTab(t.id); setNotice(null); }}>{t.label}</button>
          ))}
        </div>
        {tab === 'platform' && <PlatformTab isAdmin={isAdmin} notify={notify} />}
        {tab === 'integrations' && <IntegrationsTab notify={notify} />}
        {tab === 'users' && isAdmin && <UsersTab currentUserId={user?.id} notify={notify} />}
        {tab === 'audit' && isAdmin && <AuditTab notify={notify} />}
        {tab === 'account' && <AccountTab user={user} refreshProfile={refreshProfile} notify={notify} />}
      </div>
    </div>
  );
}
