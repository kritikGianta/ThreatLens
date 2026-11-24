// Live Threat Map — real attacker IPs (from incidents), geolocated, with arcs to HQ.
import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { geoNaturalEarth1, geoPath, geoGraticule10 } from 'd3-geo';
import { feature } from 'topojson-client';
import world from 'world-atlas/countries-110m.json';
import api, { getApiErrorMessage } from '../services/api';
import { useLive, useLiveRefresh } from '../contexts/LiveEventsContext';
import { LivePill } from './live/LiveToasts';

const WIDTH = 960;
const HEIGHT = 500;
const COLORS = { CRITICAL: '#EF4444', HIGH: '#F59E0B', MEDIUM: '#60A5FA', LOW: '#34D399' };
const WINDOWS = [{ h: 1, label: '1 hour' }, { h: 24, label: '24 hours' }, { h: 168, label: '7 days' }];

const countries = feature(world, world.objects.countries).features;
const projection = geoNaturalEarth1().fitExtent([[8, 8], [WIDTH - 8, HEIGHT - 8]], { type: 'Sphere' });
const pathGen = geoPath(projection);
const graticule = pathGen(geoGraticule10());
const sphere = pathGen({ type: 'Sphere' });
const countryPaths = countries.map((c) => ({ id: c.id, d: pathGen(c) }));

function arcPath([x1, y1], [x2, y2]) {
  const mx = (x1 + x2) / 2;
  const my = (y1 + y2) / 2;
  const dist = Math.hypot(x2 - x1, y2 - y1);
  return `M${x1},${y1} Q${mx},${my - Math.min(dist * 0.35, 160)} ${x2},${y2}`;
}

const isRecent = (iso, minutes = 3) => iso && Date.now() - new Date(`${iso}Z`).getTime() < minutes * 60000;

export default function ThreatMap() {
  const navigate = useNavigate();
  const live = useLive();
  const [hours, setHours] = useState(24);
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [hover, setHover] = useState(null);
  const [loading, setLoading] = useState(true);
  const [flash, setFlash] = useState({});
  const flashTimers = useRef({});
  const retryTimer = useRef(null);

  const load = useCallback(async () => {
    try {
      const res = await api.get(`/dashboard/threat-map?hours=${hours}`);
      setData(res.data);
      setError(null);
      // Geolocation is rate-limited upstream: retry shortly while some attackers are still unlocated.
      clearTimeout(retryTimer.current);
      if (res.data.unlocated > 0) retryTimer.current = setTimeout(() => load(), 15000);
    } catch (err) {
      setError(getApiErrorMessage(err, 'Failed to load the threat map.'));
    } finally {
      setLoading(false);
    }
  }, [hours]);

  useEffect(() => { setLoading(true); load(); return () => clearTimeout(retryTimer.current); }, [load]);
  useLiveRefresh(() => load(), ['incident'], 2500);

  // Flash an attacker the moment a new incident for it streams in.
  useEffect(() => {
    if (!live) return undefined;
    return live.subscribe((event) => {
      const ip = event.type === 'incident' ? event.data.source_ip : null;
      if (!ip) return;
      setFlash((f) => ({ ...f, [ip]: Date.now() }));
      clearTimeout(flashTimers.current[ip]);
      flashTimers.current[ip] = setTimeout(() => setFlash((f) => { const n = { ...f }; delete n[ip]; return n; }), 6000);
    });
  }, [live]);

  const hq = data?.hq;
  const hqXY = hq ? projection([hq.lon, hq.lat]) : null;
  const points = useMemo(() => (data?.points || []).map((p) => ({ ...p, xy: projection([p.lon, p.lat]) })).filter((p) => p.xy), [data]);
  const recent = points.filter((p) => isRecent(p.last_seen) || flash[p.ip]);
  const blocked = points.filter((p) => p.blocked).length;
  const critical = points.filter((p) => p.risk_level === 'CRITICAL').length;

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-header-title">Live Threat Map</h1>
          <p className="page-header-sub">
            External attackers seen by ThreatLens, geolocated from their real IP addresses, targeting {hq?.name || 'your network'}.
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <LivePill />
          {WINDOWS.map((w) => (
            <button key={w.h} className={`filter-btn-sm ${hours === w.h ? 'fbsm-active' : ''}`} onClick={() => setHours(w.h)}>{w.label}</button>
          ))}
        </div>
      </div>

      <div className="page-body">
        {error && <div className="auth-error" style={{ marginBottom: 12 }}>{error}</div>}
        <div className="map-layout">
          <div className="card map-card">
            <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} className="threat-map-svg" role="img" aria-label="World map of attack sources">
              <defs>
                <radialGradient id="tm-glow"><stop offset="0" stopColor="#F59E0B" stopOpacity="0.55" /><stop offset="1" stopColor="#F59E0B" stopOpacity="0" /></radialGradient>
              </defs>
              <path d={sphere} className="tm-sphere" />
              <path d={graticule} className="tm-graticule" />
              {countryPaths.map((c) => <path key={c.id} d={c.d} className="tm-country" />)}

              {hqXY && points.map((p) => (
                <path
                  key={`arc-${p.ip}`}
                  d={arcPath(p.xy, hqXY)}
                  className={`tm-arc ${flash[p.ip] || isRecent(p.last_seen) ? 'tm-arc-live' : ''}`}
                  stroke={COLORS[p.risk_level] || COLORS.MEDIUM}
                />
              ))}

              {points.map((p) => (
                <g
                  key={p.ip}
                  transform={`translate(${p.xy[0]},${p.xy[1]})`}
                  className="tm-point"
                  onMouseEnter={() => setHover(p)}
                  onMouseLeave={() => setHover(null)}
                  onClick={() => navigate(`/investigate?ip=${encodeURIComponent(p.ip)}`)}
                >
                  {(flash[p.ip] || isRecent(p.last_seen)) && <circle r="14" className="tm-pulse" fill={COLORS[p.risk_level]} />}
                  <circle r={Math.min(3 + Math.log2(p.alerts + 1) * 1.6, 11)} fill={COLORS[p.risk_level] || COLORS.MEDIUM}
                          stroke="#0C0A09" strokeWidth="1.2" opacity={p.blocked ? 0.55 : 0.95} />
                  {p.blocked && <path d="M-3,-3L3,3M3,-3L-3,3" stroke="#0C0A09" strokeWidth="1.6" />}
                </g>
              ))}

              {hqXY && (
                <g transform={`translate(${hqXY[0]},${hqXY[1]})`}>
                  <circle r="26" fill="url(#tm-glow)" />
                  <circle r="6" fill="#F59E0B" stroke="#FDE68A" strokeWidth="2" />
                  <text y="-12" textAnchor="middle" className="tm-hq-label">{hq.name}</text>
                </g>
              )}
            </svg>

            {hover && (
              <div className="tm-tooltip">
                <strong>{hover.ip}</strong>
                <span>{[hover.city, hover.country].filter(Boolean).join(', ')}{hover.isp ? ` · ${hover.isp}` : ''}</span>
                <span>{hover.alerts} alerts · {hover.incidents} cases · <b style={{ color: COLORS[hover.risk_level] }}>{hover.risk_level}</b>{hover.blocked ? ' · BLOCKED' : ''}</span>
                <span className="tm-tooltip-threats">{hover.threats.join(' · ')}</span>
              </div>
            )}

            <div className="tm-legend">
              {Object.entries(COLORS).map(([k, c]) => <span key={k}><i style={{ background: c }} />{k}</span>)}
              <span><i className="tm-legend-blocked" />Blocked</span>
            </div>
            {loading && !data && <div className="tm-empty">Geolocating attacker IP addresses…</div>}
            {data && points.length === 0 && (
              <div className="tm-empty">
                No external attackers in this window yet. Start live traffic or launch a scenario from <strong>Live Demo</strong>.
                {data.unlocated > 0 && ` (${data.unlocated} could not be geolocated — check internet access.)`}
              </div>
            )}
          </div>

          <div className="map-side">
            <div className="map-stats">
              <div><strong>{data ? points.length : '—'}</strong><span>attacker IPs</span></div>
              <div><strong>{data ? new Set(points.map((p) => p.country)).size : '—'}</strong><span>countries</span></div>
              <div><strong style={{ color: COLORS.CRITICAL }}>{data ? critical : '—'}</strong><span>critical</span></div>
              <div><strong style={{ color: 'var(--success)' }}>{data ? blocked : '—'}</strong><span>blocked</span></div>
            </div>

            <div className="card">
              <div className="card-header"><span className="card-title">Top source countries</span></div>
              <div className="card-body">
                {(data?.top_countries || []).map((c) => {
                  const max = data.top_countries[0]?.alerts || 1;
                  return (
                    <div key={c.country} className="tm-country-row">
                      <span>{c.country}</span>
                      <div className="tm-bar"><div style={{ width: `${(c.alerts / max) * 100}%` }} /></div>
                      <b>{c.alerts}</b>
                    </div>
                  );
                })}
                {!data?.top_countries?.length && <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>No data yet.</span>}
              </div>
            </div>

            <div className="card">
              <div className="card-header"><span className="card-title">Active right now</span><span className="ft-count">{recent.length}</span></div>
              <div className="tm-recent">
                {(recent.length ? recent : points.slice(0, 8)).slice(0, 8).map((p) => (
                  <button key={p.ip} className="tm-recent-row" onClick={() => navigate(`/investigate?ip=${encodeURIComponent(p.ip)}`)}>
                    <span className="tm-recent-dot" style={{ background: COLORS[p.risk_level] }} />
                    <span className="tm-recent-ip">{p.ip}</span>
                    <span className="tm-recent-meta">{p.country_code || p.country} · {p.threats[0]}</span>
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
