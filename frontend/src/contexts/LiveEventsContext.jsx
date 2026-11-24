// Real-time event stream (Server-Sent Events) shared by every page.
import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import api, { API_BASE_URL } from '../services/api';
import { useAuth } from './AuthContext';

const LiveEventsContext = createContext(null);
const EVENT_TYPES = ['log', 'incident', 'soar', 'scenario', 'simulator', 'hello'];
const MAX_EVENTS = 80;
const TOAST_LIMIT = 4;

function toastFor(event) {
  const d = event.data || {};
  if (event.type === 'incident' && (d.created || d.reopened) && ['CRITICAL', 'HIGH'].includes(d.risk_level)) {
    return {
      tone: d.risk_level === 'CRITICAL' ? 'critical' : 'high',
      title: `${d.risk_level}: ${d.threat_type}`,
      body: `${d.source_ip || 'internal host'} · ${d.mitre_technique || 'no technique'}${d.multi_stage ? ` · ${d.multi_stage}` : ''}`,
      link: `/incidents/${d.id}`,
    };
  }
  if (event.type === 'soar' && d.action === 'block_ip' && String(d.detail || '').includes('added')) {
    return { tone: 'success', title: 'SOAR: attacker blocked', body: d.detail, link: '/soar' };
  }
  if (event.type === 'scenario' && d.event === 'started') {
    return { tone: 'info', title: `Attack scenario started: ${d.scenario?.name}`, body: `Attacker ${d.scenario?.attacker_ip}`, link: '/demo' };
  }
  if (event.type === 'scenario' && d.event === 'finished') {
    return { tone: 'info', title: `Scenario ${d.scenario?.status}: ${d.scenario?.name}`, body: `${d.scenario?.incident_ids?.length || 0} incidents opened`, link: '/campaigns' };
  }
  return null;
}

export function LiveEventsProvider({ children }) {
  const { token } = useAuth();
  const [connected, setConnected] = useState(false);
  const [events, setEvents] = useState([]);
  const [toasts, setToasts] = useState([]);
  const [muted, setMuted] = useState(() => {
    try { return localStorage.getItem('tl_toasts_muted') === '1'; } catch { return false; }
  });
  const listeners = useRef(new Set());
  const logTimes = useRef([]);
  const [rate, setRate] = useState(0);
  const mutedRef = useRef(muted);
  mutedRef.current = muted;

  const dismiss = useCallback((id) => setToasts((list) => list.filter((t) => t.id !== id)), []);

  const handle = useCallback((event) => {
    if (event.type === 'log') logTimes.current.push(Date.now());
    if (event.type !== 'hello') setEvents((list) => [event, ...list].slice(0, MAX_EVENTS));
    listeners.current.forEach((fn) => { try { fn(event); } catch { /* listener errors never break the stream */ } });
    const toast = !mutedRef.current && toastFor(event);
    if (toast) {
      const id = `${event.id}-${Math.random().toString(36).slice(2, 6)}`;
      setToasts((list) => [{ id, ...toast }, ...list].slice(0, TOAST_LIMIT));
      setTimeout(() => dismiss(id), 7000);
    }
  }, [dismiss]);

  useEffect(() => {
    if (!token) return undefined;
    let source = null;
    let retryTimer = null;
    let cancelled = false;
    let backoff = 2000;

    const connect = async () => {
      try {
        const { data } = await api.post('/stream/ticket');
        if (cancelled) return;
        source = new EventSource(`${API_BASE_URL}/stream/events?ticket=${encodeURIComponent(data.ticket)}`);
        source.addEventListener('open', () => { setConnected(true); backoff = 2000; });
        EVENT_TYPES.forEach((type) => source.addEventListener(type, (message) => {
          try { handle(JSON.parse(message.data)); } catch { /* ignore malformed */ }
        }));
        source.onerror = () => {
          setConnected(false);
          source.close();
          if (!cancelled) retryTimer = setTimeout(connect, backoff);
          backoff = Math.min(backoff * 2, 30000);
        };
      } catch {
        setConnected(false);
        if (!cancelled) retryTimer = setTimeout(connect, backoff);
        backoff = Math.min(backoff * 2, 30000);
      }
    };
    connect();
    return () => {
      cancelled = true;
      clearTimeout(retryTimer);
      if (source) source.close();
      setConnected(false);
    };
  }, [token, handle]);

  // Rolling "events per minute" counter.
  useEffect(() => {
    const timer = setInterval(() => {
      const cutoff = Date.now() - 60000;
      logTimes.current = logTimes.current.filter((t) => t >= cutoff);
      setRate(logTimes.current.length);
    }, 2000);
    return () => clearInterval(timer);
  }, []);

  const subscribe = useCallback((fn) => {
    listeners.current.add(fn);
    return () => listeners.current.delete(fn);
  }, []);

  const toggleMute = useCallback(() => {
    setMuted((m) => {
      try { localStorage.setItem('tl_toasts_muted', m ? '0' : '1'); } catch { /* storage unavailable */ }
      return !m;
    });
  }, []);

  const value = useMemo(() => ({ connected, events, rate, toasts, dismiss, subscribe, muted, toggleMute }),
    [connected, events, rate, toasts, dismiss, subscribe, muted, toggleMute]);
  return <LiveEventsContext.Provider value={value}>{children}</LiveEventsContext.Provider>;
}

export const useLive = () => useContext(LiveEventsContext);

/** Run `callback` (debounced) whenever a matching live event arrives. */
export function useLiveRefresh(callback, types = ['incident'], delay = 1500) {
  const live = useLive();
  const saved = useRef(callback);
  saved.current = callback;
  const key = types.join(',');
  useEffect(() => {
    if (!live) return undefined;
    let timer = null;
    const wanted = key.split(',');
    const off = live.subscribe((event) => {
      if (!wanted.includes(event.type)) return;
      clearTimeout(timer);
      timer = setTimeout(() => saved.current(event), delay);
    });
    return () => { off(); clearTimeout(timer); };
  }, [live, key, delay]);
}
