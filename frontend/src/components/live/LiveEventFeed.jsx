import React from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import { useLive } from '../../contexts/LiveEventsContext';

const SOURCE_LABELS = {
  live_traffic: 'network',
  attack_simulation: 'scenario',
  manual_analysis: 'studio',
  'lab-ssh': 'lab · ssh',
  'lab-web': 'lab · web',
  'lab-shell': 'lab · shell',
};

const time = (iso) => new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

/** Scrolling feed of pipeline events received over the real-time stream. */
export default function LiveEventFeed({ limit = 12, threatsOnly = false }) {
  const live = useLive();
  const navigate = useNavigate();
  const items = (live?.events || [])
    .filter((e) => e.type === 'log' && (!threatsOnly || e.data.threat))
    .slice(0, limit);

  if (!live?.connected && items.length === 0) {
    return <div className="live-feed-empty">Connecting to the real-time stream…</div>;
  }
  if (items.length === 0) {
    return (
      <div className="live-feed-empty">
        Waiting for events. Start live traffic or launch an attack scenario from <strong>Live Demo</strong>,
        or send logs to the webhook.
      </div>
    );
  }
  return (
    <div className="live-feed">
      <AnimatePresence initial={false}>
        {items.map((event) => {
          const d = event.data;
          const level = (d.risk_level || '').toLowerCase();
          return (
            <motion.div
              key={event.id}
              layout
              initial={{ opacity: 0, y: -8, backgroundColor: d.threat ? 'rgba(239,68,68,0.18)' : 'rgba(245,158,11,0.08)' }}
              animate={{ opacity: 1, y: 0, backgroundColor: 'rgba(0,0,0,0)' }}
              transition={{ duration: 0.6 }}
              className={`live-feed-row ${d.threat ? 'lfr-threat' : ''}`}
              onClick={() => d.source_ip && navigate(`/investigate?ip=${encodeURIComponent(d.source_ip)}`)}
              title={d.excerpt}
            >
              <span className="lfr-time">{time(event.ts)}</span>
              <span className="lfr-source">{SOURCE_LABELS[d.source] || d.source}</span>
              <span className="lfr-text">{d.threat ? <strong>{d.threat}</strong> : d.excerpt}</span>
              {d.threat
                ? <span className={`severity-chip ${level}`}>{d.risk_level}</span>
                : <span className="lfr-ip">{d.source_ip || ''}</span>}
            </motion.div>
          );
        })}
      </AnimatePresence>
    </div>
  );
}
