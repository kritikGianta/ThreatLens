import React from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import { useLive } from '../../contexts/LiveEventsContext';

/** Stack of real-time notifications (new HIGH/CRITICAL incidents, auto-blocks, scenarios). */
export default function LiveToasts() {
  const live = useLive();
  const navigate = useNavigate();
  if (!live) return null;
  return (
    <div className="live-toasts" aria-live="polite">
      <AnimatePresence initial={false}>
        {live.toasts.map((toast) => (
          <motion.div
            key={toast.id}
            className={`live-toast lt-${toast.tone}`}
            initial={{ opacity: 0, x: 40, scale: 0.96 }}
            animate={{ opacity: 1, x: 0, scale: 1 }}
            exit={{ opacity: 0, x: 40 }}
            transition={{ duration: 0.25 }}
            onClick={() => { live.dismiss(toast.id); if (toast.link) navigate(toast.link); }}
            role="status"
          >
            <span className="live-toast-dot" />
            <div className="live-toast-text">
              <strong>{toast.title}</strong>
              {toast.body && <span>{toast.body}</span>}
            </div>
            <button
              className="live-toast-close"
              aria-label="Dismiss notification"
              onClick={(e) => { e.stopPropagation(); live.dismiss(toast.id); }}
            >
              ×
            </button>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  );
}

/** Compact connection + throughput indicator. */
export function LivePill({ compact = false }) {
  const live = useLive();
  if (!live) return null;
  return (
    <span className={`live-pill ${live.connected ? 'lp-on' : 'lp-off'}`} title={live.connected ? 'Real-time stream connected' : 'Reconnecting to real-time stream'}>
      <span className="live-pill-dot" />
      {live.connected ? (compact ? 'LIVE' : `LIVE · ${live.rate}/min`) : 'OFFLINE'}
    </span>
  );
}
