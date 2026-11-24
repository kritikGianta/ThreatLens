import React, { useId } from 'react';

/** ThreatLens brand mark: a lens with a targeting reticle. */
export function LogoMark({ size = 28, title = 'ThreatLens' }) {
  const id = useId().replace(/:/g, '');
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" role="img" aria-label={title} style={{ flexShrink: 0, display: 'block' }}>
      <defs>
        <linearGradient id={`tl-${id}`} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#FBBF24" />
          <stop offset="1" stopColor="#D97706" />
        </linearGradient>
      </defs>
      <rect width="32" height="32" rx="8" fill="#14110E" />
      <circle cx="14" cy="14" r="7.4" fill="none" stroke={`url(#tl-${id})`} strokeWidth="2.6" />
      <path d="M19.6 19.6 25 25" stroke={`url(#tl-${id})`} strokeWidth="3.2" strokeLinecap="round" />
      <path d="M14 8.3v2.2M14 17.5v2.2M8.3 14h2.2M17.5 14h2.2" stroke="#FDE68A" strokeWidth="1.3" strokeLinecap="round" />
      <circle cx="14" cy="14" r="2.1" fill="#FDE68A" />
    </svg>
  );
}

/** Mark + wordmark. `tone` controls the wordmark colour for light or dark backgrounds. */
export default function Logo({ size = 28, tone = 'light', showText = true, style, onClick }) {
  const color = tone === 'dark' ? '#111111' : '#F5F0E8';
  return (
    <span
      onClick={onClick}
      style={{ display: 'inline-flex', alignItems: 'center', gap: Math.round(size * 0.36), cursor: onClick ? 'pointer' : 'default', ...style }}
    >
      <LogoMark size={size} />
      {showText && (
        <span style={{ fontFamily: 'Inter, system-ui, sans-serif', fontWeight: 800, fontSize: Math.round(size * 0.68), letterSpacing: '-0.03em', color, lineHeight: 1 }}>
          Threat<span style={{ color: '#F59E0B' }}>Lens</span>
        </span>
      )}
    </span>
  );
}
