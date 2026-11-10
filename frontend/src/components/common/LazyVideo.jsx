import React, { useEffect, useRef, useState } from 'react';

/**
 * Muted, looping background video that only downloads once it nears the viewport,
 * pauses when off-screen, and degrades to its poster/background if playback fails.
 */
export default function LazyVideo({ src, poster, style, className, eager = false, label }) {
  const ref = useRef(null);
  const [active, setActive] = useState(eager);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    const node = ref.current;
    if (!node || typeof IntersectionObserver === 'undefined') {
      setActive(true);
      return undefined;
    }
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setActive(true);
          const playback = node.play?.();
          if (playback && typeof playback.catch === 'function') playback.catch(() => {});
        } else if (!node.paused) {
          node.pause();
        }
      },
      { rootMargin: '300px 0px' }
    );
    observer.observe(node);
    return () => observer.disconnect();
  }, []);

  return (
    <video
      ref={ref}
      className={className}
      src={active && !failed ? src : undefined}
      poster={poster}
      autoPlay
      loop
      muted
      playsInline
      preload={eager ? 'auto' : 'none'}
      aria-label={label}
      onError={() => setFailed(true)}
      style={{ width: '100%', height: '100%', objectFit: 'cover', display: 'block', background: '#0a0a0c', ...style }}
    />
  );
}
