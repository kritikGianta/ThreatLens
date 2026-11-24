import React, { useRef, useState, useEffect } from 'react';
import { Box, Typography, Button } from '@mui/material';
import { motion, useScroll, useTransform, useSpring, AnimatePresence } from 'framer-motion';
import { useNavigate } from 'react-router-dom';

const fontSans = '"Inter", "-apple-system", sans-serif';



const CyberThreatGlobeComponent = () => {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let width = (canvas.width = canvas.parentElement.clientWidth || 500);
    let height = (canvas.height = canvas.parentElement.clientHeight || 500);

    const handleResize = () => {
      if (!canvas.parentElement) return;
      width = canvas.width = canvas.parentElement.clientWidth;
      height = canvas.height = canvas.parentElement.clientHeight;
    };
    window.addEventListener('resize', handleResize);

    const numDots = 320;
    const radius = Math.min(width, height) * 0.38;
    const dots = [];
    const phiSpan = Math.PI * (3 - Math.sqrt(5));

    for (let i = 0; i < numDots; i++) {
      const y = 1 - (i / (numDots - 1)) * 2;
      const radiusAtY = Math.sqrt(1 - y * y);
      const theta = phiSpan * i;
      const x = Math.cos(theta) * radiusAtY;
      const z = Math.sin(theta) * radiusAtY;
      const isThreat = i % 14 === 0;
      dots.push({ x, y, z, isThreat, size: isThreat ? 2.8 : 1.2 });
    }

    let angleY = 0;
    let angleX = 0.25;
    let rafId;

    const render = () => {
      ctx.clearRect(0, 0, width, height);
      const cx = width / 2;
      const cy = height / 2;

      angleY += 0.004;

      const projected = [];
      const cosY = Math.cos(angleY), sinY = Math.sin(angleY);
      const cosX = Math.cos(angleX), sinX = Math.sin(angleX);

      for (let i = 0; i < dots.length; i++) {
        let { x, y, z, isThreat, size } = dots[i];

        let x1 = x * cosY - z * sinY;
        let z1 = z * cosY + x * sinY;

        let y2 = y * cosX - z1 * sinX;
        let z2 = z1 * cosX + y * sinX;

        const fov = 350;
        const scale = fov / (fov + z2 * radius + radius * 1.5);
        const px = cx + x1 * radius * scale;
        const py = cy + y2 * radius * scale;

        projected.push({ px, py, z: z2, isThreat, size, scale });
      }

      projected.sort((a, b) => b.z - a.z);

      for (let i = 0; i < projected.length; i++) {
        if (projected[i].z < 0.1) {
          for (let j = i + 1; j < projected.length; j++) {
            if (projected[j].z < 0.1) {
              const dx = projected[i].px - projected[j].px;
              const dy = projected[i].py - projected[j].py;
              const dist = Math.sqrt(dx * dx + dy * dy);
              if (dist < radius * 0.45) {
                const alpha = (1 - dist / (radius * 0.45)) * 0.35 * ((projected[i].isThreat || projected[j].isThreat) ? 0.8 : 0.25);
                ctx.beginPath();
                ctx.moveTo(projected[i].px, projected[i].py);
                ctx.lineTo(projected[j].px, projected[j].py);
                ctx.strokeStyle = (projected[i].isThreat || projected[j].isThreat)
                  ? `rgba(255, 107, 53, ${alpha})`
                  : `rgba(255, 255, 255, ${alpha * 0.5})`;
                ctx.lineWidth = 0.8;
                ctx.stroke();
              }
            }
          }
        }
      }

      for (let i = 0; i < projected.length; i++) {
        const p = projected[i];
        const alpha = Math.max(0.1, (1 - p.z) * 0.5);

        ctx.beginPath();
        ctx.arc(p.px, p.py, p.size * p.scale, 0, Math.PI * 2);
        if (p.isThreat) {
          ctx.fillStyle = `rgba(255, 107, 53, ${alpha * 1.5})`;
          ctx.shadowColor = '#FF6B35';
          ctx.shadowBlur = 10;
          ctx.fill();
          ctx.shadowBlur = 0;
        } else {
          ctx.fillStyle = `rgba(255, 255, 255, ${alpha * 0.8})`;
          ctx.fill();
        }
      }

      rafId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(rafId);
      window.removeEventListener('resize', handleResize);
    };
  }, []);

  return (
    <Box sx={{ width: '100%', height: '100%', position: 'relative', overflow: 'hidden', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      {/* Blurry Background Typography Behind the Globe */}
      <Box
        sx={{
          position: 'absolute',
          top: '50%',
          left: '50%',
          transform: 'translate(-50%, -50%)',
          zIndex: 0,
          textAlign: 'center',
          pointerEvents: 'none',
          width: '100%',
          px: 2,
        }}
      >
        <Typography
          sx={{
            fontFamily: fontSans,
            fontWeight: 900,
            fontSize: { xs: '2.5rem', sm: '3.8rem', md: '5rem' },
            color: 'rgba(255, 255, 255, 0.08)',
            filter: 'blur(3px)',
            letterSpacing: '-0.02em',
            lineHeight: 1.1,
            textTransform: 'uppercase',
            mb: 1,
          }}
        >
          2,244 ATTACKS / DAY
        </Typography>
        <Typography
          sx={{
            fontFamily: 'monospace',
            fontWeight: 700,
            fontSize: { xs: '0.9rem', sm: '1.2rem', md: '1.4rem' },
            color: 'rgba(255, 107, 53, 0.22)',
            filter: 'blur(1.5px)',
            letterSpacing: '0.15em',
            mb: 1.5,
          }}
        >
          1 GLOBAL BREACH EVERY 39 SECONDS
        </Typography>
        <Typography
          sx={{
            fontFamily: fontSans,
            fontWeight: 700,
            fontSize: { xs: '1rem', sm: '1.3rem', md: '1.6rem' },
            color: 'rgba(255, 255, 255, 0.06)',
            filter: 'blur(2px)',
            letterSpacing: '0.05em',
          }}
        >
          450,000+ NEW MALWARE SIGNATURES IDENTIFIED DAILY
        </Typography>
      </Box>

      <canvas ref={canvasRef} style={{ width: '100%', height: '100%', display: 'block', position: 'relative', zIndex: 1 }} />


    </Box>
  );
};

const MinimalistHero = () => {

  return (
    <Box sx={{
      position: 'relative', width: '100%', height: '100%', minHeight: '100vh',
      background: 'linear-gradient(to bottom, #000000 0%, #000000 40%, #2A1F18 100%)',
      color: '#F7F5F0', overflow: 'hidden',
      display: 'grid',
      gridTemplateColumns: { xs: '100%', md: '55% 45%' },
      alignItems: 'stretch',
    }}>

      {/* Left Column: Complete Editorial Hierarchy Stack */}
      <Box sx={{
        position: 'relative',
        p: { xs: 4, md: 8 },
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        zIndex: 10,
        borderRight: { md: '1px solid rgba(255,255,255,0.08)' }
      }}>
        {/* Faint rotating geometric wireframe in background */}
        <Box sx={{ position: 'absolute', top: '15%', right: '10%', opacity: 0.04, pointerEvents: 'none' }}>
          <motion.svg width="340" height="340" viewBox="0 0 100 100" animate={{ rotate: 360 }} transition={{ duration: 60, repeat: Infinity, ease: 'linear' }}>
            <polygon points="50,5 95,27 95,72 50,95 5,72 5,27" fill="none" stroke="#fff" strokeWidth="0.5" />
            <polygon points="50,15 85,32 85,67 50,85 15,67 15,32" fill="none" stroke="#fff" strokeWidth="0.5" />
            <circle cx="50" cy="50" r="20" fill="none" stroke="#fff" strokeWidth="0.5" />
          </motion.svg>
        </Box>

        {/* Top: Massive Headline */}
        <Box sx={{ pt: { xs: 4, md: 6 } }}>
          <Typography sx={{
            position: 'relative', zIndex: 10,
            fontFamily: '"Outfit", "Inter", sans-serif',
            fontWeight: 800,
            fontSize: { xs: '3.2rem', md: '5.5rem', lg: '7.2rem' },
            lineHeight: 0.95,
            letterSpacing: '-0.04em',
            color: '#fff',
            mb: 4
          }}>
            Autonomous threat<br />intelligence.
          </Typography>
        </Box>

        {/* Bottom: Subtitle, Quote & CTA */}
        <Box sx={{ pb: { xs: 2, md: 4 }, mt: { xs: 6, md: 8 } }}>
          <Typography sx={{ fontSize: { xs: '1rem', md: '1.15rem' }, opacity: 0.85, lineHeight: 1.65, mb: 6, fontFamily: fontSans, maxWidth: '580px' }}>
            ThreatLens is above all the convergence of autonomous AI and human expertise, driven by the desire to capture, analyze, and neutralize threats with singular precision in real-time.
          </Typography>

          <Box sx={{ display: 'flex', flexDirection: { xs: 'column', sm: 'row' }, alignItems: { xs: 'flex-start', sm: 'center' }, justifyContent: 'space-between', gap: 4, pt: 4, borderTop: '1px solid rgba(255,255,255,0.1)' }}>
            <Box sx={{ maxWidth: '360px' }}>
              <Typography sx={{ fontSize: { xs: '0.85rem', md: '0.95rem' }, lineHeight: 1.6, opacity: 0.9, fontFamily: fontSans, fontStyle: 'italic', mb: 1 }}>
                "Defenders think in lists. Attackers think in graphs. As long as this is true, attackers win."
              </Typography>
              <Typography sx={{ fontSize: '0.75rem', opacity: 0.5, fontFamily: fontSans, fontWeight: 700, letterSpacing: '0.08em' }}>
                — JOHN LAMBERT
              </Typography>
            </Box>

            <Box sx={{
              display: 'inline-flex', alignItems: 'center',
              position: 'relative',
              cursor: 'pointer',
              bgcolor: 'rgba(255,255,255,0.05)',
              px: 3.5, py: 1.8,
              transition: 'all 0.3s ease',
              '&:hover': { bgcolor: 'rgba(255,255,255,0.12)', transform: 'translateY(-2px)' }
            }}>
              {/* Corner brackets */}
              <Box sx={{ position: 'absolute', top: 0, left: 0, width: 8, height: 8, borderTop: '1px solid #fff', borderLeft: '1px solid #fff' }} />
              <Box sx={{ position: 'absolute', top: 0, right: 0, width: 8, height: 8, borderTop: '1px solid #fff', borderRight: '1px solid #fff' }} />
              <Box sx={{ position: 'absolute', bottom: 0, left: 0, width: 8, height: 8, borderBottom: '1px solid #fff', borderLeft: '1px solid #fff' }} />
              <Box sx={{ position: 'absolute', bottom: 0, right: 0, width: 8, height: 8, borderBottom: '1px solid #fff', borderRight: '1px solid #fff' }} />

              <Typography sx={{ fontSize: '0.85rem', fontWeight: 600, letterSpacing: '0.05em', textTransform: 'uppercase' }}>
                Explore Platform →
              </Typography>
            </Box>
          </Box>
        </Box>
      </Box>

      {/* Right Column: Centered 3D Cyber Threat Globe with Blurry Stats Behind It */}
      <Box sx={{
        position: 'relative',
        p: 0,
        overflow: 'hidden',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        minHeight: { xs: '500px', md: '100vh' }
      }}>
        <CyberThreatGlobeComponent />
      </Box>

    </Box>
  );
};

// --- 3D Carousel Ring Hero Effect ---
const Carousel3DHero = ({ transparent = false }) => {
  const containerRef = useRef(null);

  // Smooth mouse tracking springs
  const mouseX = useSpring(0, { stiffness: 60, damping: 20, mass: 1 });
  const mouseY = useSpring(0, { stiffness: 60, damping: 20, mass: 1 });

  const handleMouseMove = (e) => {
    if (!containerRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    const x = (e.clientX - rect.left) / rect.width * 2 - 1;
    const y = (e.clientY - rect.top) / rect.height * 2 - 1;
    mouseX.set(x);
    mouseY.set(y);
  };

  const handleMouseLeave = () => {
    mouseX.set(0);
    mouseY.set(0);
  };

  // FIX: Reduced the rotation speed by 50% so it's much smoother and easier to track.
  // Mapping to [-180, 180] means a full screen swipe rotates it half a turn.
  const ringRotateY = useTransform(mouseX, [-1, 1], [-180, 180]);
  const ringRotateX = useTransform(mouseY, [-1, 1], [10, -10]);

  const carouselFeatures = [
    {
      title: "SOC Copilot",
      desc: "Ask questions in plain English; answers are grounded in your live incident data.",
      color: "#FF6B35",
      tags: ["GenAI", "RAG"],
      stats: "Per-user memory",
      list: ["Database-grounded answers", "Multi-turn investigations", "Works without an LLM key"]
    },
    {
      title: "Automated Response",
      desc: "SOAR rules escalate cases, block attacker IPs and alert the team the moment a case opens.",
      color: "#D3A376",
      tags: ["SOAR", "Playbooks"],
      stats: "Sub-second response",
      list: ["Auto-block attacker IPs", "Slack, Teams & e-mail alerts", "Firewall-ready blocklist export"]
    },
    {
      title: "Live Threat Map",
      desc: "Real attacker IPs from your incidents, geolocated and drawn as they hit your network.",
      color: "#8E9C7E",
      tags: ["Geo-IP", "Real-time"],
      stats: "Streamed live",
      list: ["Attack arcs to HQ", "Top source countries", "Blocked vs. active attackers"]
    },
    {
      title: "Campaign Correlation",
      desc: "Links events from the same attacker across days and recognises 15 known attack chains.",
      color: "#A8B0A5",
      tags: ["Kill chain", "Correlation"],
      stats: "No time-out",
      list: ["Slow brute force", "Distributed password spraying", "Full kill-chain view"]
    },
    {
      title: "MITRE ATT&CK Mapping",
      desc: "Every detection mapped to ATT&CK, with a live heatmap of what is detectable and what was seen.",
      color: "#FF6B35",
      tags: ["MITRE", "Coverage"],
      stats: "706 techniques",
      list: ["Technique explorer", "Coverage heatmap", "Observed incidents per technique"]
    },
    {
      title: "Audit & Reporting",
      desc: "Every analyst and automation action is recorded; incident and executive reports on demand.",
      color: "#D3A376",
      tags: ["Audit", "RBAC"],
      stats: "Every action logged",
      list: ["Role-based access", "Incident reports", "Executive KPIs"]
    },
    {
      title: "Threat Intelligence",
      desc: "CISA KEV, abuse.ch and IPsum feeds refreshed hourly and checked against every log.",
      color: "#8E9C7E",
      tags: ["OSINT", "IOC"],
      stats: "5 live feeds",
      list: ["Known-exploited CVEs", "Botnet C2 servers", "Multi-blocklist IPs"]
    },
    {
      title: "Attack Lab",
      desc: "A real victim server and attacker toolkit in Docker: run nmap, sqlmap and hydra and watch it respond.",
      color: "#A8B0A5",
      tags: ["Docker", "Real tools"],
      stats: "Real logs",
      list: ["SSH brute force", "SQL injection", "Post-exploitation"]
    },
  ];

  const numCards = carouselFeatures.length;
  // Reverted back to the original size and radius so they fit perfectly in the section bounds
  const radius = 600;

  const CarouselCardWidget = ({ data }) => (
    <Box sx={{
      width: '100%', height: '100%',
      // Cut-corner sci-fi architectural monolith instead of standard rounded cards
      bgcolor: 'rgba(18, 18, 18, 0.85)',
      backdropFilter: 'blur(16px)',
      border: '1px solid rgba(255, 255, 255, 0.12)',
      borderRadius: '0px', // Zero border radius for sharp architectural geometry
      clipPath: 'polygon(0 0, calc(100% - 24px) 0, 100% 24px, 100% 100%, 24px 100%, 0 calc(100% - 24px))',
      padding: '28px',
      display: 'flex', flexDirection: 'column',
      boxShadow: '0 20px 40px rgba(0,0,0,0.5)',
      color: '#fff',
      position: 'relative',
      overflow: 'hidden'
    }}>
      {/* Top / Bottom Corner Brackets */}
      <Box sx={{ position: 'absolute', top: 0, left: 0, width: 16, height: 16, borderTop: `2px solid ${data.color}`, borderLeft: `2px solid ${data.color}` }} />
      <Box sx={{ position: 'absolute', bottom: 0, right: 0, width: 16, height: 16, borderBottom: `2px solid ${data.color}`, borderRight: `2px solid ${data.color}` }} />

      <Box sx={{ position: 'relative', zIndex: 1, display: 'flex', flexDirection: 'column', height: '100%' }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', pb: 2, mb: 2, borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Box sx={{ width: 8, height: 8, bgcolor: data.color }} />
            <Typography sx={{ fontFamily: 'monospace', fontSize: '0.65rem', color: '#888', letterSpacing: '0.15em' }}>
              {"// HUD-MONOLITH"}
            </Typography>
          </Box>
          <Typography sx={{ fontFamily: 'monospace', color: data.color, fontSize: '0.7rem', fontWeight: 700, bgcolor: 'rgba(255,255,255,0.06)', px: 1, py: 0.4 }}>
            {data.stats}
          </Typography>
        </Box>

        <Typography sx={{ fontFamily: fontSans, fontWeight: 800, fontSize: '1.45rem', mb: 1, lineHeight: 1.1, letterSpacing: '-0.02em', color: '#fff' }}>
          {data.title}
        </Typography>
        <Typography sx={{ fontFamily: fontSans, fontWeight: 400, fontSize: '0.82rem', color: '#AAAAAA', lineHeight: 1.5, mb: 3 }}>
          {data.desc}
        </Typography>

        <Box sx={{ display: 'flex', gap: 1, mb: 3, flexWrap: 'wrap' }}>
          {data.tags.map(tag => (
            <Box key={tag} sx={{ px: 1.2, py: 0.4, border: '1px solid rgba(255,255,255,0.15)', fontSize: '0.62rem', color: '#CCCCCC', fontFamily: 'monospace', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              [{tag}]
            </Box>
          ))}
        </Box>

        <Box sx={{ mt: 'auto', pt: 2, borderTop: '1px dashed rgba(255,255,255,0.08)' }}>
          {data.list.map((item, i) => (
            <Box key={i} sx={{ display: 'flex', alignItems: 'center', gap: 1.2, mb: 1 }}>
              <Typography sx={{ fontFamily: 'monospace', fontSize: '0.65rem', color: data.color, fontWeight: 700 }}>►</Typography>
              <Typography sx={{ fontSize: '0.75rem', color: '#DDDDDD', fontFamily: fontSans }}>{item}</Typography>
            </Box>
          ))}
        </Box>
      </Box>
    </Box>
  );

  return (
    <Box
      ref={containerRef}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      sx={{
        position: 'relative', width: '100%', height: '100%',
        display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center',
        perspective: '1500px',
        overflow: 'hidden',
        bgcolor: transparent ? 'transparent' : '#0B0F14',
        background: transparent ? 'transparent' : 'radial-gradient(circle at 0% 0%, rgba(255,120,40,0.04) 0%, transparent 65%), radial-gradient(circle at 100% 100%, rgba(255,160,70,0.03) 0%, transparent 65%), linear-gradient(180deg, #0B0F14 0%, #1E2633 70%, #1E2633 100%)'
      }}
    >
      {/* 3. Minimalist Registration Crosshairs */}
      <Box sx={{ position: 'absolute', top: '12%', left: '10%', zIndex: 5, pointerEvents: 'none', opacity: 0.2, fontFamily: 'monospace', color: '#fff', fontSize: '1.2rem' }}>
        +
      </Box>
      <Box sx={{ position: 'absolute', top: '12%', right: '10%', zIndex: 5, pointerEvents: 'none', opacity: 0.2, fontFamily: 'monospace', color: '#fff', fontSize: '1.2rem' }}>
        +
      </Box>
      <Box sx={{ position: 'absolute', bottom: '15%', left: '10%', zIndex: 5, pointerEvents: 'none', opacity: 0.2, fontFamily: 'monospace', color: '#fff', fontSize: '1.2rem' }}>
        +
      </Box>
      <Box sx={{ position: 'absolute', bottom: '15%', right: '10%', zIndex: 5, pointerEvents: 'none', opacity: 0.2, fontFamily: 'monospace', color: '#fff', fontSize: '1.2rem' }}>
        +
      </Box>

      {/* Top Left Ecosystem Badge */}
      <Box sx={{ position: 'absolute', top: { xs: '5%', md: '8%' }, left: { xs: '5%', md: '8%' }, zIndex: 20 }}>
        <Typography sx={{ color: '#fff', fontFamily: 'monospace', fontWeight: 600, fontSize: '0.85rem', letterSpacing: '0.2em', opacity: 0.4 }}>
          {"// THREATLENS ECOSYSTEM"}
        </Typography>
      </Box>

      {/* Interactive 3D Carousel Ring */}
      <motion.div
        style={{
          position: 'absolute',
          width: '100%', height: '100%',
          transformStyle: 'preserve-3d',
          zIndex: 10,
          rotateX: ringRotateX,
          rotateY: ringRotateY
        }}
      >
        {carouselFeatures.map((feat, i) => {
          const angle = (360 / numCards) * i;
          return (
            <Box
              key={i}
              sx={{
                position: 'absolute',
                top: '50%', left: '50%',
                width: '320px', height: '420px',
                marginLeft: '-160px', marginTop: '-210px',
                transform: `rotateY(${angle}deg) translateZ(${radius}px)`
              }}
            >
              <CarouselCardWidget data={feat} />
            </Box>
          );
        })}
      </motion.div>
    </Box>
  );
};

// --- UI Widgets for Scrolling Sections ---
const IngestionUI = () => (
  <Box sx={{ width: '100%', maxWidth: '640px', minHeight: '420px', height: 'auto', bgcolor: '#F9F8F6', borderRadius: '20px', border: '2px solid #1A1A1A', p: { xs: 2, sm: 3 }, display: 'flex', flexDirection: 'column', overflow: 'hidden', position: 'relative', fontFamily: fontSans, boxShadow: '8px 8px 0px rgba(26,26,26,0.1)' }}>
    {/* Header Bar */}
    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2, pb: 1.5, borderBottom: '2px solid #1A1A1A', flexShrink: 0, flexWrap: 'wrap', gap: 1 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
        <Box sx={{ display: 'flex', gap: 0.8 }}>
          <Box sx={{ width: 10, height: 10, borderRadius: '50%', bgcolor: '#E25C5C', border: '1px solid #111' }} />
          <Box sx={{ width: 10, height: 10, borderRadius: '50%', bgcolor: '#F1C40F', border: '1px solid #111' }} />
          <Box sx={{ width: 10, height: 10, borderRadius: '50%', bgcolor: '#2ECC71', border: '1px solid #111' }} />
        </Box>
        <Typography sx={{ ml: 1, fontSize: { xs: '0.7rem', sm: '0.8rem' }, fontWeight: 700, color: '#1A1A1A', letterSpacing: '0.05em' }}>
          INGESTION PIPELINE // DAEMON v4.2
        </Typography>
      </Box>
      <Box sx={{ display: 'flex', gap: 1.5, alignItems: 'center' }}>
        <Box sx={{ px: 1.5, py: 0.4, bgcolor: '#1A1A1A', color: '#2ECC71', borderRadius: '4px', fontSize: '0.65rem', fontFamily: 'monospace', fontWeight: 700 }}>
          ● LIVE STREAM
        </Box>
        <Box sx={{ px: 1.2, py: 0.4, bgcolor: '#E8D96B', color: '#1A1A1A', border: '1px solid #1A1A1A', borderRadius: '4px', fontSize: '0.65rem', fontFamily: 'monospace', fontWeight: 700 }}>
          GROQ LLM ACTIVE
        </Box>
      </Box>
    </Box>

    <Box sx={{ flex: 1, minHeight: 0, display: 'grid', gridTemplateColumns: { xs: '1fr', sm: '1.25fr 1fr' }, gap: 2.5 }}>
      {/* Left Column: Live Stream & Pipeline Stats */}
      <Box sx={{ height: '100%', minHeight: 0, display: 'flex', flexDirection: 'column', bgcolor: '#111', borderRadius: '12px', p: 1.8, border: '1.5px solid #1A1A1A', overflow: 'hidden', position: 'relative' }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1, pb: 0.8, borderBottom: '1px solid rgba(255,255,255,0.15)', flexShrink: 0 }}>
          <Typography sx={{ fontFamily: 'monospace', color: '#E8D96B', fontSize: '0.65rem', fontWeight: 700 }}>RAW_LOG_STREAM [SYS_01]</Typography>
          <Typography sx={{ fontFamily: 'monospace', color: '#2ECC71', fontSize: '0.65rem' }}>0.4ms avg</Typography>
        </Box>

        <Box sx={{ flex: 1, overflow: 'hidden', position: 'relative' }}>
          <motion.div animate={{ y: ['0%', '-50%'] }} transition={{ duration: 14, repeat: Infinity, ease: 'linear' }}>
            {[
              { time: '04:49:12', ip: '192.168.1.104', proto: 'SSH', status: 'FAILED_AUTH', color: '#E25C5C' },
              { time: '04:49:13', ip: '10.0.4.22', proto: 'HTTPS', status: 'OK_200', color: '#2ECC71' },
              { time: '04:49:14', ip: '185.220.101.5', proto: 'DNS', status: 'TXT_QUERY', color: '#F1C40F' },
              { time: '04:49:15', ip: '192.168.1.104', proto: 'SSH', status: 'ROOT_LOGIN', color: '#E25C5C' },
              { time: '04:49:16', ip: '172.16.0.8', proto: 'SMB', status: 'PIPE_ACCESS', color: '#F1C40F' },
              { time: '04:49:17', ip: '91.108.4.232', proto: 'TCP', status: 'SYN_FLOOD', color: '#E25C5C' },
              { time: '04:49:18', ip: '10.0.0.1', proto: 'HTTPS', status: 'POST_PAYLOAD', color: '#2ECC71' },
              { time: '04:49:19', ip: '192.168.1.104', proto: 'SSH', status: 'EXFIL_START', color: '#E25C5C' },
            ].concat([
              { time: '04:49:20', ip: '192.168.1.104', proto: 'SSH', status: 'FAILED_AUTH', color: '#E25C5C' },
              { time: '04:49:21', ip: '10.0.4.22', proto: 'HTTPS', status: 'OK_200', color: '#2ECC71' },
              { time: '04:49:22', ip: '185.220.101.5', proto: 'DNS', status: 'TXT_QUERY', color: '#F1C40F' },
              { time: '04:49:23', ip: '192.168.1.104', proto: 'SSH', status: 'ROOT_LOGIN', color: '#E25C5C' },
              { time: '04:49:24', ip: '172.16.0.8', proto: 'SMB', status: 'PIPE_ACCESS', color: '#F1C40F' },
              { time: '04:49:25', ip: '91.108.4.232', proto: 'TCP', status: 'SYN_FLOOD', color: '#E25C5C' },
              { time: '04:49:26', ip: '10.0.0.1', proto: 'HTTPS', status: 'POST_PAYLOAD', color: '#2ECC71' },
              { time: '04:49:27', ip: '192.168.1.104', proto: 'SSH', status: 'EXFIL_START', color: '#E25C5C' },
            ]).map((log, i) => (
              <Box key={i} sx={{ mb: 1, fontFamily: 'monospace', fontSize: '0.64rem', lineHeight: 1.3 }}>
                <span style={{ color: 'rgba(255,255,255,0.4)' }}>[{log.time}]</span>{' '}
                <span style={{ color: '#fff', fontWeight: 600 }}>{log.ip}</span>{' '}
                <span style={{ color: '#7BA4B8', backgroundColor: 'rgba(123,164,184,0.18)', padding: '1px 4px', borderRadius: '3px' }}>{log.proto}</span>{' '}
                <span style={{ color: log.color, fontWeight: 700 }}>{log.status}</span>
              </Box>
            ))}
          </motion.div>
        </Box>
      </Box>

      {/* Right Column: Normalized Threat Schema & Classification */}
      <Box sx={{ height: '100%', minHeight: 0, display: 'flex', flexDirection: 'column', justifyContent: 'space-between', bgcolor: '#fff', borderRadius: '12px', p: 1.8, border: '1.5px solid #1A1A1A', overflow: 'hidden' }}>
        <Box>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1.2 }}>
            <Typography sx={{ fontWeight: 800, fontSize: '0.68rem', color: '#1A1A1A', letterSpacing: '0.08em' }}>NORMALIZED SCHEMA</Typography>
            <Box sx={{ bgcolor: '#E25C5C', color: '#fff', px: 1, py: 0.2, borderRadius: '4px', fontSize: '0.6rem', fontWeight: 800, fontFamily: 'monospace' }}>SEV 98</Box>
          </Box>

          <Box sx={{ bgcolor: '#F9F8F6', p: 1.2, borderRadius: '8px', border: '1px solid #E5E0D8', mb: 1, fontFamily: 'monospace', fontSize: '0.64rem' }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.6 }}>
              <span style={{ color: '#666' }}>Tactic:</span>
              <span style={{ fontWeight: 700, color: '#111' }}>Brute Force → C2</span>
            </Box>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.6 }}>
              <span style={{ color: '#666' }}>MITRE:</span>
              <span style={{ fontWeight: 700, color: '#D35400' }}>T1110.001</span>
            </Box>
            <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: '#666' }}>Parser:</span>
              <span style={{ fontWeight: 700, color: '#27AE60' }}>Groq-Llama3-70B</span>
            </Box>
          </Box>
        </Box>

        {/* Live Ingestion Velocity Histogram */}
        <Box sx={{ mt: 'auto' }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 0.6 }}>
            <Typography sx={{ fontSize: '0.6rem', fontWeight: 700, color: '#666', fontFamily: 'monospace' }}>BURST VELOCITY</Typography>
            <Typography sx={{ fontSize: '0.6rem', fontWeight: 700, color: '#E25C5C', fontFamily: 'monospace' }}>+340% SPIKE</Typography>
          </Box>
          <Box sx={{ display: 'flex', alignItems: 'flex-end', gap: 0.8, height: '50px', pt: 0.5, borderBottom: '1.5px solid #1A1A1A' }}>
            {[35, 45, 30, 40, 55, 60, 50, 95, 100].map((h, i) => (
              <motion.div key={i}
                animate={{ height: [`${h}%`, `${Math.min(100, Math.max(20, h + (Math.random() * 30 - 15)))}%`, `${h}%`] }}
                transition={{ duration: 1.8 + i * 0.1, repeat: Infinity }}
                style={{ flex: 1, backgroundColor: i >= 7 ? '#E25C5C' : '#1A1A1A', borderRadius: '3px 3px 0 0', opacity: i >= 7 ? 1 : 0.85 }}
              />
            ))}
          </Box>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 0.4, fontFamily: 'monospace', fontSize: '0.52rem', color: '#888' }}>
            <span>-60s</span>
            <span>-30s</span>
            <span>NOW</span>
          </Box>
        </Box>
      </Box>
    </Box>
  </Box>
);

const DetectionUI = () => (
  <Box sx={{ width: '100%', maxWidth: '640px', minHeight: '420px', height: 'auto', bgcolor: '#F9F8F6', borderRadius: '20px', border: '2px solid #1A1A1A', p: { xs: 2, sm: 3 }, display: 'flex', flexDirection: 'column', overflow: 'hidden', position: 'relative', fontFamily: fontSans, boxShadow: '8px 8px 0px rgba(26,26,26,0.1)' }}>
    {/* Header Bar */}
    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2, pb: 1.5, borderBottom: '2px solid #1A1A1A', flexShrink: 0, flexWrap: 'wrap', gap: 1 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
        <Box sx={{ px: 1.2, py: 0.3, bgcolor: '#E25C5C', color: '#fff', borderRadius: '4px', fontSize: '0.65rem', fontWeight: 800, fontFamily: 'monospace' }}>
          META-ALERT FIRED
        </Box>
        <Typography sx={{ fontSize: { xs: '0.7rem', sm: '0.8rem' }, fontWeight: 700, color: '#1A1A1A', letterSpacing: '0.05em' }}>
          COMPOUND HEURISTIC CORRELATION
        </Typography>
      </Box>
      <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
        <Typography sx={{ fontSize: '0.68rem', fontFamily: 'monospace', fontWeight: 700, color: '#666' }}>
          11 RULES ACTIVE //
        </Typography>
        <Typography sx={{ fontSize: '0.68rem', fontFamily: 'monospace', fontWeight: 800, color: '#E25C5C' }}>
          3 VIOLATIONS DETECTED
        </Typography>
      </Box>
    </Box>

    <Box sx={{ flex: 1, minHeight: 0, display: 'grid', gridTemplateColumns: { xs: '1fr', sm: '1.25fr 1fr' }, gap: 2.5 }}>
      {/* Left Panel: Live Lateral Movement Attack Graph */}
      <Box sx={{ height: '100%', minHeight: 0, display: 'flex', flexDirection: 'column', bgcolor: '#111', borderRadius: '12px', p: 1.8, border: '1.5px solid #1A1A1A', position: 'relative', overflow: 'hidden', justifyContent: 'space-between' }}>
        {/* Background Grid */}
        <Box sx={{ position: 'absolute', inset: 0, backgroundImage: 'radial-gradient(rgba(255,255,255,0.15) 1px, transparent 1px)', backgroundSize: '16px 16px', opacity: 0.5 }} />

        <Box sx={{ display: 'flex', justifyContent: 'space-between', position: 'relative', zIndex: 2, flexShrink: 0 }}>
          <Typography sx={{ fontFamily: 'monospace', color: '#888', fontSize: '0.65rem', fontWeight: 700 }}>TOPOLOGY KILL-CHAIN</Typography>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.6 }}>
            <motion.div animate={{ opacity: [1, 0.2, 1] }} transition={{ duration: 1, repeat: Infinity }}>
              <Box sx={{ width: 6, height: 6, borderRadius: '50%', bgcolor: '#E25C5C' }} />
            </motion.div>
            <Typography sx={{ fontFamily: 'monospace', color: '#E25C5C', fontSize: '0.65rem', fontWeight: 700 }}>LIVE TRACKING</Typography>
          </Box>
        </Box>

        {/* Network Nodes Diagram */}
        <Box sx={{ position: 'relative', zIndex: 2, my: 'auto', display: 'flex', flexDirection: 'column', gap: 1.8, px: 0.5 }}>
          {/* Node 1: Compromised Workstation */}
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.2 }}>
            <Box sx={{ width: 32, height: 32, borderRadius: '8px', bgcolor: 'rgba(226,92,92,0.2)', border: '1.5px solid #E25C5C', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.9rem', flexShrink: 0 }}>
              💻
            </Box>
            <Box sx={{ flex: 1 }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                <Typography sx={{ color: '#fff', fontSize: '0.72rem', fontWeight: 700, fontFamily: 'monospace' }}>WS-FINANCE-04</Typography>
                <Typography sx={{ color: '#E25C5C', fontSize: '0.62rem', fontWeight: 700, fontFamily: 'monospace' }}>PATIENT 0</Typography>
              </Box>
              <Typography sx={{ color: '#888', fontSize: '0.6rem', fontFamily: 'monospace' }}>10.0.4.22 • Mimikatz Executed</Typography>
            </Box>
          </Box>

          {/* Connecting Trajectory Vector */}
          <Box sx={{ ml: 2, borderLeft: '2px dashed #E25C5C', pl: 2, py: 0.2, position: 'relative' }}>
            <motion.div animate={{ y: [0, 14, 0] }} transition={{ duration: 1.5, repeat: Infinity }} style={{ position: 'absolute', left: '-5px', top: '2px', width: '8px', height: '8px', borderRadius: '50%', backgroundColor: '#E25C5C' }} />
            <Box sx={{ bgcolor: 'rgba(255,255,255,0.08)', px: 1, py: 0.3, borderRadius: '4px', display: 'inline-block' }}>
              <Typography sx={{ color: '#E8D96B', fontSize: '0.6rem', fontFamily: 'monospace', fontWeight: 700 }}>
                ⚡ LATERAL VECTOR: SMB/Port 445
              </Typography>
            </Box>
          </Box>

          {/* Node 2: Target Domain Controller */}
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.2 }}>
            <Box sx={{ width: 32, height: 32, borderRadius: '8px', bgcolor: 'rgba(241,196,15,0.15)', border: '1.5px solid #F1C40F', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.9rem', flexShrink: 0 }}>
              🏢
            </Box>
            <Box sx={{ flex: 1 }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                <Typography sx={{ color: '#fff', fontSize: '0.72rem', fontWeight: 700, fontFamily: 'monospace' }}>DC-PRIMARY-01</Typography>
                <Typography sx={{ color: '#F1C40F', fontSize: '0.62rem', fontWeight: 700, fontFamily: 'monospace' }}>TARGET</Typography>
              </Box>
              <Typography sx={{ color: '#888', fontSize: '0.6rem', fontFamily: 'monospace' }}>10.0.0.1 • Kerberos TGT Probe</Typography>
            </Box>
          </Box>
        </Box>

        <Typography sx={{ fontFamily: 'monospace', color: '#666', fontSize: '0.6rem', position: 'relative', zIndex: 2, flexShrink: 0 }}>
          GRAPH DEPTH: 3 HOPS • MITRE ID: TA0008
        </Typography>
      </Box>

      {/* Right Panel: Triggered Rules & Merged Incident */}
      <Box sx={{ height: '100%', minHeight: 0, display: 'flex', flexDirection: 'column', justifyContent: 'space-between', bgcolor: '#fff', borderRadius: '12px', p: 1.8, border: '1.5px solid #1A1A1A', overflow: 'hidden' }}>
        <Box>
          <Typography sx={{ fontWeight: 800, fontSize: '0.68rem', color: '#1A1A1A', letterSpacing: '0.08em', mb: 1.2 }}>
            SIMULTANEOUS RULE HITS
          </Typography>

          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
            {[
              { rule: 'SEC-04', title: 'LSASS Memory Dump', score: 'CRITICAL', color: '#E25C5C', bg: 'rgba(226,92,92,0.1)' },
              { rule: 'NET-12', title: 'Anomalous SMB Ticket', score: 'HIGH', color: '#D35400', bg: 'rgba(211,84,0,0.1)' },
              { rule: 'SYS-89', title: 'WMI Remote Spawn', score: 'CRITICAL', color: '#E25C5C', bg: 'rgba(226,92,92,0.1)' },
            ].map((hit, i) => (
              <Box key={i} sx={{ p: 1, borderRadius: '6px', border: '1px solid #E5E0D8', bgcolor: '#F9F8F6' }}>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 0.2 }}>
                  <Typography sx={{ fontSize: '0.62rem', fontFamily: 'monospace', fontWeight: 700, color: '#666' }}>[{hit.rule}]</Typography>
                  <Box sx={{ px: 0.7, py: 0.1, bgcolor: hit.bg, color: hit.color, borderRadius: '3px', fontSize: '0.56rem', fontWeight: 800, fontFamily: 'monospace' }}>{hit.score}</Box>
                </Box>
                <Typography sx={{ fontSize: '0.7rem', fontWeight: 700, color: '#111' }}>{hit.title}</Typography>
              </Box>
            ))}
          </Box>
        </Box>

        {/* Auto-Merged Meta Alert Footer */}
        <Box sx={{ mt: 'auto', p: 1.2, bgcolor: '#1A1A1A', borderRadius: '8px', color: '#fff', flexShrink: 0 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 0.3 }}>
            <Typography sx={{ fontSize: '0.6rem', fontFamily: 'monospace', color: '#E8D96B', fontWeight: 700 }}>AUTO-MERGED ACTION</Typography>
            <Typography sx={{ fontSize: '0.6rem', fontFamily: 'monospace', color: '#2ECC71' }}>SCORE 96/100</Typography>
          </Box>
          <Typography sx={{ fontSize: '0.68rem', fontWeight: 700 }}>
            Combined 3 alerts into INC#8821
          </Typography>
        </Box>
      </Box>
    </Box>
  </Box>
);

const EnrichmentUI = () => (
  <Box sx={{ width: '100%', maxWidth: '640px', minHeight: '420px', height: 'auto', bgcolor: '#F9F8F6', borderRadius: '20px', border: '2px solid #1A1A1A', p: { xs: 2, sm: 3 }, display: 'flex', flexDirection: 'column', overflow: 'hidden', position: 'relative', fontFamily: fontSans, boxShadow: '8px 8px 0px rgba(26,26,26,0.1)' }}>
    {/* Header Bar */}
    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2, pb: 1.5, borderBottom: '2px solid #1A1A1A', flexShrink: 0, flexWrap: 'wrap', gap: 1 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
        <Box sx={{ px: 1.2, py: 0.3, bgcolor: '#8E9C7E', color: '#111', borderRadius: '4px', fontSize: '0.65rem', fontWeight: 800, fontFamily: 'monospace' }}>
          OSINT FEDERATION
        </Box>
        <Typography sx={{ fontSize: { xs: '0.7rem', sm: '0.8rem' }, fontWeight: 700, color: '#1A1A1A', letterSpacing: '0.05em' }}>
          MULTI-SOURCE KNOWLEDGE ENRICHMENT
        </Typography>
      </Box>
      <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
        <Typography sx={{ fontSize: '0.68rem', fontFamily: 'monospace', fontWeight: 700, color: '#666' }}>
          SYNCED FEEDS: 4 //
        </Typography>
        <Typography sx={{ fontSize: '0.68rem', fontFamily: 'monospace', fontWeight: 800, color: '#2ECC71' }}>
          CONFIDENCE 99.9%
        </Typography>
      </Box>
    </Box>

    <Box sx={{ flex: 1, minHeight: 0, display: 'grid', gridTemplateColumns: { xs: '1fr', sm: '1.2fr 1fr' }, gap: 2.5 }}>
      {/* Left Panel: Relational Intelligence Graph */}
      <Box sx={{ height: '100%', minHeight: 0, display: 'flex', flexDirection: 'column', bgcolor: '#111', borderRadius: '12px', p: 1.8, border: '1.5px solid #1A1A1A', position: 'relative', overflow: 'hidden', justifyContent: 'space-between' }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', pb: 0.8, borderBottom: '1px solid rgba(255,255,255,0.15)', flexShrink: 0 }}>
          <Typography sx={{ fontFamily: 'monospace', color: '#8E9C7E', fontSize: '0.65rem', fontWeight: 700 }}>LIVE RELATIONAL LINKING</Typography>
          <Typography sx={{ fontFamily: 'monospace', color: '#2ECC71', fontSize: '0.65rem' }}>SHA256 MATCH</Typography>
        </Box>

        <Box sx={{ my: 'auto', display: 'flex', flexDirection: 'column', gap: 1.5 }}>
          {/* Target Artifact */}
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.2, p: 1, bgcolor: 'rgba(255,255,255,0.05)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.1)' }}>
            <Box sx={{ width: 28, height: 28, borderRadius: '6px', bgcolor: '#8E9C7E', color: '#111', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 800, fontSize: '0.75rem' }}>
              IOC
            </Box>
            <Box>
              <Typography sx={{ color: '#fff', fontSize: '0.7rem', fontWeight: 700, fontFamily: 'monospace' }}>0x8F92A01E...99B2</Typography>
              <Typography sx={{ color: '#888', fontSize: '0.58rem', fontFamily: 'monospace' }}>Payload Binary • Dropped via SMB</Typography>
            </Box>
          </Box>

          {/* Federated Intelligence Feeds */}
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.8, pl: 1.5, borderLeft: '2px solid #8E9C7E' }}>
            {[
              { feed: 'CISA KEV Catalog', status: 'ACTIVE EXPLOIT', color: '#E25C5C' },
              { feed: 'VirusTotal API', status: '64/70 ENGINES', color: '#E25C5C' },
              { feed: 'Abuse.ch Feodo', status: 'C2 BOTNET NODE', color: '#F1C40F' },
            ].map((f, i) => (
              <Box key={i} sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', bgcolor: 'rgba(0,0,0,0.4)', p: 0.8, borderRadius: '6px' }}>
                <Typography sx={{ color: '#ccc', fontSize: '0.62rem', fontWeight: 600 }}>{f.feed}</Typography>
                <Typography sx={{ color: f.color, fontSize: '0.58rem', fontFamily: 'monospace', fontWeight: 800 }}>{f.status}</Typography>
              </Box>
            ))}
          </Box>
        </Box>

        <Typography sx={{ fontFamily: 'monospace', color: '#666', fontSize: '0.6rem', flexShrink: 0 }}>
          TF-IDF RAG · KNOWLEDGE BASE + CISA KEV
        </Typography>
      </Box>

      {/* Right Panel: APT Threat Actor Dossier */}
      <Box sx={{ height: '100%', minHeight: 0, display: 'flex', flexDirection: 'column', justifyContent: 'space-between', bgcolor: '#fff', borderRadius: '12px', p: 1.8, border: '1.5px solid #1A1A1A', overflow: 'hidden' }}>
        <Box>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1.2 }}>
            <Typography sx={{ fontWeight: 800, fontSize: '0.68rem', color: '#1A1A1A', letterSpacing: '0.08em' }}>ACTOR DOSSIER</Typography>
            <Box sx={{ bgcolor: '#1A1A1A', color: '#E8D96B', px: 1, py: 0.2, borderRadius: '4px', fontSize: '0.6rem', fontWeight: 800, fontFamily: 'monospace' }}>APT-29</Box>
          </Box>

          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, mb: 1 }}>
            <Box sx={{ p: 1, bgcolor: '#F9F8F6', borderRadius: '6px', border: '1px solid #E5E0D8' }}>
              <Typography sx={{ fontSize: '0.58rem', color: '#666', textTransform: 'uppercase', fontWeight: 700 }}>Known Alias</Typography>
              <Typography sx={{ fontSize: '0.75rem', fontWeight: 800, color: '#111' }}>Cozy Bear / Midnight Blizzard</Typography>
            </Box>
            <Box sx={{ p: 1, bgcolor: '#F9F8F6', borderRadius: '6px', border: '1px solid #E5E0D8' }}>
              <Typography sx={{ fontSize: '0.58rem', color: '#666', textTransform: 'uppercase', fontWeight: 700 }}>Primary Objective</Typography>
              <Typography sx={{ fontSize: '0.72rem', fontWeight: 700, color: '#111' }}>Espionage • Active Directory Dominance</Typography>
            </Box>
          </Box>
        </Box>

        <Box sx={{ mt: 'auto', p: 1.2, bgcolor: '#8E9C7E', borderRadius: '8px', color: '#111', flexShrink: 0 }}>
          <Typography sx={{ fontSize: '0.6rem', fontFamily: 'monospace', fontWeight: 800 }}>ATT&CK CAMPAIGN STAGE</Typography>
          <Typography sx={{ fontSize: '0.7rem', fontWeight: 800 }}>
            Phase 4: Privilege Escalation
          </Typography>
        </Box>
      </Box>
    </Box>
  </Box>
);

const ResponseUI = () => (
  <Box sx={{ width: '100%', maxWidth: '640px', minHeight: '420px', height: 'auto', bgcolor: '#F9F8F6', borderRadius: '20px', border: '2px solid #1A1A1A', p: { xs: 2, sm: 3 }, display: 'flex', flexDirection: 'column', overflow: 'hidden', position: 'relative', fontFamily: fontSans, boxShadow: '8px 8px 0px rgba(26,26,26,0.1)' }}>
    {/* Header Bar */}
    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2, pb: 1.5, borderBottom: '2px solid #1A1A1A', flexShrink: 0, flexWrap: 'wrap', gap: 1 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
        <Box sx={{ px: 1.2, py: 0.3, bgcolor: '#7BA4B8', color: '#111', borderRadius: '4px', fontSize: '0.65rem', fontWeight: 800, fontFamily: 'monospace' }}>
          SOAR ACTIVE
        </Box>
        <Typography sx={{ fontSize: { xs: '0.7rem', sm: '0.8rem' }, fontWeight: 700, color: '#1A1A1A', letterSpacing: '0.05em' }}>
          REAL-TIME AUTONOMOUS MITIGATION
        </Typography>
      </Box>
      <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
        <Typography sx={{ fontSize: '0.68rem', fontFamily: 'monospace', fontWeight: 700, color: '#666' }}>
          EXEC VELOCITY //
        </Typography>
        <Typography sx={{ fontSize: '0.68rem', fontFamily: 'monospace', fontWeight: 800, color: '#2ECC71' }}>
          45 MILLISECONDS
        </Typography>
      </Box>
    </Box>

    <Box sx={{ flex: 1, minHeight: 0, display: 'grid', gridTemplateColumns: { xs: '1fr', sm: '1.1fr 1.1fr' }, gap: 2.5 }}>
      {/* Left Panel: SOAR Playbook Execution Matrix */}
      <Box sx={{ height: '100%', minHeight: 0, display: 'flex', flexDirection: 'column', justifyContent: 'space-between', bgcolor: '#fff', borderRadius: '12px', p: 1.8, border: '1.5px solid #1A1A1A', overflow: 'hidden' }}>
        <Box>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1.2 }}>
            <Typography sx={{ fontWeight: 800, fontSize: '0.68rem', color: '#1A1A1A', letterSpacing: '0.08em' }}>PLAYBOOK // PB-CONTAIN-09</Typography>
            <Box sx={{ bgcolor: '#2ECC71', color: '#111', px: 0.8, py: 0.1, borderRadius: '3px', fontSize: '0.6rem', fontWeight: 800, fontFamily: 'monospace' }}>SUCCESS</Box>
          </Box>

          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.9 }}>
            {[
              { step: '01', action: 'Escalate case → Investigating', time: 'instant', status: 'COMPLETE' },
              { step: '02', action: 'Add attacker IP to blocklist', time: 'instant', status: 'COMPLETE' },
              { step: '03', action: 'Post alert to Slack webhook', time: 'async', status: 'COMPLETE' },
              { step: '04', action: 'E-mail the on-call analyst', time: 'async', status: 'COMPLETE' },
            ].map((pb, i) => (
              <Box key={i} sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', p: 0.9, bgcolor: '#F9F8F6', borderRadius: '6px', border: '1px solid #E5E0D8' }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flex: 1 }}>
                  <Box sx={{ width: 18, height: 18, borderRadius: '50%', bgcolor: '#1A1A1A', color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.55rem', fontWeight: 800, fontFamily: 'monospace' }}>{pb.step}</Box>
                  <Typography sx={{ fontSize: '0.65rem', fontWeight: 700, color: '#111' }}>{pb.action}</Typography>
                </Box>
                <Typography sx={{ fontSize: '0.58rem', fontFamily: 'monospace', color: '#2ECC71', fontWeight: 800 }}>{pb.time}</Typography>
              </Box>
            ))}
          </Box>
        </Box>

        <Box sx={{ mt: 'auto', p: 1, bgcolor: '#F9F8F6', borderRadius: '6px', border: '1px solid #E5E0D8', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexShrink: 0 }}>
          <Typography sx={{ fontSize: '0.6rem', fontWeight: 700, color: '#666' }}>AUTOMATED IN</Typography>
          <Typography sx={{ fontSize: '0.7rem', fontWeight: 800, color: '#1A1A1A' }}>{'< 1 SECOND'}</Typography>
        </Box>
      </Box>

      {/* Right Panel: Blocklist Gate Terminal */}
      <Box sx={{ height: '100%', minHeight: 0, display: 'flex', flexDirection: 'column', bgcolor: '#111', borderRadius: '12px', p: 1.8, border: '1.5px solid #1A1A1A', position: 'relative', overflow: 'hidden', justifyContent: 'space-between' }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', pb: 0.8, borderBottom: '1px solid rgba(255,255,255,0.15)', flexShrink: 0 }}>
          <Typography sx={{ fontFamily: 'monospace', color: '#7BA4B8', fontSize: '0.65rem', fontWeight: 700 }}>BLOCKLIST GATE</Typography>
          <Typography sx={{ fontFamily: 'monospace', color: '#2ECC71', fontSize: '0.65rem' }}>DAEMON ONLINE</Typography>
        </Box>

        <Box sx={{ my: 'auto', fontFamily: 'monospace', fontSize: '0.64rem', lineHeight: 1.5 }}>
          <Typography sx={{ color: '#888', fontSize: '0.62rem' }}>{">"} executing non-blocking daemon thread...</Typography>
          <Typography sx={{ color: '#2ECC71' }}>[OK] 185.220.101.47 added to blocklist</Typography>
          <Typography sx={{ color: '#2ECC71' }}>[OK] case #412 escalated → Investigating</Typography>
          <Typography sx={{ color: '#F1C40F' }}>[OK] webhook delivered to #soc-alerts</Typography>
          <Typography sx={{ color: '#2ECC71', fontWeight: 700, mt: 0.8 }}>{"> RESPONSE COMPLETE IN < 1s."}</Typography>
        </Box>

        <Box sx={{ p: 1, bgcolor: 'rgba(123,164,184,0.15)', borderRadius: '6px', border: '1px solid rgba(123,164,184,0.3)', flexShrink: 0 }}>
          <Typography sx={{ color: '#7BA4B8', fontSize: '0.6rem', fontFamily: 'monospace', fontWeight: 700 }}>
            🔒 STATUS: ATTACKER BLOCKED
          </Typography>
        </Box>
      </Box>
    </Box>
  </Box>
);

const FeatureWidget = ({ id, category, pillText, pillColor, title, buttonText, uiWidget }) => {
  const navigate = useNavigate();

  const getModalContent = () => {
    if (id === "01") {
      return {
        title: "INGESTION PIPELINE",
        subtitle: "Every source flows through one parse → detect → correlate → respond pipeline.",
        specs: [
          { label: "Log formats", value: "13: Windows Event Log, Linux/SSH, Cisco ASA, Palo Alto, Snort/Suricata, firewall, proxy, AWS CloudTrail, Azure, GCP, web server, DNS, syslog" },
          { label: "Ingestion channels", value: "Authenticated webhook (API key) for log shippers, 1,000-line bulk jobs, Threat Studio, Windows Event Log collector" },
          { label: "Measured latency", value: "Benchmark: p50 9 ms · p95 23 ms per event on PostgreSQL; live values on the Executive View" },
          { label: "Unknown formats", value: "URL-decoding before detection; optional Groq LLM fallback parser" }
        ],
        code: `# Forward logs from any shipper (Filebeat, Fluent Bit, Vector, a script)
curl -X POST https://threatlens.example.com/api/v1/logs/webhook \\
  -H "X-API-Key: $INGEST_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"source": "linux-auth",
       "logs": ["sshd[812]: Failed password for root from 198.51.100.7 port 22 ssh2"]}'
# → {"status": "accepted", "logs_processed": 1, "incidents_created": 0}`,
        actionText: "Launch Live Log Analyzer →",
        actionPath: "/analyze"
      };
    } else if (id === "02") {
      return {
        title: "DETECTION ENGINE",
        subtitle: "MITRE-mapped rules where every match fires, plus campaign correlation across days.",
        specs: [
          { label: "Detection rules", value: "28 rules + 2 correlation detections (slow and distributed brute force)" },
          { label: "Validated on real attacks", value: "93 of 261 public attack recordings (EVTX-ATTACK-SAMPLES) — reproducible script in the repo" },
          { label: "Attack chains", value: "15 multi-stage patterns, e.g. Breach → Credential Theft → Lateral Spread" },
          { label: "Noise reduction", value: "Repeat alerts grouped into cases — measured live on the Executive View" }
        ],
        code: `# A ThreatLens detection rule (services/detector.py)
{
    "name": "Credential Dumping Attempt",
    "check": lambda p, s: bool(RX_CRED_DUMP.search(_raw(p))),
    "impact": 25, "confidence": 0.90,
    "mitre": "T1003", "stage": "Credential Access",
}
# RX_CRED_DUMP matches lsass, mimikatz, procdump, sekurlsa,
# ntds.dit, secretsdump, /etc/shadow … with word boundaries`,
        actionText: "Open Threat Investigator →",
        actionPath: "/investigate"
      };
    } else if (id === "03") {
      return {
        title: "INTEGRATIONS",
        subtitle: "Public threat intelligence, enrichment services and outbound alerting.",
        specs: [
          { label: "Threat-intel feeds", value: "CISA KEV, abuse.ch Feodo Tracker, IPsum (no key) · URLhaus, ThreatFox (free abuse.ch key)" },
          { label: "Enrichment", value: "VirusTotal reputation, NIST NVD CVEs, ip-api / IPinfo / OpenCage geolocation" },
          { label: "AI", value: "Groq-hosted Llama for summaries and the Copilot — optional, with a rule-engine fallback" },
          { label: "Outbound", value: "Slack, Teams or any webhook · SMTP e-mail · firewall-ready blocklist export" }
        ],
        code: `GET /api/v1/system/status
{
  "database": { "engine": "postgresql", "reachable": true },
  "mitre_techniques_loaded": 706,
  "integrations": [
    { "name": "Groq LLM",   "env_var": "GROQ_API_KEY",     "configured": true },
    { "name": "VirusTotal", "env_var": "VT_API_KEY",       "configured": true },
    { "name": "abuse.ch",   "env_var": "ABUSECH_AUTH_KEY", "configured": false }
  ]
}`,
        actionText: "Explore Threat Intel Feeds →",
        actionPath: "/intel"
      };
    } else {
      return {
        title: "SOAR AUTOMATION",
        subtitle: "Rules that act in the same transaction that detected the threat.",
        specs: [
          { label: "Conditions", value: "Severity, minimum severity, threat type, multi-stage campaign" },
          { label: "Actions", value: "Escalate case, block IP, webhook (Slack/Teams/custom), e-mail" },
          { label: "When rules run", value: "On every new case and whenever a case escalates — never twice for the same rule" },
          { label: "Accountability", value: "Every automated action is written to the case and the immutable audit log" }
        ],
        code: `POST /api/v1/alerts/rules
{
  "name": "Auto-block critical attackers",
  "condition_type": "risk_level",
  "condition_value": "CRITICAL",
  "action_type": "block_ip"
}
# → attacker IPs on CRITICAL cases are blocked automatically
#   and shown in SOAR → IP Blocklist (exportable as TXT/CSV)`,
        actionText: "View SOAR Rules →",
        actionPath: "/soar"
      };
    }
  };

  const modalData = getModalContent();

  const [isFlipped, setIsFlipped] = useState(false);

  useEffect(() => {
    if (isFlipped) {
      document.body.style.overflow = 'hidden';
      document.documentElement.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
      document.documentElement.style.overflow = '';
    }
    return () => {
      document.body.style.overflow = '';
      document.documentElement.style.overflow = '';
    };
  }, [isFlipped]);

  return (
    <Box sx={{ width: '100%', height: '100%', position: 'relative', display: 'flex', alignItems: 'center', bgcolor: 'transparent', overflow: 'hidden' }}>

      {/* Static Background Grid */}
      <Box
        sx={{
          position: 'absolute', inset: 0, zIndex: 0,
          backgroundImage: 'linear-gradient(rgba(0,0,0,0.02) 1px, transparent 1px), linear-gradient(90deg, rgba(0,0,0,0.02) 1px, transparent 1px)',
          backgroundSize: '100px 100px'
        }}
      />

      <Box sx={{ position: 'relative', zIndex: 1, width: '100%', height: '100%', display: 'flex', flexDirection: { xs: 'column', lg: 'row' }, alignItems: 'center', justifyContent: 'space-between', maxWidth: '1600px', margin: '0 auto', px: { xs: 2, sm: 4, lg: 6 } }}>

        {/* Left Sidebar Indicator */}
        <Box sx={{ width: { xs: '0%', lg: '8%' }, display: { xs: 'none', lg: 'flex' }, flexDirection: 'column', justifyContent: 'center', alignItems: 'center', borderRight: '1px solid rgba(0,0,0,0.05)' }}>
          <Typography sx={{ color: '#1A1A1A', fontFamily: fontSans, fontWeight: 600, fontSize: '0.9rem', mb: 15 }}>{id}</Typography>
          <Typography sx={{ color: '#1A1A1A', fontFamily: fontSans, fontWeight: 600, fontSize: '0.9rem', mt: 15, transform: 'rotate(-90deg)', whiteSpace: 'nowrap', letterSpacing: '0.2em', textTransform: 'uppercase' }}>{category}</Typography>
        </Box>

        {/* Text Content Area (Left Side) */}
        <Box sx={{ width: { xs: '100%', lg: '42%' }, display: 'flex', flexDirection: 'column', justifyContent: 'center', p: { xs: 2, sm: 4, md: 6, lg: 8 } }}>
          <motion.div initial={{ opacity: 0, y: 30 }} whileInView={{ opacity: 1, y: 0 }} transition={{ duration: 0.8, ease: 'easeOut' }}>
            <Box sx={{ bgcolor: pillColor, color: '#fff', borderRadius: '50px', px: 3, py: 0.8, mb: 4, display: 'inline-flex', fontFamily: fontSans, fontWeight: 700, fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
              {pillText}
            </Box>
            <Typography sx={{ color: '#1A1A1A', fontFamily: fontSans, fontWeight: 500, fontSize: { xs: '2.2rem', sm: '2.8rem', lg: '3.6rem' }, lineHeight: 1.05, letterSpacing: '-0.03em', mb: 4 }}>
              {title}
            </Typography>

            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
              <Button
                onClick={() => setIsFlipped(!isFlipped)}
                sx={{
                  bgcolor: isFlipped ? '#333333' : '#1A1A1A',
                  color: '#fff',
                  borderRadius: '0px', // Sharp Swiss architectural feel
                  px: { xs: 3, sm: 5 }, py: 2,
                  border: '1px solid rgba(255,255,255,0.2)',
                  fontFamily: 'monospace', fontWeight: 700, fontSize: '0.8rem',
                  textTransform: 'uppercase', letterSpacing: '0.12em',
                  transition: 'all 0.25s ease',
                  '&:hover': { bgcolor: '#fff', color: '#000' }
                }}
              >
                {isFlipped ? `[ ← CLOSE SPECIFICATION ]` : `[ + ${buttonText} ]`}
              </Button>
            </Box>
          </motion.div>
        </Box>

        {/* Widget Area (Right Side) */}
        <Box sx={{ width: { xs: '100%', lg: '50%' }, display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative', my: { xs: 4, lg: 0 } }}>
          {/* Ambient subtle monochrome glow */}
          <motion.div
            animate={{ scale: [1, 1.05, 1], opacity: [0.1, 0.2, 0.1] }}
            transition={{ duration: 6, repeat: Infinity, ease: 'easeInOut' }}
            style={{ position: 'absolute', width: '450px', height: '450px', borderRadius: '50%', background: 'radial-gradient(circle, rgba(0,0,0,0.15) 0%, transparent 70%)', zIndex: 0 }}
          />

          <motion.div
            animate={{ opacity: isFlipped ? 0.2 : 1, scale: isFlipped ? 0.95 : 1 }}
            transition={{ duration: 0.4 }}
            style={{ position: 'relative', zIndex: 1, width: '100%', maxWidth: '680px', display: 'flex', justifyContent: 'center' }}
          >
            {uiWidget}
          </motion.div>
        </Box>
      </Box>

      {/* Centered Bright, Vibrant & Opaque Architectural Specification Sheet */}
      <AnimatePresence>
        {isFlipped && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setIsFlipped(false)}
            data-modal-scroll="true"
            style={{
              position: 'fixed', inset: 0, zIndex: 999999,
              backgroundColor: 'rgba(20, 22, 26, 0.55)',
              backdropFilter: 'blur(16px)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              padding: '20px'
            }}
            onWheel={e => e.stopPropagation()}
          >
            <motion.div
              initial={{ rotateY: -90, scale: 0.7, opacity: 0 }}
              animate={{ rotateY: 0, scale: 1, opacity: 1 }}
              exit={{ rotateY: 90, scale: 0.7, opacity: 0 }}
              transition={{ duration: 0.5, type: 'spring', damping: 24, stiffness: 150 }}
              onClick={e => e.stopPropagation()}
              data-modal-scroll="true"
              style={{
                width: '100%', maxWidth: '640px',
                maxHeight: '68vh',
                overflow: 'hidden',
                // Vibrant, opaque frosted sandstone / quartz titanium finish (No complete white!)
                background: 'linear-gradient(145deg, rgba(244, 240, 233, 0.97) 0%, rgba(232, 227, 218, 0.98) 100%)',
                backdropFilter: 'blur(32px) saturate(200%)',
                border: '1px solid rgba(0, 0, 0, 0.14)',
                boxShadow: '0 30px 80px rgba(0, 0, 0, 0.25), 0 4px 15px rgba(0, 0, 0, 0.08)',
                padding: '24px 28px',
                display: 'flex', flexDirection: 'column',
                color: '#16181C',
                fontFamily: fontSans
              }}
            >
              {/* Pinned Top Header Strip */}
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', pb: 1.8, mb: 1.5, borderBottom: '1px solid rgba(0, 0, 0, 0.12)', flexShrink: 0 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                  <Box sx={{ width: 8, height: 8, bgcolor: pillColor }} />
                  <Typography sx={{ fontFamily: 'monospace', fontSize: '0.68rem', fontWeight: 800, color: pillColor, letterSpacing: '0.15em', textTransform: 'uppercase' }}>
                    {"// SPEC SHEET : {id}"}
                  </Typography>
                </Box>
                <Button
                  onClick={() => setIsFlipped(false)}
                  sx={{ fontFamily: 'monospace', color: '#444444', fontSize: '0.72rem', border: '1px solid rgba(0,0,0,0.2)', px: 2, py: 0.4, borderRadius: 0, '&:hover': { bgcolor: '#16181C', color: '#FFFFFF' } }}
                >
                  [ ✕ CLOSE ]
                </Button>
              </Box>

              {/* Internal Card Scrollable Body Only */}
              <Box
                data-modal-scroll="true"
                sx={{
                  overflowY: 'auto',
                  flex: 1,
                  minHeight: 0, // CRITICAL CSS FIX: Prevents flex child from growing beyond card maxHeight!
                  pr: 1.5,
                  my: 0.5,
                  '&::-webkit-scrollbar': { width: '5px' },
                  '&::-webkit-scrollbar-thumb': { bgcolor: 'rgba(0,0,0,0.2)', borderRadius: '3px' }
                }}
                onWheel={e => e.stopPropagation()}
              >
                {/* Title & Technical Paragraph */}
                <Typography sx={{ fontWeight: 900, fontSize: { xs: '1.5rem', md: '1.8rem' }, letterSpacing: '-0.03em', mb: 1, color: '#16181C', lineHeight: 1.15 }}>
                  {modalData.title}
                </Typography>
                <Typography sx={{ fontSize: '0.86rem', color: '#4A4D54', mb: 2.5, lineHeight: 1.6 }}>
                  {modalData.subtitle} Multi-threaded vector parsing engines guaranteeing deterministic runtime behavior under adversarial network surges.
                </Typography>

                {/* Compact & Detailed Specification Rows */}
                <Box sx={{ borderTop: '1px solid rgba(0,0,0,0.12)', mb: 2.5 }}>
                  {modalData.specs.map((item, idx) => (
                    <Box key={idx} sx={{ py: 1.5, borderBottom: '1px solid rgba(0,0,0,0.12)', display: 'flex', flexDirection: { xs: 'column', sm: 'row' }, justifyContent: 'space-between', gap: 1.5 }}>
                      <Typography sx={{ fontFamily: 'monospace', fontSize: '0.68rem', fontWeight: 800, color: pillColor, textTransform: 'uppercase', letterSpacing: '0.1em', width: '180px', flexShrink: 0 }}>
                        0{idx + 1}{' // '}{item.label}
                      </Typography>
                      <Typography sx={{ fontSize: '0.82rem', color: '#2C3038', flex: 1, lineHeight: 1.5, fontWeight: 500 }}>
                        <strong style={{ color: '#000' }}>{item.value}.</strong> Continuous enterprise operations with zero allocation churn.
                      </Typography>
                    </Box>
                  ))}
                </Box>

                {/* Warm Sandstone Code & Configuration Blueprint Block */}
                <Box sx={{ mb: 1 }}>
                  <Typography sx={{ fontFamily: 'monospace', fontSize: '0.66rem', fontWeight: 700, color: '#666666', mb: 0.8, letterSpacing: '0.1em' }}>
                    {"// PROTOCOL DEFINITION & RUNTIME SCHEMA"}
                  </Typography>
                  <Box sx={{ bgcolor: '#EAE6DD', color: '#16181C', p: 2.2, border: '1px solid rgba(0,0,0,0.12)', fontFamily: 'monospace', fontSize: '0.74rem', lineHeight: 1.5, overflowX: 'auto', whiteSpace: 'pre' }}>
                    {modalData.code}
                  </Box>
                </Box>
              </Box>

              {/* Pinned Bottom Action Strip */}
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', pt: 1.8, mt: 1, borderTop: '1px solid rgba(0, 0, 0, 0.12)', flexShrink: 0 }}>
                <Typography sx={{ fontFamily: 'monospace', fontSize: '0.65rem', color: '#666666', fontWeight: 600 }}>
                  STATUS : VERIFIED // AES-256-GCM
                </Typography>
                <Button
                  onClick={() => navigate(modalData.actionPath)}
                  sx={{
                    bgcolor: '#16181C', color: '#FFFFFF', borderRadius: 0, py: 1.1, px: 3,
                    fontFamily: 'monospace', fontWeight: 800, fontSize: '0.75rem', textTransform: 'uppercase',
                    letterSpacing: '0.1em', '&:hover': { bgcolor: pillColor, color: '#FFFFFF' }
                  }}
                >
                  ACCESS CONSOLE →
                </Button>
              </Box>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </Box>
  );
};

// ---- Animated Visual Cards for each Architecture component ----

const IngestionVisual = () => (
  <Box sx={{ width: '100%', height: '100%', bgcolor: 'transparent', position: 'relative', overflow: 'hidden', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
    {[...Array(7)].map((_, i) => (
      <motion.div key={i} animate={{ y: ['-100%', '120%'], opacity: [0, 1, 1, 0] }}
        transition={{ duration: 2 + i * 0.3, delay: i * 0.4, repeat: Infinity, ease: 'linear' }}
        style={{
          position: 'absolute', top: 0, left: `${8 + i * 13}%`, width: '2px', height: '30%',
          background: `linear-gradient(to bottom, transparent, #FF6B35, transparent)`
        }} />
    ))}
    <Box sx={{ width: '60px', height: '60px', borderRadius: '50%', border: '2px solid #FF6B35', display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative', zIndex: 2 }}>
      <motion.div animate={{ scale: [1, 1.3, 1], opacity: [0.5, 1, 0.5] }} transition={{ duration: 1.5, repeat: Infinity }}>
        <Box sx={{ width: '20px', height: '20px', borderRadius: '50%', bgcolor: '#FF6B35' }} />
      </motion.div>
    </Box>
    <Box sx={{ position: 'absolute', bottom: 24, left: 24 }}>
      <Typography sx={{ color: '#FF6B35', fontFamily: 'monospace', fontSize: '0.7rem', letterSpacing: '0.1em' }}>REGEX + LLM FALLBACK</Typography>
      <Typography sx={{ color: 'rgba(255,255,255,0.4)', fontFamily: 'monospace', fontSize: '0.65rem' }}>12 formats detected</Typography>
    </Box>
  </Box>
);

const GraphVisual = () => {
  const nodes = [{ x: 50, y: 50 }, { x: 20, y: 20 }, { x: 80, y: 25 }, { x: 15, y: 70 }, { x: 75, y: 70 }, { x: 50, y: 85 }, { x: 35, y: 45 }, { x: 65, y: 40 }];
  const edges = [[0, 1], [0, 2], [0, 3], [0, 4], [0, 5], [1, 6], [2, 7], [3, 6], [4, 7]];
  return (
    <Box sx={{ width: '100%', height: '100%', bgcolor: 'transparent', position: 'relative', overflow: 'hidden' }}>
      <svg width="100%" height="100%" style={{ position: 'absolute', top: 0, left: 0 }}>
        {edges.map(([a, b], i) => (
          <motion.line key={i} x1={`${nodes[a].x}%`} y1={`${nodes[a].y}%`} x2={`${nodes[b].x}%`} y2={`${nodes[b].y}%`}
            stroke="#D3A376" strokeWidth="1" strokeOpacity="0.4"
            animate={{ strokeOpacity: [0.2, 0.6, 0.2] }} transition={{ duration: 2 + i * 0.3, repeat: Infinity, delay: i * 0.2 }} />
        ))}
        {nodes.map((n, i) => (
          <motion.circle key={i} cx={`${n.x}%`} cy={`${n.y}%`} r={i === 0 ? 8 : 5} fill={i === 0 ? '#D3A376' : '#2A2010'}
            stroke="#D3A376" strokeWidth="1.5"
            animate={{ r: i === 0 ? [8, 10, 8] : [4, 6, 4], opacity: [0.7, 1, 0.7] }}
            transition={{ duration: 2, repeat: Infinity, repeatType: 'reverse', delay: i * 0.2 }} />
        ))}
      </svg>
      {nodes.map((n, i) => (
        <motion.div key={i} animate={{ scale: [1, 1.2, 1] }} transition={{ duration: 3, repeat: Infinity, delay: i * 0.3 }}
          style={{ position: 'absolute', left: `${n.x}%`, top: `${n.y}%`, width: i === 6 ? '12px' : '6px', height: i === 6 ? '12px' : '6px', borderRadius: '50%', backgroundColor: i === 6 ? '#111' : 'rgba(0,0,0,0.4)', transform: 'translate(-50%, -50%)' }} />
      ))}
    </Box>
  );
};

const AIVisual = () => (
  <Box sx={{ width: '100%', height: '100%', bgcolor: 'transparent', position: 'relative', overflow: 'hidden', display: 'flex', flexDirection: 'column', p: 3 }}>
    {['> Analyzing brute force pattern...', '> Cross-referencing CISA KEV...', '> Generating SOC summary...', '> Risk score: CRITICAL (88)', '> MITRE T1110.001 detected'].map((line, i) => (
      <motion.div key={i} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.6, duration: 0.4, repeat: Infinity, repeatDelay: 3 }}>
        <Typography sx={{ fontFamily: 'monospace', fontSize: '0.72rem', color: i === 3 ? '#111' : 'rgba(0,0,0,0.6)', fontWeight: i === 3 ? 700 : 400, mb: 1.5 }}>
          {line}
        </Typography>
      </motion.div>
    ))}
    <motion.div animate={{ opacity: [0, 1, 0] }} transition={{ duration: 1, repeat: Infinity }} style={{ width: '8px', height: '14px', backgroundColor: '#111', marginTop: '8px' }} />
    <Typography sx={{ position: 'absolute', bottom: 24, left: 24, fontFamily: 'monospace', fontSize: '0.6rem', color: 'rgba(0,0,0,0.4)', letterSpacing: '0.2em' }}>GROQ LLM · TF-IDF RAG</Typography>
  </Box>
);

const SOARVisual = () => (
  <Box sx={{ width: '100%', height: '100%', bgcolor: 'transparent', position: 'relative', overflow: 'hidden', display: 'flex', flexDirection: 'column', justifyContent: 'center', p: 4 }}>
    {[
      { label: 'Credential Dumping', action: '→ Block IP', color: '#111', bg: 'rgba(0,0,0,0.1)' },
      { label: 'Risk ≥ CRITICAL', action: '→ Slack Alert', color: 'rgba(0,0,0,0.8)', bg: 'rgba(0,0,0,0.05)' },
      { label: 'Unknown Binary', action: '→ Sandboxing', color: 'rgba(0,0,0,0.6)', bg: 'rgba(0,0,0,0.03)' }
    ].map((rule, i) => (
      <Box key={i} sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2, p: 1.5, borderLeft: `2px solid ${rule.color}`, bgcolor: rule.bg }}>
        <Typography sx={{ fontFamily: 'monospace', fontSize: '0.7rem', color: rule.color }}>IF {rule.label}</Typography>
        <Typography sx={{ fontFamily: 'monospace', fontSize: '0.7rem', color: rule.color, fontWeight: 700 }}>{rule.action}</Typography>
      </Box>
    ))}
  </Box>
);

const AttackOriginsVisual = () => (
  <Box sx={{ width: '100%', height: '100%', bgcolor: 'transparent', position: 'relative', overflow: 'hidden', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
    {[...Array(6)].map((_, i) => {
      const angle = (i / 6) * Math.PI * 2;
      const r = 80 + (i % 2) * 40;
      return (
        <motion.div key={i} animate={{ scale: [1, 1.5, 1], opacity: [0.2, 0.8, 0.2] }} transition={{ duration: 2, repeat: Infinity, delay: i * 0.3 }}
          style={{ position: 'absolute', width: '6px', height: '6px', borderRadius: '50%', backgroundColor: 'rgba(0,0,0,0.5)', left: `calc(50% + ${Math.cos(angle) * r}px)`, top: `calc(50% + ${Math.sin(angle) * r}px)` }}
        />
      );
    })}
    <Box sx={{ width: '40px', height: '40px', borderRadius: '50%', border: '2px dashed rgba(0,0,0,0.6)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <Typography sx={{ color: '#111', fontSize: '1.2rem', fontWeight: 700 }}>!</Typography>
    </Box>
    <Typography sx={{ position: 'absolute', bottom: 24, left: 24, fontFamily: 'monospace', fontSize: '0.65rem', color: 'rgba(0,0,0,0.5)', letterSpacing: '0.1em' }}>
      LIVE ATTACK ORIGINS<br />geolocated · streamed in real time
    </Typography>
  </Box>
);

const AttackLabVisual = () => (
  <Box sx={{ width: '100%', height: '100%', bgcolor: 'transparent', position: 'relative', overflow: 'hidden', display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', gap: 2, p: 3 }}>
    {['nmap service scan', 'sqlmap injection', 'hydra SSH brute force', 'Detected · blocked'].map((step, i) => (
      <motion.div key={i} animate={{ opacity: [0.3, 1, 0.3] }} transition={{ duration: 2, repeat: Infinity, delay: i * 0.5 }} style={{ width: '100%' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, p: 1.5, borderRadius: '8px', border: `1px solid rgba(0,0,0,0.1)`, bgcolor: 'rgba(0,0,0,0.03)' }}>
          <Box sx={{ width: '12px', height: '12px', borderRadius: '50%', bgcolor: i === 3 ? '#111' : 'rgba(0,0,0,0.3)' }} />
          <Typography sx={{ fontFamily: 'monospace', fontSize: '0.75rem', color: i === 3 ? '#111' : 'rgba(0,0,0,0.6)' }}>{step}</Typography>
        </Box>
      </motion.div>
    ))}
  </Box>
);

const AnomalyVisual = () => {
  const dots = Array.from({ length: 20 }).map(() => ({ x: Math.random() * 100, y: Math.random() * 100 }));
  dots[7] = { x: dots[7].x, y: 82 }; // The anomaly
  return (
    <Box sx={{ width: '100%', height: '100%', bgcolor: 'transparent', position: 'relative', overflow: 'hidden' }}>
      <svg width="100%" height="100%" style={{ position: 'absolute' }}>
        {dots.map((d, i) => (
          <motion.circle key={i} cx={`${d.x}%`} cy={`${d.y}%`} r={i === 7 ? 7 : 3}
            fill={i === 7 ? '#111' : 'rgba(0,0,0,0.15)'}
            animate={i === 7 ? { scale: [1, 1.5, 1] } : {}} transition={{ duration: 1, repeat: Infinity }}
          />
        ))}
        <motion.circle cx={`${dots[7].x}%`} cy={`${dots[7].y}%`} r="20" fill="none" stroke="#111" strokeWidth="1" strokeDasharray="4 4"
          animate={{ rotate: 360, scale: [1, 1.2, 1] }} transition={{ duration: 4, repeat: Infinity, ease: 'linear' }} style={{ transformOrigin: `${dots[7].x}% ${dots[7].y}%` }} />
      </svg>
    </Box>
  );
};

const RiskEngineVisual = () => (
  <Box sx={{ width: '100%', height: '100%', bgcolor: 'transparent', position: 'relative', overflow: 'hidden', p: 3, display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 2 }}>
    {[
      { label: 'Detection Confidence', val: 95, color: '#111' },
      { label: 'VirusTotal Reputation', val: 78, color: 'rgba(0,0,0,0.7)' },
      { label: 'CVSS Score', val: 82, color: 'rgba(0,0,0,0.5)' }
    ].map((f, i) => (
      <Box key={i} sx={{ width: '100%' }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
          <Typography sx={{ fontFamily: 'monospace', fontSize: '0.7rem', color: 'rgba(0,0,0,0.7)' }}>{f.label}</Typography>
          <Typography sx={{ fontFamily: 'monospace', fontSize: '0.7rem', color: f.color, fontWeight: 700 }}>{f.val}</Typography>
        </Box>
        <Box sx={{ width: '100%', height: '4px', bgcolor: 'rgba(0,0,0,0.1)', borderRadius: '2px', overflow: 'hidden' }}>
          <motion.div initial={{ width: 0 }} animate={{ width: `${f.val}%` }} transition={{ duration: 1.5, delay: 0.2 }} style={{ height: '100%', backgroundColor: f.color }} />
        </Box>
      </Box>
    ))}
    <Typography sx={{ mt: 2, textAlign: 'right', fontFamily: 'monospace', fontSize: '1.2rem', color: '#111', fontWeight: 700 }}>SCORE: 88</Typography>
  </Box>
);

const ThreatIntelVisual = () => (
  <Box sx={{ width: '100%', height: '100%', bgcolor: 'transparent', position: 'relative', overflow: 'hidden', p: 3, display: 'flex', flexDirection: 'column' }}>
    <Typography sx={{ fontFamily: 'monospace', fontSize: '0.65rem', color: 'rgba(0,0,0,0.5)', mb: 2, letterSpacing: '0.1em' }}>{"// LIVE FEED INGESTION"}</Typography>
    {[
      { src: 'CISA KEV', ioc: 'CVE-2024-21887', type: 'vuln', color: '#111' },
      { src: 'URLhaus', ioc: 'http://185.x.x/payload.bin', type: 'url', color: 'rgba(0,0,0,0.7)' },
      { src: 'Feodo', ioc: '91.103.x.x:443', type: 'c2', color: 'rgba(0,0,0,0.5)' }
    ].map((f, i) => (
      <motion.div key={i} initial={{ x: 20, opacity: 0 }} animate={{ x: 0, opacity: 1 }} transition={{ delay: i * 0.3 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', py: 1.2, borderBottom: '1px solid rgba(0,0,0,0.1)' }}>
          <Box>
            <Typography sx={{ fontFamily: 'sans-serif', fontSize: '0.7rem', fontWeight: 600, color: '#111' }}>{f.src}</Typography>
            <Typography sx={{ fontFamily: 'monospace', fontSize: '0.65rem', color: 'rgba(0,0,0,0.6)', mt: 0.2 }}>{f.ioc}</Typography>
          </Box>
          <Typography sx={{ fontFamily: 'monospace', fontSize: '0.6rem', color: f.color, border: `1px solid ${f.color}`, px: 1, py: 0.2, borderRadius: '4px' }}>{f.type.toUpperCase()}</Typography>
        </Box>
      </motion.div>
    ))}
  </Box>
);

const CampaignVisual = () => (
  <Box sx={{ width: '100%', height: '100%', bgcolor: 'transparent', position: 'relative', overflow: 'hidden', p: 3, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
    {[
      { date: 'Jan 14', stage: 'Brute Force', color: 'rgba(0,0,0,0.4)' },
      { date: 'Jan 14', stage: 'Success Login', color: 'rgba(0,0,0,0.6)' },
      { date: 'Mar 02', stage: 'Dormant / Recon', color: 'rgba(0,0,0,0.4)' },
      { date: 'Mar 22', stage: 'Lateral Move', color: '#111' }
    ].map((c, i) => (
      <Box key={i} sx={{ display: 'flex', gap: 2, position: 'relative', pb: 3 }}>
        {i !== 3 && <Box sx={{ position: 'absolute', left: 3, top: 10, bottom: -10, width: '1px', bgcolor: 'rgba(0,0,0,0.2)' }} />}
        <Box sx={{ width: '7px', height: '7px', borderRadius: '50%', bgcolor: c.color, mt: 0.6, position: 'relative', zIndex: 1 }} />
        <Box>
          <Typography sx={{ fontFamily: 'monospace', fontSize: '0.65rem', color: 'rgba(0,0,0,0.5)', mb: 0.2 }}>{c.date}</Typography>
          <Typography sx={{ fontFamily: 'sans-serif', fontSize: '0.8rem', color: c.color, fontWeight: i === 3 ? 700 : 400 }}>{c.stage}</Typography>
        </Box>
      </Box>
    ))}
  </Box>
);

const BlocklistVisual = () => (
  <Box sx={{ width: '100%', height: '100%', bgcolor: 'transparent', position: 'relative', overflow: 'hidden', display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 3 }}>
    <motion.div animate={{ scale: [1, 1.05, 1] }} transition={{ duration: 2, repeat: Infinity }}>
      <Box sx={{ width: '100px', height: '100px', borderRadius: '50%', border: '3px solid #111', display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative' }}>
        <Box sx={{ position: 'absolute', inset: -8, borderRadius: '50%', border: '1px dashed rgba(0,0,0,0.3)' }} />
        <Typography sx={{ fontFamily: 'monospace', fontWeight: 700, fontSize: '1.2rem', color: '#111' }}>DROP</Typography>
      </Box>
    </motion.div>
    <Box sx={{ display: 'flex', gap: 1 }}>
      {[...Array(5)].map((_, i) => (
        <motion.div key={i} animate={{ y: [0, -10, 0], opacity: [0.2, 1, 0.2] }} transition={{ duration: 1, delay: i * 0.2, repeat: Infinity }}>
          <Box sx={{ width: '4px', height: '4px', borderRadius: '50%', bgcolor: '#111' }} />
        </motion.div>
      ))}
    </Box>
  </Box>
);

const CorrelationVisual = () => (
  <Box sx={{ width: '100%', height: '100%', bgcolor: 'transparent', position: 'relative', overflow: 'hidden', p: 3, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
    <Typography sx={{ fontFamily: 'monospace', fontSize: '0.65rem', color: 'rgba(0,0,0,0.5)', mb: 3, letterSpacing: '0.1em' }}>{"// SWEEP EVERY 5 MINUTES"}</Typography>
    {[
      { time: '00:00', events: 1 }, { time: '02:00', events: 1 }, { time: '06:00', events: 1 },
      { time: '14:00', events: 1 }, { time: '22:00', events: 1 }
    ].map((b, i) => (
      <Box key={i} sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 1.5 }}>
        <Typography sx={{ fontFamily: 'monospace', fontSize: '0.65rem', color: 'rgba(0,0,0,0.6)', width: '40px' }}>{b.time}</Typography>
        <Box sx={{ flex: 1, height: '4px', bgcolor: 'rgba(0,0,0,0.1)' }}>
          <motion.div initial={{ width: 0 }} whileInView={{ width: '20%' }} transition={{ delay: i * 0.1 }} style={{ height: '100%', backgroundColor: 'rgba(0,0,0,0.4)' }} />
        </Box>
      </Box>
    ))}
    <Typography sx={{ fontFamily: 'sans-serif', fontSize: '0.75rem', color: '#111', mt: 1, fontWeight: 600 }}>Pattern Identified: Slow Brute Force (24h)</Typography>
  </Box>
);

const SOCCopilotVisual = () => (
  <Box sx={{ width: '100%', height: '100%', bgcolor: 'transparent', position: 'relative', overflow: 'hidden', p: 3, display: 'flex', flexDirection: 'column', justifyContent: 'flex-end', gap: 2 }}>
    {[
      { role: 'analyst', text: 'Which IPs brute-forced us this week?', color: 'rgba(0,0,0,0.6)' },
      { role: 'ai', text: 'Found 3 IPs: 185.x.x.45 (CRITICAL), 91.x.x.232 (HIGH), 203.x.x.99 (MED). Campaign #7 spans all three.', color: '#111' },
      { role: 'analyst', text: 'Block the critical ones.', color: 'rgba(0,0,0,0.6)' }
    ].map((msg, i) => (
      <motion.div key={i} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.8 }}>
        <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: msg.role === 'ai' ? 'flex-start' : 'flex-end' }}>
          <Typography sx={{ fontFamily: 'sans-serif', fontSize: '0.75rem', color: msg.color, bgcolor: msg.role === 'ai' ? 'rgba(0,0,0,0.05)' : 'transparent', border: msg.role === 'analyst' ? '1px solid rgba(0,0,0,0.2)' : 'none', p: 1.5, borderRadius: '8px', maxWidth: '90%' }}>
            {msg.text}
          </Typography>
        </Box>
      </motion.div>
    ))}
  </Box>
);

const TimelineVisual = () => (
  <Box sx={{ width: '100%', height: '100%', bgcolor: 'transparent', position: 'relative', overflow: 'hidden', p: 3, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
    {[
      { time: '09:14', event: 'Reconnaissance scan from 203.x.x.99', sev: 'LOW', color: 'rgba(0,0,0,0.4)' },
      { time: '09:31', event: 'Brute force — 47 failed logins', sev: 'HIGH', color: 'rgba(0,0,0,0.7)' },
      { time: '09:44', event: 'Successful login after brute force', sev: 'CRIT', color: '#111' },
      { time: '10:02', event: 'Lateral movement via PsExec', sev: 'CRIT', color: '#111' },
      { time: '10:18', event: 'Data exfiltration — 2.3GB sent', sev: 'CRIT', color: '#111' }
    ].map((item, i) => (
      <motion.div key={i} initial={{ x: -10, opacity: 0 }} whileInView={{ x: 0, opacity: 1 }} transition={{ delay: i * 0.2 }}>
        <Box sx={{ display: 'flex', gap: 2, mb: 2, opacity: i < 2 ? 0.7 : 1 }}>
          <Typography sx={{ fontFamily: 'monospace', fontSize: '0.62rem', color: 'rgba(0,0,0,0.5)', flexShrink: 0, pt: 0.3 }}>{item.time}</Typography>
          <Box sx={{ width: '2px', bgcolor: item.color, flexShrink: 0 }} />
          <Box>
            <Typography sx={{ fontFamily: 'monospace', fontSize: '0.68rem', color: 'rgba(0,0,0,0.8)', lineHeight: 1.3 }}>{item.event}</Typography>
            <Typography sx={{ fontFamily: 'monospace', fontSize: '0.55rem', color: item.color, mt: 0.5 }}>{item.sev}</Typography>
          </Box>
        </Box>
      </motion.div>
    ))}
  </Box>
);

const BulkIngestVisual = () => (
  <Box sx={{ width: '100%', height: '100%', bgcolor: 'transparent', position: 'relative', overflow: 'hidden', p: 3, display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 2 }}>
    <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
      <Typography sx={{ fontFamily: 'monospace', fontSize: '0.65rem', color: 'rgba(0,0,0,0.6)' }}>job_id: a7f3c</Typography>
      <motion.div animate={{ opacity: [1, 0.5, 1] }} transition={{ duration: 1, repeat: Infinity }}>
        <Typography sx={{ fontFamily: 'monospace', fontSize: '0.65rem', color: '#111', fontWeight: 700 }}>PROCESSING</Typography>
      </motion.div>
    </Box>
    <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 1 }}>
      {[...Array(15)].map((_, i) => (
        <motion.div key={i} initial={{ opacity: 0, scale: 0.5 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: i * 0.05 }}>
          <Box sx={{ height: '8px', borderRadius: '2px', bgcolor: i < 12 ? '#111' : 'rgba(0,0,0,0.1)' }} />
        </motion.div>
      ))}
    </Box>
    <Typography sx={{ fontFamily: 'monospace', fontSize: '0.65rem', color: 'rgba(0,0,0,0.5)', mt: 1, textAlign: 'right' }}>12/15 BATCHES</Typography>
  </Box>
);

const ArchitectureHoverExpand = ({ transparent = false }) => {
  const [activeCardIndex, setActiveCardIndex] = useState(null);

  // Soft, Muted Matte Colors (Exactly matching the flat pastel aesthetic of the screenshot)
  const components = [
    {
      title: "Ingestion Engine", tag: "CORE", color: '#4A451A',
      bg: '#E2D775', image: "/assets/cards/img1.webp",
      desc: "Every log enters through one pipeline — Threat Studio, the authenticated webhook used by log shippers, bulk jobs or the Windows collector. Extractors recognise 13 formats (Windows Event Log, Linux/SSH, Cisco ASA, Palo Alto, Snort/Suricata, firewalls, proxies, AWS CloudTrail, Azure, GCP, web servers, DNS and syslog) and normalise them into structured fields. URL-encoded payloads are decoded before detection, and an optional Groq LLM parses formats no pattern recognises.",
      stat1: "13 log formats", stat2: "< 20 ms per event",
      visual: <IngestionVisual />
    },
    {
      title: "ATT&CK Mapping", tag: "DATA", color: '#1C2E17',
      bg: '#85AA7F', image: null,
      desc: "Every detection is mapped to a MITRE ATT&CK technique and tactic from the official catalogue of 706 techniques. A live coverage heatmap shows which techniques ThreatLens can detect and how often each has been observed in your environment, and every campaign is drawn as a kill chain across the tactics it reached.",
      stat1: "706 techniques", stat2: "Live coverage heatmap",
      visual: <GraphVisual />
    },
    {
      title: "AI Reasoning Core", tag: "ML", color: '#2A1F45',
      bg: '#9A8BBA', image: "/assets/cards/img3.webp",
      desc: "Turns detections into analyst-grade reports: executive summary, technical analysis, business impact and recommended actions. With a Groq key it uses a Llama 3.3 70B model, grounded by a TF-IDF retrieval index over a curated threat knowledge base and the CISA Known Exploited Vulnerabilities catalogue. Without a key, a deterministic rule engine writes the same sections from the same evidence — the product never depends on an AI being online.",
      stat1: "Groq LLM (optional)", stat2: "Retrieval-grounded",
      visual: <AIVisual />
    },
    {
      title: "Automated SOAR", tag: "OPS", color: '#1A3445',
      bg: '#7BA4B8', image: "/assets/cards/img4.webp",
      desc: "Rules evaluate every new or escalating case against severity, threat-type and multi-stage conditions, then act in the same transaction that detected it: escalate the case, add the attacker to the blocklist, call a Slack, Teams or custom webhook, or send an e-mail. Every automated action is recorded on the case and in the audit log.",
      stat1: "4 action types", stat2: "Sub-second response",
      visual: <SOARVisual />
    },
    {
      title: "Attack Lab", tag: "INTEL", color: '#4A1D20',
      bg: '#C97A7E', image: null,
      desc: "A real, deliberately weak Linux server (OpenSSH + nginx) and an attacker container with nmap, sqlmap and hydra run on an isolated Docker network. A log shipper forwards the server's genuine logs to ThreatLens over the authenticated webhook, so you can launch a real intrusion and watch every stage get detected, correlated and blocked.",
      stat1: "Real tools", stat2: "Real logs",
      visual: <AttackOriginsVisual />
    },
    {
      title: "Live Threat Map", tag: "NET", color: '#153A33',
      bg: '#72B1A4', image: null,
      desc: "Attacker IP addresses from your incidents are geolocated and drawn on a world map, with arcs to your headquarters as attacks happen. Points are sized by alert volume, coloured by severity and marked once SOAR has blocked them — streamed to every analyst's browser in real time over Server-Sent Events.",
      stat1: "Real-time stream", stat2: "Geolocated attackers",
      visual: <AttackLabVisual />
    },
    {
      title: "Detection Engine", tag: "ML", color: '#4A210D',
      bg: '#E29D75', image: null,
      desc: "Twenty-eight MITRE-mapped rules run against every log and all matching rules fire, so an encoded PowerShell command that also dumps LSASS raises both detections. Rules are context-aware — a scanner requesting /ftp/upload is reconnaissance, not exfiltration — and two correlation detections catch slow and distributed brute force across days.",
      stat1: "28 rules, all fire", stat2: "Context-aware",
      visual: <AnomalyVisual />
    },
    {
      title: "Risk Engine", tag: "SCORE", color: '#451616',
      bg: '#C47070', image: "/assets/cards/img8.webp",
      desc: "A transparent 0–100 score built from ten factors: detection confidence, technique impact, time decay, campaign depth, attack-chain match, CVSS of related CVEs, VirusTotal reputation, blocklist status, threat-intel matches and failed-login history. Every point is itemised on the case, so an analyst can always see why something is CRITICAL.",
      stat1: "10 scoring factors", stat2: "Every point explained",
      visual: <RiskEngineVisual />
    },
    {
      title: "Threat Intel Feeds", tag: "OSINT", color: '#123035',
      bg: '#6E9BA1', image: "/assets/cards/img9.webp",
      desc: "Five public feeds refresh automatically: the CISA Known Exploited Vulnerabilities catalogue, abuse.ch Feodo Tracker botnet servers and IPsum's multi-blocklist IPs need no key, and URLhaus and ThreatFox are enabled with a free abuse.ch key. Every incoming log is cross-checked against thousands of indicators, and a known-bad IP is a detection on its own.",
      stat1: "5 live feeds", stat2: "Hourly refresh",
      visual: <ThreatIntelVisual />
    },
    {
      title: "Campaign Tracker", tag: "HUNT", color: '#241D45',
      bg: '#9089B3', image: "/assets/cards/img10.webp",
      desc: "Events from the same attacker are linked into a campaign that never times out: a brute force in January and lateral movement in March land in the same story. Fifteen known attack chains — such as Breach → Credential Theft → Lateral Spread, or a full ransomware kill chain — raise confidence when they appear.",
      stat1: "No time-out", stat2: "15 attack chains",
      visual: <CampaignVisual />
    },
    {
      title: "Blocklist Gate", tag: "OPS", color: '#47210E',
      bg: '#D68965', image: "/assets/cards/img11.webp",
      desc: "Every log's source IP is checked against the blocklist before scoring, and a blocked address is escalated to CRITICAL regardless of content. Analysts block and unblock from the SOAR page, SOAR rules add attackers automatically, and the list exports as firewall-ready text or CSV.",
      stat1: "Auto + manual", stat2: "Firewall export",
      visual: <BlocklistVisual />
    },
    {
      title: "Correlation Engine", tag: "5MIN", color: '#293813',
      bg: '#9DB374', image: "/assets/cards/img12.webp",
      desc: "Every five minutes a background sweep hunts for what single events can't reveal: slow brute force spread over 12+ hours, password spraying from many IPs against one account, campaigns that have reached three stages, and repeat offenders that should be blocked.",
      stat1: "5-minute sweeps", stat2: "Low & slow detection",
      visual: <CorrelationVisual />
    },
    {
      title: "SOC Copilot", tag: "AI", color: '#421626',
      bg: '#B57088', image: "/assets/cards/img13.webp",
      desc: "Ask questions in plain English — 'what happened to 203.0.113.45?' — and get answers grounded in your live incidents, campaigns, blocklist and threat intelligence. Conversations keep per-user memory for follow-up questions, and without an LLM key the Copilot still answers with a structured briefing built from the same data.",
      stat1: "Grounded in your data", stat2: "Per-user memory",
      visual: <SOCCopilotVisual />
    },
    {
      title: "Attack Timeline", tag: "UI", color: '#453211',
      bg: '#D1AC6B', image: "/assets/cards/img14.webp",
      desc: "For any IP address, raw log lines and the incidents they produced are merged into one chronological story alongside the campaign they belong to — from the first scan to the final exfiltration attempt.",
      stat1: "Logs + incidents", stat2: "Per-IP dossier",
      visual: <TimelineVisual />
    },
    {
      title: "Bulk Ingestion", tag: "ASYNC", color: '#113324',
      bg: '#62A388', image: "/assets/cards/img15.webp",
      desc: "POST up to 1,000 log lines and get a job ID straight back. The batch is processed in the background in groups of 50, each committed independently so a malformed line never loses progress, and a status endpoint reports processed lines, incidents, threat-intel hits and errors.",
      stat1: "1,000 lines / job", stat2: "Per-batch commits",
      visual: <BulkIngestVisual />
    },
  ];

  return (
    <Box sx={{
      width: '100%',
      minHeight: '100vh',
      bgcolor: transparent ? 'transparent' : '#0B0F14',
      background: transparent ? 'transparent' : 'radial-gradient(circle at 0% 0%, rgba(255,120,40,0.04) 0%, transparent 65%), radial-gradient(circle at 100% 100%, rgba(255,160,70,0.03) 0%, transparent 65%), linear-gradient(180deg, #1E2633 0%, #1E2633 30%, #0B0F14 100%)',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      py: 16,
      position: 'relative',
      overflow: 'hidden'
    }}>
      {!transparent && (
        <Box sx={{ position: 'absolute', top: 0, left: 0, right: 0, height: '140px', background: 'linear-gradient(180deg, #1E2633 0%, transparent 100%)', pointerEvents: 'none', zIndex: 20 }} />
      )}
      <Box
        sx={{
          display: 'flex',
          justifyContent: 'flex-start',
          width: '100%',
          maxWidth: '1800px',
          height: '750px',
          border: '1px solid rgba(255, 255, 255, 0.14)',
          borderRadius: '20px',
          overflow: 'hidden',
          boxShadow: '0 30px 90px rgba(0, 0, 0, 0.9)',
          bgcolor: '#0E0E11',
          position: 'relative',
          zIndex: 10
        }}
      >
        {components.map((comp, i) => {
          const isActive = activeCardIndex === i;
          return (
            <div
              key={i}
              className="train-strip"
              onClick={() => setActiveCardIndex(activeCardIndex === i ? null : i)}
              style={{
                height: '100%',
                boxSizing: 'border-box',
                willChange: 'transform, width, flex-grow',
                width: isActive ? 'min(760px, calc(100vw - 320px))' : (activeCardIndex === null ? '100%' : 'min(74px, 10vw)'),
                flexShrink: isActive ? 0 : 1,
                flexGrow: isActive ? 0 : (activeCardIndex === null ? 1 : 0),
                transition: 'width 0.65s cubic-bezier(0.16, 1, 0.3, 1), flex-grow 0.65s cubic-bezier(0.16, 1, 0.3, 1)',
                borderRight: '1px solid rgba(255, 255, 255, 0.3)',
                borderLeft: '1px solid rgba(255, 255, 255, 0.3)',
                background: isActive ? 'transparent' : 'linear-gradient(180deg, #18191E 0%, #0E0E11 100%)',
                cursor: 'pointer',
                display: 'flex',
                position: 'relative',
                overflow: 'hidden'
              }}
            >
              {/* Expanded Card Content */}
              <div style={{
                position: 'absolute', top: 0, left: 0, width: '100%', height: '100%',
                opacity: isActive ? 1 : 0,
                transition: 'opacity 0.3s ease',
                display: 'flex', flexDirection: 'row',
                pointerEvents: isActive ? 'auto' : 'none',
                zIndex: 2
              }}>
                <Box sx={{ width: '80px', height: '100%', position: 'relative', borderRight: '1px solid rgba(255, 255, 255, 0.24)', flexShrink: 0, bgcolor: '#111' }}>
                  <Typography sx={{ position: 'absolute', top: 20, left: '50%', transform: 'translateX(-50%)', fontFamily: 'monospace', fontSize: '0.75rem', fontWeight: 800, color: '#ffffff' }}>
                    {(i + 1).toString().padStart(2, '0')}
                  </Typography>
                  <Typography sx={{ position: 'absolute', bottom: 32, left: '50%', transform: 'translateX(-50%) rotate(180deg)', writingMode: 'vertical-rl', fontFamily: fontSans, fontSize: '1rem', color: '#fff', whiteSpace: 'nowrap', fontWeight: 600 }}>
                    {comp.title}
                  </Typography>
                </Box>
                <Box sx={{ flex: 1, position: 'relative', overflow: 'hidden', display: 'flex', bgcolor: '#0B0F14' }}>
                  {isActive && (
                    <>
                      {/* Full-bleed background slide image covering 100% of the card */}
                      {comp.image ? (
                        <Box
                          component="img"
                          src={comp.image}
                          alt={comp.title}
                          sx={{
                            position: 'absolute',
                            top: 0,
                            left: 0,
                            width: '100%',
                            height: '100%',
                            objectFit: 'cover',
                            objectPosition: 'center',
                            opacity: 0.95,
                            filter: 'brightness(0.92) contrast(1.08)',
                            zIndex: 0
                          }}
                        />
                      ) : (
                        <Box sx={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%', zIndex: 0, opacity: 0.5, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                          {comp.visual}
                        </Box>
                      )}

                      {/* Subtle ambient vignette overlay */}
                      <Box
                        sx={{
                          position: 'absolute',
                          top: 0,
                          left: 0,
                          width: '100%',
                          height: '100%',
                          background: 'radial-gradient(circle at 70% 50%, transparent 20%, rgba(11,15,20,0.55) 100%)',
                          zIndex: 1
                        }}
                      />

                      {/* Transparent Glassmorphic Text Panel Floating Above Background */}
                      <Box
                        sx={{
                          position: 'relative',
                          zIndex: 2,
                          m: { xs: 3, md: 4.5 },
                          p: { xs: 3.5, md: 4.5 },
                          display: 'flex',
                          flexDirection: 'column',
                          justifyContent: 'space-between',
                          height: 'calc(100% - 72px)',
                          width: '100%',
                          maxWidth: '500px',
                          bgcolor: 'rgba(11, 15, 20, 0.68)',
                          backdropFilter: 'blur(16px)',
                          WebkitBackdropFilter: 'blur(16px)',
                          border: '1px solid rgba(255, 255, 255, 0.18)',
                          borderRadius: '24px',
                          boxShadow: '0 25px 60px rgba(0, 0, 0, 0.65)'
                        }}
                      >
                        <Box>
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
                            <Box sx={{ width: 10, height: 10, bgcolor: comp.color || '#E25C5C', boxShadow: `0 0 12px ${comp.color || '#E25C5C'}` }} />
                            <Typography sx={{ fontFamily: 'monospace', fontSize: '0.72rem', color: comp.color || '#E25C5C', letterSpacing: '0.15em', fontWeight: 700 }}>
                              {"// FEATURE // {comp.tag}"}
                            </Typography>
                          </Box>

                          <Typography sx={{ fontFamily: fontSans, fontWeight: 800, fontSize: '2.1rem', color: '#ffffff', mb: 2.5, lineHeight: 1.15, letterSpacing: '-0.02em' }}>
                            {comp.title}
                          </Typography>

                          <Typography sx={{ fontFamily: fontSans, fontSize: '0.94rem', color: 'rgba(255, 255, 255, 0.88)', lineHeight: 1.65 }}>
                            {comp.desc}
                          </Typography>
                        </Box>

                        <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2, mt: 4 }}>
                          <Box sx={{ bgcolor: 'rgba(255,255,255,0.06)', backdropFilter: 'blur(12px)', border: '1px solid rgba(255,255,255,0.12)', borderRadius: '12px', p: 2 }}>
                            <Typography sx={{ fontFamily: 'monospace', fontSize: '0.65rem', color: comp.color || '#E25C5C', mb: 0.5, letterSpacing: '0.08em' }}>
                              KEY FEATURE
                            </Typography>
                            <Typography sx={{ fontFamily: fontSans, fontSize: '0.88rem', color: '#fff', fontWeight: 700 }}>
                              {comp.stat1}
                            </Typography>
                          </Box>

                          <Box sx={{ bgcolor: 'rgba(255,255,255,0.06)', backdropFilter: 'blur(12px)', border: '1px solid rgba(255,255,255,0.12)', borderRadius: '12px', p: 2 }}>
                            <Typography sx={{ fontFamily: 'monospace', fontSize: '0.65rem', color: comp.color || '#E25C5C', mb: 0.5, letterSpacing: '0.08em' }}>
                              CAPABILITY
                            </Typography>
                            <Typography sx={{ fontFamily: fontSans, fontSize: '0.88rem', color: '#fff', fontWeight: 700 }}>
                              {comp.stat2}
                            </Typography>
                          </Box>
                        </Box>
                      </Box>
                    </>
                  )}
                </Box>
              </div>

              {/* Collapsed / Unhovered Strip Visual */}
              <div style={{
                position: 'absolute', top: 0, left: 0, width: '100%', height: '100%',
                opacity: isActive ? 0 : 1,
                transition: 'opacity 0.25s ease',
                pointerEvents: 'none',
                zIndex: 1
              }}>
                <Typography sx={{ position: 'absolute', top: 22, left: '50%', transform: 'translateX(-50%)', fontFamily: 'monospace', fontSize: '0.78rem', fontWeight: 800, color: '#ffffff', letterSpacing: '0.05em' }}>
                  {(i + 1).toString().padStart(2, '0')}
                </Typography>
                <Typography sx={{
                  position: 'absolute', bottom: 32, left: '50%', transform: 'translateX(-50%) rotate(180deg)',
                  writingMode: 'vertical-rl', fontFamily: fontSans, fontSize: '0.98rem', color: 'rgba(255,255,255,0.88)',
                  whiteSpace: 'nowrap', fontWeight: 600, letterSpacing: '0.05em'
                }}>
                  {comp.title}
                </Typography>
              </div>
            </div>
          )
        })}
      </Box>
    </Box>
  );
};

// Background visual for the problem statement
const ChaosBackground = () => (
  <Box sx={{ width: '100%', height: '100%', opacity: 0.05, overflow: 'hidden' }}>
    <svg width="100%" height="100%">
      <pattern id="diagonalHatch" width="6" height="6" patternTransform="rotate(45 0 0)" patternUnits="userSpaceOnUse">
        <line x1="0" y1="0" x2="0" y2="6" stroke="#000" strokeWidth="1" />
      </pattern>
      <rect width="100%" height="100%" fill="url(#diagonalHatch)" />
    </svg>
  </Box>
);

const RandomWhiteDotsBackground = () => {
  const dots = React.useMemo(() => {
    return Array.from({ length: 80 }).map((_, i) => ({
      top: `${Math.floor((i * 17 + 23) % 96) + 2}%`,
      left: `${Math.floor((i * 31 + 11) % 96) + 2}%`,
      size: (i % 3) + 1.5,
      opacity: ((i % 5) + 2) * 0.12,
      duration: ((i % 4) + 3)
    }));
  }, []);

  return (
    <Box sx={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%', overflow: 'hidden', pointerEvents: 'none', zIndex: 0 }}>
      {dots.map((d, idx) => (
        <motion.div
          key={idx}
          animate={{ opacity: [d.opacity * 0.3, d.opacity, d.opacity * 0.3] }}
          transition={{ duration: d.duration, repeat: Infinity, ease: 'easeInOut' }}
          style={{
            position: 'absolute',
            top: d.top,
            left: d.left,
            width: `${d.size}px`,
            height: `${d.size}px`,
            borderRadius: '50%',
            backgroundColor: '#ffffff',
            boxShadow: d.size > 2 ? '0 0 8px rgba(255, 255, 255, 0.7)' : 'none'
          }}
        />
      ))}
    </Box>
  );
};

const MergedEcosystemExperience = () => {
  const layer2Ref = useRef(null);
  const trainWaveRef = useRef(0);

  useEffect(() => {
    let rafId = null;

    const updateLoop = () => {
      if (layer2Ref.current) {
        const rect = layer2Ref.current.getBoundingClientRect();
        // Trigger train wave as soon as the slides section enters the viewport
        const isVisible = rect.top < window.innerHeight * 0.85 && rect.bottom > 0;

        if (isVisible) {
          trainWaveRef.current = Math.min(1, trainWaveRef.current + 0.015); // ~1.1s train arrival
        } else if (rect.top >= window.innerHeight * 0.85) {
          trainWaveRef.current = 0; // Reset when scrolled back above
        }

        const waveP = trainWaveRef.current;
        const strips = layer2Ref.current.querySelectorAll('.train-strip');
        if (strips && strips.length > 0) {
          const numStrips = strips.length;
          for (let i = 0; i < numStrips; i++) {
            if (waveP >= 0.999) {
              if (strips[i].style.transform !== 'translate3d(0vw, 0px, 0px)') {
                strips[i].style.transform = 'translate3d(0vw, 0px, 0px)';
              }
            } else {
              const start = (i / numStrips) * 0.65;
              const end = Math.min(1, start + 0.35);
              const stripP = Math.max(0, Math.min(1, (waveP - start) / (end - start)));

              const easeP = 1 - Math.pow(1 - stripP, 3);
              const tx = (1 - easeP) * -120;

              strips[i].style.transform = `translate3d(${tx}vw, 0px, 0px)`;
            }
          }
        }
      }

      rafId = requestAnimationFrame(updateLoop);
    };

    rafId = requestAnimationFrame(updateLoop);
    return () => {
      if (rafId) cancelAnimationFrame(rafId);
    };
  }, []);

  const ContinuousTickerBanner = () => {
    const tickerItems = [
      "THREATLENS SECURITY OPERATIONS",
      "REAL-TIME DETECTION PIPELINE",
      "MULTI-STAGE CAMPAIGN CORRELATION",
      "706 MITRE ATT&CK TECHNIQUES",
      "LIVE THREAT-INTEL FEEDS",
      "SOC COPILOT NATURAL LANGUAGE QUERY",
      "AUTOMATED SOAR RESPONSE"
    ];
    const repeatedItems = [...tickerItems, ...tickerItems, ...tickerItems, ...tickerItems];

    return (
      <Box sx={{ width: '100%', py: 3.5, position: 'relative', overflow: 'hidden', zIndex: 10 }}>
        <motion.div
          animate={{ x: ['0%', '-50%'] }}
          transition={{ repeat: Infinity, ease: 'linear', duration: 30 }}
          style={{ display: 'flex', width: 'max-content', alignItems: 'center' }}
        >
          {repeatedItems.map((item, index) => (
            <Box key={index} sx={{ display: 'flex', alignItems: 'center', mx: 5 }}>
              <Typography sx={{ fontFamily: fontSans, fontSize: '0.9rem', fontWeight: 600, color: '#ffffff', letterSpacing: '0.25em', textTransform: 'uppercase', whiteSpace: 'nowrap', opacity: 0.85 }}>
                {item}
              </Typography>
              <Box sx={{ width: 4, height: 4, borderRadius: '50%', bgcolor: 'rgba(255, 255, 255, 0.4)', ml: 5 }} />
            </Box>
          ))}
        </motion.div>
      </Box>
    );
  };

  return (
    <Box sx={{ width: '100%', bgcolor: '#0B0F14', position: 'relative', zIndex: 5 }}>
      {/* Random White Starry/Node Dots Across Entire Background */}
      <RandomWhiteDotsBackground />

      {/* Section 1: 3D Rotating Cards */}
      <Box sx={{ width: '100%', height: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative', overflow: 'hidden' }}>
        <Carousel3DHero transparent={true} />
      </Box>

      {/* Continuous Right-to-Left Ticker Banner */}
      <ContinuousTickerBanner />

      {/* Section 2: Widescreen Architecture Slides */}
      <Box ref={layer2Ref} sx={{ width: '100%', height: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative', overflow: 'hidden' }}>
        <ArchitectureHoverExpand transparent={true} />
      </Box>
    </Box>
  );
};

const SECTIONS = [
  {
    type: 'text',
    bg: '#111111',
    content: <MinimalistHero />
  },
  {
    type: 'feature-widget',
    bg: '#F2EDE4',
    content: (
      <FeatureWidget
        id="01" category="Ingestion" pillText="Auto-Classify" pillColor="#FF6B35"
        title="Transform chaotic telemetry into structured intelligence" buttonText="SEE PARSING SPECS"
        uiWidget={<IngestionUI />}
      />
    )
  },
  {
    type: 'feature-widget',
    bg: '#E8EBE5',
    content: (
      <FeatureWidget
        id="02" category="Detection" pillText="Multi-Threaded" pillColor="#D3A376"
        title="Parallel threat matching across real-time frameworks" buttonText="VIEW DETECTION RULES"
        uiWidget={<DetectionUI />}
      />
    )
  },
  {
    type: 'feature-widget',
    bg: '#E2E4E8',
    content: (
      <FeatureWidget
        id="03" category="Enrichment" pillText="Live Feeds" pillColor="#8E9C7E"
        title="Real-time correlation against global threat intelligence" buttonText="EXPLORE INTEGRATIONS"
        uiWidget={<EnrichmentUI />}
      />
    )
  },
  {
    type: 'feature-widget',
    bg: '#D9DBE0',
    content: (
      <FeatureWidget
        id="04" category="Response" pillText="Containment" pillColor="#A8B0A5"
        title="Autonomous mitigation and precise threat isolation" buttonText="SEE AUTOMATION"
        uiWidget={<ResponseUI />}
      />
    )
  },
  {
    type: 'merged-ecosystem',
    customContainer: true,
    content: <MergedEcosystemExperience />
  }
];

// Video-Inspired Brutalist Architecture Text Section
// --- Refined Option 2 Timeline Sections (Natural, Detailed & Compact) ---

const paradigmItems = [
  {
    side: 'right',
    num: '01',
    category: 'THE CORE ISSUE',
    highlight: '277 Days to Contain a Breach (IBM, 2022)',
    label: 'Flawed Premise: Reactive Defense',
    text: 'Traditional security architecture operates purely post-breach, relying on static signatures and stale log indexing. By the time an alert triggers in a legacy SIEM dashboard, sophisticated actors have already established persistence across internal subnets.',
    takeaway: 'Takeaway: Relying on post-breach detection guarantees adversary persistence.'
  },
  {
    side: 'left',
    num: '02',
    category: 'HUMAN BOTTLENECK',
    highlight: 'Alert Fatigue',
    label: 'Analyst Fatigue & Fragmented Data',
    text: 'SOC teams face thousands of uncoordinated alerts a day across disconnected tools, and much of an analyst\'s shift goes to manually cross-referencing noise — creating blind spots during the attack windows that matter most.',
    takeaway: 'Takeaway: Alert overload turns human analysts into a structural liability.'
  },
  {
    side: 'right',
    num: '03',
    category: 'ASYMMETRIC ADVANTAGE',
    highlight: 'Sub-Second Exfiltration',
    label: 'Adversaries Exploit the Noise',
    text: 'While security teams manually stitch together stale SIEM queries and open triage tickets, automated adversarial scripts execute reconnaissance and data exfiltration in seconds. Asymmetry favors the attacker whenever defense relies on human reaction speeds.',
    takeaway: 'Takeaway: Automated attacks cannot be defeated by manual human triage.'
  },
];

const prototypeItems = [
  {
    side: 'left',
    num: '01',
    category: 'UNIFIED INGESTION',
    highlight: '13 Log Formats',
    label: 'One Pipeline for Every Source',
    text: "Windows, Linux, firewalls, proxies, cloud audit logs and web servers stream in through an authenticated webhook, bulk jobs or Threat Studio. Each event is parsed, decoded and normalised before a single rule runs.",
    takeaway: "Impact: one consistent view of activity, whatever produced the log."
  },
  {
    side: 'right',
    num: '02',
    category: 'CORRELATED DETECTION',
    highlight: '28 Rules · 15 Attack Chains',
    label: 'Context Instead of Alert Floods',
    text: "Every matching rule fires, events from the same attacker are linked into campaigns that never time out, and repeat alerts collapse into a single case \u2014 so analysts see the attack story, not hundreds of fragments.",
    takeaway: "Impact: fewer, richer cases with the full kill chain attached."
  },
  {
    side: 'left',
    num: '03',
    category: 'AUTOMATED RESPONSE',
    highlight: 'Under 20 ms per Event',
    label: 'Respond While the Attack Is Happening',
    text: "Severity-based SOAR rules escalate cases, block attacker IPs and notify the team in the same transaction that detected the threat, and an AI copilot answers questions about it in plain English.",
    takeaway: "Impact: containment starts in under a second, with every action audited."
  },
];

const TimelineItem = ({ item, lineColor, dotColor, textColor, labelColor, cardBg, isDark }) => (
  <Box sx={{ display: 'flex', alignItems: 'flex-start', justifyContent: item.side === 'right' ? 'flex-start' : 'flex-end', position: 'relative', mb: { xs: 0.8, md: 1 } }}>
    {/* Card */}
    <Box sx={{
      width: 'calc(50% - 36px)',
      p: { xs: 1.3, md: 1.5 },
      border: `1px solid ${lineColor}`,
      borderRadius: '4px',
      bgcolor: cardBg,
      order: item.side === 'right' ? 3 : 1,
      boxShadow: isDark ? '0 4px 20px rgba(0,0,0,0.3)' : '0 4px 20px rgba(0,0,0,0.03)',
    }}>
      {/* Top Metadata Row */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 0.6, flexWrap: 'wrap', gap: 1 }}>
        <Typography sx={{ fontFamily: 'monospace', fontSize: '0.72rem', fontWeight: 700, color: dotColor, letterSpacing: '0.08em' }}>
          [ {item.num} ] {item.category}
        </Typography>
        <Typography sx={{ fontFamily: 'monospace', fontSize: '0.72rem', fontWeight: 600, color: labelColor, opacity: 0.8 }}>
          {item.highlight}
        </Typography>
      </Box>

      {/* Main Headline */}
      <Typography sx={{ fontFamily: fontSans, fontWeight: 600, fontSize: '1.02rem', color: labelColor, mb: 0.5, letterSpacing: '-0.01em' }}>
        {item.label}
      </Typography>

      {/* Description Narrative */}
      <Typography sx={{ fontSize: '0.83rem', lineHeight: 1.5, color: textColor, opacity: 0.85, mb: 0.8 }}>
        {item.text}
      </Typography>

      {/* Bottom Takeaway Anchor */}
      <Box sx={{ pt: 0.8, borderTop: `1px dashed ${lineColor}` }}>
        <Typography sx={{ fontFamily: fontSans, fontSize: '0.75rem', fontWeight: 600, color: labelColor, opacity: 0.9 }}>
          {item.takeaway}
        </Typography>
      </Box>
    </Box>

    {/* Center dot */}
    <Box sx={{
      order: 2,
      width: '72px',
      flexShrink: 0,
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'flex-start',
      pt: { xs: 1.5, md: 1.8 },
    }}>
      <Box sx={{
        width: '12px',
        height: '12px',
        borderRadius: '50%',
        bgcolor: dotColor,
        border: `2px solid ${isDark ? '#122018' : '#F4F3ED'}`,
        boxShadow: `0 0 0 3px ${lineColor}`,
        flexShrink: 0
      }} />
    </Box>

    {/* Empty side placeholder */}
    <Box sx={{ width: 'calc(50% - 36px)', order: item.side === 'right' ? 1 : 3 }} />
  </Box>
);

const ParadigmFlowSection = () => (
  <Box sx={{ position: 'relative', width: '100%', height: '100vh', display: 'flex', flexDirection: 'column', justifyContent: 'center', pt: { xs: 6, md: 7 }, pb: { xs: 3, md: 4 }, overflow: 'hidden', bgcolor: '#F4F3ED', fontFamily: fontSans }}>
    <ChaosBackground />
    <Box sx={{ position: 'relative', zIndex: 10, width: '100%', maxWidth: '1120px', mx: 'auto', px: { xs: 4, md: 6 } }}>

      {/* Header row */}
      <Box sx={{ display: 'flex', flexDirection: { xs: 'column', md: 'row' }, justifyContent: 'space-between', alignItems: 'flex-end', mb: { xs: 2, md: 2.5 }, gap: 4 }}>
        <Box>
          <Typography sx={{ fontFamily: 'monospace', fontSize: '0.75rem', fontWeight: 700, color: '#666', letterSpacing: '0.12em', mb: 0.3 }}>
            WHY LEGACY CYBERSECURITY IS BROKEN
          </Typography>
          <Typography sx={{ fontFamily: fontSans, fontWeight: 300, fontSize: { xs: '2.5rem', md: '3.6rem' }, lineHeight: 1.0, color: '#1a1a1a', letterSpacing: '-0.03em' }}>
            The Paradigm
          </Typography>
        </Box>
        <Typography sx={{ fontSize: { xs: '0.84rem', md: '0.9rem' }, lineHeight: 1.5, color: '#2C2C2C', opacity: 0.8, maxWidth: '460px', textAlign: { xs: 'left', md: 'right' } }}>
          Traditional SIEM and SOC workflows force human analysts into a losing battle against automated adversaries. Post-breach forensics and static rules create structural blind spots.
        </Typography>
      </Box>

      {/* Timeline */}
      <Box sx={{ position: 'relative' }}>
        {/* Center vertical line */}
        <Box sx={{ position: 'absolute', left: '50%', top: 0, bottom: 0, width: '1.5px', bgcolor: '#2C2C2C', opacity: 0.2, transform: 'translateX(-50%)' }} />

        {paradigmItems.map((item, i) => (
          <TimelineItem
            key={i}
            item={item}
            lineColor="rgba(44,44,44,0.22)"
            dotColor="#1a1a1a"
            textColor="#2C2C2C"
            labelColor="#1a1a1a"
            cardBg="rgba(235,233,224,0.7)"
            isDark={false}
          />
        ))}
      </Box>

    </Box>
  </Box>
);

// Unified Prototype & Conclusion Section (4 Stages: 3 rotating dial steps + 1 conclusion footer step)
const PrototypeFlowSection = () => {
  const [activeIndex, setActiveIndex] = useState(0);
  const sectionRef = useRef(null);
  const activeIndexRef = useRef(0);
  const scrollCooldown = useRef(false);
  const sectionActiveRef = useRef(false);
  const wrapperRef = useRef(null);
  const scrollContainerRef = useRef(null);

  const totalStages = 4; // 0, 1, 2 = dial steps; 3 = conclusion footer stage

  useEffect(() => {
    activeIndexRef.current = activeIndex;
    const wrapper = wrapperRef.current;
    if (wrapper) {
      wrapper.setAttribute('data-lock-down', activeIndex < totalStages - 1 ? 'true' : 'false');
      wrapper.setAttribute('data-lock-up', activeIndex > 0 ? 'true' : 'false');
    }
  }, [activeIndex]);

  useEffect(() => {
    const el = sectionRef.current;
    if (!el) return;

    let scrollContainer = el.parentElement;
    while (scrollContainer && scrollContainer !== document.body) {
      const style = window.getComputedStyle(scrollContainer);
      if (style.overflowY === 'scroll' || style.overflowY === 'auto') break;
      scrollContainer = scrollContainer.parentElement;
    }
    if (!scrollContainer) return;
    scrollContainerRef.current = scrollContainer;

    let wrapper = el.parentElement;
    while (wrapper && wrapper.parentElement !== scrollContainer) {
      wrapper = wrapper.parentElement;
    }
    if (!wrapper) return;
    wrapperRef.current = wrapper;

    wrapper.setAttribute('data-scroll-checkpoint', 'true');
    wrapper.setAttribute('data-lock-down', 'true');
    wrapper.setAttribute('data-lock-up', 'false');

    const checkActive = () => {
      const wrapperTop = wrapper.offsetTop;
      const isDocked = Math.abs(scrollContainer.scrollTop - wrapperTop) < 10;
      sectionActiveRef.current = isDocked;
    };
    scrollContainer.addEventListener('scroll', checkActive, { passive: true });
    checkActive();

    const handleNativeWheel = (e) => {
      if (!sectionActiveRef.current) return;

      const currentIdx = activeIndexRef.current;
      const isLastStep = currentIdx >= totalStages - 1;
      const isFirstStep = currentIdx === 0;

      if (e.deltaY > 10 && isLastStep) return;
      if (e.deltaY < -10 && isFirstStep) return;

      if (Math.abs(e.deltaY) > 10) {
        e.preventDefault();
        e.stopPropagation();
        if (scrollCooldown.current) return;
        if (e.deltaY > 10) setActiveIndex(currentIdx + 1);
        else setActiveIndex(currentIdx - 1);
        scrollCooldown.current = true;
        setTimeout(() => { scrollCooldown.current = false; }, 650);
      }
    };

    el.addEventListener('wheel', handleNativeWheel, { passive: false });
    return () => {
      el.removeEventListener('wheel', handleNativeWheel);
      scrollContainer.removeEventListener('scroll', checkActive);
    };
  }, []);

  const activeItem = prototypeItems[activeIndex < 3 ? activeIndex : 2] || prototypeItems[0];

  return (
    <Box
      ref={sectionRef}
      sx={{
        position: 'relative',
        width: '100%',
        height: '100vh',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        pt: { xs: 8, md: 10 },
        pb: { xs: 4, md: 5 },
        px: { xs: 4, md: 6 },
        overflow: 'hidden',
        bgcolor: activeIndex === 3 ? '#EAD85B' : '#122018',
        transition: 'background-color 0.6s cubic-bezier(0.16, 1, 0.3, 1)',
        fontFamily: fontSans,
        userSelect: 'none'
      }}
    >
      {/* Background Dotted Horizon Line & Header (Visible during prototype dial steps 0, 1, 2) */}
      <AnimatePresence>
        {activeIndex < 3 && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.4 }}
            style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%', pointerEvents: 'none', zIndex: 1 }}
          >
            <Box sx={{ position: 'absolute', top: '34%', left: 0, width: '100%', height: '240px' }}>
              <svg width="100%" height="240" viewBox="0 0 1400 240" preserveAspectRatio="none">
                <path d="M -150 210 Q 700 -60 1550 210" stroke="#8DA696" strokeWidth="2" strokeDasharray="6 10" fill="none" opacity="0.28" />
              </svg>
            </Box>

            <Box sx={{ position: 'relative', zIndex: 10, width: '100%', maxWidth: '1240px', mx: 'auto', display: 'flex', flexDirection: { xs: 'column', md: 'row' }, justifyContent: 'space-between', alignItems: 'flex-end', pt: { xs: 8, md: 10 }, px: { xs: 4, md: 6 }, mb: 1, gap: 4, pointerEvents: 'auto' }}>
              <Typography sx={{ fontSize: { xs: '0.86rem', md: '0.92rem' }, lineHeight: 1.6, color: '#D0DED4', opacity: 0.8, maxWidth: '460px' }}>
                ThreatLens turns raw logs into correlated, explained cases and responds automatically — in milliseconds per event — with an AI copilot for the questions that follow.
              </Typography>
              <Box sx={{ textAlign: { xs: 'left', md: 'right' } }}>
                <Typography sx={{ fontFamily: 'monospace', fontSize: '0.75rem', fontWeight: 700, color: '#8DA696', letterSpacing: '0.12em', mb: 0.5 }}>
                  THE NEXT GENERATION OF CYBER DEFENSE
                </Typography>
                <Typography sx={{ fontFamily: fontSans, fontWeight: 300, fontSize: { xs: '2.6rem', md: '3.6rem' }, lineHeight: 1.0, color: '#D0DED4', letterSpacing: '-0.03em' }}>
                  The Prototype
                </Typography>
              </Box>
            </Box>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Stage Content Switcher */}
      <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center', position: 'relative', zIndex: 10 }}>
        <AnimatePresence mode="wait">
          {activeIndex < 3 ? (
            <motion.div
              key="prototype-dial-stage"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.4 }}
              style={{ width: '100%', height: '100%', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}
            >
              {/* Rotating Dial / Orbital Wheel Stage */}
              <Box sx={{ position: 'relative', height: '170px', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 5, my: 1 }}>
                <Box
                  sx={{
                    position: 'absolute',
                    top: '10px',
                    left: '50%',
                    width: '800px',
                    height: '800px',
                    transform: `translateX(-50%) rotate(${-activeIndex * 32}deg)`,
                    transition: 'transform 0.8s cubic-bezier(0.16, 1, 0.3, 1)',
                    transformOrigin: '50% 360px',
                    pointerEvents: 'none'
                  }}
                >
                  {prototypeItems.map((item, i) => {
                    const itemAngle = i * 32;
                    const isActive = i === activeIndex;
                    return (
                      <Box
                        key={i}
                        sx={{
                          position: 'absolute',
                          top: '0px',
                          left: '50%',
                          transformOrigin: '50% 360px',
                          transform: `translateX(-50%) rotate(${itemAngle}deg)`,
                          display: 'flex',
                          justifyContent: 'center',
                          alignItems: 'center',
                          pointerEvents: 'auto',
                          cursor: 'pointer'
                        }}
                        onClick={() => setActiveIndex(i)}
                      >
                        <Typography
                          sx={{
                            fontFamily: fontSans,
                            fontWeight: 800,
                            fontSize: { xs: '4.8rem', md: '6.5rem' },
                            lineHeight: 1,
                            letterSpacing: '-0.04em',
                            color: isActive ? '#D0DED4' : 'transparent',
                            WebkitTextStroke: isActive ? 'none' : '2px rgba(141, 166, 150, 0.45)',
                            textShadow: isActive ? '0 0 45px rgba(208, 222, 212, 0.35)' : 'none',
                            opacity: isActive ? 1 : 0.6,
                            transform: isActive ? 'scale(1.05)' : 'scale(0.85)',
                            transition: 'all 0.75s cubic-bezier(0.16, 1, 0.3, 1)',
                          }}
                        >
                          {item.num}
                        </Typography>
                      </Box>
                    );
                  })}
                </Box>
              </Box>

              {/* Active Card Details Centered Below Wheel */}
              <Box sx={{ position: 'relative', zIndex: 10, width: '100%', maxWidth: '780px', mx: 'auto', mb: { xs: 2, md: 4 }, textAlign: 'center' }}>
                <AnimatePresence mode="wait">
                  <motion.div
                    key={activeIndex}
                    initial={{ opacity: 0, y: 20, scale: 0.96 }}
                    animate={{ opacity: 1, y: 0, scale: 1 }}
                    exit={{ opacity: 0, y: -16, scale: 0.96 }}
                    transition={{ duration: 0.45, ease: [0.16, 1, 0.3, 1] }}
                  >
                    <Box sx={{ display: 'inline-flex', alignItems: 'center', bgcolor: '#E8E6DA', color: '#122018', px: 3, py: 0.6, borderRadius: '50px', mb: 2, boxShadow: '0 8px 20px rgba(0,0,0,0.25)' }}>
                      <Typography sx={{ fontFamily: 'monospace', fontSize: '0.75rem', fontWeight: 800, letterSpacing: '0.12em', textTransform: 'uppercase' }}>
                        • {activeItem.category} •
                      </Typography>
                    </Box>

                    <Typography sx={{ fontFamily: fontSans, fontWeight: 600, fontSize: { xs: '1.7rem', md: '2.3rem' }, color: '#D0DED4', mb: 1.2, letterSpacing: '-0.02em' }}>
                      {activeItem.label}
                    </Typography>

                    <Typography sx={{ fontSize: { xs: '0.92rem', md: '1.04rem' }, lineHeight: 1.6, color: '#D0DED4', opacity: 0.85, maxWidth: '640px', mx: 'auto', mb: 2 }}>
                      {activeItem.text}
                    </Typography>

                    <Box sx={{ display: 'inline-block', pt: 1.2, borderTop: '1px dashed rgba(141,166,150,0.35)', px: 4 }}>
                      <Typography sx={{ fontFamily: 'monospace', fontSize: '0.8rem', fontWeight: 700, color: '#8DA696', letterSpacing: '0.05em' }}>
                        {activeItem.takeaway}
                      </Typography>
                    </Box>
                  </motion.div>
                </AnimatePresence>
              </Box>
            </motion.div>
          ) : (
            <motion.div
              key="conclusion-stage"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              transition={{ duration: 0.55, ease: [0.16, 1, 0.3, 1] }}
              style={{ width: '100%', height: '100%', display: 'flex', flexDirection: 'column', justifyContent: 'center', position: 'relative' }}
            >
              {/* ── Architectural Blueprint Grid & Simple Geometric Lines ── */}
              <Box sx={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%', pointerEvents: 'none', zIndex: 1 }}>
                <svg width="100%" height="100%" style={{ position: 'absolute', top: 0, left: 0 }}>
                  <line x1="0" y1="20%" x2="100%" y2="20%" stroke="#1A1A1A" strokeWidth="1" opacity="0.22" />
                  <line x1="15%" y1="18.5%" x2="15%" y2="21.5%" stroke="#1A1A1A" strokeWidth="1.5" opacity="0.4" />
                  <line x1="50%" y1="18.5%" x2="50%" y2="21.5%" stroke="#1A1A1A" strokeWidth="1.5" opacity="0.4" />
                  <line x1="85%" y1="18.5%" x2="85%" y2="21.5%" stroke="#1A1A1A" strokeWidth="1.5" opacity="0.4" />

                  <line x1="0" y1="82%" x2="100%" y2="82%" stroke="#1A1A1A" strokeWidth="1" strokeDasharray="6 8" opacity="0.2" />
                  <circle cx="14.4%" cy="82%" r="4" fill="#1A1A1A" opacity="0.5" />
                  <circle cx="86.4%" cy="82%" r="4" fill="#1A1A1A" opacity="0.5" />

                  <line x1="22%" y1="0" x2="22%" y2="100%" stroke="#1A1A1A" strokeWidth="1" strokeDasharray="3 9" opacity="0.15" />
                  <line x1="78%" y1="0" x2="78%" y2="100%" stroke="#1A1A1A" strokeWidth="1" strokeDasharray="3 9" opacity="0.15" />

                  <line x1="22%" y1="19.3%" x2="22%" y2="20.7%" stroke="#1A1A1A" strokeWidth="1.5" opacity="0.45" />
                  <line x1="21.6%" y1="20%" x2="22.4%" y2="20%" stroke="#1A1A1A" strokeWidth="1.5" opacity="0.45" />
                  <line x1="78%" y1="19.3%" x2="78%" y2="20.7%" stroke="#1A1A1A" strokeWidth="1.5" opacity="0.45" />
                  <line x1="77.6%" y1="20%" x2="78.4%" y2="20%" stroke="#1A1A1A" strokeWidth="1.5" opacity="0.45" />
                  <line x1="22%" y1="81.3%" x2="22%" y2="82.7%" stroke="#1A1A1A" strokeWidth="1.5" opacity="0.45" />
                  <line x1="21.6%" y1="82%" x2="22.4%" y2="82%" stroke="#1A1A1A" strokeWidth="1.5" opacity="0.45" />
                  <line x1="78%" y1="81.3%" x2="78%" y2="82.7%" stroke="#1A1A1A" strokeWidth="1.5" opacity="0.45" />
                  <line x1="77.6%" y1="82%" x2="78.4%" y2="82%" stroke="#1A1A1A" strokeWidth="1.5" opacity="0.45" />

                  <line x1="5%" y1="90%" x2="28%" y2="65%" stroke="#1A1A1A" strokeWidth="1" opacity="0.16" />
                  <line x1="95%" y1="90%" x2="72%" y2="65%" stroke="#1A1A1A" strokeWidth="1" opacity="0.16" />
                  <line x1="12%" y1="12%" x2="32%" y2="32%" stroke="#1A1A1A" strokeWidth="1" strokeDasharray="4 4" opacity="0.14" />
                  <line x1="88%" y1="12%" x2="68%" y2="32%" stroke="#1A1A1A" strokeWidth="1" strokeDasharray="4 4" opacity="0.14" />
                </svg>

                <Typography sx={{ position: 'absolute', top: '17.2%', left: '15.5%', fontFamily: 'monospace', fontSize: '0.68rem', color: '#1A1A1A', opacity: 0.7, letterSpacing: '0.12em' }}>
                  [ SYS_DATUM // SEC_04_END ]
                </Typography>
                <Typography sx={{ position: 'absolute', top: '17.2%', right: '15.5%', fontFamily: 'monospace', fontSize: '0.68rem', color: '#1A1A1A', opacity: 0.7, letterSpacing: '0.12em' }}>
                  [ PIPELINE_ONLINE ]
                </Typography>
              </Box>

              {/* Rich Brutalist Wireframe Objects Collection */}
              <motion.div
                animate={{ y: [0, -15, 0], rotate: [0, 3, 0] }}
                transition={{ duration: 6, repeat: Infinity, ease: "easeInOut" }}
                style={{ position: 'absolute', top: '8%', right: '10%', pointerEvents: 'none', zIndex: 2 }}
              >
                <svg width="120" height="280" viewBox="0 0 120 300" fill="none" stroke="#1A1A1A" strokeWidth="1.5" opacity="0.38">
                  <rect x="10" y="10" width="100" height="280" rx="4" />
                  <line x1="10" y1="50" x2="110" y2="50" />
                  <line x1="10" y1="90" x2="110" y2="90" />
                  <circle cx="30" cy="30" r="5" />
                  <circle cx="50" cy="30" r="5" />
                  <rect x="25" y="110" width="70" height="150" />
                  <line x1="25" y1="130" x2="95" y2="130" />
                  <line x1="25" y1="150" x2="95" y2="150" />
                  <line x1="25" y1="170" x2="95" y2="170" />
                </svg>
              </motion.div>

              <motion.div
                animate={{ y: [0, 18, 0], rotate: [0, -6, 0] }}
                transition={{ duration: 7, repeat: Infinity, ease: "easeInOut" }}
                style={{ position: 'absolute', bottom: '12%', left: '7%', pointerEvents: 'none', zIndex: 2 }}
              >
                <svg width="170" height="170" viewBox="0 0 200 200" fill="none" stroke="#1A1A1A" strokeWidth="1.5" opacity="0.35">
                  <polygon points="100,20 180,70 150,160 50,160 20,70" />
                  <circle cx="100" cy="100" r="35" strokeDasharray="4 4" />
                  <circle cx="100" cy="100" r="18" />
                  <line x1="100" y1="20" x2="100" y2="65" />
                  <line x1="180" y1="70" x2="130" y2="88" />
                  <line x1="20" y1="70" x2="70" y2="88" />
                  <circle cx="100" cy="100" r="6" fill="#1A1A1A" />
                </svg>
              </motion.div>

              <motion.div
                animate={{ rotate: [0, 360] }}
                transition={{ duration: 35, repeat: Infinity, ease: "linear" }}
                style={{ position: 'absolute', top: '10%', left: '9%', pointerEvents: 'none', zIndex: 2 }}
              >
                <svg width="150" height="150" viewBox="0 0 160 160" fill="none" stroke="#1A1A1A" strokeWidth="1.2" opacity="0.32">
                  <circle cx="80" cy="80" r="70" strokeDasharray="8 6" />
                  <circle cx="80" cy="80" r="48" />
                  <path d="M 80 10 A 70 70 0 0 1 150 80 L 80 80 Z" fill="#1A1A1A" opacity="0.15" />
                  <line x1="80" y1="0" x2="80" y2="160" strokeDasharray="2 4" />
                  <line x1="0" y1="80" x2="160" y2="80" strokeDasharray="2 4" />
                </svg>
              </motion.div>

              <motion.div
                animate={{ y: [0, -12, 0], x: [0, 8, 0] }}
                transition={{ duration: 8, repeat: Infinity, ease: "easeInOut" }}
                style={{ position: 'absolute', top: '42%', left: '5%', pointerEvents: 'none', zIndex: 2 }}
              >
                <svg width="100" height="110" viewBox="0 0 100 110" fill="none" stroke="#1A1A1A" strokeWidth="1.3" opacity="0.3">
                  <polygon points="50,5 95,28 95,80 50,105 5,80 5,28" />
                  <line x1="50" y1="5" x2="50" y2="55" />
                  <line x1="95" y1="28" x2="50" y2="55" />
                  <line x1="5" y1="28" x2="50" y2="55" />
                  <line x1="50" y1="55" x2="50" y2="105" />
                </svg>
              </motion.div>

              <motion.div
                animate={{ y: [0, 15, 0], rotate: [0, 5, 0] }}
                transition={{ duration: 9, repeat: Infinity, ease: "easeInOut" }}
                style={{ position: 'absolute', bottom: '10%', right: '8%', pointerEvents: 'none', zIndex: 2 }}
              >
                <svg width="140" height="160" viewBox="0 0 140 160" fill="none" stroke="#1A1A1A" strokeWidth="1.4" opacity="0.34">
                  <path d="M 70 10 L 125 35 V 80 C 125 120 70 150 70 150 C 70 150 15 120 15 80 V 35 L 70 10 Z" />
                  <circle cx="70" cy="75" r="22" strokeDasharray="3 3" />
                  <circle cx="70" cy="75" r="8" fill="#1A1A1A" />
                  <line x1="70" y1="30" x2="70" y2="53" />
                  <line x1="70" y1="97" x2="70" y2="125" />
                </svg>
              </motion.div>

              <motion.div
                animate={{ y: [0, 10, 0], scale: [1, 1.05, 1] }}
                transition={{ duration: 7.5, repeat: Infinity, ease: "easeInOut" }}
                style={{ position: 'absolute', top: '5%', left: '46%', pointerEvents: 'none', zIndex: 2 }}
              >
                <svg width="110" height="110" viewBox="0 0 100 100" fill="none" stroke="#1A1A1A" strokeWidth="1.2" opacity="0.25">
                  <polygon points="50,10 85,30 85,70 50,90 15,70 15,30" />
                  <polygon points="50,25 72,38 72,62 50,75 28,62 28,38" strokeDasharray="4 3" />
                </svg>
              </motion.div>

              {/* Conclusion Text Centerpiece */}
              <Box sx={{ maxWidth: '860px', mx: 'auto', textAlign: 'center', px: 2, position: 'relative', zIndex: 20 }}>
                <Box sx={{ display: 'inline-flex', alignItems: 'center', bgcolor: 'transparent', border: '1px solid rgba(26,26,26,0.3)', px: 2.5, py: 0.5, borderRadius: '50px', mb: 3 }}>
                  <Typography sx={{ fontFamily: 'monospace', fontSize: '0.78rem', color: '#1A1A1A', letterSpacing: '0.15em', textTransform: 'uppercase', fontWeight: 700 }}>
                    PROJECT CONCLUSION
                  </Typography>
                </Box>

                <Typography sx={{ fontFamily: fontSans, fontSize: { xs: '1.1rem', md: '1.35rem' }, color: '#1A1A1A', opacity: 0.85, lineHeight: 1.6, fontWeight: 400, mb: 4, maxWidth: '720px', mx: 'auto' }}>
                  This is the dawn of proactive intelligence. The architecture is robust, the prototype is live, and the future of autonomous cybersecurity is unfolding before us. We are no longer just monitoring threats; we are anticipating them.
                </Typography>

                <Typography sx={{ fontFamily: fontSans, fontWeight: 500, fontSize: { xs: '2.8rem', md: '4.8rem', lg: '5.5rem' }, color: '#1A1A1A', letterSpacing: '-0.04em', lineHeight: 1.05 }}>
                  Made to detect, designed to endure.
                </Typography>
              </Box>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Step Indicators (4 dots: 0, 1, 2 for dial, 3 for conclusion) */}
        <Box sx={{ display: 'flex', justifyContent: 'center', gap: 1.2, mt: 3, position: 'relative', zIndex: 25 }}>
          {[0, 1, 2, 3].map((stageIdx) => (
            <Box
              key={stageIdx}
              onClick={() => setActiveIndex(stageIdx)}
              sx={{
                width: activeIndex === stageIdx ? '28px' : '8px',
                height: '8px',
                borderRadius: '4px',
                bgcolor: activeIndex === 3 ? (activeIndex === stageIdx ? '#1A1A1A' : 'rgba(26,26,26,0.35)') : (activeIndex === stageIdx ? '#D0DED4' : 'rgba(141,166,150,0.3)'),
                cursor: 'pointer',
                transition: 'all 0.4s cubic-bezier(0.16, 1, 0.3, 1)'
              }}
            />
          ))}
        </Box>
      </Box>
    </Box>
  );
};

// Add the architecture sections to the global array
SECTIONS.push(
  {
    type: 'text-white',
    bg: '#F4F3ED',
    content: <ParadigmFlowSection />
  },
  {
    type: 'text-dark',
    bg: '#122018',
    content: <PrototypeFlowSection />
  }
);

const Navbar = () => {
  const navigate = useNavigate();
  return (
    <Box sx={{
      position: 'fixed', top: 0, left: 0, right: 0, zIndex: 1000,
      display: 'flex', justifyContent: 'space-between', alignItems: 'center',
      px: { xs: 2, md: 6 }, py: { xs: 2, md: 3 },
      background: 'transparent',
      mixBlendMode: 'difference',
      color: '#fff'
    }}>
      <Box sx={{ display: 'flex', alignItems: 'center' }}>
        <Typography onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })} sx={{
          fontFamily: fontSans, fontWeight: 500, fontSize: { xs: '1.15rem', md: '1.4rem' },
          cursor: 'pointer', letterSpacing: '-0.02em', whiteSpace: 'nowrap'
        }}>
          ThreatLens
        </Typography>
      </Box>
      <Box sx={{ display: 'flex', gap: { xs: 1, md: 2 } }}>
        {[
          { label: 'OVERVIEW', path: '/', desktopOnly: true },
          { label: 'ABOUT', path: '/about', desktopOnly: true },
          { label: 'LOG IN', path: '/login' },
          { label: 'CREATE ACCESS', mobileLabel: 'SIGN UP', path: '/signup' }
        ].map((btn) => (
          <Button
            key={btn.label}
            onClick={() => navigate(btn.path)}
            sx={{
              display: btn.desktopOnly ? { xs: 'none', md: 'inline-flex' } : 'inline-flex',
              background: btn.label === 'CREATE ACCESS' ? '#fff' : 'transparent',
              color: btn.label === 'CREATE ACCESS' ? '#000' : '#fff',
              borderRadius: '50px',
              px: { xs: 1.6, md: 3 }, py: 0.6, minWidth: 0, whiteSpace: 'nowrap', fontFamily: fontSans, fontWeight: 700,
              fontSize: { xs: '0.68rem', md: '0.75rem' }, textTransform: 'uppercase', letterSpacing: '0.05em',
              border: btn.label === 'CREATE ACCESS' ? '1px solid #fff' : '1px solid rgba(255,255,255,0.3)',
              '&:hover': { background: '#fff', color: '#000', mixBlendMode: 'normal' }
            }}
          >
            <Box component="span" sx={{ display: { xs: 'none', sm: 'inline' } }}>{btn.label}</Box>
            <Box component="span" sx={{ display: { xs: 'inline', sm: 'none' } }}>{btn.mobileLabel || btn.label}</Box>
          </Button>
        ))}
      </Box>
    </Box>
  );
};

const PanelContent = ({ data, scrollYProgress }) => {
  if (typeof data.content === 'function') {
    return data.content(scrollYProgress);
  }
  if (data.type !== 'image') {
    return data.content;
  }
  return null;
};

// Custom lightweight smooth scroll hook to provide momentum without heavy libraries
const useSmoothScroll = (containerRef) => {
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    let targetY = container.scrollTop;
    let currentY = container.scrollTop;
    let rafId = null;
    let isScrolling = false;

    const lerp = (start, end, factor) => start + (end - start) * factor;

    const handleWheel = (e) => {
      // If an internal component handled scroll or modal is open, do NOT hijack wheel events!
      if (e.defaultPrevented || document.body.style.overflow === 'hidden' || e.target.closest('[data-modal-scroll="true"]') || e.target.closest('[data-wheel-lock="true"]')) {
        targetY = container.scrollTop;
        currentY = container.scrollTop;
        return;
      }

      // Prevent native rigid scroll
      e.preventDefault();

      // Calculate target position based on scroll wheel intensity
      targetY += e.deltaY;

      // ── Checkpoint momentum gating ────────────────────────────────────────────
      // When fast-scrolling, accumulated targetY can overshoot the PrototypeFlowSection.
      // These data-attrs (set by PrototypeFlowSection) tell us whether to clamp or not.
      // 300px window = generous enough to catch even large fast-scroll deltas.
      const checkpoints = container.querySelectorAll('[data-scroll-checkpoint="true"]');
      checkpoints.forEach((cp) => {
        const dockY = cp.offsetTop;
        // Scrolling DOWN into a section that still has steps → clamp
        if (e.deltaY > 0 && container.scrollTop <= dockY + 300 && targetY > dockY && cp.getAttribute('data-lock-down') === 'true') {
          targetY = dockY;
        }
        // Scrolling UP into a section that still has steps → clamp
        if (e.deltaY < 0 && container.scrollTop >= dockY - 300 && targetY < dockY && cp.getAttribute('data-lock-up') === 'true') {
          targetY = dockY;
        }
      });

      // Clamp to top and bottom bounds
      targetY = Math.max(0, Math.min(targetY, container.scrollHeight - container.clientHeight));

      // Start the animation loop if not already running
      if (!isScrolling) {
        isScrolling = true;
        update();
      }
    };

    const update = () => {
      // Smoothly interpolate towards the target
      currentY = lerp(currentY, targetY, 0.08);

      container.scrollTop = currentY;

      // Stop the loop when we are close enough to the target
      if (Math.abs(targetY - currentY) < 1) {
        currentY = targetY;
        container.scrollTop = currentY;
        isScrolling = false;
        return;
      }

      rafId = requestAnimationFrame(update);
    };

    // { passive: false } is required so we can call e.preventDefault()
    container.addEventListener('wheel', handleWheel, { passive: false });

    return () => {
      container.removeEventListener('wheel', handleWheel);
      if (rafId) cancelAnimationFrame(rafId);
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
};

const LandingPage = () => {
  const scrollContainerRef = useRef(null);

  // Apply our custom buttery smooth momentum scroll
  useSmoothScroll(scrollContainerRef);

  // Hook into the scroll progress for parallax effects in child sections
  const { scrollYProgress } = useScroll({ container: scrollContainerRef });

  return (
    <Box
      ref={scrollContainerRef}
      sx={{
        bgcolor: '#F9F9F7',
        height: '100vh',
        width: '100vw',
        overflowY: 'scroll',
        overflowX: 'hidden',
        // Hide scrollbar for a cleaner premium look
        '&::-webkit-scrollbar': { display: 'none' },
        msOverflowStyle: 'none',
        scrollbarWidth: 'none',
      }}
    >
      <Navbar />

      {/* 
        Zero-Lag Architecture:
        We use 'position: sticky' to make the sections perfectly slide over each other natively.
        Our custom useSmoothScroll hook intercepts the mouse wheel and applies a mathematical momentum curve.
      */}
      {SECTIONS.map((sec, i) => {
        if (sec.customContainer) {
          return (
            <Box key={i} sx={{ position: 'relative', zIndex: i, width: '100%' }}>
              {sec.content}
            </Box>
          );
        }
        return (
          <Box
            key={i}
            sx={{
              position: 'sticky',
              top: 0,
              left: 0,
              width: '100%',
              height: '100vh',
              zIndex: i,
              background: sec.bg || '#000',
              boxShadow: sec.boxShadow || 'none',
              overflow: 'hidden',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}
          >
            <PanelContent data={sec} scrollYProgress={scrollYProgress} />
          </Box>
        );
      })}
    </Box>
  );
};

export default LandingPage;
