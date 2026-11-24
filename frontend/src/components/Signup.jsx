// src/components/Signup.jsx
import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { motion, AnimatePresence } from 'framer-motion';
import { getApiErrorMessage } from '../services/api';
import Logo from './brand/Logo';

const fontSans = '"Inter", "Helvetica Neue", Arial, sans-serif';
const fontMono = '"JetBrains Mono", monospace';

export default function Signup() {
  const [form, setForm] = useState({ username: '', full_name: '', email: '', organization: '', password: '', confirm: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [focused, setFocused] = useState('');
  const { signup } = useAuth();
  const navigate = useNavigate();

  const validate = () => {
    if (!form.username || !form.email || !form.password) return 'Username, email and password are required.';
    if (!/^[A-Za-z0-9_.-]{3,32}$/.test(form.username)) return 'Username must be 3-32 characters: letters, numbers, ".", "_" or "-".';
    if (form.password.length < 8) return 'Password must be at least 8 characters.';
    if (!/[A-Z]/.test(form.password) || !/[a-z]/.test(form.password) || !/\d/.test(form.password)) return 'Password needs an uppercase letter, a lowercase letter and a number.';
    if (form.password !== form.confirm) return 'Passwords do not match.';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email)) return 'Enter a valid email address.';
    return null;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const err = validate();
    if (err) { setError(err); return; }
    setLoading(true); setError('');
    try {
      await signup({ username: form.username, full_name: form.full_name || undefined, email: form.email, organization: form.organization || undefined, password: form.password });
      navigate('/dashboard', { replace: true });
    } catch (err) {
      setError(getApiErrorMessage(err, 'Failed to initialize node. Try a different username.'));
    } finally { setLoading(false); }
  };

  return (
    <div style={{ 
      minHeight: '100vh', 
      background: '#F9F9F7', 
      color: '#111111', 
      display: 'flex', 
      flexDirection: 'column',
      fontFamily: fontSans 
    }}>
      <style>{`
        .ledger-input {
          width: 100%;
          background: transparent;
          border: none;
          color: #111111;
          font-family: ${fontSans};
          font-size: 1.1rem;
          font-weight: 500;
          padding: 14px 0;
          outline: none;
          box-sizing: border-box;
        }
        .ledger-input::placeholder {
          color: #A0A09C;
          font-weight: 400;
        }
        .ledger-row {
          border-bottom: 1px solid rgba(0,0,0,0.12);
          position: relative;
          transition: border-color 0.3s ease;
        }
        .ledger-row-focused {
          border-bottom: 2px solid #111111;
        }
      `}</style>

      {/* Top Architectural Bar */}
      <div style={{ 
        display: 'flex', 
        justifyContent: 'space-between', 
        alignItems: 'center', 
        padding: '24px 48px', 
        borderBottom: '1px solid rgba(0,0,0,0.12)',
        background: '#F9F9F7'
      }}>
        <div 
          onClick={() => navigate('/')} 
          style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 16 }}
        >
          <Logo size={30} tone="dark" />
        </div>
        <Link to="/" style={{ fontFamily: fontMono, fontSize: '0.75rem', color: '#111111', textDecoration: 'none', fontWeight: 700, letterSpacing: '0.05em' }}>
          ← BACK TO HOME
        </Link>
      </div>

      {/* Main Architectural Ledger Split (ZERO CARDS!) */}
      <div style={{ flex: 1, display: 'flex', flexDirection: window.innerWidth < 900 ? 'column' : 'row' }}>
        
        {/* Left Sidebar — Ledger Index */}
        <div style={{ 
          width: window.innerWidth < 900 ? '100%' : '360px', 
          borderRight: window.innerWidth < 900 ? 'none' : '1px solid rgba(0,0,0,0.12)', 
          borderBottom: window.innerWidth < 900 ? '1px solid rgba(0,0,0,0.12)' : 'none',
          padding: '48px 48px', 
          display: 'flex', 
          flexDirection: 'column', 
          justifyContent: 'space-between',
          flexShrink: 0
        }}>
          <div>
            <div style={{ fontFamily: fontMono, fontSize: '0.7rem', fontWeight: 700, color: '#888', letterSpacing: '0.15em', marginBottom: '24px' }}>
              GET STARTED
            </div>

            <h2 style={{ fontWeight: 900, fontSize: '2.2rem', letterSpacing: '-0.04em', margin: '0 0 32px', lineHeight: 1.1 }}>
              Create your<br/>SOC workspace.
            </h2>

            {['WATCH ATTACKS ON A LIVE MAP', 'TRIAGE CORRELATED CASES', 'AUTOMATE THE RESPONSE', 'ASK THE AI COPILOT'].map((item, idx) => (
              <div key={idx} style={{ borderBottom: '1px solid rgba(0,0,0,0.12)', padding: '16px 0', display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ fontFamily: fontMono, fontSize: '0.72rem', fontWeight: 700, color: '#111', letterSpacing: '0.08em' }}>
                  0{idx + 1} / {item}
                </span>
                <span style={{ fontFamily: fontMono, fontSize: '0.7rem', color: idx === 0 ? '#111' : '#888' }}>
                  {'✓'}
                </span>
              </div>
            ))}
          </div>

          <div style={{ marginTop: '32px' }}>
            <figure style={{ margin: 0, borderRadius: '14px', overflow: 'hidden', background: '#0b0f14', boxShadow: '0 18px 40px rgba(0,0,0,0.18)', border: '1px solid rgba(0,0,0,0.08)' }}>
              <img
                src="/assets/images/attack-campaigns.webp"
                alt="ThreatLens attack campaign view"
                width="1600"
                height="1067"
                decoding="async"
                style={{ display: 'block', width: '100%', height: 'auto', aspectRatio: '3 / 2', objectFit: 'cover' }}
              />
            </figure>
          </div>

          <div style={{ fontFamily: fontMono, fontSize: '0.7rem', color: '#666', lineHeight: 1.6, borderTop: '1px solid rgba(0,0,0,0.12)', paddingTop: '24px', marginTop: '32px' }}>
            <div style={{ fontWeight: 700, color: '#111', marginBottom: '4px' }}>→ First account becomes the administrator</div>
            <div>The first person to sign up gets the admin role and can invite analysts and read-only viewers from Settings → Users.</div>
          </div>
        </div>

        {/* Right Form Area — Edge-to-Edge Ledger Form Sheet */}
        <div style={{ flex: 1, padding: '48px 64px', display: 'flex', flexDirection: 'column', justify: 'center', maxWidth: '780px' }}>
          
          <div style={{ marginBottom: '36px' }}>
            <div style={{ fontFamily: fontMono, fontSize: '0.75rem', fontWeight: 700, color: '#111', letterSpacing: '0.12em', marginBottom: '8px' }}>
              NEW ACCOUNT
            </div>
            <h1 style={{ fontSize: '2.8rem', fontWeight: 900, letterSpacing: '-0.04em', margin: 0, lineHeight: 1 }}>
              Create account.
            </h1>
          </div>

          <AnimatePresence>
            {error && (
              <motion.div 
                initial={{ opacity: 0, height: 0 }} 
                animate={{ opacity: 1, height: 'auto' }} 
                exit={{ opacity: 0, height: 0 }}
                style={{ 
                  fontFamily: fontMono, 
                  fontSize: '0.8rem', 
                  color: '#D32F2F', 
                  borderTop: '1px solid #D32F2F',
                  borderBottom: '1px solid #D32F2F',
                  padding: '14px 0', 
                  marginBottom: '28px' 
                }}
              >
                ⚠️ REGISTRATION EXCEPTION: {error}
              </motion.div>
            )}
          </AnimatePresence>

          <form onSubmit={handleSubmit}>
            <div style={{ display: 'grid', gridTemplateColumns: window.innerWidth < 600 ? '1fr' : '1fr 1fr', gap: '24px', marginBottom: '24px' }}>
              {/* Field 1: Username */}
              <div className={`ledger-row ${focused === 'username' ? 'ledger-row-focused' : ''}`}>
                <label style={{ fontFamily: fontMono, fontSize: '0.65rem', fontWeight: 700, color: focused === 'username' ? '#111' : '#777', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                  USERNAME *
                </label>
                <input className="ledger-input" type="text" placeholder="analyst_01"
                  value={form.username} onChange={e => setForm({ ...form, username: e.target.value })}
                  onFocus={() => setFocused('username')} onBlur={() => setFocused('')}
                  autoComplete="username" autoFocus />
              </div>

              {/* Field 2: Full Name */}
              <div className={`ledger-row ${focused === 'full_name' ? 'ledger-row-focused' : ''}`}>
                <label style={{ fontFamily: fontMono, fontSize: '0.65rem', fontWeight: 700, color: focused === 'full_name' ? '#111' : '#777', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                  FULL NAME
                </label>
                <input className="ledger-input" type="text" placeholder="Jane Smith"
                  value={form.full_name} onChange={e => setForm({ ...form, full_name: e.target.value })}
                  onFocus={() => setFocused('full_name')} onBlur={() => setFocused('')}
                  autoComplete="name" />
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: window.innerWidth < 600 ? '1fr' : '1fr 1fr', gap: '24px', marginBottom: '24px' }}>
              {/* Field 3: Email */}
              <div className={`ledger-row ${focused === 'email' ? 'ledger-row-focused' : ''}`}>
                <label style={{ fontFamily: fontMono, fontSize: '0.65rem', fontWeight: 700, color: focused === 'email' ? '#111' : '#777', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                  WORK EMAIL *
                </label>
                <input className="ledger-input" type="email" placeholder="analyst@company.com"
                  value={form.email} onChange={e => setForm({ ...form, email: e.target.value })}
                  onFocus={() => setFocused('email')} onBlur={() => setFocused('')}
                  autoComplete="email" />
              </div>

              {/* Field 4: Organization */}
              <div className={`ledger-row ${focused === 'org' ? 'ledger-row-focused' : ''}`}>
                <label style={{ fontFamily: fontMono, fontSize: '0.65rem', fontWeight: 700, color: focused === 'org' ? '#111' : '#777', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                  ORGANIZATION
                </label>
                <input className="ledger-input" type="text" placeholder="Acme Security Corp"
                  value={form.organization} onChange={e => setForm({ ...form, organization: e.target.value })}
                  onFocus={() => setFocused('org')} onBlur={() => setFocused('')} />
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: window.innerWidth < 600 ? '1fr' : '1fr 1fr', gap: '24px', marginBottom: '36px' }}>
              {/* Field 5: Password */}
              <div className={`ledger-row ${focused === 'pass' ? 'ledger-row-focused' : ''}`}>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <label style={{ fontFamily: fontMono, fontSize: '0.65rem', fontWeight: 700, color: focused === 'pass' ? '#111' : '#777', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                    PASSWORD *
                  </label>
                  <span onClick={() => setShowPassword(!showPassword)} style={{ fontFamily: fontMono, fontSize: '0.65rem', fontWeight: 700, cursor: 'pointer', color: '#111', textDecoration: 'underline' }}>
                    {showPassword ? 'HIDE' : 'SHOW'}
                  </span>
                </div>
                <input className="ledger-input" type={showPassword ? 'text' : 'password'} placeholder="Min 8 characters"
                  value={form.password} onChange={e => setForm({ ...form, password: e.target.value })}
                  onFocus={() => setFocused('pass')} onBlur={() => setFocused('')}
                  autoComplete="new-password" />
              </div>

              {/* Field 6: Confirm */}
              <div className={`ledger-row ${focused === 'confirm' ? 'ledger-row-focused' : ''}`}>
                <label style={{ fontFamily: fontMono, fontSize: '0.65rem', fontWeight: 700, color: focused === 'confirm' ? '#111' : '#777', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                  CONFIRM PASSWORD *
                </label>
                <input className="ledger-input" type={showPassword ? 'text' : 'password'} placeholder="Repeat password"
                  value={form.confirm} onChange={e => setForm({ ...form, confirm: e.target.value })}
                  onFocus={() => setFocused('confirm')} onBlur={() => setFocused('')}
                  autoComplete="new-password" />
              </div>
            </div>

            {/* Full Width Architectural Bar */}
            <motion.button type="submit" disabled={loading}
              whileHover={{ bgcolor: '#222222' }} whileTap={{ scale: 0.995 }}
              style={{
                width: '100%', background: '#111111', color: '#FFFFFF', border: 'none', padding: '24px 32px',
                fontFamily: fontMono, fontWeight: 700, fontSize: '0.9rem', textTransform: 'uppercase',
                letterSpacing: '0.15em', cursor: loading ? 'not-allowed' : 'pointer',
                opacity: loading ? 0.7 : 1, transition: 'all 0.2s',
                display: 'flex', justifyContent: 'space-between', alignItems: 'center'
              }}>
              <span>{loading ? 'CREATING ACCOUNT…' : 'CREATE ACCOUNT'}</span>
              <span>→</span>
            </motion.button>
          </form>

          <div style={{ marginTop: '40px', paddingTop: '20px', borderTop: '1px solid rgba(0,0,0,0.12)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontFamily: fontSans, fontSize: '0.9rem', color: '#666' }}>Already have an account?</span>
            <Link to="/login" style={{ fontFamily: fontMono, fontSize: '0.8rem', fontWeight: 700, color: '#111111', textDecoration: 'none', borderBottom: '2px solid #111111', paddingBottom: '4px', letterSpacing: '0.05em' }}>
              SIGN IN →
            </Link>
          </div>

        </div>

      </div>
    </div>
  );
}
