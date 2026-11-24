import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { useAuth } from '../contexts/AuthContext';
import { useTheme } from '../contexts/ThemeContext';
import { useLive } from '../contexts/LiveEventsContext';
import { LogoMark } from './brand/Logo';
import LiveToasts, { LivePill } from './live/LiveToasts';

const NAV_ITEMS = [
  { id: 'dashboard', label: 'Dashboard', icon: 'DB', path: '/dashboard' },
  { id: 'threat-map', label: 'Threat Map', icon: 'MP', path: '/threat-map' },
  { id: 'executive', label: 'Executive View', icon: 'EX', path: '/executive' },
  { id: 'analyze', label: 'Threat Studio', icon: 'TS', path: '/analyze' },
  { id: 'campaigns', label: 'Campaigns', icon: 'CP', path: '/campaigns' },
  { id: 'investigate', label: 'Investigate', icon: 'IN', path: '/investigate' },
  { id: 'soar', label: 'SOAR', icon: 'SR', path: '/soar' },
  { id: 'intel', label: 'Threat Intel', icon: 'TI', path: '/intel' },
  { id: 'copilot', label: 'AI Copilot', icon: 'AI', path: '/copilot' },
  { id: 'mitre', label: 'MITRE ATT&CK', icon: 'MT', path: '/mitre' },
  { id: 'assets', label: 'Assets', icon: 'AS', path: '/assets' },
  { id: 'reports', label: 'Reports', icon: 'RP', path: '/reports' },
  { id: 'demo', label: 'Live Demo', icon: 'LD', path: '/demo' },
  { id: 'settings', label: 'Settings', icon: 'ST', path: '/settings' },
].map((item, index) => ({ ...item, tag: String(index + 1).padStart(2, '0') }));

export default function AppShell({ children }) {
  const navigate = useNavigate();
  const location = useLocation();
  const { user, logout } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const [collapsed, setCollapsed] = useState(false);
  const [showUserMenu, setShowUserMenu] = useState(false);
  const live = useLive();

  const active = location.pathname.startsWith('/incidents')
    ? 'investigate'
    : NAV_ITEMS.find((item) => location.pathname.startsWith(item.path))?.id;
  const initials = user?.full_name
    ? user.full_name.split(' ').map((part) => part[0]).join('').slice(0, 2).toUpperCase()
    : user?.username?.slice(0, 2).toUpperCase() || 'TL';

  return (
    <div className={`app-shell ${collapsed ? 'shell-collapsed' : ''} ${theme === 'light' ? 'theme-light' : 'theme-dark'}`}>
      <aside className="sidebar">
        <div className="sidebar-brand">
          <span style={{ display: 'inline-flex', cursor: 'pointer' }} onClick={() => navigate('/')} title="ThreatLens home">
            <LogoMark size={32} />
          </span>

          {!collapsed && (
            <motion.div
              className="brand-text"
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.3 }}
            >
              <span className="brand-name">ThreatLens</span>
              <span className="brand-version">Security Operations</span>
            </motion.div>
          )}

          <button
            className="collapse-btn"
            onClick={() => setCollapsed(!collapsed)}
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            title={collapsed ? 'Expand' : 'Collapse'}
          >
            {collapsed ? '>' : '<'}
          </button>
        </div>

        <div className="sidebar-section">
          {!collapsed && (
            <div className="sidebar-heading">
              <span className="sidebar-kicker">Navigation</span>
              <LivePill />
            </div>
          )}

          <nav className="sidebar-nav">
            {NAV_ITEMS.map((item, index) => (
              <div key={item.id} className="nav-item-wrapper">
                <motion.button
                  className={`nav-item ${active === item.id ? 'nav-active' : ''}`}
                  onClick={() => navigate(item.path)}
                  title={collapsed ? item.label : undefined}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: index * 0.04, duration: 0.3 }}
                  whileTap={{ scale: 0.98 }}
                >
                  <span className="nav-icon">{item.icon}</span>
                  {!collapsed && (
                    <>
                      <span className="nav-label">{item.label}</span>
                      <span className="nav-tag">{item.tag}</span>
                    </>
                  )}
                </motion.button>

                {collapsed && (
                  <div className="nav-tooltip">
                    <strong>{item.label}</strong>
                  </div>
                )}
              </div>
            ))}
          </nav>
        </div>

        <div className="sidebar-footer">
          <div style={{ display: 'flex', gap: '8px', paddingBottom: '8px' }}>
            <button
              className="btn-ghost"
              onClick={toggleTheme}
              style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px', border: '1px solid var(--tl-border, rgba(215, 163, 90, 0.1))', padding: '6px' }}
              title="Toggle theme"
            >
              {theme === 'light' ? '🌙' : '☀️'}{!collapsed && (theme === 'light' ? ' Dark' : ' Light')}
            </button>
            {live && (
              <button
                className="btn-ghost"
                onClick={live.toggleMute}
                style={{ flex: 1, border: '1px solid var(--tl-border, rgba(215, 163, 90, 0.1))', padding: '6px' }}
                title={live.muted ? 'Turn live alerts on' : 'Mute live alerts'}
              >
                {live.muted ? '🔕' : '🔔'}{!collapsed && (live.muted ? ' Muted' : ' Alerts')}
              </button>
            )}
          </div>
          <div className="user-area" onClick={() => setShowUserMenu(!showUserMenu)} title="Account options">
            <div className="user-avatar">{initials}</div>
            {!collapsed && (
              <div className="user-info">
                <span className="user-name">{user?.full_name || user?.username}</span>
                <span className="user-role">{user?.role || 'analyst'}</span>
              </div>
            )}
          </div>

          <AnimatePresence>
            {showUserMenu && (
              <motion.div
                className="user-menu"
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: 6 }}
                transition={{ duration: 0.2 }}
              >
                <div className="user-menu-header">
                  <span className="user-menu-email">{user?.email}</span>
                </div>
                <button
                  className="user-menu-item"
                  onClick={() => {
                    logout();
                    navigate('/');
                  }}
                >
                  Sign out →
                </button>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </aside>

      <LiveToasts />
      <main className="app-main">
        <motion.div
          className="shell-content"
          key={location.pathname}
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
        >
          {children}
        </motion.div>
      </main>
    </div>
  );
}
