// src/services/api.jsx — shared HTTP client for the ThreatLens API
import axios from 'axios';

// Same-origin by default: nginx (docker) and the CRA dev-server proxy both forward /api → backend.
// Override with REACT_APP_API_BASE_URL (e.g. https://api.example.com/api/v1) for split deployments.
export const API_BASE_URL = (process.env.REACT_APP_API_BASE_URL || '/api/v1').replace(/\/$/, '');
export const API_ORIGIN = API_BASE_URL.replace(/\/api\/v1$/, '');

// Long-running operations get a generous timeout; everything else fails fast.
export const LONG_TIMEOUT = 180000;

const TOKEN_KEY = 'token';
const REFRESH_KEY = 'refresh_token';

export const tokenStore = {
  get access() { return localStorage.getItem(TOKEN_KEY); },
  get refresh() { return localStorage.getItem(REFRESH_KEY); },
  set({ access_token, refresh_token }) {
    if (access_token) localStorage.setItem(TOKEN_KEY, access_token);
    if (refresh_token) localStorage.setItem(REFRESH_KEY, refresh_token);
  },
  clear() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(REFRESH_KEY);
  },
};

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: { 'Content-Type': 'application/json' },
  timeout: 30000,
});

export const getApiErrorMessage = (error, fallback = 'Something went wrong.') => {
  if (error?.code === 'ECONNABORTED') return 'The request timed out. The server may still be processing it — refresh in a moment.';
  if (!error?.response && error?.message === 'Network Error') return 'Cannot reach the ThreatLens API. Is the backend running?';
  if (error?.response?.status === 403) return error.response.data?.detail || 'You do not have permission to perform this action.';
  if (error?.response?.status === 429) return 'Too many requests — please wait a moment and try again.';

  const detail = error?.response?.data?.detail;
  if (typeof detail === 'string' && detail.trim()) return detail;
  if (Array.isArray(detail) && detail.length > 0) {
    const text = detail
      .map((item) => {
        if (typeof item === 'string') return item;
        const field = Array.isArray(item?.loc) ? item.loc.filter((p) => p !== 'body').join(' › ') : '';
        return item?.msg ? (field ? `${field}: ${item.msg}` : item.msg) : null;
      })
      .filter(Boolean)
      .join(' | ');
    if (text) return text;
  }
  const message = error?.response?.data?.message || error?.message;
  return typeof message === 'string' && message.trim() ? message : fallback;
};

// ── Request interceptor: attach JWT ─────────────────────────────────────────
api.interceptors.request.use((request) => {
  const token = tokenStore.access;
  if (token) request.headers.Authorization = `Bearer ${token}`;
  return request;
});

// ── Response interceptor: transparently refresh an expired access token ─────
let refreshPromise = null;

const redirectToLogin = () => {
  tokenStore.clear();
  if (!window.location.pathname.startsWith('/login')) {
    window.location.assign('/login');
  }
};

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const original = error.config || {};
    const isAuthCall = /\/auth\/(login|refresh|signup)/.test(original.url || '');

    if (error.response?.status !== 401 || original._retry || isAuthCall) {
      return Promise.reject(error);
    }
    if (!tokenStore.refresh) {
      redirectToLogin();
      return Promise.reject(error);
    }

    original._retry = true;
    try {
      refreshPromise = refreshPromise || axios
        .post(`${API_BASE_URL}/auth/refresh`, { refresh_token: tokenStore.refresh })
        .then(({ data }) => {
          tokenStore.set(data);
          return data.access_token;
        })
        .finally(() => { refreshPromise = null; });

      const newToken = await refreshPromise;
      original.headers = { ...(original.headers || {}), Authorization: `Bearer ${newToken}` };
      return api(original);
    } catch (refreshError) {
      redirectToLogin();
      return Promise.reject(refreshError);
    }
  }
);

// ── Convenience calls ───────────────────────────────────────────────────────
export const analyzeLog = async (logText) => {
  const response = await api.post('/analysis/analyze', { log: logText }, { timeout: LONG_TIMEOUT });
  return response.data;
};

export const parseLog = async (logText) => {
  const response = await api.post('/logs/parse', { log: logText });
  return response.data;
};

export const getMitreTechnique = async (techId) => {
  const response = await api.get(`/mitre/technique/${encodeURIComponent(techId)}`);
  return response.data;
};

export const searchMitre = async (query, tactic) => {
  const params = new URLSearchParams({ q: query || '', limit: '30' });
  if (tactic) params.set('tactic', tactic);
  const response = await api.get(`/mitre/search?${params.toString()}`);
  return response.data;
};

export default api;
