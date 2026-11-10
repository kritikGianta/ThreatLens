# ThreatLens — Frontend

React 18 single-page app (Create React App) for the ThreatLens SOC platform: public marketing
pages (landing, about, sign-in/up) and the authenticated analyst workspace.

## Development

```bash
npm ci
npm start          # http://localhost:3000 — proxies /api to the backend on :8000
```

Start the backend first (see the repository README). No frontend `.env` is needed for local
development; see `.env.example` for the optional `REACT_APP_API_BASE_URL` override.

## Scripts

| Command | Purpose |
|---|---|
| `npm start` | Dev server with hot reload |
| `npm run lint` | ESLint (`react-app` rules, zero warnings allowed) |
| `npm test` | Jest unit tests (non-interactive) |
| `npm run build` | Production bundle in `build/` |

## Structure

```
src/
  components/          pages (Dashboard, LogAnalysis = Threat Studio, ThreatIntel, Copilot, …)
    common/LazyVideo   viewport-aware background video
    soc/               shared SOC widgets
  contexts/            AuthContext (JWT session + roles), ThemeContext
  services/api.jsx     axios client: auth header, silent token refresh, error mapping
  utils/               pure helpers (safe chat formatting) + tests
public/assets/
  images/  cards/      WebP artwork used by the marketing pages
  videos/              H.264 MP4 background videos (lazy-loaded below the fold)
```

## Production

`Dockerfile` builds the bundle and serves it with nginx (`nginx.conf`), which also reverse-proxies
`/api`, `/health`, `/ready` and `/docs` to the backend container and applies security headers and
long-lived caching for static media.
