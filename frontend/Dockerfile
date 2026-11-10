# syntax=docker/dockerfile:1.7
# ── Build ─────────────────────────────────────────────────────────────────────
FROM node:20-alpine AS build
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund --loglevel=error

COPY . .
# The SPA talks to the API through the same origin (nginx proxies /api → backend).
ARG REACT_APP_API_BASE_URL=/api/v1
ENV REACT_APP_API_BASE_URL=$REACT_APP_API_BASE_URL \
    GENERATE_SOURCEMAP=false \
    DISABLE_ESLINT_PLUGIN=true \
    NODE_OPTIONS=--max-old-space-size=4096
RUN npm run build

# ── Serve ─────────────────────────────────────────────────────────────────────
FROM nginx:1.27-alpine AS runtime
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/build /usr/share/nginx/html
EXPOSE 80
HEALTHCHECK --interval=15s --timeout=4s --retries=5 CMD wget -qO- http://127.0.0.1/nginx-health || exit 1
