# syntax=docker/dockerfile:1
# One image, two runtimes: Express BFF (Node) + FastAPI (Python/uv).
# Trivy scans the *final* image and must discover npm packages, Python packages
# and Debian OS packages on its own — no SBOM is copied in.

ARG NODE_VERSION=22
ARG PYTHON_VERSION=3.12

# ---------- frontend build (devDependencies live and die here) ----------
FROM node:${NODE_VERSION}-bookworm-slim AS fe-build
WORKDIR /src
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npx vite build

# ---------- frontend runtime deps only ----------
FROM node:${NODE_VERSION}-bookworm-slim AS fe-deps
WORKDIR /src
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund

# ---------- backend: uv installs exactly what uv.lock says, minus dev group ----------
FROM python:${PYTHON_VERSION}-slim-bookworm AS be-build
COPY --from=ghcr.io/astral-sh/uv:0.13.1 /uv /bin/uv
ENV UV_PYTHON_DOWNLOADS=never UV_LINK_MODE=copy UV_COMPILE_BYTECODE=1
WORKDIR /app/backend
COPY backend/pyproject.toml backend/uv.lock ./
RUN uv sync --frozen --no-dev
COPY backend/app ./app

# ---------- final image ----------
FROM python:${PYTHON_VERSION}-slim-bookworm
# Copy the Node runtime in from the official image (not apt), so the OS layer stays Debian-only.
COPY --from=fe-build /usr/local/bin/node /usr/local/bin/node
WORKDIR /app
COPY --from=be-build /app/backend /app/backend
COPY --from=fe-deps  /src/node_modules /app/frontend/node_modules
COPY --from=fe-build /src/dist /app/frontend/dist
COPY frontend/package.json frontend/server.js /app/frontend/
COPY docker/start.sh /app/start.sh
ENV PATH="/app/backend/.venv/bin:$PATH" BACKEND_URL=http://127.0.0.1:8000
EXPOSE 3000
USER nobody
CMD ["/app/start.sh"]
