#!/bin/sh
# Demo only: run both processes in one container.
set -e
cd /app/backend && uvicorn app.main:app --host 127.0.0.1 --port 8000 &
cd /app/frontend && exec node server.js
