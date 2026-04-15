#!/usr/bin/env bash
set -euo pipefail
E2E_DIR="$(cd "$(dirname "$0")" && pwd)"
PIDFILE="${E2E_DIR}/run/broker.pid"
if [ ! -f "${PIDFILE}" ]; then
    echo "no pidfile at ${PIDFILE}"
    exit 0
fi
PID=$(cat "${PIDFILE}")
if kill -0 "${PID}" 2>/dev/null; then
    kill -TERM "${PID}"
    for i in $(seq 1 30); do
        kill -0 "${PID}" 2>/dev/null || break
        sleep 0.1
    done
    if kill -0 "${PID}" 2>/dev/null; then
        kill -KILL "${PID}"
    fi
    echo "broker stopped (pid ${PID})"
fi
rm -f "${PIDFILE}"
