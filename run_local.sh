#!/usr/bin/env bash
#
# CyberSight DW — run application code on the host (no Docker for Python).
# Installs Python deps from etl/ and dashboard/, sets localhost-oriented env vars,
# optionally brings up backing services with Docker Compose, then starts Kafka producer,
# consumer, and Streamlit.
#
# Prerequisites: Python 3.10+ and pip. For --docker-infra: Docker with Compose v2.
#
# Kafka from the host: Compose advertises the broker as kafka:9092. If connections
# fail, add this line to /etc/hosts (requires sudo):  127.0.0.1 kafka
#

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

VENV="${ROOT}/.venv"
PID_FILE="${ROOT}/.local_run_pids"
INSTALL_ONLY=0
DOCKER_INFRA=0
SKIP_KSQL=0
KEEP_INFRA=0
STOP_DOCKER_INFRA_ON_EXIT=0

usage() {
  sed -n '2,20p' "$0" | sed 's/^# //'
  echo ""
  echo "Usage: $0 [options]"
  echo "  --install-only   Create .venv and pip install only (no servers)."
  echo "  --docker-infra   Run: docker compose up -d for DBs, Kafka, Zookeeper, ksqlDB."
  echo "  --keep-infra     With --docker-infra: do not stop those containers on exit (default: stop)."
  echo "  --skip-ksql      Do not run etl/ksql_init.py before apps."
  echo ""
  echo "Environment (optional):"
  echo "  STREAMLIT_PORT   Dashboard port (default 8501)."
  echo "  -h, --help       Show this help."
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install-only) INSTALL_ONLY=1 ;;
    --docker-infra) DOCKER_INFRA=1 ;;
    --keep-infra)   KEEP_INFRA=1 ;;
    --skip-ksql)    SKIP_KSQL=1 ;;
    -h|--help)      usage; exit 0 ;;
    *)              echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
  shift
done

install_deps() {
  if [[ ! -d "$VENV" ]]; then
    python3 -m venv "$VENV"
  fi
  # shellcheck source=/dev/null
  source "${VENV}/bin/activate"
  pip install --upgrade pip
  pip install -r "${ROOT}/etl/requirements.txt" -r "${ROOT}/dashboard/requirements.txt"
}

export_local_env() {
  # Match docker-compose.yml published ports when using --docker-infra
  export KAFKA_BOOTSTRAP="${KAFKA_BOOTSTRAP:-localhost:9092}"
  export PG_HOST="${PG_HOST:-localhost}"
  export PG_PORT="${PG_PORT:-5433}"
  export PG_DB="${PG_DB:-cybersight}"
  export PG_USER="${PG_USER:-postgres}"
  export PG_PASSWORD="${PG_PASSWORD:-postgres}"
  export MONGO_URI="${MONGO_URI:-mongodb://localhost:27018}"
  export NEO4J_URI="${NEO4J_URI:-bolt://localhost:7688}"
  export NEO4J_USER="${NEO4J_USER:-neo4j}"
  export NEO4J_PASSWORD="${NEO4J_PASSWORD:-password}"
  export STREAMLIT_PORT="${STREAMLIT_PORT:-8501}"
  export KSQLDB_URL="${KSQLDB_URL:-http://127.0.0.1:8088}"
  export KSQL_SQL_PATH="${KSQL_SQL_PATH:-${ROOT}/sql/ksql_init.sql}"
  export DATA_DIR="${DATA_DIR:-${ROOT}/data/cicids2017/}"
}

wait_for_tcp() {
  local host="$1" port="$2" label="$3" max="${4:-60}"
  local i=0
  echo "Waiting for ${label} (${host}:${port})..."
  while [[ $i -lt "$max" ]]; do
    if command -v nc >/dev/null 2>&1; then
      if nc -z "$host" "$port" 2>/dev/null; then
        echo "${label} is up."
        return 0
      fi
    else
      if python3 -c "import socket; s=socket.socket(); s.settimeout(1); s.connect(('${host}',${port})); s.close()" 2>/dev/null; then
        echo "${label} is up."
        return 0
      fi
    fi
    sleep 1
    i=$((i + 1))
  done
  echo "Timeout waiting for ${label}." >&2
  return 1
}

# True if something accepts TCP connections on host:port.
tcp_is_open() {
  local host="$1" port="$2"
  if command -v nc >/dev/null 2>&1; then
    nc -z "$host" "$port" 2>/dev/null
  else
    python3 -c "import socket; s=socket.socket(); s.settimeout(1); s.connect(('${host}',${port})); s.close()" 2>/dev/null
  fi
}

# Require Postgres, Mongo, Neo4j, Kafka on published compose ports (or exit).
ensure_backends_for_local() {
  local pg_port="${PG_PORT:-5433}"
  echo "Checking PostgreSQL, MongoDB, Neo4j, and Kafka (same ports as docker-compose.yml)..."
  wait_for_tcp 127.0.0.1 "$pg_port" "PostgreSQL" 45 || {
    echo "PostgreSQL not reachable on 127.0.0.1:${pg_port}." >&2
    echo "Start the stack: $0 --docker-infra" >&2
    exit 1
  }
  wait_for_tcp 127.0.0.1 27018 "MongoDB" 30 || {
    echo "MongoDB not reachable on 127.0.0.1:27018. Try: $0 --docker-infra" >&2
    exit 1
  }
  wait_for_tcp 127.0.0.1 7688 "Neo4j Bolt" 45 || {
    echo "Neo4j not reachable on 127.0.0.1:7688. Try: $0 --docker-infra" >&2
    exit 1
  }
  wait_for_tcp 127.0.0.1 9092 "Kafka" 60 || {
    echo "Kafka not reachable on 127.0.0.1:9092. Try: $0 --docker-infra" >&2
    exit 1
  }
}

require_free_port() {
  local port="$1" purpose="$2"
  if tcp_is_open 127.0.0.1 "$port"; then
    echo "ERROR: Port ${port} is already in use (${purpose})." >&2
    echo "If you still have Docker Compose app containers up, stop them, e.g.:" >&2
    echo "  docker compose -f \"${ROOT}/docker-compose.yml\" stop producer dashboard" >&2
    echo "Or stop the process using that port and retry." >&2
    exit 1
  fi
}

start_docker_infra() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "docker not found. Install Docker or start Postgres/Mongo/Neo4j/Kafka yourself." >&2
    exit 1
  fi
  echo "Starting infrastructure containers (zookeeper, kafka, ksqldb-server, postgres, mongodb, neo4j)..."
  docker compose -f "${ROOT}/docker-compose.yml" up -d zookeeper kafka ksqldb-server postgres mongodb neo4j
  wait_for_tcp 127.0.0.1 5433 "PostgreSQL" 90
  wait_for_tcp 127.0.0.1 27018 "MongoDB" 60
  wait_for_tcp 127.0.0.1 7688 "Neo4j Bolt" 120
  wait_for_tcp 127.0.0.1 9092 "Kafka" 120
  wait_for_tcp 127.0.0.1 8088 "ksqlDB (TCP)" 120
}

# Port 8088 can accept before the REST API serves /info; match compose healthcheck.
wait_for_ksql_http() {
  local i=0
  local max=90
  echo "Waiting for ksqlDB REST /info..."
  while [[ $i -lt "$max" ]]; do
    if curl -sf "http://127.0.0.1:8088/info" >/dev/null 2>&1; then
      echo "ksqlDB REST API is ready."
      return 0
    fi
    sleep 2
    i=$((i + 1))
  done
  echo "ksqlDB did not respond on http://127.0.0.1:8088/info." >&2
  echo "Check: docker compose logs ksqldb-server" >&2
  echo "If containers exit with 137, raise Docker Desktop memory or ensure native arm64 images (no platform: linux/amd64)." >&2
  return 1
}

# Kill a PID and any children (streamlit may fork).
kill_tree() {
  local pid="$1"
  if [[ -z "$pid" ]] || [[ ! "$pid" =~ ^[0-9]+$ ]]; then
    return 0
  fi
  local c
  while read -r c; do
    [[ -n "$c" ]] && kill_tree "$c"
  done < <(pgrep -P "$pid" 2>/dev/null || true)
  kill -TERM "$pid" 2>/dev/null || true
}

CLEANUP_RAN=0
cleanup() {
  [[ "$CLEANUP_RAN" -eq 1 ]] && return
  CLEANUP_RAN=1
  set +e
  if [[ -f "$PID_FILE" ]]; then
    echo "Stopping local apps (producer, consumer, dashboard)..."
    while read -r pid; do
      [[ -n "$pid" ]] || continue
      kill_tree "$pid"
    done < "$PID_FILE"
    sleep 0.5
    while read -r pid; do
      [[ -n "$pid" ]] || continue
      kill -KILL "$pid" 2>/dev/null || true
    done < "$PID_FILE"
    rm -f "$PID_FILE"
  fi
  if [[ "$STOP_DOCKER_INFRA_ON_EXIT" -eq 1 ]]; then
    echo "Stopping Docker infrastructure (zookeeper, kafka, ksqldb-server, postgres, mongodb, neo4j)..."
    docker compose -f "${ROOT}/docker-compose.yml" stop zookeeper kafka ksqldb-server postgres mongodb neo4j 2>/dev/null || true
  fi
  set -e
}

trap cleanup EXIT INT TERM

record_pid() {
  echo "$1" >> "$PID_FILE"
}

install_deps

if [[ "$INSTALL_ONLY" -eq 1 ]]; then
  echo "Dependencies installed in ${VENV}. Activate with: source ${VENV}/bin/activate"
  exit 0
fi

export_local_env

if [[ "$DOCKER_INFRA" -eq 1 ]]; then
  start_docker_infra
  if [[ "$KEEP_INFRA" -eq 0 ]]; then
    STOP_DOCKER_INFRA_ON_EXIT=1
  fi
else
  ensure_backends_for_local
fi

# shellcheck source=/dev/null
source "${VENV}/bin/activate"

if ! grep -qE '^127\.0\.0\.1[[:space:]]+kafka(\s|$)' /etc/hosts 2>/dev/null; then
  echo "Note: If Kafka clients fail from the host, add to /etc/hosts: 127.0.0.1 kafka"
fi

: > "$PID_FILE"

if [[ "$SKIP_KSQL" -eq 0 ]]; then
  echo "Running ksqlDB initializer..."
  if [[ "$DOCKER_INFRA" -eq 0 ]]; then
    echo "Tip: use --docker-infra if ksqlDB is not already running (needs port 8088)." >&2
  fi
  if wait_for_ksql_http; then
    (cd "${ROOT}/etl" && python ksql_init.py) || {
      echo "ksql_init.py failed. Continuing; use --skip-ksql to skip next time." >&2
    }
  else
    echo "Skipping ksql_init. Start ksqlDB, then re-run or use: $0 --docker-infra" >&2
  fi
fi

require_free_port "${STREAMLIT_PORT}" "Streamlit dashboard"

echo "Starting Kafka producer (CSV → topic)..."
(cd "${ROOT}/etl" && python producer.py) &
record_pid $!

echo "Starting consumer..."
(cd "${ROOT}/etl" && python consumer.py) &
record_pid $!

echo "Starting Streamlit dashboard on :${STREAMLIT_PORT}..."
if [[ "$STOP_DOCKER_INFRA_ON_EXIT" -eq 1 ]]; then
  echo "Open http://localhost:${STREAMLIT_PORT} — exit the dashboard (Ctrl+C) to stop apps and Docker infra from this run."
else
  echo "Open http://localhost:${STREAMLIT_PORT} — Ctrl+C stops the dashboard; producer and consumer stop on exit."
fi
# Foreground so the terminal sends Ctrl+C to Streamlit; background jobs would not get SIGINT.
(cd "${ROOT}/dashboard" && streamlit run app.py --server.port "${STREAMLIT_PORT}" --server.address 0.0.0.0)
