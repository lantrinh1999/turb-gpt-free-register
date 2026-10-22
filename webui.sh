#!/usr/bin/env bash
set -euo pipefail

# Turb GPT Free Register WebUI management script
#
# Usage:
#   ./webui.sh start      start WebUI
#   ./webui.sh stop       stop WebUI
#   ./webui.sh restart    restart WebUI
#   ./webui.sh status     Show status
#   ./webui.sh logs       Follow logs in real time
#
# Optional environment variables:
#   HOST=127.0.0.1
#   PORT=5000
#   OPEN_BROWSER=1
#   VERBOSE=1
#   AUTH_CODE=xxx
#   EXTRA_ARGS="..."

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

RUN_DIR="$ROOT_DIR/run"
LOG_DIR="$ROOT_DIR/logs"
PID_FILE="$RUN_DIR/webui.pid"
LOG_FILE="$LOG_DIR/webui.log"

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-5000}"
OPEN_BROWSER="${OPEN_BROWSER:-0}"
VERBOSE="${VERBOSE:-0}"
AUTH_CODE="${AUTH_CODE:-}"
EXTRA_ARGS="${EXTRA_ARGS:-}"

mkdir -p "$RUN_DIR" "$LOG_DIR"

usage() {
  cat <<EOF
Usage:$0 <command>

commands:
  start      start WebUI
  stop       stop WebUI
  restart    restart WebUI
  status     Show running status
  logs       Follow logs in real time

Environment variables:
  HOST=127.0.0.1 PORT=5000 OPEN_BROWSER=1 VERBOSE=1 AUTH_CODE=xxx EXTRA_ARGS="..."

Example:
  ./webui.sh start
  PORT=8000 OPEN_BROWSER=1 ./webui.sh start
  HOST=0.0.0.0 PORT=5000 ./webui.sh restart
EOF
}

is_running() {
  local pid="${1:-}"
  [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1
}

read_pid() {
  [[ -f "$PID_FILE" ]] && cat "$PID_FILE" 2>/dev/null || true
}

find_pids_by_port() {
  pgrep -f "python.*web\.py.*--port[ =]${PORT}" 2>/dev/null || true
}

get_python() {
  local venv_python="$ROOT_DIR/.venv/bin/python"
  if [[ -x "$venv_python" ]] && "$venv_python" -c 'import sys; print(sys.executable)' >/dev/null 2>&1; then
    echo "$venv_python"
  elif [[ -e "$venv_python" ]]; then
    echo "Detected .venv, but the Python in the virtual environment is no longer valid." >&2
    echo "Please recreate the virtual environment and install dependencies:" >&2
    echo "  rm -rf .venv && python3 -m venv .venv" >&2
    echo "  .venv/bin/python -m pip install -r requirements.txt" >&2
    return 1
  elif command -v python3 >/dev/null 2>&1; then
    local system_python
    system_python="$(command -v python3)"
    if "$system_python" -c 'import flask' >/dev/null 2>&1; then
      echo "$system_python"
    else
      echo "No usable Python environment found: system Python lacks Flask, please create .venv first and install requirements.txt" >&2
      return 1
    fi
  else
    echo "Python not found: please create .venv first or install python3" >&2
    return 1
  fi
}

collect_running_pids() {
  local pids=()
  local pid
  pid="$(read_pid)"
  if is_running "$pid"; then
    pids+=("$pid")
  fi

  while IFS= read -r pid; do
    [[ -n "$pid" ]] && pids+=("$pid")
  done < <(find_pids_by_port)

  local unique=()
  local seen x
  for pid in "${pids[@]:-}"; do
    [[ -z "$pid" || "$pid" == "$$" ]] && continue
    seen=0
    for x in "${unique[@]:-}"; do
      [[ "$x" == "$pid" ]] && seen=1 && break
    done
    [[ "$seen" == "0" ]] && unique+=("$pid")
  done

  printf '%s\n' "${unique[@]:-}"
}

cmd_start() {
  local old_pid py pid
  old_pid="$(read_pid)"
  if is_running "$old_pid"; then
    echo "WebUI is already running: PID=${old_pid}, address:http://${HOST}:${PORT}"
    return 0
  fi
  rm -f "$PID_FILE"

  py="$(get_python)"

  local args=("web.py" "--host" "$HOST" "--port" "$PORT")
  if [[ "$OPEN_BROWSER" == "1" || "$OPEN_BROWSER" == "true" ]]; then
    args+=("--open-browser")
  fi
  if [[ "$VERBOSE" == "1" || "$VERBOSE" == "true" ]]; then
    args+=("--verbose")
  fi
  if [[ -n "$AUTH_CODE" ]]; then
    args+=("--auth-code" "$AUTH_CODE")
  fi
  if [[ -n "$EXTRA_ARGS" ]]; then
    # shellcheck disable=SC2206
    local extra_parts=($EXTRA_ARGS)
    args+=("${extra_parts[@]}")
  fi

  echo "Starting WebUI:http://${HOST}:${PORT}"
  echo "Log file:$LOG_FILE"
  nohup "$py" "${args[@]}" >> "$LOG_FILE" 2>&1 &
  pid=$!
  echo "$pid" > "$PID_FILE"

  sleep 1
  if is_running "$pid"; then
    echo "Started successfully:PID=$pid"
  else
    echo "Start failed, please check the log:$LOG_FILE" >&2
    rm -f "$PID_FILE"
    return 1
  fi
}

cmd_stop() {
  local pids=()
  local pid
  while IFS= read -r pid; do
    [[ -n "$pid" ]] && pids+=("$pid")
  done < <(collect_running_pids)

  if [[ "${#pids[@]}" -eq 0 ]]; then
    echo "WebUI is not running"
    rm -f "$PID_FILE"
    return 0
  fi

  echo "Stopping WebUI:PID=${pids[*]}"
  for pid in "${pids[@]}"; do
    kill "$pid" >/dev/null 2>&1 || true
  done

  local alive
  for _ in {1..15}; do
    alive=0
    for pid in "${pids[@]}"; do
      if is_running "$pid"; then
        alive=1
        break
      fi
    done
    [[ "$alive" == "0" ]] && break
    sleep 1
  done

  for pid in "${pids[@]}"; do
    if is_running "$pid"; then
      echo "Process did not exit, force killing:PID=$pid"
      kill -9 "$pid" >/dev/null 2>&1 || true
    fi
  done

  rm -f "$PID_FILE"
  echo "Stopped WebUI"
}

cmd_restart() {
  cmd_stop
  sleep 1
  cmd_start
}

cmd_status() {
  local pids=()
  local pid
  while IFS= read -r pid; do
    [[ -n "$pid" ]] && pids+=("$pid")
  done < <(collect_running_pids)

  if [[ "${#pids[@]}" -eq 0 ]]; then
    echo "WebUI is not running"
    return 1
  fi

  echo "WebUI is running:PID=${pids[*]}"
  echo "Address:http://${HOST}:${PORT}"
  echo "Log:$LOG_FILE"
}

cmd_logs() {
  touch "$LOG_FILE"
  tail -n 120 -f "$LOG_FILE"
}

cmd="${1:-}"
case "$cmd" in
  start) cmd_start ;;
  stop) cmd_stop ;;
  restart) cmd_restart ;;
  status) cmd_status ;;
  logs|log) cmd_logs ;;
  -h|--help|help|"") usage ;;
  *)
    echo "Unknown command:$cmd" >&2
    usage >&2
    exit 2
    ;;
esac
