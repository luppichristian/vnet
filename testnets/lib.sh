#!/usr/bin/env bash
set -euo pipefail
TESTNET_NAME="${TESTNET_NAME:-unnamed}"
VNET_BIN="${VNET_BIN:-$PWD}"

if [[ $# -ne 1 ]]; then
  printf 'Usage: %s <artifact-directory>\n' "$(basename "$0")" >&2
  exit 1
fi

TESTNET_DIR="$1"
if [[ -x "$VNET_BIN/connect.exe" ]]; then
  VNET_EXECUTABLE_SUFFIX=.exe
elif [[ -x "$VNET_BIN/connect" ]]; then
  VNET_EXECUTABLE_SUFFIX=
else
  VNET_EXECUTABLE_SUFFIX=${VNET_EXECUTABLE_SUFFIX:-}
fi

vnet_target() {
  printf '%s/%s%s' "$VNET_BIN" "$1" "$VNET_EXECUTABLE_SUFFIX"
}

declare -a TARGET_PIDS=()
declare -a TARGET_FDS=()
declare -A TARGET_FD_BY_NAME=()
declare -A TARGET_PID_BY_NAME=()

require_binaries() {
  local target
  for target in connect host hub switch router dhcp_server dns_server watch; do
    [[ -x "$(vnet_target "$target")" ]] || {
      printf 'Missing %s. Build first with: bbs build -t "*"\n' "$(vnet_target "$target")" >&2
      exit 1
    }
  done
}

prepare_testnet() {
  require_binaries
  mkdir -p "$TESTNET_DIR" "$TESTNET_DIR/media"
  printf 'Testnet: %s\nDirectory: %s\n' "$TESTNET_NAME" "$TESTNET_DIR"
}

start_target() {
  local name="$1"
  shift
  local fifo="$TESTNET_DIR/$name.stdin"
  mkfifo "$fifo"
  local fd
  exec {fd}<>"$fifo"
  local executable="$1"
  shift
  local argument
  local -a arguments=()
  for argument in "$@"; do
    if [[ "$VNET_EXECUTABLE_SUFFIX" == .exe && "$argument" == /* ]]; then
      arguments+=("$(cygpath -w "$argument")")
    else
      arguments+=("$argument")
    fi
  done
  "$executable" "${arguments[@]}" <"$fifo" >"$TESTNET_DIR/$name.log" 2>&1 &
  local pid=$!
  TARGET_PIDS+=("$pid")
  TARGET_FDS+=("$fd")
  TARGET_FD_BY_NAME["$name"]="$fd"
  TARGET_PID_BY_NAME["$name"]="$pid"
  printf '  started %-16s pid=%s\n' "$name" "$pid"
}

send_command() {
  local name="$1"
  shift
  local fd="${TARGET_FD_BY_NAME[$name]:-}"
  [[ -n "$fd" ]] || { printf 'Unknown target: %s\n' "$name" >&2; return 1; }
  printf '%s\n' "$*" >&"$fd"
}

show_logs() {
  local log
  for log in "$TESTNET_DIR"/*.log; do
    [[ -e "$log" ]] || continue
    printf '\n===== %s =====\n' "$(basename "$log")"
    tail -n 80 "$log" || true
  done
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM HUP
  printf '\nStopping testnet %s...\n' "$TESTNET_NAME"
  local name pid fd
  for name in "${!TARGET_FD_BY_NAME[@]}"; do send_command "$name" quit || true; done
  sleep 0.2
  for pid in "${TARGET_PIDS[@]}"; do
    [[ -n "$pid" ]] || continue
    kill "$pid" 2>/dev/null || true
    python -c "import subprocess; subprocess.run(['taskkill','/F','/T','/PID','$pid'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)" || true
  done
  for fd in "${TARGET_FDS[@]}"; do
    [[ -n "$fd" ]] || continue
    eval "exec ${fd}>&-" || true
  done
  printf 'Logs and media remain in: %s\n' "$TESTNET_DIR"
  exit "$status"
}

trap cleanup EXIT INT TERM HUP

wait_for_user() {
  printf '\nTestnet is running. Press Enter to stop all targets and retain the logs.\n'
  read -r _
}
