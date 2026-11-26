#!/usr/bin/env bash
# Shared demo helpers: a typewriter prompt + paced line printing.
# Used by the demo playback scripts that termtosvg records.
type_cmd() {  # $1 = command string to "type" after a prompt
  printf '\033[1;32m➜\033[0m \033[1;36maura\033[0m '
  local rest="${1#aura }"
  for ((i=0; i<${#rest}; i++)); do printf '%s' "${rest:$i:1}"; sleep 0.035; done
  printf '\n'; sleep 0.5
}
line() { printf '%b\n' "$1"; sleep "${2:-0.12}"; }
pause() { sleep "${1:-0.8}"; }
