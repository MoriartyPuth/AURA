#!/usr/bin/env bash
cd "$(dirname "$0")"; source _player.sh
clear
line "\033[2m# AURA — automated IDOR / BOLA hunter (Autorize-style, in a scanner)\033[0m" 0.2
line "\033[2m# config.yaml: two accounts (victim + attacker) → replay every endpoint\033[0m" 0.2
pause 0.5
type_cmd "aura -t http://localhost:8888      # crAPI, authz enabled"
pause 0.3
line "\033[34m[*]\033[0m Phase 1: replaying in-scope endpoints as victim / attacker / anonymous" 0.35
line "\033[90m      GET /workshop/api/shop/orders/6        (victim owns this order)\033[0m" 0.3
line "\033[90m      GET /identity/api/v2/user/dashboard     (per-user data — control)\033[0m" 0.4
pause 0.5
line "\033[1;31m[CRITICAL]\033[0m attacker's token reads the victim's order → broken access control" 0.3
pause 0.6
while IFS= read -r l; do printf '%s\n' "$l"; sleep 0.08; done < authz_block.txt
pause 1.5
