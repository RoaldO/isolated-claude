#!/bin/bash
# Security hardening tests voor isolated-claude
# Draait binnen de container via: docker compose run --rm test

set -uo pipefail

PASS=0
FAIL=0

green="\033[0;32m"
red="\033[0;31m"
reset="\033[0m"

pass() {
    echo -e "  ${green}PASS${reset}  $1"
    ((PASS++))
}

fail() {
    echo -e "  ${red}FAIL${reset}  $1"
    ((FAIL++))
}

assert_blocked() {
    local description="$1"
    local command="$2"
    if eval "$command" >/dev/null 2>&1; then
        fail "$description (verwacht geblokkeerd, maar lukte)"
    else
        pass "$description"
    fi
}

assert_allowed() {
    local description="$1"
    local command="$2"
    if eval "$command" >/dev/null 2>&1; then
        pass "$description"
    else
        fail "$description (verwacht toegestaan, maar mislukt)"
    fi
}

echo ""
echo "=== Firewall: geblokkeerd verkeer ==="

assert_blocked \
    "Willekeurige website (example.com)" \
    "curl --connect-timeout 5 https://example.com"

assert_blocked \
    "Google (google.com)" \
    "curl --connect-timeout 5 https://google.com"

assert_blocked \
    "Docker Hub (hub.docker.com)" \
    "curl --connect-timeout 5 https://hub.docker.com"

assert_blocked \
    "Extern IP-adres (1.1.1.1)" \
    "curl --connect-timeout 5 https://1.1.1.1"

echo ""
echo "=== Firewall: toegestaan verkeer ==="

assert_allowed \
    "Anthropic API (api.anthropic.com)" \
    "curl --connect-timeout 10 https://api.anthropic.com"

assert_allowed \
    "GitHub API (api.github.com)" \
    "curl --connect-timeout 10 https://api.github.com/zen"

assert_allowed \
    "npm registry (registry.npmjs.org)" \
    "curl --connect-timeout 10 https://registry.npmjs.org"

assert_allowed \
    "GitHub git (github.com)" \
    "curl --connect-timeout 10 https://github.com"

echo ""
echo "=== Container isolatie ==="

assert_blocked \
    "Host /etc/passwd niet leesbaar buiten workspace" \
    "test -r /host/etc/passwd"

assert_blocked \
    "Host /home niet gemount" \
    "test -d /host/home"

if [[ "$(stat -c %d /workspace 2>/dev/null)" != "$(stat -c %d / 2>/dev/null)" ]] || mountpoint -q /workspace 2>/dev/null; then
    pass "/workspace is een gemount volume (niet het rootfs)"
else
    fail "/workspace lijkt niet geïsoleerd van rootfs"
fi

echo ""
echo "=== Firewall: bypass pogingen ==="

assert_blocked \
    "iptables aanpassen als node user" \
    "iptables -F"

assert_blocked \
    "sudo iptables (niet in sudoers)" \
    "sudo iptables -A OUTPUT -j ACCEPT"

assert_blocked \
    "ipset aanpassen als node user" \
    "ipset add allowed-domains 93.184.216.34"

# Controleer dat example.com na bypass-pogingen nog steeds geblokkeerd is
assert_blocked \
    "example.com nog steeds geblokkeerd na bypass-pogingen" \
    "curl --connect-timeout 5 https://example.com"

echo ""
echo "=== Claude Code permissies (settings.json) ==="

SETTINGS="/workspace/.claude/settings.json"
if [[ ! -f "$SETTINGS" ]]; then
    fail "settings.json niet gevonden op $SETTINGS"
else
    pass "settings.json bestaat"

    if jq -e '.permissions.deny[]? | select(. == "Bash(git push:*)")' "$SETTINGS" >/dev/null 2>&1; then
        pass "git push staat in deny-lijst"
    else
        fail "git push staat NIET in deny-lijst"
    fi

    if jq -e '.permissions.deny[]? | select(. == "Bash(gh:*)")' "$SETTINGS" >/dev/null 2>&1; then
        pass "gh CLI staat in deny-lijst"
    else
        fail "gh CLI staat NIET in deny-lijst"
    fi
fi

echo ""
echo "=== Resultaat ==="
echo -e "  ${green}Geslaagd: $PASS${reset}"
if [[ $FAIL -gt 0 ]]; then
    echo -e "  ${red}Mislukt:  $FAIL${reset}"
    echo ""
    exit 1
else
    echo ""
    exit 0
fi
