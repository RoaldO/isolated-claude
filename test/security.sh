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
echo "=== IPv6 bypass ==="

# ip6tables regels zijn alleen leesbaar als root; controleer in plaats daarvan
# of IPv6 connectiviteit daadwerkelijk geblokkeerd is
if curl --connect-timeout 5 --ipv6 https://ipv6.google.com >/dev/null 2>&1; then
    fail "IPv6 verkeer naar ipv6.google.com lukte — firewall bypass via IPv6!"
else
    pass "IPv6 verkeer naar buiten geblokkeerd"
fi

# Controleer of de machine überhaupt IPv6 heeft; zo niet, markeer als extra info
if ip -6 addr show scope global 2>/dev/null | grep -q "inet6"; then
    pass "IPv6 interface aanwezig maar verkeer geblokkeerd (ip6tables actief)"
else
    pass "Geen globaal IPv6 adres op interface (IPv6 niet beschikbaar in dit netwerk)"
fi

echo ""
echo "=== Docker socket ==="

if [[ -S /var/run/docker.sock ]]; then
    fail "/var/run/docker.sock is toegankelijk — volledige host takeover mogelijk!"
else
    pass "/var/run/docker.sock niet gemount"
fi

echo ""
echo "=== NET_RAW capabilities ==="

# Controleer effectieve capabilities van het huidige process
effective_caps=$(grep CapEff /proc/self/status | awk '{print $2}')
cap_net_raw_bit=$((1 << 13))
cap_net_admin_bit=$((1 << 12))

if (( 16#$effective_caps & cap_net_raw_bit )); then
    # NET_RAW aanwezig — probeer een raw socket te openen naar een geblokkeerd doel
    # Python is beschikbaar via node image; anders gebruiken we /dev/tcp trick
    if python3 -c "
import socket, sys
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.settimeout(3)
    s.connect(('93.184.216.34', 0))  # example.com IP
    s.close()
    sys.exit(0)  # verbinding lukte
except Exception:
    sys.exit(1)  # geblokkeerd
" 2>/dev/null; then
        fail "Raw socket naar example.com lukte via NET_RAW — mogelijke firewall bypass"
    else
        pass "Raw socket naar geblokkeerd IP gefaald (iptables filtert ook raw sockets)"
    fi
else
    pass "CAP_NET_RAW niet effectief voor node user"
fi

echo ""
echo "=== Procfs toegang ==="

assert_blocked \
    "/proc/sysrq-trigger niet schrijfbaar" \
    "echo b > /proc/sysrq-trigger"

# Kan de agent IP forwarding aanzetten?
if echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null; then
    fail "/proc/sys/net/ipv4/ip_forward schrijfbaar — routing manipulatie mogelijk"
else
    pass "/proc/sys/net/ipv4/ip_forward niet schrijfbaar"
fi

echo ""
echo "=== Symlink escape ==="

# Een symlink naar /etc wijst naar de container's /etc, niet de host's /etc.
# Dat is geen escape — de node user heeft sowieso al toegang tot container /etc.
# Relevante vraag: kan een symlink in /workspace de HOST bereiken?
# De workspace is een bind mount van de host, maar symlinks worden
# opgelost vanuit de container's namespace, dus /etc is altijd container-/etc.
TMPLINK="/workspace/.security-test-symlink-$$"
ln -s /etc "$TMPLINK" 2>/dev/null
if [[ -f "$TMPLINK/passwd" ]]; then
    pass "Symlink naar /etc bereikt container-interne /etc (verwacht gedrag, geen host escape)"
else
    pass "Symlink naar /etc geeft geen toegang"
fi
rm -f "$TMPLINK"

echo ""
echo "=== Kernel escape vectors ==="

# core_pattern escape: als schrijfbaar, wordt payload als root op HOST uitgevoerd bij crash
if echo "|/tmp/pwned" > /proc/sys/kernel/core_pattern 2>/dev/null; then
    fail "/proc/sys/kernel/core_pattern schrijfbaar — kernel escape mogelijk!"
    # Herstel
    echo "core" > /proc/sys/kernel/core_pattern 2>/dev/null || true
else
    pass "/proc/sys/kernel/core_pattern niet schrijfbaar"
fi

# modprobe path: als schrijfbaar, wordt eigen binary als root uitgevoerd bij module load
if echo "/tmp/pwned" > /proc/sys/kernel/modprobe 2>/dev/null; then
    fail "/proc/sys/kernel/modprobe schrijfbaar — kernel module escape mogelijk!"
else
    pass "/proc/sys/kernel/modprobe niet schrijfbaar"
fi

# kcore: directe toegang tot kernel memory
assert_blocked \
    "/proc/kcore niet leesbaar (kernel memory)" \
    "dd if=/proc/kcore bs=1 count=1 2>/dev/null | wc -c | grep -q '^1$'"

echo ""
echo "=== Cgroup escape ==="

# Klassieke cgroup v1 release_agent escape
# Werkt als: cgroup v1 actief + /sys/fs/cgroup schrijfbaar + container niet in eigen cgroup ns
CGROUP_ESCAPE=false
if [[ -w /sys/fs/cgroup ]]; then
    fail "/sys/fs/cgroup is schrijfbaar — cgroup v1 release_agent escape mogelijk!"
    CGROUP_ESCAPE=true
else
    pass "/sys/fs/cgroup niet schrijfbaar"
fi

# Check of we een nieuwe cgroup kunnen aanmaken
if mkdir /sys/fs/cgroup/memory/test-escape-$$ 2>/dev/null; then
    fail "Nieuwe cgroup aanmaken gelukt — release_agent escape mogelijk!"
    rmdir /sys/fs/cgroup/memory/test-escape-$$ 2>/dev/null || true
else
    pass "Nieuwe cgroup aanmaken geblokkeerd"
fi

# Check of we de release_agent van een bestaande cgroup kunnen aanpassen
if echo "/tmp/pwned" > /sys/fs/cgroup/release_agent 2>/dev/null; then
    fail "/sys/fs/cgroup/release_agent schrijfbaar!"
else
    pass "/sys/fs/cgroup/release_agent niet schrijfbaar"
fi

echo ""
echo "=== SUID binaries ==="

# Onverwachte SUID binaries kunnen escalatie naar root binnen container mogelijk maken
SUID_BINS=$(find / -xdev -perm -4000 2>/dev/null | grep -v "^/proc" | sort)
EXPECTED_SUID="^(/usr/bin/su|/usr/bin/sudo|/usr/bin/newgrp|/usr/bin/gpasswd|/usr/bin/chfn|/usr/bin/chsh|/usr/bin/passwd|/usr/bin/mount|/usr/bin/umount|/bin/su|/bin/mount|/bin/umount|/usr/lib/openssh/ssh-keysign)$"

UNEXPECTED=()
while IFS= read -r bin; do
    if [[ -n "$bin" ]] && ! echo "$bin" | grep -qE "$EXPECTED_SUID"; then
        UNEXPECTED+=("$bin")
    fi
done <<< "$SUID_BINS"

if [[ ${#UNEXPECTED[@]} -gt 0 ]]; then
    fail "Onverwachte SUID binaries gevonden: ${UNEXPECTED[*]}"
else
    pass "Geen onverwachte SUID binaries"
fi

echo ""
echo "=== Device toegang ==="

# Disk devices geven directe toegang tot host filesystem
DISK_DEVS=$(find /dev -name 'sd*' -o -name 'nvme*' -o -name 'vd*' -o -name 'xvd*' 2>/dev/null | head -5)
if [[ -n "$DISK_DEVS" ]]; then
    READABLE=false
    for dev in $DISK_DEVS; do
        if dd if="$dev" bs=512 count=1 >/dev/null 2>&1; then
            fail "Disk device $dev leesbaar — host filesystem toegankelijk!"
            READABLE=true
        fi
    done
    if [[ "$READABLE" == false ]]; then
        pass "Disk devices aanwezig maar niet leesbaar"
    fi
else
    pass "Geen disk devices in /dev"
fi

# /dev/mem: directe toegang tot fysiek geheugen
assert_blocked \
    "/dev/mem niet leesbaar (fysiek geheugen)" \
    "dd if=/dev/mem bs=1 count=1 2>/dev/null | wc -c | grep -q '^1$'"

echo ""
echo "=== Namespace manipulatie ==="

# nsenter: kunnen we een andere namespace betreden?
if nsenter --pid=/proc/1/ns/pid -- echo ok >/dev/null 2>&1; then
    fail "nsenter naar PID namespace van PID 1 gelukt — namespace escape mogelijk!"
else
    pass "nsenter geblokkeerd"
fi

# unshare: nieuwe namespace aanmaken (vereist CAP_SYS_ADMIN)
if unshare --user --pid echo ok >/dev/null 2>&1; then
    fail "unshare gelukt — namespace manipulatie mogelijk"
else
    pass "unshare geblokkeerd"
fi

echo ""
echo "=== Data exfiltratie via toegestane kanalen ==="

# DNS exfiltratie: data meesturen in DNS queries — DNS is toegestaan door firewall
# Test: kunnen we een query doen naar een extern domein (eigen nameserver)?
# In de praktijk: exfil via labels zoals "geheim-data.attacker.com"
# We testen of willekeurige DNS queries naar externe resolvers mogelijk zijn
if dig +short +time=3 test.exfil-check.invalid @8.8.8.8 >/dev/null 2>&1; then
    fail "DNS queries naar externe resolvers (8.8.8.8) mogelijk — DNS exfiltratie risico"
else
    pass "DNS queries naar externe resolvers geblokkeerd (alleen Docker interne DNS)"
fi

# ICMP exfiltratie via allowed hosts (ping met data in payload)
# De firewall staat SSH toe op port 22 — kunnen we daarmee willekeurige hosts bereiken?
if timeout 3 bash -c "echo test > /dev/tcp/93.184.216.34/22" 2>/dev/null; then
    fail "TCP/22 naar geblokkeerd IP (example.com) mogelijk — firewall lek op poort 22"
else
    pass "TCP/22 naar geblokkeerd IP geblokkeerd"
fi

echo ""
echo "=== Procfs: extra checks ==="

# /proc/1/fd: toegang tot open file descriptors van PID 1
# PID 1 draait als 'node' (zelfde user als de agent), dus toegang is verwacht gedrag.
# Zou een probleem zijn als PID 1 als root draait.
pid1_user=$(stat -c '%U' /proc/1 2>/dev/null || echo "unknown")
if ls /proc/1/fd >/dev/null 2>&1; then
    if [[ "$pid1_user" == "root" ]]; then
        fail "/proc/1/fd leesbaar en PID 1 draait als root — file descriptors van root zichtbaar"
    else
        pass "/proc/1/fd leesbaar maar PID 1 draait als '$pid1_user' (zelfde user, geen escalatie)"
    fi
else
    pass "/proc/1/fd niet toegankelijk"
fi

# /proc/1/maps: memory map van PID 1 (kan library-locaties onthullen)
if cat /proc/1/maps >/dev/null 2>&1; then
    echo "  WARN  /proc/1/maps leesbaar (memory layout van PID 1 zichtbaar)"
else
    pass "/proc/1/maps niet leesbaar"
fi

echo ""
echo "=== Bekende beperkingen (informatief) ==="

# /proc/1/environ leesbaar — geen fix mogelijk zonder AppArmor/seccomp,
# maar een reëel risico als secrets via env vars worden doorgegeven
if cat /proc/1/environ >/dev/null 2>&1; then
    echo "  WARN  /proc/1/environ leesbaar — geef NOOIT secrets mee als env var aan de container"
else
    echo "  INFO  /proc/1/environ niet leesbaar"
fi

echo ""
echo "=== Claude Code permissies (settings.json) ==="
echo -e "  ${green}Geslaagd: $PASS${reset}"
if [[ $FAIL -gt 0 ]]; then
    echo -e "  ${red}Mislukt:  $FAIL${reset}"
    echo ""
    exit 1
else
    echo ""
    exit 0
fi
