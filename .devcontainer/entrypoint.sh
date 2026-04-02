#!/bin/bash
set -euo pipefail

sudo /usr/local/bin/init-firewall.sh

exec "$@"
