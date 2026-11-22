#!/usr/bin/env bash
# SecurityWatch 4.1.0 – bisheriger Einstieg für den bestehenden Zeitplan.
set -euo pipefail
securitywatch_program_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${securitywatch_program_dir}/securitywatch.py" "$@"
