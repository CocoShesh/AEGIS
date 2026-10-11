#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
python_bin="${SENTINEL_PYTHON:-.venv/bin/python}"
if [[ ! -x "$python_bin" ]]; then
  echo 'Install the unified runtime first:'
  echo 'python3 -m venv .venv'
  echo '.venv/bin/pip install -r repository/requirements.txt -r repository/requirements-scanners.txt'
  exit 1
fi
exec "$python_bin" sentinel.py "$@"
