#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
venv_input="$repo_root/.venv"
requested_python=""
verify_only=false
with_test=false
recreate=false

usage() {
  cat <<'EOF'
Usage: ./scripts/setup_env.sh [--verify-only] [--python PATH] [--venv-dir PATH]
                              [--with-test] [--recreate] [--help]

Create or verify a ChipChain virtual environment. Relative --venv-dir paths
are resolved from the repository root. --python selects the interpreter for
creation; --recreate permits replacement of an incompatible existing venv.
EOF
}

fail() {
  printf '[ChipChain] Environment setup FAIL: %s\n' "$*" >&2
  exit 1
}

while (($#)); do
  case $1 in
    --help|-h) usage; exit 0 ;;
    --verify-only) verify_only=true; shift ;;
    --with-test) with_test=true; shift ;;
    --recreate) recreate=true; shift ;;
    --python|--venv-dir)
      option=$1
      (($# >= 2)) || fail "$option requires a path."
      [[ -n $2 ]] || fail "$option requires a nonempty path."
      if [[ $option == --python ]]; then
        requested_python=$2
      elif [[ $2 == /* ]]; then
        venv_input=$2
      else
        venv_input="$repo_root/$2"
      fi
      shift 2 ;;
    *) fail "Unknown option: $1. Run --help for usage." ;;
  esac
done

if $verify_only && { $recreate || $with_test || [[ -n $requested_python ]]; }; then
  fail '--verify-only cannot be combined with --python, --with-test or --recreate.'
fi

[[ ! -L $venv_input ]] || fail "Refusing a symlinked environment path: $venv_input"
venv_dir=$(realpath -m -- "$venv_input")
[[ $venv_dir != / && $venv_dir != "$repo_root" ]] ||
  fail "Unsafe environment path: $venv_dir. Choose a dedicated virtual-environment directory."

pyproject="$repo_root/pyproject.toml"
[[ -f $pyproject ]] || fail "Missing project metadata: $pyproject"
in_project=false
requirement=""
while IFS= read -r line || [[ -n $line ]]; do
  if [[ $line =~ ^[[:space:]]*\[([^]]+)\][[:space:]]*$ ]]; then
    [[ ${BASH_REMATCH[1]} == project ]] && in_project=true || in_project=false
    continue
  fi
  if $in_project && [[ $line =~ ^[[:space:]]*requires-python[[:space:]]*= ]]; then
    [[ -z $requirement ]] || fail "Duplicate requires-python in $pyproject"
    if [[ $line =~ ^[[:space:]]*requires-python[[:space:]]*=[[:space:]]*\"(\>=[0-9]+\.[0-9]+(\.[0-9]+)?)\"[[:space:]]*(#.*)?$ ]]; then
      requirement=${BASH_REMATCH[1]}
    else
      fail "Unsupported requires-python expression in $pyproject: $line"
    fi
  fi
done < "$pyproject"
[[ -n $requirement ]] || fail "Missing or unsupported requires-python in $pyproject"
minimum=${requirement#>=}
IFS=. read -r minimum_major minimum_minor minimum_patch <<< "$minimum"
minimum_patch=${minimum_patch:-0}

printf '[ChipChain] Repository: %s\n' "$repo_root"
printf '[ChipChain] Required Python: %s\n' "$requirement"
printf '[ChipChain] Environment: %s\n' "$venv_dir"

version_satisfies() {
  local version=$1 major minor patch
  [[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  IFS=. read -r major minor patch <<< "$version"
  ((10#$major > 10#$minimum_major)) && return 0
  ((10#$major == 10#$minimum_major)) || return 1
  ((10#$minor > 10#$minimum_minor)) && return 0
  ((10#$minor == 10#$minimum_minor)) || return 1
  ((10#$patch >= 10#$minimum_patch))
}

probe_python() {
  local executable=$1 result
  if ! result=$("$executable" -B -c 'import sys; v=sys.version_info; print("%d.%d.%d|%s|%s|%s" % (v.major, v.minor, v.micro, sys.executable, sys.prefix, sys.base_prefix))' 2>/dev/null); then
    return 1
  fi
  IFS='|' read -r probe_version probe_executable probe_prefix probe_base_prefix <<< "$result"
  [[ $probe_version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && -n $probe_executable && -n $probe_prefix && -n $probe_base_prefix ]]
}

venv_python="$venv_dir/bin/python"
existing=false
if [[ -e $venv_dir ]]; then
  [[ -d $venv_dir && -f $venv_dir/pyvenv.cfg && -x $venv_python && -f $venv_dir/bin/activate ]] ||
    fail "Existing path is not a recognizable Python virtual environment and was left untouched: $venv_dir"
  existing=true
  probe_python "$venv_python" || fail "Existing environment Python cannot be inspected; environment was not modified."
  [[ $(realpath -m -- "$probe_prefix") == "$venv_dir" && $probe_prefix != "$probe_base_prefix" ]] ||
    fail "Existing environment Python is not bound to $venv_dir; environment was not modified."
  printf '[ChipChain] Existing environment Python: %s (%s)\n' "$probe_version" "$probe_executable"
  if version_satisfies "$probe_version"; then
    printf '[ChipChain] Reusing compatible environment.\n'
    if $verify_only; then
      :
    else
      selected_python=""
    fi
  elif $verify_only || ! $recreate; then
    printf '[ChipChain] Project requires Python %s. Environment was not modified.\n' "$requirement" >&2
    fail "Existing environment uses Python $probe_version. Re-run with a compatible interpreter and --recreate."
  fi
elif $verify_only; then
  fail "No virtual environment exists at $venv_dir. Run ./scripts/setup_env.sh first."
fi

select_interpreter() {
  local candidate resolved
  local -a names=(python3.15 python3.14 python3.13 python3.12 python3.11 python3)
  local -a detected=()
  if [[ -n $requested_python ]]; then
    names=("$requested_python")
  fi
  for candidate in "${names[@]}"; do
    resolved=$(command -v -- "$candidate" 2>/dev/null) || {
      [[ -z $requested_python ]] || detected+=("$candidate -> unavailable")
      continue
    }
    if ! probe_python "$resolved"; then
      detected+=("$candidate -> could not inspect interpreter")
      continue
    fi
    if version_satisfies "$probe_version"; then
      selected_python=$probe_executable
      selected_version=$probe_version
      printf '[ChipChain] Selected Python: %s (%s)\n' "$selected_version" "$selected_python"
      return 0
    fi
    detected+=("$candidate -> $probe_version (too old)")
  done
  printf '[ChipChain] No compatible Python interpreter found.\n' >&2
  if ((${#detected[@]})); then
    printf '[ChipChain] Detected:\n' >&2
    printf '  %s\n' "${detected[@]}" >&2
  fi
  fail "Install/provide Python $minimum or newer and rerun with --python /path/to/python."
}

if ! $existing || { ! version_satisfies "$probe_version" && $recreate; }; then
  select_interpreter
  if ! "$selected_python" -B -c 'import venv' >/dev/null 2>&1; then
    fail "Python $selected_version is compatible, but the venv module is unavailable. Install its Python venv package and retry."
  fi
  if $existing; then
    [[ -f $venv_dir/pyvenv.cfg && -x $venv_python && -f $venv_dir/bin/activate ]] ||
      fail "Environment changed during validation; refusing to recreate $venv_dir"
    printf '[ChipChain] Replacing incompatible environment after validating Python %s...\n' "$selected_version"
    rm -rf -- "$venv_dir"
  fi
  mkdir -p -- "$(dirname -- "$venv_dir")"
  if ! "$selected_python" -m venv "$venv_dir"; then
    rm -rf -- "$venv_dir"
    fail "Python $selected_version could not create a venv. Install the corresponding Python venv package and retry."
  fi
  printf '[ChipChain] Created environment with Python %s.\n' "$selected_version"
fi

verify_environment() {
  probe_python "$venv_python" || fail "Environment Python cannot be inspected: $venv_python"
  version_satisfies "$probe_version" || fail "Environment Python $probe_version does not satisfy $requirement."
  [[ $(realpath -m -- "$probe_prefix") == "$venv_dir" && $probe_prefix != "$probe_base_prefix" ]] ||
    fail "Environment Python is not bound to $venv_dir."
  if ! "$venv_python" -B -c '
import json
import sys
from importlib import metadata
from pathlib import Path
from urllib.parse import unquote, urlparse

import chipchain

distribution = metadata.distribution("chipchain")
direct_url = distribution.read_text("direct_url.json")
if not direct_url:
    sys.exit("missing editable-install metadata")
record = json.loads(direct_url)
url = urlparse(record.get("url", ""))
if url.scheme != "file" or not record.get("dir_info", {}).get("editable"):
    sys.exit("chipchain is not an editable local installation")
if Path(unquote(url.path)).resolve() != Path(sys.argv[1]).resolve():
    sys.exit("chipchain editable installation points to another checkout")
' "$repo_root"; then
    fail "ChipChain import/package metadata does not match this editable checkout. Run setup without --verify-only to repair it."
  fi
  "$venv_python" -B -m chipchain.cli --help >/dev/null ||
    fail 'The ChipChain CLI failed its --help smoke check.'
  printf '[ChipChain] Verified Python: %s\n' "$probe_version"
  printf '[ChipChain] Environment setup PASS\n'
  printf '[ChipChain] Activate:\n  source %s/bin/activate\n' "$venv_dir"
}

if ! $verify_only; then
  printf '[ChipChain] Upgrading pip inside the environment...\n'
  "$venv_python" -m pip install --upgrade pip
  if $with_test; then
    printf '[ChipChain] Installing ChipChain with test dependencies...\n'
    "$venv_python" -m pip install -e "${repo_root}[test]"
  else
    printf '[ChipChain] Installing ChipChain...\n'
    "$venv_python" -m pip install -e "$repo_root"
  fi
fi

verify_environment
