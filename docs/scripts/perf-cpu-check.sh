#!/usr/bin/env bash
# Sample CPU hotspots of one running process with perf.
#
# Usage:
#   docs/scripts/perf-cpu-check.sh [PID|PROCESS] [SECONDS] [OUTPUT_DIR]
#
# Examples:
#   docs/scripts/perf-cpu-check.sh photon 60
#   docs/scripts/perf-cpu-check.sh 1234 120 /tmp/photon-perf-1234
#
# Set CALL_GRAPH=fp to lower profiling overhead.  The default DWARF unwind is
# more reliable for Go stacks, at the cost of a small amount of overhead.

set -euo pipefail

target="${1:-photon}"
seconds="${2:-60}"
output_dir="${3:-./perf-$(date +%Y%m%d-%H%M%S)}"
call_graph="${CALL_GRAPH:-dwarf,16384}"

usage() {
  sed -n '2,13p' "$0" >&2
}

if ! [[ "$seconds" =~ ^[1-9][0-9]*$ ]]; then
  echo "SECONDS must be a positive integer; got: $seconds" >&2
  usage
  exit 2
fi

if [[ "$target" =~ ^[1-9][0-9]*$ ]]; then
  pid="$target"
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "PID $pid is not running or is not accessible." >&2
    exit 1
  fi
else
  mapfile -t pids < <(pgrep -x "$target" || true)
  case "${#pids[@]}" in
    1) pid="${pids[0]}" ;;
    0)
      echo "No process named '$target' is running." >&2
      exit 1
      ;;
    *)
      echo "More than one '$target' process is running: ${pids[*]}" >&2
      echo "Pass the PID explicitly." >&2
      exit 2
      ;;
  esac
fi

if ! command -v perf >/dev/null; then
  echo "perf is not installed or not in PATH." >&2
  exit 1
fi

mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

exe="$(sudo readlink -f "/proc/$pid/exe")"
command_line="$(ps -p "$pid" -o args= 2>/dev/null || echo '<unavailable>')"
{
  printf 'pid: %s\n' "$pid"
  printf 'command: %s\n' "$command_line"
  printf 'exe: %s\n' "$exe"
  printf 'started_at: %s\n' "$(date --iso-8601=seconds)"
  printf 'duration_seconds: %s\n' "$seconds"
  printf 'call_graph: %s\n' "$call_graph"
} > "$output_dir/metadata.txt"

echo "Sampling PID $pid ($exe) for ${seconds}s …"
echo "Output: $output_dir"

sudo perf record \
  --freq 199 \
  --call-graph "$call_graph" \
  --pid "$pid" \
  --output "$output_dir/perf.data" \
  -- sleep "$seconds"

# Keep reports next to perf.data so they can be sent without requiring the
# recipient to know the exact report flags used.
sudo perf report \
  --input "$output_dir/perf.data" \
  --stdio \
  --no-children \
  --percent-limit 1 \
  --sort comm,dso,symbol > "$output_dir/report-self.txt"

sudo perf report \
  --input "$output_dir/perf.data" \
  --stdio \
  --children \
  --percent-limit 1 \
  --sort comm,dso,symbol > "$output_dir/report-inclusive.txt"

sudo perf script \
  --input "$output_dir/perf.data" \
  --fields comm,pid,tid,time,event,ip,sym,dso,period > "$output_dir/perf.script"

# perf.data is written by sudo; return ownership to the user that launched the
# script so every artifact can be inspected or archived without sudo.
if [[ "$(id -u)" != "0" ]]; then
  sudo chown "$(id -u):$(id -g)" "$output_dir/perf.data"
fi

cat <<EOF

Done.  Read these first:
  $output_dir/report-self.txt       # cost in the sampled function itself
  $output_dir/report-inclusive.txt  # cost including callees

Interactive drill-down:
  sudo perf report --input $output_dir/perf.data

If Photon frames are still shown as raw addresses, profile a binary built
without '-ldflags -s -w' (the release/Nix package is stripped), then rerun.
EOF
