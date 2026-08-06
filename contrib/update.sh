#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd || true)
if [ -n "$script_dir" ] && [ -f "${script_dir}/install.sh" ]; then
	exec sh "${script_dir}/install.sh" --update "$@"
fi

repo="${PHOTON_GITHUB_REPOSITORY:-HiggsNet/photon}"
ref="${PHOTON_INSTALLER_REF:-master}"
tmp_file=$(mktemp)
trap 'rm -f "$tmp_file"' EXIT HUP INT TERM

command -v curl >/dev/null 2>&1 || {
	echo "error: curl is required" >&2
	exit 1
}

curl -fL --retry 3 -o "$tmp_file" "https://raw.githubusercontent.com/${repo}/${ref}/contrib/install.sh"
sh "$tmp_file" --update "$@"
