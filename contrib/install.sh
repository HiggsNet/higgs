#!/bin/sh

set -eu

repo="${HIGGS_GITHUB_REPOSITORY:-HiggsNet/higgs}"
version="${HIGGS_VERSION:-latest}"
install_dir="${HIGGS_INSTALL_DIR:-/usr/local/bin}"
service_dir="${HIGGS_SYSTEMD_DIR:-/etc/systemd/system}"
update_only=false
install_service=true
enable_service=false
skip_dependency_check=${HIGGS_SKIP_DEPENDENCY_CHECK:-false}

usage() {
	cat <<'EOF'
Install Higgs from a GitHub Release.

Usage: install.sh [--version VERSION] [--install-dir DIR] [--no-service] [--enable-service] [--skip-dependency-check] [--update]

Options:
  --version VERSION   Release tag to install (default: latest)
  --install-dir DIR   Binary destination (default: /usr/local/bin)
  --no-service        Do not install the systemd service
  --enable-service    Enable higgsnet.service after installing it (does not start it)
  --skip-dependency-check
                      Skip host runtime dependency checks (for control-plane-only
                      or externally managed deployments)
  --update            Do nothing when the installed version is current
  -h, --help          Show this help

Environment:
  HIGGS_GITHUB_REPOSITORY  GitHub owner/repository (default: HiggsNet/higgs)
  HIGGS_VERSION            Same as --version
  HIGGS_INSTALL_DIR        Same as --install-dir
  HIGGS_SYSTEMD_DIR        systemd unit directory (default: /etc/systemd/system)
  HIGGS_SKIP_DEPENDENCY_CHECK
                           Set to true to skip runtime dependency checks
EOF
}

check_runtime_dependencies() {
	missing=
	for dependency in ip ping bird birdc nft iptables ip6tables ipset swanctl; do
		if ! command -v "$dependency" >/dev/null 2>&1; then
			if [ -n "$missing" ]; then
				missing="${missing}, ${dependency}"
			else
				missing=$dependency
			fi
		fi
	done

	if [ -n "$missing" ]; then
		cat >&2 <<EOF
error: missing Higgs runtime commands: ${missing}

A full data-plane installation needs:
  iproute2: ip
  iputils: ping
  BIRD 2.14+: bird, birdc
  nftables: nft
  iptables fallback: iptables, ip6tables, ipset
  StrongSwan: swanctl (with a running charon/VICI service when IPsec is enabled)

Ubuntu 24.04+ example:
  apt install bird2 iproute2 ipset iptables iputils-ping nftables strongswan-charon strongswan-swanctl

Other distributions must provide BIRD 2.14 or newer; for example, Debian
Bookworm's stock BIRD 2.0.12 package is too old for the supported baseline.

Install the missing dependencies and retry. For a control-plane-only or
externally managed deployment, pass --skip-dependency-check explicitly.
EOF
		return 1
	fi

	bird_version_raw=$(bird --version 2>&1 | sed -n '1p')
	bird_version=$(printf '%s\n' "$bird_version_raw" | sed -n 's/^.*BIRD version \([0-9][0-9.]*\).*$/\1/p')
	bird_major=$(printf '%s\n' "$bird_version" | cut -d. -f1)
	bird_minor=$(printf '%s\n' "$bird_version" | cut -d. -f2)
	if [ -z "$bird_major" ] || [ -z "$bird_minor" ] || ! { [ "$bird_major" -gt 2 ] || { [ "$bird_major" -eq 2 ] && [ "$bird_minor" -ge 14 ]; }; } 2>/dev/null; then
		cat >&2 <<EOF
error: unsupported BIRD version: ${bird_version_raw:-unknown}

Higgs native data-plane installations require BIRD 2.14 or newer.
Ubuntu 24.04 and newer provide a compatible bird2 package. For a
control-plane-only or externally managed deployment, pass
--skip-dependency-check explicitly.
EOF
		return 1
	fi

	echo "Runtime dependency check passed (BIRD ${bird_version})"
}

while [ "$#" -gt 0 ]; do
	case "$1" in
		--version)
			[ "$#" -ge 2 ] || { echo "error: --version needs a value" >&2; exit 2; }
			version=$2
			shift 2
			;;
		--install-dir)
			[ "$#" -ge 2 ] || { echo "error: --install-dir needs a value" >&2; exit 2; }
			install_dir=$2
			shift 2
			;;
		--update)
			update_only=true
			shift
			;;
		--no-service)
			install_service=false
			shift
			;;
		--enable-service)
			enable_service=true
			shift
			;;
		--skip-dependency-check)
			skip_dependency_check=true
			shift
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			echo "error: unknown argument: $1" >&2
			usage >&2
			exit 2
			;;
	esac
done

command -v curl >/dev/null 2>&1 || {
	echo "error: curl is required" >&2
	exit 1
}
command -v sha256sum >/dev/null 2>&1 || {
	echo "error: sha256sum is required" >&2
	exit 1
}

case "$(uname -s)" in
	Linux) os=linux ;;
	*) echo "error: only Linux releases are currently available" >&2; exit 1 ;;
esac

case "$(uname -m)" in
	x86_64|amd64) arch=amd64 ;;
	aarch64|arm64) arch=arm64 ;;
	*) echo "error: unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

case "$skip_dependency_check" in
	true) ;;
	false) check_runtime_dependencies ;;
	*)
		echo "error: HIGGS_SKIP_DEPENDENCY_CHECK must be true or false" >&2
		exit 2
		;;
esac

if [ "$version" = latest ]; then
	latest_url=$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/${repo}/releases/latest")
	version=${latest_url##*/}
	[ -n "$version" ] && [ "$version" != latest ] || {
		echo "error: could not determine the latest release tag" >&2
		exit 1
	}
fi

case "$version" in
	v*) ;;
	*) version="v${version}" ;;
esac

already_current=false
if [ "$update_only" = true ] && command -v higgsnet >/dev/null 2>&1 && command -v higgs-services >/dev/null 2>&1; then
	current=$(higgsnet version 2>/dev/null | sed -n '1s/^higgs //p')
	if [ "$current" = "$version" ]; then
		already_current=true
	fi
fi

archive="higgs-${version}-${os}-${arch}.tar.gz"
checksum="higgs-${os}-${arch}.sha256"
base_url="https://github.com/${repo}/releases/download/${version}"
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

if [ "$already_current" = false ]; then
	echo "Downloading higgs ${version} for ${os}/${arch}..."
	curl -fL --retry 3 -o "${tmp_dir}/${archive}" "${base_url}/${archive}"
	curl -fL --retry 3 -o "${tmp_dir}/${checksum}" "${base_url}/${checksum}"
	(
		cd "$tmp_dir"
		sha256sum -c "$checksum"
	)
	tar -xzf "${tmp_dir}/${archive}" -C "$tmp_dir"
	binary="${tmp_dir}/higgs-${version}-${os}-${arch}/higgs"
	services_binary="${tmp_dir}/higgs-${version}-${os}-${arch}/higgs-services"
	[ -x "$binary" ] || { echo "error: release archive does not contain higgs" >&2; exit 1; }
	[ -x "$services_binary" ] || { echo "error: release archive does not contain higgs-services" >&2; exit 1; }

	if [ -d "$install_dir" ] && [ -w "$install_dir" ]; then
		install -m 0755 "$binary" "${install_dir}/higgsnet"
		install -m 0755 "$services_binary" "${install_dir}/higgs-services"
	elif [ ! -e "$install_dir" ] && [ -w "$(dirname "$install_dir")" ]; then
		mkdir -p "$install_dir"
		install -m 0755 "$binary" "${install_dir}/higgsnet"
		install -m 0755 "$services_binary" "${install_dir}/higgs-services"
	elif command -v sudo >/dev/null 2>&1; then
		sudo install -d "$install_dir"
		sudo install -m 0755 "$binary" "${install_dir}/higgsnet"
		sudo install -m 0755 "$services_binary" "${install_dir}/higgs-services"
	else
		echo "error: ${install_dir} is not writable; rerun as root or set HIGGS_INSTALL_DIR" >&2
		exit 1
	fi

	echo "Installed higgsnet ${version} and higgs-services to ${install_dir}"
	"${install_dir}/higgsnet" version
else
	echo "higgsnet ${version} is already installed"
fi

if [ "$install_service" = true ]; then
	service_source="${tmp_dir}/higgsnet.service"
	archive_service="${tmp_dir}/higgs-${version}-${os}-${arch}/higgsnet.service"
	if [ -f "$archive_service" ]; then
		cp "$archive_service" "$service_source.source"
	elif ! curl -fsL --retry 3 -o "$service_source.source" \
		"https://raw.githubusercontent.com/${repo}/${version}/contrib/systemd/higgsnet.service"; then
		installer_ref="${HIGGS_INSTALLER_REF:-master}"
		curl -fL --retry 3 -o "$service_source.source" \
			"https://raw.githubusercontent.com/${repo}/${installer_ref}/contrib/systemd/higgsnet.service"
	fi
	sed "s|^ExecStart=.*|ExecStart=${install_dir}/higgsnet daemon|" \
		"$service_source.source" > "$service_source"

	if [ -d "$service_dir" ] && [ -w "$service_dir" ]; then
		install -m 0644 "$service_source" "${service_dir}/higgsnet.service"
	elif command -v sudo >/dev/null 2>&1; then
		sudo install -d "$service_dir"
		sudo install -m 0644 "$service_source" "${service_dir}/higgsnet.service"
	else
		echo "error: ${service_dir} is not writable; rerun as root or use --no-service" >&2
		exit 1
	fi

	if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
		if [ "$(id -u)" -eq 0 ]; then
			systemctl daemon-reload
			[ "$enable_service" = false ] || systemctl enable higgsnet.service
		else
			sudo systemctl daemon-reload
			[ "$enable_service" = false ] || sudo systemctl enable higgsnet.service
		fi
	fi
	echo "Installed ${service_dir}/higgsnet.service (not started)"
fi
