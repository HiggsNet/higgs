#!/bin/sh

set -eu

repo="${PHOTON_GITHUB_REPOSITORY:-HiggsNet/photon}"
version="${PHOTON_VERSION:-latest}"
install_dir="${PHOTON_INSTALL_DIR:-/usr/local/bin}"
service_dir="${PHOTON_SYSTEMD_DIR:-/etc/systemd/system}"
update_only=false
install_service=true
enable_service=false
install_admin=false
skip_dependency_check=${PHOTON_SKIP_DEPENDENCY_CHECK:-false}

usage() {
	cat <<'EOF'
Install Photon from a GitHub Release.

Usage: install.sh [--version VERSION] [--install-dir DIR] [--admin] [--no-service] [--enable-service] [--skip-dependency-check] [--update]

Options:
  --version VERSION   Release tag to install (default: latest)
  --install-dir DIR   Binary destination (default: /usr/local/bin)
  --admin             Also install the photon-admin command, configuration,
                      and photon-admin.service
  --no-service        Do not install the systemd service
  --enable-service    Enable installed Photon services (does not start them)
  --skip-dependency-check
                      Skip host runtime dependency checks (for control-plane-only
                      or externally managed deployments)
  --update            Do nothing when the installed version is current; an
                      existing photon-admin installation is updated automatically
  -h, --help          Show this help

Environment:
  PHOTON_GITHUB_REPOSITORY  GitHub owner/repository (default: HiggsNet/photon)
  PHOTON_VERSION            Same as --version
  PHOTON_INSTALL_DIR        Same as --install-dir
  PHOTON_SYSTEMD_DIR        systemd unit directory (default: /etc/systemd/system)
  PHOTON_SKIP_DEPENDENCY_CHECK
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
	if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] && ! systemctl cat strongswan.service >/dev/null 2>&1; then
		if [ -n "$missing" ]; then
			missing="${missing}, strongswan.service"
		else
			missing=strongswan.service
		fi
	fi

	if [ -n "$missing" ]; then
		cat >&2 <<EOF
error: missing Photon runtime dependencies: ${missing}

A full data-plane installation needs:
  iproute2: ip
  iputils: ping
  BIRD 2.14+: bird, birdc
  nftables: nft
  iptables fallback: iptables, ip6tables, ipset
  StrongSwan: swanctl and strongswan.service (with charon/VICI running when IPsec is enabled)

Ubuntu 24.04+ example:
  apt install bird2 charon-systemd iproute2 ipset iptables iputils-ping nftables strongswan-swanctl

On Ubuntu, charon-systemd provides the strongswan.service unit and the VICI-
enabled charon daemon used by swanctl. Installing strongswan-swanctl alone only
provides the client command.

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

Photon native data-plane installations require BIRD 2.14 or newer.
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
		--admin)
			install_admin=true
			shift
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

# update.sh should preserve an existing dual-role installation even when the
# operator does not need to repeat --admin on every upgrade.
if [ "$update_only" = true ] && [ -x "${install_dir}/photon-admin" ]; then
	install_admin=true
fi

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
		echo "error: PHOTON_SKIP_DEPENDENCY_CHECK must be true or false" >&2
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
if [ "$update_only" = true ] && command -v photon >/dev/null 2>&1 && command -v photon-services >/dev/null 2>&1 && { [ "$install_admin" = false ] || [ -x "${install_dir}/photon-admin" ]; }; then
	current=$(photon version 2>/dev/null | sed -n '1s/^photon //p')
	if [ "$current" = "$version" ]; then
		already_current=true
	fi
fi

archive="photon-${version}-${os}-${arch}.tar.gz"
checksum="photon-${os}-${arch}.sha256"
base_url="https://github.com/${repo}/releases/download/${version}"
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

if [ "$already_current" = false ]; then
	echo "Downloading photon ${version} for ${os}/${arch}..."
	curl -fL --retry 3 -o "${tmp_dir}/${archive}" "${base_url}/${archive}"
	curl -fL --retry 3 -o "${tmp_dir}/${checksum}" "${base_url}/${checksum}"
	(
		cd "$tmp_dir"
		sha256sum -c "$checksum"
	)
	tar -xzf "${tmp_dir}/${archive}" -C "$tmp_dir"
	binary="${tmp_dir}/photon-${version}-${os}-${arch}/photon"
	services_binary="${tmp_dir}/photon-${version}-${os}-${arch}/photon-services"
	[ -x "$binary" ] || { echo "error: release archive does not contain photon" >&2; exit 1; }
	[ -x "$services_binary" ] || { echo "error: release archive does not contain photon-services" >&2; exit 1; }
	if [ "$install_admin" = true ]; then
		archive_admin_wrapper="${tmp_dir}/photon-${version}-${os}-${arch}/photon-admin"
		admin_wrapper="${tmp_dir}/photon-admin"
		if [ -f "$archive_admin_wrapper" ]; then
			cp "$archive_admin_wrapper" "$admin_wrapper"
		elif ! curl -fsL --retry 3 -o "$admin_wrapper" \
			"https://raw.githubusercontent.com/${repo}/${version}/contrib/photon-admin"; then
			installer_ref="${PHOTON_INSTALLER_REF:-master}"
			curl -fL --retry 3 -o "$admin_wrapper" \
				"https://raw.githubusercontent.com/${repo}/${installer_ref}/contrib/photon-admin"
		fi
	fi

	if [ -d "$install_dir" ] && [ -w "$install_dir" ]; then
		install -m 0755 "$binary" "${install_dir}/photon"
		[ "$install_admin" = false ] || install -m 0755 "$admin_wrapper" "${install_dir}/photon-admin"
		install -m 0755 "$services_binary" "${install_dir}/photon-services"
	elif [ ! -e "$install_dir" ] && [ -w "$(dirname "$install_dir")" ]; then
		mkdir -p "$install_dir"
		install -m 0755 "$binary" "${install_dir}/photon"
		[ "$install_admin" = false ] || install -m 0755 "$admin_wrapper" "${install_dir}/photon-admin"
		install -m 0755 "$services_binary" "${install_dir}/photon-services"
	elif command -v sudo >/dev/null 2>&1; then
		sudo install -d "$install_dir"
		sudo install -m 0755 "$binary" "${install_dir}/photon"
		[ "$install_admin" = false ] || sudo install -m 0755 "$admin_wrapper" "${install_dir}/photon-admin"
		sudo install -m 0755 "$services_binary" "${install_dir}/photon-services"
	else
		echo "error: ${install_dir} is not writable; rerun as root or set PHOTON_INSTALL_DIR" >&2
		exit 1
	fi

	if [ "$install_admin" = true ]; then
		echo "Installed photon ${version}, photon-admin, and photon-services to ${install_dir}"
	else
		echo "Installed photon ${version} and photon-services to ${install_dir}"
	fi
	"${install_dir}/photon" version
else
	echo "photon ${version} is already installed"
fi

if [ "$install_admin" = true ]; then
	admin_config_dir="/etc/photon/admin"
	admin_config="${admin_config_dir}/config.yaml"
	admin_config_tmp="${tmp_dir}/admin-config.yaml"
	cat > "$admin_config_tmp" <<EOF
# Photon admin instance. Keep its identity, gossip/observer ports, and data-plane
# resources distinct from the node instance in /etc/photon/config.yaml.
data_dir: ${admin_config_dir}
state_path: ${admin_config_dir}/photon.db
gossip:
  listen_addr: "[::]:33435"
EOF
	if [ "$(id -u)" -eq 0 ]; then
		install -d -m 0700 /etc/photon "$admin_config_dir"
		[ -e "$admin_config" ] || install -m 0600 "$admin_config_tmp" "$admin_config"
	elif command -v sudo >/dev/null 2>&1; then
		sudo install -d -m 0700 /etc/photon "$admin_config_dir"
		[ -e "$admin_config" ] || sudo install -m 0600 "$admin_config_tmp" "$admin_config"
	else
		echo "error: cannot prepare ${admin_config_dir}; rerun as root" >&2
		exit 1
	fi
fi

if [ "$install_service" = true ]; then
	service_source="${tmp_dir}/photon.service"
	archive_service="${tmp_dir}/photon-${version}-${os}-${arch}/photon.service"
	if [ -f "$archive_service" ]; then
		cp "$archive_service" "$service_source.source"
	elif ! curl -fsL --retry 3 -o "$service_source.source" \
		"https://raw.githubusercontent.com/${repo}/${version}/contrib/systemd/photon.service"; then
		installer_ref="${PHOTON_INSTALLER_REF:-master}"
		curl -fL --retry 3 -o "$service_source.source" \
			"https://raw.githubusercontent.com/${repo}/${installer_ref}/contrib/systemd/photon.service"
	fi
	sed \
		-e "s|^ExecStart=.*|ExecStart=${install_dir}/photon daemon|" \
		"$service_source.source" > "$service_source"
	if [ "$install_admin" = true ]; then
		admin_service_source="${tmp_dir}/photon-admin.service"
		archive_admin_service="${tmp_dir}/photon-${version}-${os}-${arch}/photon-admin.service"
		if [ -f "$archive_admin_service" ]; then
			cp "$archive_admin_service" "$admin_service_source.source"
		elif ! curl -fsL --retry 3 -o "$admin_service_source.source" \
			"https://raw.githubusercontent.com/${repo}/${version}/contrib/systemd/photon-admin.service"; then
			installer_ref="${PHOTON_INSTALLER_REF:-master}"
			curl -fL --retry 3 -o "$admin_service_source.source" \
				"https://raw.githubusercontent.com/${repo}/${installer_ref}/contrib/systemd/photon-admin.service"
		fi
		sed \
			-e "s|^ExecStart=.*|ExecStart=${install_dir}/photon-admin daemon|" \
			"$admin_service_source.source" > "$admin_service_source"
	fi

	if [ -d "$service_dir" ] && [ -w "$service_dir" ]; then
		install -m 0644 "$service_source" "${service_dir}/photon.service"
		[ "$install_admin" = false ] || install -m 0644 "$admin_service_source" "${service_dir}/photon-admin.service"
	elif command -v sudo >/dev/null 2>&1; then
		sudo install -d "$service_dir"
		sudo install -m 0644 "$service_source" "${service_dir}/photon.service"
		[ "$install_admin" = false ] || sudo install -m 0644 "$admin_service_source" "${service_dir}/photon-admin.service"
	else
		echo "error: ${service_dir} is not writable; rerun as root or use --no-service" >&2
		exit 1
	fi

	if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
		if [ "$(id -u)" -eq 0 ]; then
			systemctl daemon-reload
			if [ "$enable_service" = true ]; then
				systemctl enable photon.service
				[ "$install_admin" = false ] || systemctl enable photon-admin.service
			fi
		else
			sudo systemctl daemon-reload
			if [ "$enable_service" = true ]; then
				sudo systemctl enable photon.service
				[ "$install_admin" = false ] || sudo systemctl enable photon-admin.service
			fi
		fi
	fi
	if [ "$install_admin" = true ]; then
		echo "Installed ${service_dir}/photon.service and ${service_dir}/photon-admin.service (not started)"
		echo "Prepared ${admin_config}; edit and initialize it with photon-admin before starting photon-admin.service"
	else
		echo "Installed ${service_dir}/photon.service (not started)"
	fi
fi
