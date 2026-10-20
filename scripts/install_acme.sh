#!/usr/bin/env bash
# Install trojan-grpc-simple as a systemd service with a Let's Encrypt
# certificate issued and renewed by acme.sh's standalone HTTP-01 mode.
set -Eeuo pipefail

readonly REPOSITORY_URL="https://github.com/willoong9559/trojan-python.git"
readonly INSTALL_DIR="/opt/trojan-python"
readonly VENV_DIR="${INSTALL_DIR}/.venv"
readonly CONFIG_DIR="/etc/trojan-grpc"
readonly CERT_DIR="${CONFIG_DIR}/certs"
readonly ENV_FILE="${CONFIG_DIR}/trojan-grpc.env"
readonly SERVICE_FILE="/etc/systemd/system/trojan-grpc.service"
readonly SERVICE_USER="trojan"

DOMAIN=""
EMAIL=""
PASSWORD=""
SERVICE_NAME="GunService"
PORT="443"
DISABLE_UDP=0
SKIP_FIREWALL=0
ACME_BIN="/root/.acme.sh/acme.sh"

log() {
  printf '[trojan-grpc] %s\n' "$*"
}

die() {
  printf '[trojan-grpc] error: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage:
  sudo ./install_acme.sh --domain DOMAIN --email EMAIL [options]

Required:
  --domain DOMAIN           Public domain pointing to this server
  --email EMAIL             Let's Encrypt account email

Options:
  --password PASSWORD       Trojan password. Omit to enter it without echoing.
  --service-name NAME       gRPC service name (default: GunService)
  --port PORT               TLS listening port (default: 443)
  --disable-udp             Disable Trojan UDP ASSOCIATE support
  --skip-firewall           Do not open TCP ports 80 and PORT with UFW/firewalld
  -h, --help                Show this help

The script uses acme.sh standalone HTTP-01 validation. Domain DNS must already
point to this machine, and public TCP port 80 must be reachable and unoccupied.
EOF
}

require_root_and_systemd() {
  [[ ${EUID} -eq 0 ]] || die "run this script as root (for example: sudo $0 ...)"
  [[ $(uname -s) == "Linux" ]] || die "this installer only supports Linux"
  command -v systemctl >/dev/null || die "systemd is required"
  [[ -d /run/systemd/system ]] || die "this host is not booted with systemd"
}

install_packages() {
  if command -v apt-get >/dev/null; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-venv python3-pip git curl socat ca-certificates
  elif command -v dnf >/dev/null; then
    dnf install -y python3 python3-pip git curl socat ca-certificates
  elif command -v yum >/dev/null; then
    yum install -y python3 python3-pip git curl socat ca-certificates
  elif command -v zypper >/dev/null; then
    zypper --non-interactive install python3 python3-pip git curl socat ca-certificates
  elif command -v pacman >/dev/null; then
    pacman --noconfirm -Sy python python-pip git curl socat ca-certificates
  else
    die "unsupported package manager; install Python 3, venv, git, curl, socat, and ca-certificates manually"
  fi
  command -v python3 >/dev/null || die "python3 installation failed"
  command -v git >/dev/null || die "git installation failed"
  command -v curl >/dev/null || die "curl installation failed"
  command -v socat >/dev/null || die "socat is required by acme.sh standalone mode"
  python3 -c 'import sys; assert sys.version_info >= (3, 9), "Python 3.9 or newer is required"' \
    || die "Python 3.9 or newer is required"
}

validate_arguments() {
  [[ $DOMAIN =~ ^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$ ]] || die "invalid domain name"
  [[ $DOMAIN != *..* ]] || die "invalid domain name"
  [[ $EMAIL == *@* ]] || die "invalid email address"
  [[ $SERVICE_NAME =~ ^[A-Za-z0-9._-]+$ ]] || die "service name may only contain letters, digits, dot, underscore, and hyphen"
  [[ $PORT =~ ^[0-9]+$ ]] && (( PORT >= 1 && PORT <= 65535 )) || die "port must be in 1..65535"
  [[ $PASSWORD != *$'\n'* && $PASSWORD != *$'\r'* ]] || die "password must not contain a newline"
}

configure_firewall() {
  (( SKIP_FIREWALL )) && return
  if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
    log "opening TCP 80 and ${PORT} with UFW"
    ufw allow 80/tcp
    ufw allow "${PORT}/tcp"
  elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    log "opening TCP 80 and ${PORT} with firewalld"
    firewall-cmd --permanent --add-port=80/tcp
    firewall-cmd --permanent --add-port="${PORT}/tcp"
    firewall-cmd --reload
  else
    log "no active UFW/firewalld detected; ensure the provider firewall permits TCP 80 and ${PORT}"
  fi
}

install_application() {
  if [[ -d ${INSTALL_DIR}/.git ]]; then
    log "updating existing checkout at ${INSTALL_DIR}"
    git -C "$INSTALL_DIR" fetch --depth 1 origin main
    git -C "$INSTALL_DIR" pull --ff-only origin main
  elif [[ -e $INSTALL_DIR ]]; then
    die "${INSTALL_DIR} exists but is not this Git checkout; move it aside before installing"
  else
    log "cloning ${REPOSITORY_URL}"
    git clone --depth 1 --branch main "$REPOSITORY_URL" "$INSTALL_DIR"
  fi

  python3 -m venv "$VENV_DIR"
  "$VENV_DIR/bin/pip" install --upgrade pip
  "$VENV_DIR/bin/pip" install "$INSTALL_DIR"
}

install_acme_sh() {
  if [[ ! -x $ACME_BIN ]]; then
    log "installing acme.sh" >&2
    curl -fsSL https://get.acme.sh | sh -s "email=${EMAIL}"
  fi
  [[ -x $ACME_BIN ]] || die "acme.sh installation failed"
}

write_service_files() {
  local escaped_password udp_argument nologin_path
  escaped_password=${PASSWORD//\\/\\\\}
  escaped_password=${escaped_password//\"/\\\"}
  udp_argument=""
  (( DISABLE_UDP )) && udp_argument=" --disable-udp"
  nologin_path=$(command -v nologin || true)
  [[ -n $nologin_path ]] || nologin_path=/usr/sbin/nologin

  if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --home-dir "$INSTALL_DIR" --shell "$nologin_path" "$SERVICE_USER"
  fi
  install -d -m 0750 -o root -g "$SERVICE_USER" "$CONFIG_DIR" "$CERT_DIR"
  umask 077
  printf 'TROJAN_PASSWORD="%s"\n' "$escaped_password" >"$ENV_FILE"
  chown root:"$SERVICE_USER" "$ENV_FILE"
  chmod 0640 "$ENV_FILE"

  cat >"$SERVICE_FILE" <<UNIT
[Unit]
Description=Trojan gRPC Python proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${VENV_DIR}/bin/trojan-grpc-server --host 0.0.0.0 --port ${PORT} --service-name ${SERVICE_NAME} --cert ${CERT_DIR}/fullchain.pem --key ${CERT_DIR}/privkey.pem --password \${TROJAN_PASSWORD}${udp_argument}
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
UNIT
}

issue_and_install_certificate() {
  local acme_bin=$1
  log "issuing or renewing an ECDSA certificate for ${DOMAIN}"
  "$acme_bin" --set-default-ca --server letsencrypt
  "$acme_bin" --issue --standalone --server letsencrypt --keylength ec-256 -d "$DOMAIN"
  "$acme_bin" --install-cert -d "$DOMAIN" --ecc \
    --key-file "${CERT_DIR}/privkey.pem" \
    --fullchain-file "${CERT_DIR}/fullchain.pem" \
    --reloadcmd "/bin/systemctl restart trojan-grpc.service"
  chown root:"$SERVICE_USER" "${CERT_DIR}/privkey.pem" "${CERT_DIR}/fullchain.pem"
  chmod 0640 "${CERT_DIR}/privkey.pem"
  chmod 0644 "${CERT_DIR}/fullchain.pem"
}

main() {
  while (($#)); do
    case $1 in
      --domain) DOMAIN=${2:?missing value for --domain}; shift 2 ;;
      --email) EMAIL=${2:?missing value for --email}; shift 2 ;;
      --password) PASSWORD=${2:?missing value for --password}; shift 2 ;;
      --service-name) SERVICE_NAME=${2:?missing value for --service-name}; shift 2 ;;
      --port) PORT=${2:?missing value for --port}; shift 2 ;;
      --disable-udp) DISABLE_UDP=1; shift ;;
      --skip-firewall) SKIP_FIREWALL=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown argument: $1" ;;
    esac
  done

  [[ -n $DOMAIN && -n $EMAIL ]] || { usage >&2; exit 2; }
  if [[ -z $PASSWORD ]]; then
    read -r -s -p "Trojan password: " PASSWORD
    printf '\n'
    [[ -n $PASSWORD ]] || die "password must not be empty"
  fi

  require_root_and_systemd
  validate_arguments
  install_packages
  configure_firewall
  install_application
  write_service_files
  install_acme_sh
  issue_and_install_certificate "$ACME_BIN"

  systemctl daemon-reload
  systemctl enable --now trojan-grpc.service
  systemctl is-active --quiet trojan-grpc.service || {
    systemctl --no-pager --full status trojan-grpc.service || true
    die "service did not start"
  }

  log "installation complete"
  log "gRPC path: /${SERVICE_NAME}/Tun"
  log "check status: systemctl status trojan-grpc"
  log "certificate renewal is handled by acme.sh; it must keep TCP 80 reachable"
}

main "$@"
