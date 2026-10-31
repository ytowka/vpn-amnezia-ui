#!/usr/bin/env bash
# macOS/Linux, Bash >= 3.2. Requires OpenSSH and standard Unix utilities.
# Calls the existing add-awg-client.py ON THE SWE SERVER.
set -euo pipefail
umask 077

usage() {
    cat <<'HELP'
Usage: bash create-awg-client.sh NAME [options]

Create an AmneziaWG client on SWE and save NAME.conf in the CURRENT directory.
The existing server script and working template must already be on SWE.
Uses your normal SSH config, keys/agent, known_hosts, and password prompts.

Options:
  --host HOST           SSH alias or user@address (default: aeza-swe)
  --remote-script PATH  Server script (default: /root/add-awg-client.py)
  --template PATH       Template ON SERVER (default: /root/template.conf)
  --remote-dir PATH     Server output dir (default: /root/awg-clients)
  --ru-ip IP            Client VPN endpoint IP (default: 178.236.242.31)
  --ru-port PORT        Client VPN endpoint UDP port (default: 4956)
  --container NAME      Explicit Docker container; otherwise auto-detect
  --server-conf PATH    Server config path INSIDE Docker; otherwise auto-detect
  --sudo               Run server Python and cat using sudo -n (no password)
  --download-only      Download an existing client; do not create a new peer
  -h, --help           Show this help

Examples:
  bash create-awg-client.sh danil-phone
  bash create-awg-client.sh danil-laptop --host root@147.45.77.8
  bash create-awg-client.sh danil-phone --download-only

Local files are never overwritten. The server copy is retained for recovery.
HELP
}

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

if [[ $# -eq 0 ]]; then usage; exit 2; fi
case "$1" in -h|--help) usage; exit 0 ;; esac
CLIENT_NAME="$1"
shift
[[ "$CLIENT_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$ ]] || die 'Invalid client name; example: danil-phone'

SSH_HOST='aeza-swe'
REMOTE_SCRIPT='/root/add-awg-client.py'
TEMPLATE='/root/template.conf'
REMOTE_DIR='/root/awg-clients'
RU_IP='178.236.242.31'
RU_PORT='4956'
CONTAINER=''
SERVER_CONF=''
USE_SUDO=0
DOWNLOAD_ONLY=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host|--remote-script|--template|--remote-dir|--ru-ip|--ru-port|--container|--server-conf)
            [[ $# -ge 2 && -n "$2" ]] || die "Missing value for $1"
            case "$1" in
                --host) SSH_HOST="$2" ;;
                --remote-script) REMOTE_SCRIPT="$2" ;;
                --template) TEMPLATE="$2" ;;
                --remote-dir) REMOTE_DIR="$2" ;;
                --ru-ip) RU_IP="$2" ;;
                --ru-port) RU_PORT="$2" ;;
                --container) CONTAINER="$2" ;;
                --server-conf) SERVER_CONF="$2" ;;
            esac
            shift 2
            ;;
        --sudo) USE_SUDO=1; shift ;;
        --download-only) DOWNLOAD_ONLY=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "Unknown option: $1" ;;
    esac
done

[[ "$SSH_HOST" != -* && ! "$SSH_HOST" =~ [[:space:][:cntrl:]] ]] || die 'Invalid SSH host'
[[ "$REMOTE_SCRIPT" == /* && "$TEMPLATE" == /* && "$REMOTE_DIR" == /* ]] || die 'Remote paths must be absolute (use /root/..., not ~/...)'
[[ "$RU_PORT" =~ ^[0-9]{1,5}$ ]] || die 'Invalid RU port'
(( 10#$RU_PORT >= 1 && 10#$RU_PORT <= 65535 )) || die 'RU port must be 1..65535'
command -v ssh >/dev/null 2>&1 || die 'OpenSSH ssh is required'

# POSIX-shell quoting: SSH sends the remote command as a string, not argv.
# No user-supplied value is interpolated as executable shell syntax.
quote() {
    local escaped
    escaped=${1//\'/\'\\\'\'}
    printf "'%s'" "$escaped"
}
join_args() {
    local item
    for item in "$@"; do quote "$item"; printf ' '; done
}

REMOTE_FILE="${REMOTE_DIR%/}/$CLIENT_NAME.conf"
REMOTE_CMD='set -eu; '
if [[ "$DOWNLOAD_ONLY" -eq 0 ]]; then
    GENERATE=(python3 "$REMOTE_SCRIPT" "$CLIENT_NAME"
        --template "$TEMPLATE" --out-dir "$REMOTE_DIR"
        --ru-ip "$RU_IP" --ru-port "$RU_PORT")
    if [[ -n "$CONTAINER" ]]; then GENERATE+=(--container "$CONTAINER"); fi
    if [[ -n "$SERVER_CONF" ]]; then GENERATE+=(--server-conf "$SERVER_CONF"); fi
    if [[ "$USE_SUDO" -eq 1 ]]; then GENERATE=(sudo -n "${GENERATE[@]}"); fi
    # Keep progress and diagnostics out of the downloaded configuration.
    REMOTE_CMD+="$(join_args "${GENERATE[@]}")>&2; "
fi
READ=(cat -- "$REMOTE_FILE")
if [[ "$USE_SUDO" -eq 1 ]]; then READ=(sudo -n "${READ[@]}"); fi
REMOTE_CMD+="$(join_args "${READ[@]}")"

DEST="$PWD/$CLIENT_NAME.conf"
[[ ! -e "$DEST" && ! -L "$DEST" ]] || die "Local file already exists: $DEST"
TEMP_FILE=$(mktemp "$PWD/.awg-client.XXXXXX") || die 'Cannot write to current directory'
cleanup() { rm -f -- "$TEMP_FILE"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

printf 'Connecting to %s ...\n' "$SSH_HOST" >&2
if ! ssh -T -- "$SSH_HOST" "$REMOTE_CMD" > "$TEMP_FILE"; then
    printf '%s\n' 'SSH/remote command failed. No local configuration was published.' >&2
    printf '%s\n' 'If creation finished on the server, rerun with --download-only to retrieve it.' >&2
    exit 1
fi

# Reject empty/truncated responses and common accidental diagnostic output.
for pattern in '^\[Interface\][[:space:]]*$' '^\[Peer\][[:space:]]*$' \
    '^[[:space:]]*PrivateKey[[:space:]]*=[[:space:]]*[^[:space:]]+' \
    '^[[:space:]]*Endpoint[[:space:]]*=[[:space:]]*[^[:space:]]+'; do
    if ! grep -Eq "$pattern" "$TEMP_FILE"; then
        die 'Downloaded data does not look like a client .conf; server copy was retained'
    fi
done
chmod 600 "$TEMP_FILE"
# Hard-link within the same directory publishes atomically without overwriting.
ln "$TEMP_FILE" "$DEST" || die "Cannot publish file (possibly already exists): $DEST"
printf 'Saved: %s\n' "$DEST"
