#!/usr/bin/env bash
#
# http-server.sh — an HTTP/1.1 web server written in Bash 5 and socat.
#
# Copyright 2026 Piyush
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Standards targeted: RFC 9110 (HTTP semantics), RFC 9112 (HTTP/1.1 syntax),
#                     RFC 9111 (conditional requests and caching headers).

set -euo pipefail

# ---------------------------------------------------------------------------
# Interpreter check.
#
# This has to be the very first thing that runs, and it has to stay parseable
# by ancient shells. Bash executes a script command by command, so an old
# interpreter reaches this gate and exits with a useful message before it ever
# meets the associative arrays and {fd} redirections further down — which is
# otherwise what happens, as "declare: -A: invalid option" on line 580.
# ---------------------------------------------------------------------------
readonly MIN_BASH_MAJOR=5
readonly MIN_BASH_MINOR=3

if [ -z "${BASH_VERSION:-}" ]; then
    echo "http-server.sh: this is a bash script; run it with bash ${MIN_BASH_MAJOR}.${MIN_BASH_MINOR} or newer." >&2
    exit 1
fi

if (( BASH_VERSINFO[0] < MIN_BASH_MAJOR ||
      (BASH_VERSINFO[0] == MIN_BASH_MAJOR && BASH_VERSINFO[1] < MIN_BASH_MINOR) )); then
    printf 'http-server.sh: error: bash %s.%s or newer is required, but this is bash %s.\n\n' \
        "$MIN_BASH_MAJOR" "$MIN_BASH_MINOR" "${BASH_VERSION%%(*}" >&2
    printf 'Install a current bash, then run the script with it explicitly:\n\n' >&2
    printf '  macOS          brew install bash\n' >&2
    printf '                 /opt/homebrew/bin/bash http-server.sh ...   (Apple silicon)\n' >&2
    printf '                 /usr/local/bin/bash http-server.sh ...      (Intel)\n\n' >&2
    printf '  Debian/Ubuntu  sudo apt update && sudo apt install bash\n' >&2
    printf '  Fedora/RHEL    sudo dnf install bash\n' >&2
    printf '  Arch           sudo pacman -S bash\n' >&2
    printf '  Alpine         apk add bash\n\n' >&2
    printf '  From source    https://ftp.gnu.org/gnu/bash/\n\n' >&2
    printf 'macOS ships bash 3.2 from 2007 as /bin/bash and will not update it, so the\n' >&2
    printf 'explicit path above is needed there even after installing a newer bash.\n' >&2
    exit 1
fi

# Byte semantics everywhere: ${#string} must count bytes, not characters, or
# every Content-Length we compute would be wrong for non-ASCII payloads.
export LC_ALL=C

readonly SERVER_VERSION="5.0.0"
readonly SERVER_BANNER="bash-httpd/${SERVER_VERSION}"
# Assembled once per process by build_constant_headers, since none of it can
# change between responses.
CONSTANT_HEADERS=""

# The OWASP Secure Headers baseline, minus anything that would silently break
# ordinary content. Policies that can break a site — Content-Security-Policy
# and Cross-Origin-Resource-Policy — are offered as options rather than
# imposed, because a header that forces operators to disable the whole set is
# worse for security than one they opt into deliberately.
build_constant_headers() {
    local headers=""

    case "$SERVER_TOKENS" in
        # Version numbers tell an attacker which advisories to try. Off by
        # default; the banner still identifies the software.
        on)   headers+="Server: ${SERVER_BANNER}"$'\r\n' ;;
        none) ;;
        *)    headers+="Server: bash-httpd"$'\r\n' ;;
    esac

    if [[ "$SECURITY_HEADERS" == true ]]; then
        headers+="X-Content-Type-Options: nosniff"$'\r\n'
        headers+="X-Frame-Options: DENY"$'\r\n'
        headers+="Referrer-Policy: no-referrer"$'\r\n'
        headers+="X-Permitted-Cross-Domain-Policies: none"$'\r\n'
        # same-origin-allow-popups rather than same-origin: it still blocks
        # cross-origin window references but leaves OAuth popups working.
        headers+="Cross-Origin-Opener-Policy: same-origin-allow-popups"$'\r\n'
        headers+="Permissions-Policy: accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"$'\r\n'
        if [[ "$TLS_ENABLED" == true ]] && (( HSTS_MAX_AGE > 0 )); then
            headers+="Strict-Transport-Security: max-age=${HSTS_MAX_AGE}"$'\r\n'
        fi
    fi

    [[ -n "$CONTENT_SECURITY_POLICY" ]] &&
        headers+="Content-Security-Policy: ${CONTENT_SECURITY_POLICY}"$'\r\n'
    [[ -n "$CROSS_ORIGIN_RESOURCE_POLICY" ]] &&
        headers+="Cross-Origin-Resource-Policy: ${CROSS_ORIGIN_RESOURCE_POLICY}"$'\r\n'

    CONSTANT_HEADERS="$headers"
    return 0
}
readonly MIN_SOCAT_VERSION="1.8.0"
readonly MIN_CURL_VERSION="8.0.0"
# An upstream that streams forever should not be able to fill the disk through
# us. Generous, but bounded.
readonly MAX_PROXY_RESPONSE=104857600

# ---------------------------------------------------------------------------
# Protocol limits. RFC 9112 leaves these to the implementation, but a server
# that does not bound them is a denial-of-service target.
# ---------------------------------------------------------------------------
readonly MAX_REQUEST_LINE_BYTES=8192
readonly MAX_HEADER_LINE_BYTES=8192
readonly MAX_HEADER_COUNT=100
readonly MAX_HEADER_TOTAL_BYTES=32768
readonly MAX_CHUNK_COUNT=10000
# Bodies at or below this are sent from a shell variable in the same write as
# the headers, which costs no process at all. Above it, streaming with cat is
# both faster and kinder to memory.
readonly INLINE_BODY_MAX_BYTES=65536

# Worker slots are handed out as single-byte tokens, so the pool cannot be
# larger than the printable byte range we are willing to encode.
readonly MAX_POOL_SIZE=127
# How long a connection waits for a free worker before giving up on the pool
# and running the handler itself. Saturation degrades, it never fails.
readonly POOL_ACQUIRE_TIMEOUT=5
# Distinguishes "no worker was reachable" from "the handler itself failed".
readonly POOL_UNAVAILABLE=3

# ---------------------------------------------------------------------------
# Configuration. Every value falls back to an inherited environment variable so
# that the per-connection and pool-worker processes re-exec with the same
# settings without re-parsing the command line.
# ---------------------------------------------------------------------------
HTTP_PORT="${HTTP_PORT:-}"
BIND_ADDRESS="${BIND_ADDRESS:-0.0.0.0}"
MAX_CONN="${MAX_CONN:-64}"
STATIC_DIR="${STATIC_DIR:-}"
PROXY_TARGET="${PROXY_TARGET:-}"
REQUEST_HANDLER="${REQUEST_HANDLER:-}"
READ_BUFFER="${READ_BUFFER:-65536}"
WRITE_BUFFER="${WRITE_BUFFER:-65536}"
ENABLE_TRACING="${ENABLE_TRACING:-false}"
ENABLE_FULL_TRACING="${ENABLE_FULL_TRACING:-false}"
TRACE_FILE="${TRACE_FILE:-trace.log}"
POOL_SIZE="${POOL_SIZE:-8}"
ENABLE_KEEPALIVE="${ENABLE_KEEPALIVE:-true}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-15}"
HEADER_TIMEOUT="${HEADER_TIMEOUT:-10}"
REQUEST_TIMEOUT="${REQUEST_TIMEOUT:-30}"
MAX_KEEPALIVE_REQ="${MAX_KEEPALIVE_REQ:-100}"
MAX_BODY_SIZE="${MAX_BODY_SIZE:-10485760}"
INDEX_FILE="${INDEX_FILE:-index.html}"
DENY_SYMLINKS="${DENY_SYMLINKS:-false}"
HANDLER_MODE="${HANDLER_MODE:-auto}"
SERVER_TOKENS="${SERVER_TOKENS:-off}"
SECURITY_HEADERS="${SECURITY_HEADERS:-true}"
CONTENT_SECURITY_POLICY="${CONTENT_SECURITY_POLICY:-}"
CROSS_ORIGIN_RESOURCE_POLICY="${CROSS_ORIGIN_RESOURCE_POLICY:-}"
HSTS_MAX_AGE="${HSTS_MAX_AGE:-31536000}"
VERBOSE_ERRORS="${VERBOSE_ERRORS:-false}"
MAX_CONN_PER_IP="${MAX_CONN_PER_IP:-0}"
FILE_CACHE_SECONDS="${FILE_CACHE_SECONDS:-0}"
TLS_MIN_VERSION="${TLS_MIN_VERSION:-TLS1.3}"
TLS_CIPHERS="${TLS_CIPHERS:-}"
STAT_FLAVOUR="${STAT_FLAVOUR:-}"
TLS_CERT="${TLS_CERT:-}"
TLS_KEY="${TLS_KEY:-}"
TLS_CA="${TLS_CA:-}"
TLS_VERIFY_CLIENT="${TLS_VERIFY_CLIENT:-false}"
TLS_ENABLED="${TLS_ENABLED:-false}"
SKIP_SOCAT_CHECK=false
INTERNAL_MODE=""
SOCAT_VERSION=""
SKIP_CURL_CHECK=false
CURL_VERSION=""
SOCAT_HAS_MIN_PROTO=false
SOCAT_HAS_COMPRESS=false
POOL_WORKER_PIDS=()

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------
show_help() {
    cat <<EOF
${SERVER_BANNER} — an HTTP/1.1 server built on bash ${MIN_BASH_MAJOR}.${MIN_BASH_MINOR}+ and socat ${MIN_SOCAT_VERSION}+

USAGE
  http-server.sh --port <port> --static-dir <dir> [options]
  http-server.sh --help

REQUIRED
  -p,  --port <port>              TCP port to listen on
  -s,  --static-dir <dir>         Directory served as static content

LISTENER
  -b,  --bind <address>           Interface to bind (default: 0.0.0.0)
  -c,  --max-connections <num>    Max simultaneous connections (default: 64)
  -rb, --read-buffer <bytes>      Socket receive buffer (default: 65536)
  -wb, --write-buffer <bytes>     Socket send buffer (default: 65536)

TLS — optional; plain HTTP is the default
       --tls-cert <file>          PEM certificate; enabling this switches to HTTPS
       --tls-key <file>           PEM private key (default: the --tls-cert file)
       --tls-ca <file>            CA bundle used to verify client certificates
       --tls-verify-client        Require a valid client certificate (mTLS)

TIMEOUTS — each phase is bounded on the clock, not just per read
       --keep-alive-timeout <sec> Idle wait for the next request on a live
                                  connection (default: 15)
       --header-timeout <sec>     Deadline for the whole header block, from the
                                  request line onwards (default: 10). Without
                                  this a client can hold a connection forever
                                  by sending one header at a time
       --request-timeout <sec>    Deadline for one complete request including
                                  its body (default: 30). Also caps how long an
                                  upstream may take under --proxy-target

KEEP-ALIVE
       --max-keepalive-requests <n>
                                  Requests per connection before close (default: 100)
       --disable-keep-alive       Answer every request with Connection: close

CONTENT
       --index-file <name>        Directory index filename (default: index.html)
       --max-body-size <bytes>    Largest accepted request body (default: 10485760)
       --deny-symlinks            Refuse to serve symlinked files (403)

DYNAMIC REQUESTS
  -rh, --request-handler <path>   Executable run when no static file matches
       --pool-size <num>          Pre-forked handler workers (default: 8, 0 disables)
       --handler-mode <mode>      auto: load a handler that defines handle_request
                                  into each worker and call it (much faster).
                                  exec: always fork+exec the handler.
                                  (default: auto)
  -r,  --proxy-target <url>       Upstream origin when no static file matches

HARDENING — OWASP secure-header baseline is on by default
       --server-tokens <mode>     off: 'Server: bash-httpd' (default)
                                  on:  include the version
                                  none: omit the header entirely
       --no-security-headers      Drop the baseline (for use behind a proxy
                                  that sets its own)
       --csp <policy>             Content-Security-Policy for all responses.
                                  Not set by default: it would break content
                                  the server knows nothing about
       --cross-origin-resource-policy <value>
                                  Cross-Origin-Resource-Policy; same-origin
                                  breaks cross-origin asset serving
       --hsts-max-age <seconds>   Strict-Transport-Security age under TLS
                                  (default: 31536000, 0 disables)
       --verbose-errors           Return the rejection reason to the client.
                                  By default it is only logged, so the parser
                                  cannot be mapped from outside
       --max-connections-per-ip <n>
                                  Concurrent connections allowed from one
                                  address (default: 0, unlimited)
       --tls-min-version <ver>    Lowest TLS version accepted (default: TLS1.3).
                                  Lower it to TLS1.2 only if you must serve
                                  clients older than roughly 2019
       --tls-ciphers <list>       OpenSSL cipher list

PERFORMANCE
       --file-cache-seconds <n>   Remember file size and mtime for up to n
                                  seconds per connection, avoiding a stat per
                                  request (default: 0, off). A file rewritten
                                  inside the window is served with its previous
                                  ETag and Last-Modified

OBSERVABILITY
       --enable-tracing           One NDJSON record per request, carrying status,
                                  byte counts and service time in microseconds
       --enable-full-tracing      Also record request headers and textual bodies
       --trace-file <path>        Trace destination (default: trace.log)

OTHER
       --skip-socat-version-check Bypass the socat >= ${MIN_SOCAT_VERSION} requirement
       --skip-curl-version-check  Bypass the curl >= ${MIN_CURL_VERSION} requirement
  -V,  --version                  Print the version and exit
  -h,  --help                     Show this help and exit

HANDLER PROTOCOL
  The handler runs with the request in CGI-style environment variables
  (REQUEST_METHOD, REQUEST_URI, PATH_INFO, QUERY_STRING, CONTENT_TYPE,
  CONTENT_LENGTH, SERVER_PROTOCOL, REMOTE_ADDR, and HTTP_* for every request
  header). The body arrives on stdin. Write an optional header block, a blank
  line, then the payload:

      Status: 200 OK
      Content-Type: application/json

      {"ok":true}

  Framing headers a handler emits (Content-Length, Transfer-Encoding,
  Connection) are discarded and recomputed by the server so that keep-alive
  connections stay in sync and response splitting is impossible.

EXAMPLES
  http-server.sh -p 8080 -s ./public
  http-server.sh -p 8080 -s ./public --disable-keep-alive
  http-server.sh -p 8443 -s ./public --tls-cert cert.pem --tls-key key.pem
  http-server.sh -p 8080 -s ./public -rh ./handler.sh --pool-size 16
  http-server.sh -p 8080 -s ./public -r http://127.0.0.1:5000
EOF
}

die() {
    printf '%s: error: %s\n' "${0##*/}" "$1" >&2
    exit "${2:-1}"
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
require_value() {
    [[ -n "${2:-}" ]] || die "option '$1' requires a value (see --help)"
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help|help)          show_help; exit 0 ;;
            -V|--version)            printf '%s\n' "$SERVER_BANNER"; exit 0 ;;
            -p|--port)               require_value "$1" "${2:-}"; HTTP_PORT="$2"; shift 2 ;;
            -b|--bind)               require_value "$1" "${2:-}"; BIND_ADDRESS="$2"; shift 2 ;;
            -c|--max-connections)    require_value "$1" "${2:-}"; MAX_CONN="$2"; shift 2 ;;
            -s|--static-dir)         require_value "$1" "${2:-}"; STATIC_DIR="$2"; shift 2 ;;
            -rb|--read-buffer)       require_value "$1" "${2:-}"; READ_BUFFER="$2"; shift 2 ;;
            -wb|--write-buffer)      require_value "$1" "${2:-}"; WRITE_BUFFER="$2"; shift 2 ;;
            --tls-cert)              require_value "$1" "${2:-}"; TLS_CERT="$2"; shift 2 ;;
            --tls-key)               require_value "$1" "${2:-}"; TLS_KEY="$2"; shift 2 ;;
            --tls-ca)                require_value "$1" "${2:-}"; TLS_CA="$2"; shift 2 ;;
            --tls-verify-client)     TLS_VERIFY_CLIENT=true; shift ;;
            --keep-alive-timeout)    require_value "$1" "${2:-}"; TIMEOUT_SECONDS="$2"; shift 2 ;;
            --header-timeout)        require_value "$1" "${2:-}"; HEADER_TIMEOUT="$2"; shift 2 ;;
            --request-timeout)       require_value "$1" "${2:-}"; REQUEST_TIMEOUT="$2"; shift 2 ;;
            --skip-curl-version-check) SKIP_CURL_CHECK=true; shift ;;
            --max-keepalive-requests) require_value "$1" "${2:-}"; MAX_KEEPALIVE_REQ="$2"; shift 2 ;;
            --disable-keep-alive|--no-keepalive) ENABLE_KEEPALIVE=false; shift ;;
            --index-file)            require_value "$1" "${2:-}"; INDEX_FILE="$2"; shift 2 ;;
            --max-body-size)         require_value "$1" "${2:-}"; MAX_BODY_SIZE="$2"; shift 2 ;;
            --deny-symlinks)         DENY_SYMLINKS=true; shift ;;
            --server-tokens)         require_value "$1" "${2:-}"; SERVER_TOKENS="$2"; shift 2 ;;
            --no-security-headers)   SECURITY_HEADERS=false; shift ;;
            --csp|--content-security-policy)
                                     require_value "$1" "${2:-}"; CONTENT_SECURITY_POLICY="$2"; shift 2 ;;
            --cross-origin-resource-policy)
                                     require_value "$1" "${2:-}"; CROSS_ORIGIN_RESOURCE_POLICY="$2"; shift 2 ;;
            --hsts-max-age)          require_value "$1" "${2:-}"; HSTS_MAX_AGE="$2"; shift 2 ;;
            --verbose-errors)        VERBOSE_ERRORS=true; shift ;;
            --max-connections-per-ip) require_value "$1" "${2:-}"; MAX_CONN_PER_IP="$2"; shift 2 ;;
            --file-cache-seconds)    require_value "$1" "${2:-}"; FILE_CACHE_SECONDS="$2"; shift 2 ;;
            --tls-min-version)       require_value "$1" "${2:-}"; TLS_MIN_VERSION="$2"; shift 2 ;;
            --tls-ciphers)           require_value "$1" "${2:-}"; TLS_CIPHERS="$2"; shift 2 ;;
            --handler-mode)          require_value "$1" "${2:-}"; HANDLER_MODE="$2"; shift 2 ;;
            -rh|--request-handler|--requestHandler)
                                     require_value "$1" "${2:-}"; REQUEST_HANDLER="$2"; shift 2 ;;
            --pool-size|--maxPoolSize)
                                     require_value "$1" "${2:-}"; POOL_SIZE="$2"; shift 2 ;;
            -r|--proxy-target)       require_value "$1" "${2:-}"; PROXY_TARGET="$2"; shift 2 ;;
            --enable-tracing)        ENABLE_TRACING=true; shift ;;
            --enable-full-tracing)   ENABLE_TRACING=true; ENABLE_FULL_TRACING=true; shift ;;
            --trace-file)            require_value "$1" "${2:-}"; TRACE_FILE="$2"; shift 2 ;;
            --skip-socat-version-check) SKIP_SOCAT_CHECK=true; shift ;;
            --internal-connection)   INTERNAL_MODE="connection"; shift ;;
            --internal-pool-worker)  INTERNAL_MODE="pool-worker"; shift ;;
            --)                      shift; break ;;
            *)                       die "unknown argument '$1' (use --help for usage)" ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# Environment validation
# ---------------------------------------------------------------------------
version_at_least() {
    local have="$1" want="$2" index
    local -a have_parts want_parts
    IFS=. read -ra have_parts <<<"$have"
    IFS=. read -ra want_parts <<<"$want"
    for (( index = 0; index < ${#want_parts[@]}; index++ )); do
        local left="${have_parts[index]:-0}" right="${want_parts[index]:-0}"
        left="${left//[^0-9]/}"; right="${right//[^0-9]/}"
        (( 10#${left:-0} > 10#${right:-0} )) && return 0
        (( 10#${left:-0} < 10#${right:-0} )) && return 1
    done
    return 0
}

# Parsed with bash rather than piped through grep, so the only external
# program the startup checks need is the one being checked.
detect_socat_version() {
    local output line version
    output="$(socat -V 2>&1)"
    while IFS= read -r line; do
        [[ "$line" == *"socat version "* ]] || continue
        version="${line#*socat version }"
        version="${version%% *}"
        version="${version//[!0-9.]/}"
        [[ -n "$version" ]] || continue
        printf '%s' "$version"
        return 0
    done <<<"$output"
    return 0
}

# printf, not a cat heredoc: this message exists to help someone whose
# environment is already broken, and cat may be exactly what they cannot reach.
curl_install_hint() {
    printf '\nInstall curl %s or newer:\n\n' "$MIN_CURL_VERSION" >&2
    printf '  macOS          brew install curl\n' >&2
    printf '  Debian/Ubuntu  sudo apt update && sudo apt install curl\n' >&2
    printf '  Fedora/RHEL    sudo dnf install curl\n' >&2
    printf '  Arch           sudo pacman -S curl\n' >&2
    printf '  Alpine         apk add curl\n\n' >&2
    printf '  From source    https://curl.se/download.html\n\n' >&2
    printf "Check with 'curl --version'. Only --proxy-target needs curl; drop it,\n" >&2
    printf 'or re-run with --skip-curl-version-check.\n' >&2
}

# curl is only reached through --proxy-target, but on that path it handles
# attacker-influenced responses from the upstream, so an old one is worth
# refusing. The 7.x series is out of support and carries known advisories.
check_curl() {
    if ! command -v curl >/dev/null 2>&1; then
        printf '%s: error: --proxy-target needs curl, which is not installed.\n' "${0##*/}" >&2
        curl_install_hint
        exit 1
    fi

    local reported
    reported="$(curl --version 2>/dev/null | head -1)"
    CURL_VERSION="${reported#curl }"
    CURL_VERSION="${CURL_VERSION%% *}"

    [[ "$SKIP_CURL_CHECK" == true ]] && return 0

    if [[ -z "$CURL_VERSION" || "$CURL_VERSION" == *[!0-9.]* ]]; then
        printf '%s: error: could not determine the curl version from '\''curl --version'\''.\n' \
            "${0##*/}" >&2
        curl_install_hint
        exit 1
    fi

    if ! version_at_least "$CURL_VERSION" "$MIN_CURL_VERSION"; then
        printf '%s: error: curl %s or newer is required, but curl %s is installed.\n' \
            "${0##*/}" "$MIN_CURL_VERSION" "$CURL_VERSION" >&2
        curl_install_hint
        exit 1
    fi
    return 0
}

socat_install_hint() {
    printf '\nInstall socat %s or newer:\n\n' "$MIN_SOCAT_VERSION" >&2
    printf '  macOS          brew install socat\n' >&2
    printf '  Debian/Ubuntu  sudo apt update && sudo apt install socat\n' >&2
    printf '  Fedora/RHEL    sudo dnf install socat\n' >&2
    printf '  Arch           sudo pacman -S socat\n' >&2
    printf '  Alpine         apk add socat\n\n' >&2
    printf '  From source    http://www.dest-unreach.org/socat/\n\n' >&2
    printf "Verify with 'socat -V'. If your distribution only packages socat 1.7.x,\n" >&2
    printf 'build 1.8 from source, or re-run with --skip-socat-version-check.\n' >&2
}

check_runtime() {
    if ! command -v socat >/dev/null 2>&1; then
        printf '%s: error: socat is not installed, or not on PATH.\n' "${0##*/}" >&2
        socat_install_hint
        exit 1
    fi

    SOCAT_VERSION="$(detect_socat_version)"
    [[ "$SKIP_SOCAT_CHECK" == true ]] && return 0

    if [[ -z "$SOCAT_VERSION" ]]; then
        printf '%s: error: could not determine the socat version from '\''socat -V'\''.\n' "${0##*/}" >&2
        socat_install_hint
        exit 1
    fi

    if ! version_at_least "$SOCAT_VERSION" "$MIN_SOCAT_VERSION"; then
        printf '%s: error: socat %s or newer is required, but socat %s is installed.\n' \
            "${0##*/}" "$MIN_SOCAT_VERSION" "$SOCAT_VERSION" >&2
        socat_install_hint
        exit 1
    fi
    return 0
}

check_tls_config() {
    if [[ -z "$TLS_CERT" && -z "$TLS_KEY" ]]; then
        TLS_ENABLED=false
        return 0
    fi
    [[ -n "$TLS_CERT" ]] || die "--tls-key requires --tls-cert"
    [[ -r "$TLS_CERT" ]] || die "TLS certificate '$TLS_CERT' is missing or unreadable"
    [[ -n "$TLS_KEY" ]] || TLS_KEY="$TLS_CERT"
    [[ -r "$TLS_KEY" ]] || die "TLS key '$TLS_KEY' is missing or unreadable"
    [[ -n "$TLS_CA" && ! -r "$TLS_CA" ]] && die "TLS CA bundle '$TLS_CA' is missing or unreadable"
    [[ "$TLS_VERIFY_CLIENT" == true && -z "$TLS_CA" ]] &&
        die "--tls-verify-client requires --tls-ca so client certificates can be validated"
    # Captured rather than piped into grep -q. grep -q exits on its first
    # match, socat then takes SIGPIPE, and under `set -o pipefail` the pipeline
    # reports failure — so the pipe form silently never fired, and a socat
    # without TLS support would have got all the way to a failed bind.
    local capabilities
    capabilities="$(socat -V 2>&1)"
    [[ "$capabilities" == *"undef WITH_OPENSSL"* ]] &&
        die "this socat build was compiled without OpenSSL support, so TLS is unavailable"

    # Which TLS knobs exist depends on how socat was built — Alpine's package,
    # for one, has no openssl-compress at all and refuses to start if handed
    # it. Ask this build what it supports rather than assuming.
    local supported
    supported="$(socat -hhh 2>&1)"
    [[ "$supported" == *openssl-min-proto-version* ]] && SOCAT_HAS_MIN_PROTO=true
    [[ "$supported" == *openssl-compress* ]] && SOCAT_HAS_COMPRESS=true
    if [[ "$SOCAT_HAS_MIN_PROTO" != true ]]; then
        printf '%s: warning: this socat build cannot set a minimum TLS version; deprecated protocol versions may be accepted.\n' \
            "${0##*/}" >&2
    fi

    TLS_CERT="$(absolute_path "$TLS_CERT")"
    TLS_KEY="$(absolute_path "$TLS_KEY")"
    [[ -n "$TLS_CA" ]] && TLS_CA="$(absolute_path "$TLS_CA")"
    TLS_ENABLED=true
    return 0
}

# True when the file declares a handle_request function at the start of a line,
# with or without the `function` keyword.
#
# Read rather than grepped: this also runs in every connection and worker
# process, where a spawn is a spawn per connection, and it means the startup
# checks need no program on PATH beyond the ones they are actually checking.
handler_defines_function() {
    local file="$1" line trimmed rest
    while IFS= read -r line; do
        trimmed="${line#"${line%%[![:space:]]*}"}"
        trimmed="${trimmed#function }"
        trimmed="${trimmed#"${trimmed%%[![:space:]]*}"}"
        [[ "$trimmed" == handle_request* ]] || continue
        rest="${trimmed#handle_request}"
        rest="${rest#"${rest%%[![:space:]]*}"}"
        [[ "$rest" == '('* ]] && return 0
    done <"$file" 2>/dev/null
    return 1
}

absolute_path() {
    local directory base
    directory="$(cd "$(dirname "$1")" 2>/dev/null && pwd -P)" || return 1
    base="$(basename "$1")"
    printf '%s/%s' "${directory%/}" "$base"
}

check_configuration() {
    [[ -n "$HTTP_PORT" ]] || die "missing required option --port (see --help)"
    [[ -n "$STATIC_DIR" ]] || die "missing required option --static-dir (see --help)"

    local name value
    for name in HTTP_PORT MAX_CONN POOL_SIZE TIMEOUT_SECONDS MAX_KEEPALIVE_REQ \
                READ_BUFFER WRITE_BUFFER MAX_BODY_SIZE MAX_CONN_PER_IP HSTS_MAX_AGE \
                FILE_CACHE_SECONDS HEADER_TIMEOUT REQUEST_TIMEOUT; do
        value="${!name}"
        [[ "$value" =~ ^[0-9]+$ ]] || die "${name} must be a non-negative integer, got '${value}'"
    done
    (( HTTP_PORT >= 1 && HTTP_PORT <= 65535 )) || die "--port must be between 1 and 65535"
    (( MAX_CONN >= 1 )) || die "--max-connections must be at least 1"
    (( POOL_SIZE <= MAX_POOL_SIZE )) ||
        die "--pool-size cannot exceed ${MAX_POOL_SIZE}; use --max-connections to raise overall concurrency"
    (( TIMEOUT_SECONDS >= 1 )) || die "--keep-alive-timeout must be at least 1"
    (( HEADER_TIMEOUT >= 1 )) || die "--header-timeout must be at least 1"
    (( REQUEST_TIMEOUT >= 1 )) || die "--request-timeout must be at least 1"
    (( REQUEST_TIMEOUT >= HEADER_TIMEOUT )) ||
        die "--request-timeout (${REQUEST_TIMEOUT}s) must be at least --header-timeout (${HEADER_TIMEOUT}s): the header block is part of the request"
    (( MAX_KEEPALIVE_REQ >= 1 )) || die "--max-keepalive-requests must be at least 1"

    STATIC_DIR="$(cd "$STATIC_DIR" 2>/dev/null && pwd -P)" ||
        die "static directory '$STATIC_DIR' does not exist or is not readable"

    if [[ -n "$REQUEST_HANDLER" ]]; then
        local resolved
        resolved="$(absolute_path "$REQUEST_HANDLER")" ||
            die "request handler '$REQUEST_HANDLER' does not exist"
        [[ -x "$resolved" ]] || die "request handler '$REQUEST_HANDLER' is not executable"
        REQUEST_HANDLER="$resolved"
    fi

    if [[ -n "$PROXY_TARGET" ]]; then
        [[ "$PROXY_TARGET" =~ ^https?://[^[:space:]/]+ ]] ||
            die "--proxy-target must be an absolute http(s) URL, got '$PROXY_TARGET'"
        check_curl
    fi

    case "$HANDLER_MODE" in
        auto|exec) ;;
        *) die "--handler-mode must be 'auto' or 'exec', got '${HANDLER_MODE}'" ;;
    esac

    case "$SERVER_TOKENS" in
        on|off|none) ;;
        *) die "--server-tokens must be 'on', 'off' or 'none', got '${SERVER_TOKENS}'" ;;
    esac

    case "$TLS_MIN_VERSION" in
        TLS1|TLS1.1|TLS1.2|TLS1.3) ;;
        *) die "--tls-min-version must be one of TLS1, TLS1.1, TLS1.2, TLS1.3, got '${TLS_MIN_VERSION}'" ;;
    esac
    case "$TLS_MIN_VERSION" in
        TLS1|TLS1.1)
            printf '%s: warning: TLS %s is deprecated by RFC 8996 and should not be used in production.\n' \
                "${0##*/}" "${TLS_MIN_VERSION#TLS}" >&2 ;;
        TLS1.2)
            printf '%s: warning: lowering the TLS floor to 1.2 admits clients without forward secrecy by default and the older handshake.\n' \
                "${0##*/}" >&2 ;;
    esac

    # Header values are copied into responses verbatim, so a newline in one
    # would be header injection by configuration.
    local policy
    for policy in CONTENT_SECURITY_POLICY CROSS_ORIGIN_RESOURCE_POLICY TLS_CIPHERS; do
        [[ "${!policy}" == *[$'\r\n']* ]] &&
            die "--${policy,,} must not contain a newline"
    done

    # A function-form handler writes nothing when executed as a program, so this
    # combination would answer every dynamic request with an empty 200.
    if [[ "$HANDLER_MODE" == "exec" && -n "$REQUEST_HANDLER" ]] &&
       handler_defines_function "$REQUEST_HANDLER"; then
        die "--handler-mode exec cannot run '${REQUEST_HANDLER}': it defines a handle_request function and produces no output when executed directly. Drop --handler-mode exec to use it, or rewrite the handler to emit its response at top level."
    fi

    [[ "$INDEX_FILE" == */* ]] && die "--index-file must be a plain filename, not a path"
    return 0
}

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
# The helpers below write into a caller-named variable instead of echoing.
# Every $(...) is a subshell fork — around 0.4 ms on a Mac — and a request that
# should cost 2 ms cannot afford five of them. printf -v assigns straight into
# the caller's scope, so these cost nothing at all.
http_date_into() { printf -v "$1" '%(%a, %d %b %Y %H:%M:%S GMT)T' "${2:--1}"; }

mime_type_into() {
    local __mime
    case "${2##*.}" in
        html|htm)   __mime='text/html; charset=utf-8' ;;
        css)        __mime='text/css; charset=utf-8' ;;
        js|mjs)     __mime='text/javascript; charset=utf-8' ;;
        json)       __mime='application/json' ;;
        xml)        __mime='application/xml; charset=utf-8' ;;
        txt|md)     __mime='text/plain; charset=utf-8' ;;
        csv)        __mime='text/csv; charset=utf-8' ;;
        wasm)       __mime='application/wasm' ;;
        pdf)        __mime='application/pdf' ;;
        zip)        __mime='application/zip' ;;
        gz)         __mime='application/gzip' ;;
        png)        __mime='image/png' ;;
        jpg|jpeg)   __mime='image/jpeg' ;;
        gif)        __mime='image/gif' ;;
        svg)        __mime='image/svg+xml' ;;
        webp)       __mime='image/webp' ;;
        avif)       __mime='image/avif' ;;
        ico)        __mime='image/x-icon' ;;
        woff)       __mime='font/woff' ;;
        woff2)      __mime='font/woff2' ;;
        ttf)        __mime='font/ttf' ;;
        mp4)        __mime='video/mp4' ;;
        webm)       __mime='video/webm' ;;
        mp3)        __mime='audio/mpeg' ;;
        *)          __mime='application/octet-stream' ;;
    esac
    printf -v "$1" '%s' "$__mime"
}

# Which stat is this — GNU or BSD? Probing per request meant that on macOS
# every static response paid for two process spawns: 'stat -c' failing, then
# 'stat -f' succeeding. At ~3 ms a spawn that was most of the request. Probe
# once at startup and export the answer instead.
#
# GNU is probed first because BSD stat rejects -c outright, whereas GNU stat
# accepts -f and quietly reports filesystem status rather than failing.
detect_stat_flavour() {
    if stat -c '%s' /dev/null >/dev/null 2>&1; then
        STAT_FLAVOUR=gnu
    elif stat -f '%z' /dev/null >/dev/null 2>&1; then
        STAT_FLAVOUR=bsd
    else
        STAT_FLAVOUR=none
    fi
}

file_size() {
    case "${STAT_FLAVOUR:-}" in
        gnu) stat -c%s "$1" 2>/dev/null || printf '0' ;;
        bsd) stat -f%z "$1" 2>/dev/null || printf '0' ;;
        *)   printf '0' ;;
    esac
}

# Size and mtime from a single stat.
#
# That stat is the last process spawn on the static path and, on a machine
# where spawning is expensive, most of what a small static response costs.
# --file-cache-seconds lets an operator trade it away: metadata is remembered
# for the life of a connection, up to that many seconds. It is off by default
# because the trade is real — a file rewritten inside the window is served with
# the previous ETag and Last-Modified, so a client can cache a stale copy.
stat_file() {
    local info

    if (( FILE_CACHE_SECONDS > 0 )); then
        local cached="${STAT_CACHE[$1]:-}"
        if [[ -n "$cached" ]]; then
            local stored_at="${cached##* }"
            if (( EPOCHSECONDS - stored_at < FILE_CACHE_SECONDS )); then
                cached="${cached% *}"
                STAT_SIZE="${cached%% *}"
                STAT_MTIME="${cached##* }"
                return 0
            fi
        fi
    fi

    case "${STAT_FLAVOUR:-}" in
        gnu) info="$(stat -c '%s %Y' "$1" 2>/dev/null)" || info="0 0" ;;
        bsd) info="$(stat -f '%z %m' "$1" 2>/dev/null)" || info="0 0" ;;
        *)   info="0 0" ;;
    esac
    STAT_SIZE="${info%% *}"
    STAT_MTIME="${info##* }"
    [[ -n "$STAT_SIZE" && "$STAT_SIZE" != *[!0-9]* ]] || STAT_SIZE=0
    [[ -n "$STAT_MTIME" && "$STAT_MTIME" != *[!0-9]* ]] || STAT_MTIME=0

    (( FILE_CACHE_SECONDS > 0 )) &&
        STAT_CACHE["$1"]="${STAT_SIZE} ${STAT_MTIME} ${EPOCHSECONDS}"
    return 0
}

# Percent-decoding that accepts only well-formed %XX escapes. Anything
# malformed is preserved literally instead of being reinterpreted, so no
# backslash escape or shell metacharacter can be smuggled through printf %b.
percent_decode_into() {
    local input="$2"
    if [[ "$input" != *%* ]]; then
        printf -v "$1" '%s' "$input"
        return 0
    fi
    # Split on '%' rather than walking character by character. A path with n
    # escapes costs n iterations instead of one per byte, and bash loop
    # iterations are the expensive part here, not the string appends.
    local -a __segments=()
    local __output __segment __hex __byte __i
    IFS='%' read -ra __segments <<<"$input"
    __output="${__segments[0]}"
    for (( __i = 1; __i < ${#__segments[@]}; __i++ )); do
        __segment="${__segments[__i]}"
        __hex="${__segment:0:2}"
        if [[ "$__hex" == [0-9A-Fa-f][0-9A-Fa-f] ]]; then
            # The escape has to be built into the format string itself:
            # printf '\x%s' would try to expand \x before %s is substituted.
            printf -v __byte "\\x${__hex}"
            __output+="${__byte}${__segment:2}"
        else
            __output+="%${__segment}"
        fi
    done
    printf -v "$1" '%s' "$__output"
}

# Purely lexical path normalisation. Because "." and ".." are resolved on the
# string itself, a request can never climb above the document root no matter
# which encoding trick produced the dot segments.
normalize_path_into() {
    local -a segments=() stack=()
    local segment
    IFS='/' read -ra segments <<<"$2"
    for segment in "${segments[@]}"; do
        case "$segment" in
            ''|.) continue ;;
            ..)   (( ${#stack[@]} > 0 )) && unset 'stack[-1]' ;;
            *)    stack+=("$segment") ;;
        esac
    done
    (( ${#stack[@]} == 0 )) && { printf -v "$1" '/'; return 0; }
    printf -v "$1" '/%s' "${stack[@]}"
}

# ---------------------------------------------------------------------------
# Response writing
# ---------------------------------------------------------------------------
# Internal locals carry a distinctive prefix on purpose: bash scopes
# dynamically, so a local named the same as a caller's out-variable would
# shadow it and the assignment would land in the wrong scope.
build_response_head() {
    local __brh_out="$1" __brh_status="$2" __brh_type="$3" __brh_length="$4"
    local __brh_connection="$5" __brh_extra="${6:-}"
    # The date changes once a second, so it is cached rather than reformatted
    # per response.
    if (( EPOCHSECONDS != CACHED_DATE_EPOCH )); then
        printf -v CACHED_DATE '%(%a, %d %b %Y %H:%M:%S GMT)T' "$EPOCHSECONDS"
        CACHED_DATE_EPOCH=$EPOCHSECONDS
    fi

    # Assembled in one printf rather than a run of conditional appends: the
    # optional fields become empty strings instead of extra commands, and the
    # invariant security headers live in CONSTANT_HEADERS, built once per
    # process rather than per response.
    local __brh_type_line="" __brh_length_line=""
    [[ -n "$__brh_type" ]]   && __brh_type_line="Content-Type: ${__brh_type}"$'\r\n'
    [[ -n "$__brh_length" ]] && __brh_length_line="Content-Length: ${__brh_length}"$'\r\n'
    RESPONSE_BYTES="${__brh_length:-0}"

    # Concatenation rather than a printf format: measured faster here, since
    # printf has to walk the format string as well as the arguments.
    printf -v "$__brh_out" '%s' \
"HTTP/1.1 ${__brh_status}"$'\r\n'"Date: ${CACHED_DATE}"$'\r\n'"Connection: ${__brh_connection}"$'\r\n'"${CONSTANT_HEADERS}${__brh_type_line}${__brh_length_line}${__brh_extra}"$'\r\n'
}

send_response_head() {
    local __srh_head=""
    build_response_head __srh_head "$@"
    printf '%s' "$__srh_head"
}

# Head and body in a single write. Two writes would let Nagle hold the second
# one back waiting for an ACK, which shows up as tens of milliseconds of
# latency for no reason at all.
send_response() {
    local __sr_body="$6" __sr_head=""
    build_response_head __sr_head "$1" "$2" "$3" "$4" "${5:-}"
    printf '%s%s' "$__sr_head" "$__sr_body"
}

send_error() {
    local status="$1" connection="$2" detail="${3:-}"

    # The reason a request was rejected is useful to an operator and useful to
    # an attacker mapping the parser. It goes to the trace log either way; it
    # only goes to the client when someone asks for that explicitly.
    TRACE_ERROR_DETAIL="$detail"

    local body="$status"
    [[ -n "$detail" && "$VERBOSE_ERRORS" == true ]] && body+=" — ${detail}"
    body+=$'\n'
    local csp="Content-Security-Policy: default-src 'none'"$'\r\n'"Cache-Control: no-store"$'\r\n'
    if [[ "$CURRENT_METHOD" == "HEAD" ]]; then
        send_response_head "$status" "text/plain; charset=utf-8" "${#body}" "$connection" "$csp"
    else
        send_response "$status" "text/plain; charset=utf-8" "${#body}" "$connection" "$csp" "$body"
    fi
    trace_end "$status" "$RESPONSE_BYTES"
    return 0
}

# ---------------------------------------------------------------------------
# Body I/O
# ---------------------------------------------------------------------------
# Seconds left before a deadline, or failure once it has passed.
#
# --keep-alive-timeout bounds a single read, and a single read only. A client
# that sends one header every few seconds never trips it, so the per-read
# timeout on its own lets a connection be held open indefinitely at almost no
# cost — a slow-drip variant of slowloris. Each phase of a request therefore
# carries a wall-clock deadline too, and every read inside that phase gets only
# the time still remaining.
seconds_until() {
    READ_BUDGET=$(( $1 - EPOCHSECONDS ))
    (( READ_BUDGET > 0 ))
}

# Copy exactly N bytes from stdin into a file. Exactness is not an optimisation
# here: over-reading by even one byte desynchronises the next request on a
# keep-alive connection, which is how request smuggling starts.
#
# read -N is the only tool for this that both stops on the exact byte and needs
# no external process. LC_ALL=C (set at the top of this script) is what makes it
# count bytes rather than characters. head -c and dd with a large block size are
# both wrong here: on a socket they may buffer past the body and swallow the
# start of the next request.
read_exact_to_file() {
    local count="$1" destination="$2" buffer=""
    : >"$destination"
    (( count == 0 )) && return 0
    seconds_until "$REQUEST_DEADLINE" || return 1
    IFS= read -r -N "$count" -t "$READ_BUDGET" buffer || return 1
    (( ${#buffer} == count )) || return 1
    printf '%s' "$buffer" >"$destination"
}

# RFC 9112 s7.1 chunked transfer decoding.
read_chunked_to_file() {
    local destination="$1"
    local line size total=0 chunks=0 discard
    CHUNKED_TOTAL=0
    : >"$destination"
    while :; do
        seconds_until "$REQUEST_DEADLINE" || return 3
        IFS= read -r -t "$READ_BUDGET" line || return 1
        line="${line%$'\r'}"
        line="${line%%;*}"
        line="${line//[[:space:]]/}"
        [[ "$line" =~ ^[0-9A-Fa-f]{1,15}$ ]] || return 1
        size=$(( 16#$line ))
        (( ++chunks > MAX_CHUNK_COUNT )) && return 2
        if (( size == 0 )); then
            # Trailers are still part of the request and share its deadline.
            while seconds_until "$REQUEST_DEADLINE" &&
                  IFS= read -r -t "$READ_BUDGET" line; do
                line="${line%$'\r'}"
                [[ -z "$line" ]] && break
            done
            return 0
        fi
        (( total += size ))
        (( total > MAX_BODY_SIZE )) && return 2
        CHUNKED_TOTAL="$total"
        read_exact_to_file "$size" "${destination}.part" || return 1
        cat -- "${destination}.part" >>"$destination"
        seconds_until "$REQUEST_DEADLINE" || return 3
        # shellcheck disable=SC2034  # the trailing CRLF is read only to consume it
        IFS= read -r -N 2 -t "$READ_BUDGET" discard || return 1
    done
}

# Reads a whole file into INLINE_BODY, or declines.
#
# `read -d ''` returns success only when it actually found the NUL delimiter,
# so a *failure* here is the good case: it means end-of-file was reached with
# no NUL, and therefore the variable holds every byte of the file. Bash cannot
# carry NUL in a variable, so files that contain one are handed back to the
# streaming path instead of being silently truncated.
read_inline_body() {
    local __path="$1" __size="$2"
    INLINE_BODY=""
    (( __size > INLINE_BODY_MAX_BYTES )) && return 1
    (( __size == 0 )) && return 0
    if IFS= read -r -d '' INLINE_BODY <"$__path"; then
        INLINE_BODY=""
        return 1
    fi
    (( ${#INLINE_BODY} == __size ))
}

# Same idea, but for a file whose size we do not already know — handler output,
# where a stat purely to learn the length would cost more than everything else
# in the response put together.
#
# The length-limited probe comes first so a large file can never be pulled into
# memory. NUL bytes only make the probe undercount, so it never wrongly treats
# a big file as small; and if any were present the NUL-safe read below declines
# anyway. Two bounded reads, no processes.
read_file_inline() {
    local __path="$1" __probe=""
    INLINE_BODY=""
    IFS= read -r -N "$(( INLINE_BODY_MAX_BYTES + 1 ))" __probe <"$__path" || :
    (( ${#__probe} > INLINE_BODY_MAX_BYTES )) && return 1
    if IFS= read -r -d '' INLINE_BODY <"$__path"; then
        INLINE_BODY=""
        return 1
    fi
    return 0
}

# Stream a file, or a byte range of it, to stdout.
#
# The whole-file case is by far the most common, and it is a single cat: bytes
# are copied by a C program with a sensible buffer instead of being pulled
# through the shell a byte at a time. Ranges cost one or two more processes,
# which is fine because they are rare. Filenames are passed as arguments and
# are never interpolated into a command string.
send_file_range() {
    local path="$1" offset="${2:-0}" count="${3:-0}"

    if (( offset == 0 )); then
        if (( count <= 0 )); then
            cat -- "$path" || true
        else
            head -c "$count" "$path" || true
        fi
    elif (( count <= 0 )); then
        tail -c "+$(( offset + 1 ))" "$path" || true
    else
        # head closing early makes tail exit on SIGPIPE; that is the intended
        # end of the transfer, not a failure.
        { tail -c "+$(( offset + 1 ))" "$path" | head -c "$count"; } 2>/dev/null || true
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Tracing
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Tracing
#
# One NDJSON record per request, emitted once, after the response is known —
# so a record carries the status, the byte count and the service time rather
# than being split across two half-entries that a reader has to stitch back
# together. Feed it to jq, Vector, Loki or anything else that eats JSON lines.
#
# Records are assembled in memory and written with a single write to a FIFO
# that a dedicated process drains. Two properties fall out of that: request
# handling never waits on disk, and because writes stay under PIPE_BUF they
# are atomic, so concurrent connections cannot interleave mid-record. The
# field caps below exist to keep that guarantee — a record that grew past
# PIPE_BUF would tear.
# ---------------------------------------------------------------------------
readonly TRACE_MAX_TARGET=512
readonly TRACE_MAX_HEADER_VALUE=256
readonly TRACE_MAX_BODY=2048
readonly TRACE_MAX_RECORD=3900

# JSON string escaping with parameter expansion only: no subshell, no sed.
json_escape_into() {
    local __js="$2"
    __js="${__js//\\/\\\\}"
    __js="${__js//\"/\\\"}"
    __js="${__js//$'\n'/\\n}"
    __js="${__js//$'\r'/\\r}"
    __js="${__js//$'\t'/\\t}"
    # Anything else below 0x20 is not legal in a JSON string; drop it rather
    # than emit a record no parser will accept.
    __js="${__js//[$'\x01'-$'\x1f']/}"
    printf -v "$1" '%s' "$__js"
}

# Captures what is known before the handler runs. No I/O happens here.
trace_begin() {
    [[ "$ENABLE_TRACING" == true ]] || return 0
    TRACE_METHOD="$1"
    TRACE_TARGET="${2:0:TRACE_MAX_TARGET}"
    TRACE_PROTO="$3"
    TRACE_START_US="${EPOCHREALTIME/./}"
    return 0
}

# Emits the record. Called once, with the status the client actually got.
trace_end() {
    [[ "$ENABLE_TRACING" == true ]] || return 0
    [[ -n "${TRACE_START_US:-}" ]] || return 0

    local status="$1" bytes="${2:-0}"
    local now_us="${EPOCHREALTIME/./}"
    local dur_us=$(( now_us - TRACE_START_US ))
    local stamp millis
    printf -v stamp '%(%Y-%m-%dT%H:%M:%S)T' -1
    millis="${now_us: -6:3}"

    local code="${status%% *}"
    [[ "$code" =~ ^[0-9]{3}$ ]] || code=0

    local method target proto remote host agent referer
    local raw_host="${REQUEST_HEADERS[host]:-}"
    local raw_agent="${REQUEST_HEADERS[user-agent]:-}"
    local raw_referer="${REQUEST_HEADERS[referer]:-}"
    json_escape_into method  "$TRACE_METHOD"
    json_escape_into target  "$TRACE_TARGET"
    json_escape_into proto   "$TRACE_PROTO"
    json_escape_into remote  "${REMOTE_ADDR:-}"
    json_escape_into host    "${raw_host:0:TRACE_MAX_HEADER_VALUE}"
    json_escape_into agent   "${raw_agent:0:TRACE_MAX_HEADER_VALUE}"
    json_escape_into referer "${raw_referer:0:TRACE_MAX_HEADER_VALUE}"

    local record
    printf -v record \
'{"ts":"%s.%sZ","dur_us":%s,"pid":%s,"remote":"%s","method":"%s","target":"%s","proto":"%s","status":%s,"bytes":%s,"req_bytes":%s,"host":"%s","ua":"%s","referer":"%s"' \
        "$stamp" "$millis" "$dur_us" "$$" "$remote" "$method" "$target" "$proto" \
        "$code" "$bytes" "${BODY_SIZE:-0}" "$host" "$agent" "$referer"

    if [[ -n "${TRACE_ERROR_DETAIL:-}" ]]; then
        local reason
        json_escape_into reason "${TRACE_ERROR_DETAIL:0:TRACE_MAX_HEADER_VALUE}"
        record+=",\"reason\":\"${reason}\""
        TRACE_ERROR_DETAIL=""
    fi

    if [[ "$ENABLE_FULL_TRACING" == true ]]; then
        record+=',"headers":{'
        local key value first=true
        for key in "${!REQUEST_HEADERS[@]}"; do
            local raw_value="${REQUEST_HEADERS[$key]:-}"
            json_escape_into value "${raw_value:0:TRACE_MAX_HEADER_VALUE}"
            if [[ "$first" == true ]]; then first=false; else record+=','; fi
            record+="\"${key}\":\"${value}\""
        done
        record+='}'

        if (( ${BODY_SIZE:-0} > 0 )); then
            local content_type="${REQUEST_HEADERS[content-type]:-}"
            if [[ "$content_type" == multipart/* || "$content_type" == application/octet-stream* ]]; then
                record+=',"body":null,"body_note":"binary omitted"'
            elif read_file_inline "$BODY_FILE"; then
                local body
                json_escape_into body "${INLINE_BODY:0:TRACE_MAX_BODY}"
                record+=",\"body\":\"${body}\""
            fi
        fi
    fi
    record+='}'

    # Last line of defence for the atomicity guarantee: if a record somehow
    # still exceeds PIPE_BUF, replace it rather than let a torn one through.
    if (( ${#record} > TRACE_MAX_RECORD )); then
        printf -v record \
'{"ts":"%s.%sZ","dur_us":%s,"pid":%s,"method":"%s","target":"%s","status":%s,"bytes":%s,"truncated":true}' \
            "$stamp" "$millis" "$dur_us" "$$" "$method" "${target:0:200}" "$code" "$bytes"
    fi

    if [[ -n "${TRACE_FD:-}" ]]; then
        printf '%s\n' "$record" 1>&"$TRACE_FD" 2>/dev/null || true
    else
        printf '%s\n' "$record" >>"$TRACE_FILE" 2>/dev/null || true
    fi
    TRACE_START_US=""
    return 0
}

# ---------------------------------------------------------------------------
# Per-connection state. socat forks one of these processes per connection.
# ---------------------------------------------------------------------------
declare -A REQUEST_HEADERS=()
# Per connection, not shared: each connection is its own process, so the memo
# dies with it and cannot outlive the keep-alive window.
declare -A STAT_CACHE=()
CURRENT_METHOD=""
BODY_SIZE=0
CHUNKED_TOTAL=0
RESPONSE_BYTES=0
TRACE_ERROR_DETAIL=""
CACHED_DATE=""
CACHED_DATE_EPOCH=0
TRACE_METHOD=""
TRACE_TARGET=""
TRACE_PROTO=""
TRACE_START_US=""
INLINE_BODY=""
HANDLER_CALLABLE=false
HANDLER_ENV=()
BODY_FILE=""
HEADER_FILE=""
HANDLER_OUT_FILE=""
PROXY_HEAD_FILE=""
RESPONSE_FIFO=""
CONN_SLOT=""
CONNECTION_ID=""
PARSE_ERROR=""
READ_BUDGET=0
HEADER_DEADLINE=0
REQUEST_DEADLINE=0

connection_cleanup() {
    rm -f -- "$BODY_FILE" "${BODY_FILE}.part" "$HEADER_FILE" "$HANDLER_OUT_FILE" \
             "$PROXY_HEAD_FILE" "$RESPONSE_FIFO" "$CONN_SLOT" 2>/dev/null || true
    return 0
}

# A global connection cap does not stop one client taking every slot. This
# bounds any single address, using one file per connection and a glob to count
# them — both shell builtins, so it costs no extra process on the accept path.
#
# Off by default: behind a NAT or a proxy, many users share an address, and a
# cap that silently breaks them is worse than no cap.
claim_connection_slot() {
    (( MAX_CONN_PER_IP > 0 )) || return 0
    [[ -n "${REMOTE_ADDR:-}" ]] || return 0
    [[ -n "${CONN_DIR:-}" && -d "${CONN_DIR:-/nonexistent}" ]] || return 0

    # The peer address comes from socat, not from a header, so it cannot be
    # spoofed by the client — but sanitise it anyway before it becomes a path.
    local key="${REMOTE_ADDR//[^0-9A-Fa-f.:]/_}"
    [[ -n "$key" ]] || return 0

    CONN_SLOT="${CONN_DIR}/${key}#${CONNECTION_ID}"
    : >"$CONN_SLOT" 2>/dev/null || { CONN_SLOT=""; return 0; }

    local -a held=("${CONN_DIR}/${key}#"*)
    if (( ${#held[@]} > MAX_CONN_PER_IP )); then
        rm -f -- "$CONN_SLOT" 2>/dev/null
        CONN_SLOT=""
        return 1
    fi
    return 0
}

init_connection_scratch() {
    # The scratch names must not be derived from the PID alone. Under
    # connection churn the kernel recycles PIDs quickly, and a connection that
    # exits just as its PID is reused would delete the new connection's files
    # from under it — which surfaces later as a mysterious 502.
    local nonce="${SRANDOM:-${RANDOM}${RANDOM}}"
    local base="${POOL_DIR:-${TMPDIR:-/tmp}}/conn.$$.${nonce}"
    BODY_FILE="${base}.body"
    HEADER_FILE="${base}.hdr"
    HANDLER_OUT_FILE="${base}.out"
    PROXY_HEAD_FILE="${base}.phdr"
    CONNECTION_ID="$$.${nonce}"
    rm -f -- "$BODY_FILE" "$HEADER_FILE" "$HANDLER_OUT_FILE" "$PROXY_HEAD_FILE"
    : >"$BODY_FILE"
    trap connection_cleanup EXIT INT TERM
    REMOTE_ADDR="${SOCAT_PEERADDR:-}"

    # Opened once for the connection's lifetime; a per-record open would put a
    # syscall back on the path this whole arrangement exists to clear.
    if [[ "$ENABLE_TRACING" == true && -n "${TRACE_FIFO:-}" && -p "${TRACE_FIFO:-/nonexistent}" ]]; then
        # Braces matter: without them the 2>/dev/null becomes part of the exec
        # and silences this connection's stderr for good, hiding every later
        # error it might report.
        { exec {TRACE_FD}>>"$TRACE_FIFO"; } 2>/dev/null || TRACE_FD=""
    fi
}

# Reads the header block. On failure PARSE_ERROR holds the status to return.
read_request_headers() {
    PARSE_ERROR=""
    REQUEST_HEADERS=()
    local line count=0 total=0 name value

    # The deadline arithmetic is inlined rather than calling seconds_until: it
    # runs once per header line, and a bash function call costs several times
    # what the subtraction inside it does.
    local budget length
    while (( (budget = HEADER_DEADLINE - EPOCHSECONDS) > 0 )) &&
          IFS= read -r -t "$budget" line; do
        line="${line%$'\r'}"
        length=${#line}
        (( length == 0 )) && return 0

        # One arithmetic test for all three limits; each is only distinguished
        # once the fast path has already been ruled out.
        if (( length > MAX_HEADER_LINE_BYTES ||
              ++count > MAX_HEADER_COUNT ||
              (total += length) > MAX_HEADER_TOTAL_BYTES )); then
            PARSE_ERROR="431 Request Header Fields Too Large"
            return 1
        fi

        # Obsolete line folding is a smuggling primitive; reject it outright
        # rather than trying to reassemble it (RFC 9112 s5.2).
        case "$line" in
            ' '*|$'\t'*)
                PARSE_ERROR="400 Bad Request"
                return 1 ;;
        esac

        name="${line%%:*}"
        if [[ "$name" == "$line" || -z "$name" ]] ||
           [[ "$name" == *[!A-Za-z0-9!\#\$%\&\'*+.^_\`\|~-]* ]]; then
            PARSE_ERROR="400 Bad Request"
            return 1
        fi
        value="${line#*:}"
        value="${value#"${value%%[![:space:]]*}"}"
        value="${value%"${value##*[![:space:]]}"}"
        name="${name,,}"

        if [[ -n "${REQUEST_HEADERS[$name]:-}" ]]; then
            case "$name" in
                # Conflicting duplicates of a framing or routing header are the
                # classic smuggling vector, so only identical repeats survive.
                content-length|host|transfer-encoding)
                    [[ "${REQUEST_HEADERS[$name]}" == "$value" ]] || {
                        PARSE_ERROR="400 Bad Request"
                        return 1
                    }
                    ;;
                *) value="${REQUEST_HEADERS[$name]}, ${value}" ;;
            esac
        fi
        REQUEST_HEADERS["$name"]="$value"
    done
    if ! seconds_until "$HEADER_DEADLINE"; then
        PARSE_ERROR="408 Request Timeout"
        TRACE_ERROR_DETAIL="header deadline exceeded"
    else
        PARSE_ERROR="408 Request Timeout"
    fi
    return 1
}

handle_connection() {
    init_connection_scratch

    if ! claim_connection_slot; then
        CURRENT_METHOD="GET"
        trace_begin "-" "-" "-"
        send_error "429 Too Many Requests" "close" "per-address connection limit reached"
        return 0
    fi

    local request_count=0 keep_alive="$ENABLE_KEEPALIVE"

    while :; do
        local request_line=""
        IFS= read -r -t "$TIMEOUT_SECONDS" request_line || break
        request_line="${request_line%$'\r'}"
        # A stray empty line before a request line is tolerated (RFC 9112 s2.2).
        while [[ -z "$request_line" ]]; do
            IFS= read -r -t "$TIMEOUT_SECONDS" request_line || return 0
            request_line="${request_line%$'\r'}"
        done

        (( ++request_count ))
        CURRENT_METHOD="GET"
        # The clock on this request starts now, not on each read.
        HEADER_DEADLINE=$(( EPOCHSECONDS + HEADER_TIMEOUT ))
        REQUEST_DEADLINE=$(( EPOCHSECONDS + REQUEST_TIMEOUT ))

        local method target version excess
        read -r method target version excess <<<"$request_line"
        CURRENT_METHOD="${method:-GET}"

        # Opened here rather than after validation: a request that gets
        # rejected still has to appear in the log, and it is the one an
        # operator is most likely to be looking for.
        trace_begin "${method:-?}" "${target:-${request_line:0:120}}" "${version:-?}"

        if (( ${#request_line} > MAX_REQUEST_LINE_BYTES )); then
            send_error "414 URI Too Long" "close"
            break
        fi

        if [[ -n "$excess" || -z "$target" || -z "$version" ]]; then
            send_error "400 Bad Request" "close" "malformed request line"
            break
        fi
        if [[ "$method" == *[!A-Za-z0-9!\#\$%\&\'*+.^_\`\|~-]* ]]; then
            send_error "400 Bad Request" "close" "invalid method token"
            break
        fi
        case "$version" in
            HTTP/1.1|HTTP/1.0) ;;
            HTTP/0.9) send_error "400 Bad Request" "close" "HTTP/0.9 is not supported"; break ;;
            HTTP/*)   send_error "505 HTTP Version Not Supported" "close"; break ;;
            *)        send_error "400 Bad Request" "close" "malformed protocol version"; break ;;
        esac

        if ! read_request_headers; then
            send_error "$PARSE_ERROR" "close"
            break
        fi

        if [[ "$version" == "HTTP/1.1" && -z "${REQUEST_HEADERS[host]:-}" ]]; then
            send_error "400 Bad Request" "close" "missing Host header"
            break
        fi

        # ---- connection persistence -------------------------------------
        local connection_header="${REQUEST_HEADERS[connection]:-}"
        connection_header="${connection_header,,}"
        if [[ "$ENABLE_KEEPALIVE" != true ]]; then
            keep_alive=false
        elif [[ "$connection_header" == *close* ]]; then
            keep_alive=false
        elif [[ "$version" == "HTTP/1.0" && "$connection_header" != *keep-alive* ]]; then
            keep_alive=false
        else
            keep_alive=true
        fi
        (( request_count >= MAX_KEEPALIVE_REQ )) && keep_alive=false

        local connection_value="keep-alive"
        [[ "$keep_alive" == true ]] || connection_value="close"

        # ---- request body ------------------------------------------------
        local transfer_encoding="${REQUEST_HEADERS[transfer-encoding]:-}"
        local content_length="${REQUEST_HEADERS[content-length]:-}"
        transfer_encoding="${transfer_encoding,,}"

        if [[ -n "$transfer_encoding" && -n "$content_length" ]]; then
            send_error "400 Bad Request" "close" "Content-Length together with Transfer-Encoding"
            break
        fi
        if [[ -n "$content_length" ]] &&
           [[ "$content_length" == *[!0-9]* || ${#content_length} -gt 15 ]]; then
            send_error "400 Bad Request" "close" "invalid Content-Length"
            break
        fi

        if [[ "${REQUEST_HEADERS[expect]:-}" == *[Cc]ontinue* ]]; then
            if [[ -n "$content_length" ]] && (( content_length > MAX_BODY_SIZE )); then
                send_error "417 Expectation Failed" "close"
                break
            fi
            printf 'HTTP/1.1 100 Continue\r\n\r\n'
        fi

        : >"$BODY_FILE"
        BODY_SIZE=0
        if [[ -n "$transfer_encoding" ]]; then
            if [[ "$transfer_encoding" != "chunked" ]]; then
                send_error "501 Not Implemented" "close" "unsupported Transfer-Encoding"
                break
            fi
            local chunk_status=0
            read_chunked_to_file "$BODY_FILE" || chunk_status=$?
            if (( chunk_status == 2 )); then
                send_error "413 Content Too Large" "close"
                break
            elif (( chunk_status == 3 )); then
                send_error "408 Request Timeout" "close" "request deadline exceeded"
                break
            elif (( chunk_status != 0 )); then
                send_error "400 Bad Request" "close" "malformed chunked body"
                break
            fi
            BODY_SIZE="$CHUNKED_TOTAL"
        elif [[ -n "$content_length" ]] && (( content_length > 0 )); then
            if (( content_length > MAX_BODY_SIZE )); then
                send_error "413 Content Too Large" "close"
                break
            fi
            if ! read_exact_to_file "$content_length" "$BODY_FILE"; then
                if ! seconds_until "$REQUEST_DEADLINE"; then
                    send_error "408 Request Timeout" "close" "request deadline exceeded"
                else
                    send_error "400 Bad Request" "close" "truncated request body"
                fi
                break
            fi
            BODY_SIZE="$content_length"
        fi

        dispatch_request "$method" "$target" "$version" "$connection_value"

        [[ "$keep_alive" == true ]] || break
    done
    return 0
}

# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------
dispatch_request() {
    local method="$1" target="$2" version="$3" connection="$4"

    case "$method" in
        TRACE|CONNECT)
            # TRACE enables cross-site tracing and CONNECT turns the server into
            # an open tunnel; neither has a safe implementation here.
            send_response_head "405 Method Not Allowed" "text/plain; charset=utf-8" "0" \
                "$connection" "Allow: GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS"$'\r\n'
            trace_end "405 Method Not Allowed" "$RESPONSE_BYTES"
            return 0
            ;;
        GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS) ;;
        *)
            if [[ -z "$REQUEST_HANDLER" ]]; then
                send_error "501 Not Implemented" "$connection" "unrecognised method"
                return 0
            fi
            ;;
    esac

    if [[ "$method" == "OPTIONS" && "$target" == "*" ]]; then
        send_response_head "204 No Content" "" "" "$connection" \
            "Allow: GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS"$'\r\n'
        trace_end "204 No Content" "$RESPONSE_BYTES"
        return 0
    fi

    # Absolute-form targets must be accepted (RFC 9112 s3.2.2). The authority is
    # dropped because Host already pins it down.
    if [[ "$target" == http://* || "$target" == https://* ]]; then
        local remainder="${target#*://}"
        if [[ "$remainder" == */* ]]; then
            target="/${remainder#*/}"
        else
            target="/"
        fi
    fi
    if [[ "$target" != /* ]]; then
        send_error "400 Bad Request" "$connection" "unsupported request-target form"
        return 0
    fi

    local raw_path="${target%%\?*}"
    local query_string=""
    [[ "$target" == *\?* ]] && query_string="${target#*\?}"

    if [[ "$raw_path" == *%00* || "$raw_path" == *%0[0-9AaBbCcDdEeFf]* ]]; then
        send_error "400 Bad Request" "$connection" "encoded control character in request target"
        return 0
    fi

    local decoded_path
    percent_decode_into decoded_path "$raw_path"
    if [[ "$decoded_path" == *[$'\x01'-$'\x1f']* || "$decoded_path" == *$'\x7f'* ]]; then
        send_error "400 Bad Request" "$connection" "control character in request target"
        return 0
    fi
    # Backslashes become separators so Windows-style traversal is normalised
    # away instead of slipping past the dot-segment resolver.
    decoded_path="${decoded_path//\\//}"

    local normalized
    normalize_path_into normalized "$decoded_path"

    local file_path="${STATIC_DIR}${normalized}"
    if [[ "$normalized" == "/" ]]; then
        file_path="${STATIC_DIR}/${INDEX_FILE}"
    elif [[ -d "$file_path" ]]; then
        file_path="${file_path}/${INDEX_FILE}"
    fi

    # Defence in depth: normalize_path already guarantees this, but the prefix
    # test is free and catches any future regression in the normaliser.
    if [[ "$file_path" != "$STATIC_DIR"/* ]]; then
        send_error "403 Forbidden" "$connection" "path escapes the document root"
        return 0
    fi

    if [[ "${file_path##*/}" == .* ]]; then
        send_error "403 Forbidden" "$connection" "dotfiles are not served"
        return 0
    fi

    if [[ -f "$file_path" ]]; then
        if [[ "$DENY_SYMLINKS" == true ]] && path_contains_symlink "$normalized"; then
            send_error "403 Forbidden" "$connection" "symlinked content is not served"
            return 0
        fi
        case "$method" in
            GET|HEAD)
                serve_static_file "$method" "$file_path" "$connection"
                return 0
                ;;
            OPTIONS)
                send_response_head "204 No Content" "" "" "$connection" \
                    "Allow: GET, HEAD, OPTIONS"$'\r\n'
                trace_end "204 No Content" "$RESPONSE_BYTES"
                return 0
                ;;
            *)
                if [[ -z "$REQUEST_HANDLER" && -z "$PROXY_TARGET" ]]; then
                    send_response_head "405 Method Not Allowed" "text/plain; charset=utf-8" "0" \
                        "$connection" "Allow: GET, HEAD, OPTIONS"$'\r\n'
                    trace_end "405 Method Not Allowed" "$RESPONSE_BYTES"
                    return 0
                fi
                ;;
        esac
    fi

    if [[ -n "$REQUEST_HANDLER" ]]; then
        invoke_handler "$method" "$target" "$normalized" "$query_string" "$version" "$connection"
        return 0
    fi
    if [[ -n "$PROXY_TARGET" ]]; then
        forward_to_upstream "$method" "$target" "$connection"
        return 0
    fi

    send_error "404 Not Found" "$connection"
    return 0
}

# Walks each component under the document root looking for a symlink, so a
# symlinked *directory* cannot smuggle content in either.
path_contains_symlink() {
    local relative="$1" walked="$STATIC_DIR" segment
    local -a segments=()
    IFS='/' read -ra segments <<<"$relative"
    for segment in "${segments[@]}"; do
        [[ -z "$segment" ]] && continue
        walked="${walked}/${segment}"
        [[ -L "$walked" ]] && return 0
    done
    return 1
}

# ---------------------------------------------------------------------------
# Static content
# ---------------------------------------------------------------------------
serve_static_file() {
    local method="$1" path="$2" connection="$3"

    if [[ ! -r "$path" ]]; then
        send_error "403 Forbidden" "$connection" "file is not readable"
        return 0
    fi

    local size mtime etag last_modified mime
    stat_file "$path"
    size="$STAT_SIZE"
    mtime="$STAT_MTIME"
    mime_type_into mime "$path"
    etag="\"${mtime}-${size}\""
    http_date_into last_modified "$mtime"

    local extra=""
    extra+="ETag: ${etag}"$'\r\n'
    extra+="Last-Modified: ${last_modified}"$'\r\n'
    extra+="Cache-Control: public, max-age=3600"$'\r\n'
    extra+="Accept-Ranges: bytes"$'\r\n'
    if [[ "$connection" == "keep-alive" ]]; then
        extra+="Keep-Alive: timeout=${TIMEOUT_SECONDS}, max=${MAX_KEEPALIVE_REQ}"$'\r\n'
    fi

    local if_none_match="${REQUEST_HEADERS[if-none-match]:-}"
    local if_modified_since="${REQUEST_HEADERS[if-modified-since]:-}"
    if [[ -n "$if_none_match" ]]; then
        if [[ "$if_none_match" == "*" || "$if_none_match" == *"$etag"* ]]; then
            send_response_head "304 Not Modified" "" "" "$connection" "$extra"
            trace_end "304 Not Modified" "$RESPONSE_BYTES"
            return 0
        fi
    elif [[ -n "$if_modified_since" && "$if_modified_since" == "$last_modified" ]]; then
        send_response_head "304 Not Modified" "" "" "$connection" "$extra"
        trace_end "304 Not Modified" "$RESPONSE_BYTES"
        return 0
    fi

    local range="${REQUEST_HEADERS[range]:-}"
    if [[ -n "$range" && "$method" == "GET" && "$range" != *,* ]]; then
        if [[ "$range" =~ ^bytes=([0-9]{0,15})-([0-9]{0,15})$ ]]; then
            local start="${BASH_REMATCH[1]}" end="${BASH_REMATCH[2]}" satisfiable=true
            if [[ -z "$start" && -z "$end" ]]; then
                satisfiable=false
            elif [[ -z "$start" ]]; then
                # Suffix form: the final <end> bytes of the representation.
                if (( end == 0 || size == 0 )); then
                    satisfiable=false
                else
                    (( end > size )) && end="$size"
                    start=$(( size - end ))
                    end=$(( size - 1 ))
                fi
            else
                [[ -z "$end" ]] && end=$(( size - 1 ))
                (( end >= size )) && end=$(( size - 1 ))
                (( start > end || start >= size )) && satisfiable=false
            fi

            if [[ "$satisfiable" == true ]]; then
                local length=$(( end - start + 1 ))
                extra+="Content-Range: bytes ${start}-${end}/${size}"$'\r\n'
                send_response_head "206 Partial Content" "$mime" "$length" "$connection" "$extra"
                send_file_range "$path" "$start" "$length"
                trace_end "206 Partial Content" "$RESPONSE_BYTES"
                return 0
            fi

            send_response_head "416 Range Not Satisfiable" "text/plain; charset=utf-8" "0" \
                "$connection" "Content-Range: bytes */${size}"$'\r\n'
            trace_end "416 Range Not Satisfiable" "$RESPONSE_BYTES"
            return 0
        fi
    fi

    if [[ "$method" != "GET" ]]; then
        send_response_head "200 OK" "$mime" "$size" "$connection" "$extra"
    elif read_inline_body "$path" "$size"; then
        send_response "200 OK" "$mime" "$size" "$connection" "$extra" "$INLINE_BODY"
    else
        send_response_head "200 OK" "$mime" "$size" "$connection" "$extra"
        send_file_range "$path" 0 "$size"
    fi
    trace_end "200 OK" "$RESPONSE_BYTES"
    return 0
}

# ---------------------------------------------------------------------------
# Dynamic requests
# ---------------------------------------------------------------------------
# Handler output is buffered so the *server* decides the framing headers. That
# keeps keep-alive connections synchronised even when a handler misbehaves, and
# makes header injection through handler output impossible.
invoke_handler() {
    local method="$1" target="$2" path_info="$3" query_string="$4" version="$5" connection="$6"

    : >"$HANDLER_OUT_FILE"

    local status=0
    if pool_is_available; then
        write_request_metadata "$method" "$target" "$path_info" "$query_string" "$version"
        pool_dispatch || status=$?
        # POOL_UNAVAILABLE means no worker could be reached, not that the
        # handler failed, so fall back to running it in this process.
        if (( status == POOL_UNAVAILABLE )); then
            status=0
            run_handler "$method" "$target" "$path_info" "$query_string" "$version" || status=$?
        fi
    else
        run_handler "$method" "$target" "$path_info" "$query_string" "$version" || status=$?
    fi

    if (( status != 0 )) && [[ ! -s "$HANDLER_OUT_FILE" ]]; then
        send_error "502 Bad Gateway" "$connection" "the request handler failed"
        return 0
    fi
    emit_handler_response "$connection"
}

pool_is_available() {
    (( POOL_SIZE > 0 )) && [[ -n "${POOL_TOKENS:-}" && -p "${POOL_TOKENS:-/nonexistent}" ]]
}

# The request line and headers go into a side file rather than the queue record
# so the record stays far below PIPE_BUF and its write remains atomic.
write_request_metadata() {
    {
        printf ':method\t%s\n'  "$1"
        printf ':target\t%s\n'  "$2"
        printf ':path\t%s\n'    "$3"
        printf ':query\t%s\n'   "$4"
        printf ':version\t%s\n' "$5"
        printf ':remote\t%s\n'  "${REMOTE_ADDR:-}"
        printf ':length\t%s\n'  "${BODY_SIZE:-0}"
        local key
        for key in "${!REQUEST_HEADERS[@]}"; do
            printf '%s\t%s\n' "$key" "${REQUEST_HEADERS[$key]}"
        done
    } >"$HEADER_FILE"
}

# Populates HANDLER_ENV in place. Building the array directly rather than
# piping through a process substitution keeps this fork-free, which matters
# because it runs on every dynamic request.
build_handler_environment() {
    local method="$1" target="$2" path_info="$3" query_string="$4" version="$5"
    HANDLER_ENV=(
        "PATH=${PATH}"
        "GATEWAY_INTERFACE=CGI/1.1"
        "SERVER_SOFTWARE=${SERVER_BANNER}"
        "SERVER_PROTOCOL=${version}"
        "SERVER_PORT=${HTTP_PORT}"
        "REQUEST_METHOD=${method}"
        "REQUEST_URI=${target}"
        "PATH_INFO=${path_info}"
        "QUERY_STRING=${query_string}"
        "DOCUMENT_ROOT=${STATIC_DIR}"
        "REMOTE_ADDR=${REMOTE_ADDR:-}"
        "CONTENT_TYPE=${REQUEST_HEADERS[content-type]:-}"
        "CONTENT_LENGTH=${BODY_SIZE:-0}"
    )
    local key upper
    for key in "${!REQUEST_HEADERS[@]}"; do
        [[ "$key" =~ ^[a-z0-9-]+$ ]] || continue
        upper="${key^^}"
        HANDLER_ENV+=("HTTP_${upper//-/_}=${REQUEST_HEADERS[$key]}")
    done
}

handler_preload_wanted() {
    [[ "$HANDLER_MODE" != "exec" ]] || return 1
    [[ -n "$REQUEST_HANDLER" && -r "$REQUEST_HANDLER" ]] || return 1

    # Only worker and connection processes are long-lived enough to benefit,
    # and only a script that actually declares the function is worth reading.
    local argument found=false
    for argument in "$@"; do
        case "$argument" in
            --internal-pool-worker|--internal-connection) found=true ;;
        esac
    done
    [[ "$found" == true ]] || return 1

    handler_defines_function "$REQUEST_HANDLER"
}

run_handler() {
    build_handler_environment "$@"

    if [[ "$HANDLER_CALLABLE" == true ]]; then
        # The subshell is deliberate: it costs one cheap fork and buys the same
        # isolation exec gives, so a handler cannot leak variables into the
        # worker or kill it by exiting.
        (
            set +e
            local pair
            for pair in "${HANDLER_ENV[@]}"; do
                export "${pair%%=*}=${pair#*=}"
            done
            handle_request
        ) <"$BODY_FILE" >"$HANDLER_OUT_FILE" 2>/dev/null
        return $?
    fi

    env -i "${HANDLER_ENV[@]}" "$REQUEST_HANDLER" \
        <"$BODY_FILE" >"$HANDLER_OUT_FILE" 2>/dev/null
}

# Hands the request to an idle pre-forked worker.
#
# Workers cannot simply share one queue FIFO: bash reads a pipe one byte at a
# time, so several workers blocked on the same FIFO interleave bytes from the
# same record and shred it. Instead each worker owns a private request FIFO —
# one reader, so reads are never split — and idleness is published as a stream
# of single-byte tokens on a shared semaphore FIFO. A one-byte read cannot be
# split either, so exactly one connection claims each idle worker, and the
# kernel does the queueing and the blocking for us.
pool_dispatch() {
    if [[ -z "$RESPONSE_FIFO" ]]; then
        RESPONSE_FIFO="${POOL_DIR}/resp.${CONNECTION_ID}"
        rm -f -- "$RESPONSE_FIFO"
        mkfifo -m 600 "$RESPONSE_FIFO" || return "$POOL_UNAVAILABLE"
        exec {RESPONSE_FD}<>"$RESPONSE_FIFO"
        exec {TOKEN_FD}<>"$POOL_TOKENS"
    fi

    local token slot
    IFS= read -r -N 1 -u "$TOKEN_FD" -t "$POOL_ACQUIRE_TIMEOUT" token ||
        return "$POOL_UNAVAILABLE"
    printf -v slot '%d' "'$token"
    (( slot -= 1 ))
    if (( slot < 0 || slot >= POOL_SIZE )); then
        return "$POOL_UNAVAILABLE"
    fi

    if ! printf '%s\t%s\t%s\t%s\n' \
            "$RESPONSE_FIFO" "$HEADER_FILE" "$BODY_FILE" "$HANDLER_OUT_FILE" \
            >>"${POOL_DIR}/worker.${slot}.req"; then
        # The worker never saw the job, so hand its token straight back.
        printf '%s' "$token" 1>&"$TOKEN_FD" 2>/dev/null || true
        return "$POOL_UNAVAILABLE"
    fi

    local reply=""
    IFS= read -r -u "$RESPONSE_FD" -t "$TIMEOUT_SECONDS" reply || return 1
    [[ "$reply" == "0" ]]
}

# Strips framing and hop-by-hop headers from the handler's output, then re-frames
# the response with a server-computed Content-Length.
emit_handler_response() {
    local connection="$1"
    local status="200 OK" content_type="text/plain; charset=utf-8" extra=""
    local line name raw_name value body_offset=0 saw_blank=false

    while IFS= read -r line; do
        (( body_offset += ${#line} + 1 ))
        line="${line%$'\r'}"
        if [[ -z "$line" ]]; then
            saw_blank=true
            break
        fi
        raw_name="${line%%:*}"
        if [[ "$raw_name" == "$line" ]]; then
            # No header block at all — treat the whole file as the body.
            break
        fi
        value="${line#*:}"
        value="${value#"${value%%[![:space:]]*}"}"
        name="${raw_name,,}"
        case "$name" in
            status)
                [[ "$value" =~ ^[1-5][0-9][0-9]([[:space:]].*)?$ ]] && status="$value"
                ;;
            content-type)
                [[ "$value" != *[$'\r\n']* ]] && content_type="$value"
                ;;
            content-length|transfer-encoding|connection|keep-alive|upgrade|te|trailer|proxy-authenticate|proxy-authorization)
                ;;
            *)
                # Emitted with the handler's own capitalisation; matching is
                # case-insensitive, but echoing it back mangled is impolite.
                [[ "$name" =~ ^[a-z0-9-]+$ ]] && extra+="${raw_name}: ${value}"$'\r\n'
                ;;
        esac
    done <"$HANDLER_OUT_FILE"

    [[ "$saw_blank" == true ]] || body_offset=0

    # Read first, measure second: pulling the reply in gives the length for
    # free, where asking stat for it would cost a process spawn. Single exit,
    # so the trace record cannot be skipped by whichever branch runs.
    local total body_length inlined=false
    if read_file_inline "$HANDLER_OUT_FILE"; then
        inlined=true
        total=${#INLINE_BODY}
    else
        total="$(file_size "$HANDLER_OUT_FILE")"
    fi
    body_length=$(( total - body_offset ))
    (( body_length < 0 )) && body_length=0

    if [[ "$CURRENT_METHOD" == "HEAD" ]] || (( body_length == 0 )); then
        send_response_head "$status" "$content_type" "$body_length" "$connection" "$extra"
    elif [[ "$inlined" == true ]]; then
        send_response "$status" "$content_type" "$body_length" "$connection" "$extra" \
            "${INLINE_BODY:body_offset}"
    else
        send_response_head "$status" "$content_type" "$body_length" "$connection" "$extra"
        send_file_range "$HANDLER_OUT_FILE" "$body_offset" "$body_length"
    fi
    trace_end "$status" "$RESPONSE_BYTES"
    return 0
}

# Runs one job. Every failure mode ends in a reply rather than an exit: a
# worker that dies takes its slot with it, and a pool that silently shrinks
# under load is far worse than a single failed request. Callers invoke this
# with `|| true`, which also suspends errexit for the whole body.
process_pool_job() {
    local response_fifo="$1" header_file="$2" body_file="$3" out_file="$4"
    local status=0

    REQUEST_HEADERS=()
    local method="GET" target="/" path_info="/" query_string="" version="HTTP/1.1"
    BODY_SIZE=0

    # The connection may have timed out and cleaned up its scratch files while
    # this job sat in the queue, so nothing here is assumed to still exist.
    if [[ -r "$header_file" ]]; then
        local key value
        while IFS=$'\t' read -r key value; do
            case "$key" in
                ':method')  method="$value" ;;
                ':target')  target="$value" ;;
                ':path')    path_info="$value" ;;
                ':query')   query_string="$value" ;;
                ':version') version="$value" ;;
                ':remote')  REMOTE_ADDR="$value" ;;
                ':length')  BODY_SIZE="$value" ;;
                '')         ;;
                *)          REQUEST_HEADERS["$key"]="$value" ;;
            esac
        done <"$header_file"
    else
        status=1
    fi

    BODY_FILE="$body_file"
    HANDLER_OUT_FILE="$out_file"

    if (( status == 0 )); then
        run_handler "$method" "$target" "$path_info" "$query_string" "$version" || status=$?
    fi

    # Opening read-write never blocks, so a client that disappeared mid-request
    # cannot wedge this worker on the reply FIFO.
    local reply_fd
    if exec {reply_fd}<>"$response_fifo" 2>/dev/null; then
        printf '%s\n' "$status" 1>&"$reply_fd" 2>/dev/null || true
        exec {reply_fd}>&- 2>/dev/null || true
    fi
    return 0
}

run_pool_worker() {
    local index="${POOL_WORKER_INDEX:-0}" hex token
    printf -v hex '%02x' "$(( index + 1 ))"
    printf -v token "\\x${hex}"

    local response_fifo header_file body_file out_file
    exec {QUEUE_FD}<"${POOL_DIR}/worker.${index}.req"
    exec {TOKEN_FD}<>"$POOL_TOKENS"

    while IFS=$'\t' read -r -u "$QUEUE_FD" response_fifo header_file body_file out_file; do
        if [[ -n "$response_fifo" && -n "$out_file" ]]; then
            process_pool_job "$response_fifo" "$header_file" "$body_file" "$out_file" || true
        fi

        # Availability is announced only once the reply is out, so no second
        # connection can target this worker while it is still busy. The worker
        # returns its own token rather than the connection returning it, so a
        # client that vanishes mid-request cannot shrink the pool.
        printf '%s' "$token" 1>&"$TOKEN_FD" 2>/dev/null || true
    done
    return 0
}

# Tracing is moved off the request path entirely: connections write records to
# a FIFO, and one dedicated process copies them to the log file. Request
# handling therefore never blocks on disk, and since a single process owns the
# file, records cannot interleave there either.
#
# cat is the right tool for this — it is a pipe-to-file copier and nothing more.
# A bash read loop would add an interpreter to every line for no benefit.
start_trace_writer() {
    [[ "$ENABLE_TRACING" == true ]] || return 0

    TRACE_FIFO="${POOL_DIR}/trace.fifo"
    if ! mkfifo -m 600 "$TRACE_FIFO" 2>/dev/null; then
        # No FIFO, no async: fall back to connections appending directly.
        TRACE_FIFO=""
        return 0
    fi

    # Held read-write for the same reason as the pool FIFOs: a write-only open
    # would block until the drain started, and holding a writer is what keeps
    # the drain from seeing EOF between requests.
    exec {TRACE_KEEPALIVE_FD}<>"$TRACE_FIFO"

    cat <"$TRACE_FIFO" >>"$TRACE_FILE" &
    TRACE_WRITER_PID=$!
    export TRACE_FIFO
    return 0
}

start_process_pool() {
    (( POOL_SIZE > 0 )) || return 0
    [[ -n "$REQUEST_HANDLER" ]] || return 0

    POOL_TOKENS="${POOL_DIR}/tokens"
    mkfifo -m 600 "$POOL_TOKENS"
    export POOL_TOKENS

    # Every FIFO below is held open read-write for the server's lifetime. The
    # read-write part matters twice over: a write-only open would block until a
    # reader appeared, and holding a writer is what stops idle workers from
    # seeing EOF. socat inherits these descriptors, so when socat exits the
    # descriptors close and every worker retires on its own.
    exec {POOL_TOKENS_FD}<>"$POOL_TOKENS"

    local index request_fifo hex token keepalive_fd
    for (( index = 0; index < POOL_SIZE; index++ )); do
        request_fifo="${POOL_DIR}/worker.${index}.req"
        mkfifo -m 600 "$request_fifo"
        # shellcheck disable=SC2034  # opened purely to hold the FIFO alive
        exec {keepalive_fd}<>"$request_fifo"

        POOL_WORKER_INDEX="$index" "$BASH_BINARY" "$SELF_PATH" --internal-pool-worker &
        POOL_WORKER_PIDS+=($!)

        printf -v hex '%02x' "$(( index + 1 ))"
        printf -v token "\\x${hex}"
        printf '%s' "$token" 1>&"$POOL_TOKENS_FD"
    done
    return 0
}

# ---------------------------------------------------------------------------
# Reverse proxy
# ---------------------------------------------------------------------------
forward_to_upstream() {
    local method="$1" target="$2" connection="$3"

    local upstream="${PROXY_TARGET%/}${target}"
    local -a options=(
        --silent --show-error
        --output "$HANDLER_OUT_FILE"
        --dump-header "$PROXY_HEAD_FILE"
        --max-time "$REQUEST_TIMEOUT"
        --connect-timeout "$TIMEOUT_SECONDS"
        --max-filesize "$MAX_PROXY_RESPONSE"
        --location=false
        --proto '=http,https'
        --request "$method"
        --header 'Expect:'
    )
    local key
    for key in "${!REQUEST_HEADERS[@]}"; do
        case "$key" in
            host|connection|keep-alive|transfer-encoding|content-length|upgrade|te|trailer|proxy-authorization|proxy-authenticate)
                continue ;;
        esac
        [[ "$key" =~ ^[a-z0-9-]+$ ]] || continue
        options+=(--header "${key}: ${REQUEST_HEADERS[$key]}")
    done
    [[ -s "$BODY_FILE" ]] && options+=(--data-binary "@${BODY_FILE}")

    if ! curl "${options[@]}" -- "$upstream" 2>/dev/null; then
        send_error "502 Bad Gateway" "$connection" "the upstream request failed"
        return 0
    fi

    # Re-frame the upstream response: only end-to-end headers are copied, and
    # Content-Length is recomputed so a hostile upstream cannot desynchronise
    # this connection.
    local status="200 OK" content_type="application/octet-stream" extra="" line name raw_name value
    while IFS= read -r line; do
        line="${line%$'\r'}"
        [[ -z "$line" ]] && continue
        if [[ "$line" == HTTP/* ]]; then
            status="${line#* }"
            continue
        fi
        raw_name="${line%%:*}"
        [[ "$raw_name" == "$line" ]] && continue
        value="${line#*:}"
        value="${value#"${value%%[![:space:]]*}"}"
        name="${raw_name,,}"
        case "$name" in
            content-type) content_type="$value" ;;
            content-length|transfer-encoding|connection|keep-alive|upgrade|te|trailer|proxy-authenticate|proxy-authorization|server|date)
                ;;
            *) [[ "$name" =~ ^[a-z0-9-]+$ ]] && extra+="${raw_name}: ${value}"$'\r\n' ;;
        esac
    done <"$PROXY_HEAD_FILE"

    [[ "$status" =~ ^[1-5][0-9][0-9] ]] || status="502 Bad Gateway"

    local size
    size="$(file_size "$HANDLER_OUT_FILE")"
    send_response_head "$status" "$content_type" "$size" "$connection" "$extra"
    if [[ "$CURRENT_METHOD" != "HEAD" ]] && (( size > 0 )); then
        send_file_range "$HANDLER_OUT_FILE" 0 "$size"
    fi
    trace_end "$status" "$RESPONSE_BYTES"
    return 0
}

# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------
build_listen_address() {
    # nodelay is not a micro-optimisation here. Responses too large to inline
    # leave as two writes — headers, then the body from cat — and with Nagle
    # enabled the kernel holds the second one waiting for an ACK that the peer
    # is itself delaying. Measured on Linux that put a flat ~40 ms on every
    # streamed response; p50 for a 4 KB binary was 43 ms against 2.6 ms for an
    # inlined one.
    # socat's default listen backlog is 5, which a burst of concurrent clients
    # overflows immediately — they get connection-refused rather than queued.
    # Size it to capacity instead, with a floor so small --max-connections
    # values still absorb a burst.
    local backlog="$MAX_CONN"
    (( backlog < 128 )) && backlog=128
    local listen_options="reuseaddr,nodelay,fork,max-children=${MAX_CONN},backlog=${backlog},rcvbuf=${READ_BUFFER},sndbuf=${WRITE_BUFFER}"
    [[ "$BIND_ADDRESS" != "0.0.0.0" ]] && listen_options+=",bind=${BIND_ADDRESS}"

    if [[ "$TLS_ENABLED" == true ]]; then
        local address="OPENSSL-LISTEN:${HTTP_PORT},${listen_options},cert=${TLS_CERT},key=${TLS_KEY}"
        # TLS 1.0 and 1.1 are deprecated (RFC 8996) and compression enables
        # CRIME, so neither is left to the library default — where this build
        # lets us say so. OpenSSL 1.1.0 and later disable compression by
        # default anyway, so the second one is belt and braces.
        [[ "$SOCAT_HAS_MIN_PROTO" == true ]] &&
            address+=",openssl-min-proto-version=${TLS_MIN_VERSION}"
        [[ "$SOCAT_HAS_COMPRESS" == true ]] &&
            address+=",openssl-compress=none"
        [[ -n "$TLS_CIPHERS" ]] && address+=",cipherlist=${TLS_CIPHERS}"
        [[ -n "$TLS_CA" ]] && address+=",cafile=${TLS_CA}"
        if [[ "$TLS_VERIFY_CLIENT" == true ]]; then
            address+=",verify=1"
        else
            address+=",verify=0"
        fi
        printf '%s' "$address"
    else
        printf 'TCP-LISTEN:%s,%s' "$HTTP_PORT" "$listen_options"
    fi
}

# How socat should hand a connection to this script.
#
# EXEC runs the interpreter directly. SYSTEM would run it through /bin/sh,
# which costs an extra fork and exec on every connection for nothing.
#
# nofork goes further: instead of relaying between the socket and a pipe pair,
# socat execs the child with the accepted socket already on its stdin and
# stdout. That removes a whole process per connection and takes socat out of
# the data path entirely — worth about 25% on connection-per-request traffic.
#
# It cannot be used with TLS: socat has to stay in the middle to run the
# session, and a child holding the raw socket would just see ciphertext.
build_execution_address() {
    local use_nofork="$1"

    # EXEC splits the command on spaces and reads commas as its own option
    # separator, with no quoting available, so an awkward install path has to
    # go through a shell instead.
    #
    # Quoting the path in the address does not help: socat strips quotes while
    # parsing, so the shell would still see a bare space. The path is therefore
    # kept out of the address entirely and passed through the environment, with
    # IFS emptied so the shell expands it without word-splitting. That copes
    # with spaces, commas and anything else a directory name can contain.
    if [[ "$BASH_BINARY" == *[[:space:],]* || "$SELF_PATH" == *[[:space:],]* ]]; then
        printf 'SYSTEM:IFS=; exec $BASH_BINARY $SELF_PATH --internal-connection'
        return 0
    fi

    if [[ "$use_nofork" == true ]]; then
        printf 'EXEC:%s %s --internal-connection,nofork' "$BASH_BINARY" "$SELF_PATH"
    else
        printf 'EXEC:%s %s --internal-connection' "$BASH_BINARY" "$SELF_PATH"
    fi
}

print_banner() {
    local scheme="http" keepalive tls pool tracing
    [[ "$TLS_ENABLED" == true ]] && scheme="https"

    if [[ "$ENABLE_KEEPALIVE" == true ]]; then
        keepalive="${TIMEOUT_SECONDS}s idle, up to ${MAX_KEEPALIVE_REQ} requests"
    else
        keepalive="disabled"
    fi
    if [[ "$TLS_ENABLED" == true ]]; then
        tls="enabled (${TLS_CERT##*/})"
        [[ "$TLS_VERIFY_CLIENT" == true ]] && tls+=" + client certificates"
    else
        tls="disabled"
    fi
    if [[ -z "$REQUEST_HANDLER" ]]; then
        pool="n/a"
    elif (( POOL_SIZE > 0 )); then
        pool="${POOL_SIZE} pre-forked workers"
    else
        pool="disabled (fork per request)"
    fi
    local hardening="baseline"
    [[ "$SECURITY_HEADERS" == true ]] || hardening="disabled"
    [[ -n "$CONTENT_SECURITY_POLICY" ]] && hardening+=" + CSP"
    [[ -n "$CROSS_ORIGIN_RESOURCE_POLICY" ]] && hardening+=" + CORP"
    [[ "$TLS_ENABLED" == true ]] && (( HSTS_MAX_AGE > 0 )) && hardening+=" + HSTS"
    (( MAX_CONN_PER_IP > 0 )) && hardening+=", ${MAX_CONN_PER_IP}/address"

    if [[ "$ENABLE_FULL_TRACING" == true ]]; then
        tracing="full -> ${TRACE_FILE}"
    elif [[ "$ENABLE_TRACING" == true ]]; then
        tracing="basic -> ${TRACE_FILE}"
    else
        tracing="disabled"
    fi

    cat >&2 <<EOF
─────────────────────────────────────────────────────────────
 ${SERVER_BANNER}   bash ${BASH_VERSION%%(*}   socat ${SOCAT_VERSION:-unknown}
─────────────────────────────────────────────────────────────
 Listening       : ${scheme}://${BIND_ADDRESS}:${HTTP_PORT}
 Document root   : ${STATIC_DIR}
 Index file      : ${INDEX_FILE}
 Max connections : ${MAX_CONN}
 Keep-alive      : ${keepalive}
 TLS             : ${tls}
 Request handler : ${REQUEST_HANDLER:-none}
 Handler pool    : ${pool}
 Reverse proxy   : ${PROXY_TARGET:-disabled}
 Max body size   : ${MAX_BODY_SIZE} bytes
 Deadlines       : ${HEADER_TIMEOUT}s headers, ${REQUEST_TIMEOUT}s request
 Security headers: ${hardening}
 File metadata   : $( (( FILE_CACHE_SECONDS > 0 )) && printf 'cached %ss per connection' "$FILE_CACHE_SECONDS" || printf 'read per request' )
 Tracing         : ${tracing}
─────────────────────────────────────────────────────────────
EOF
}

shutdown_server() {
    [[ -n "${SOCAT_PID:-}" ]] && kill "$SOCAT_PID" 2>/dev/null
    # Workers block on their request FIFOs, whose write ends this process
    # holds; they would never see EOF while it is still alive, so say so
    # explicitly rather than leaving them orphaned.
    (( ${#POOL_WORKER_PIDS[@]} > 0 )) && kill "${POOL_WORKER_PIDS[@]}" 2>/dev/null
    if [[ -n "${TRACE_WRITER_PID:-}" ]]; then
        # Closing our write end lets the drain finish the queue and exit.
        exec {TRACE_KEEPALIVE_FD}>&- 2>/dev/null || true
        kill "$TRACE_WRITER_PID" 2>/dev/null
    fi
    [[ -n "${POOL_DIR:-}" && -d "${POOL_DIR:-}" ]] && rm -rf -- "$POOL_DIR"
    return 0
}

main() {
    parse_arguments "$@"

    # Anything this process creates — scratch files, the trace log — should not
    # be readable by other users on the machine.
    umask 077

    # Every process that writes a response needs the header block, and the
    # per-connection and worker processes take their configuration from the
    # environment rather than the command line.
    build_constant_headers

    case "$INTERNAL_MODE" in
        connection)  handle_connection; exit 0 ;;
        pool-worker) run_pool_worker;   exit 0 ;;
    esac

    detect_stat_flavour
    check_runtime
    check_configuration
    check_tls_config
    # TLS state is only known after the check, and HSTS depends on it.
    build_constant_headers

    BASH_BINARY="${BASH:-$(command -v bash)}"
    SELF_PATH="$(absolute_path "${BASH_SOURCE[0]}")"
    POOL_DIR="$(mktemp -d "${TMPDIR:-/tmp}/bash-httpd.XXXXXX")"
    chmod 700 "$POOL_DIR"
    CONN_DIR="${POOL_DIR}/conn"
    mkdir -m 700 "$CONN_DIR"
    export CONN_DIR
    trap shutdown_server EXIT INT TERM

    if [[ "$ENABLE_TRACING" == true ]]; then
        TRACE_FILE="$(absolute_path "$TRACE_FILE")" ||
            die "the directory for --trace-file does not exist"
    fi

    export SELF_PATH POOL_DIR BASH_BINARY
    export HTTP_PORT BIND_ADDRESS STATIC_DIR PROXY_TARGET REQUEST_HANDLER INDEX_FILE
    export READ_BUFFER WRITE_BUFFER MAX_BODY_SIZE POOL_SIZE DENY_SYMLINKS HANDLER_MODE
    export SERVER_TOKENS SECURITY_HEADERS CONTENT_SECURITY_POLICY TLS_ENABLED
    export CROSS_ORIGIN_RESOURCE_POLICY HSTS_MAX_AGE VERBOSE_ERRORS MAX_CONN_PER_IP
    export FILE_CACHE_SECONDS
    export STAT_FLAVOUR
    export ENABLE_TRACING ENABLE_FULL_TRACING TRACE_FILE
    export ENABLE_KEEPALIVE TIMEOUT_SECONDS MAX_KEEPALIVE_REQ
    export HEADER_TIMEOUT REQUEST_TIMEOUT

    start_trace_writer
    start_process_pool
    print_banner

    local use_nofork=true
    [[ "$TLS_ENABLED" == true ]] && use_nofork=false

    socat -d0 \
        "$(build_listen_address)" \
        "$(build_execution_address "$use_nofork")" &
    SOCAT_PID=$!
    wait "$SOCAT_PID"
}

# A handler that defines `handle_request` is loaded once per long-lived process
# and then simply called, which is what makes pooling pay for itself: a request
# costs one cheap fork instead of a fork, an exec, and a fresh interpreter
# re-parsing the script.
#
# This has to happen here, at true top-level scope. Sourcing from inside a
# function would make every `declare` in the handler function-local, so the
# lookup tables and connections a handler sets up at load time would vanish
# before the first request arrived.
#
# The probe runs in a subshell so a handler that fails or exits while loading
# cannot take the process with it; anything that does not cleanly define the
# function keeps the exec-per-request path.
if handler_preload_wanted "$@"; then
    # shellcheck disable=SC1090  # the handler path is chosen at runtime
    if ( source "$REQUEST_HANDLER" >/dev/null 2>&1
         declare -F handle_request >/dev/null 2>&1 ); then
        # shellcheck disable=SC1090
        if source "$REQUEST_HANDLER" >/dev/null 2>&1 &&
           declare -F handle_request >/dev/null 2>&1; then
            HANDLER_CALLABLE=true
        fi
    fi
fi

main "$@"
