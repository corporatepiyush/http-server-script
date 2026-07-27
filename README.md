# http-server-script

A real HTTP/1.1 web server in a single Bash script.

No runtime to install, no dependency tree, no build step. One file you can read
start to finish, plus `socat` to own the socket. It serves static files, runs
your own request handlers from a pre-forked process pool, reverse-proxies to an
upstream, and speaks TLS when you hand it a certificate.

```bash
mkdir -p public && echo '<h1>hello</h1>' > public/index.html
./http-server.sh --port 8080 --static-dir ./public
```

That's it. Open <http://localhost:8080>.

---

## Contents

- [Why this exists](#why-this-exists)
- [Requirements](#requirements)
- [Cheat sheet](#cheat-sheet)
- [Options](#options)
- [Examples](#examples) — the bulk of this document
- [Writing a request handler](#writing-a-request-handler)
- [How concurrency works](#how-concurrency-works)
- [Performance and tuning](#performance-and-tuning)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)

---

## Why this exists

Sometimes you need a web server on a box where installing one is the hard part:
a hardened container, a build agent, a router, an air-gapped VM. Bash and socat
are already there, or are a single package away.

So this is not a toy that answers `200 OK` to everything. It implements the
parts of RFC 9110 and RFC 9112 that decide whether a server is safe to point at
a network: exact request framing, chunked decoding, conditional requests, byte
ranges, keep-alive that stays in sync, and hard limits on everything a client
can make you allocate. It ships with a [test suite](#testing) that tries to
break all of it.

**Where it fits:** local development, internal tooling, health endpoints,
static sites, CI fixtures, environments where a "real" server isn't an option.

**Where it doesn't:** it is not nginx. Expect low thousands of requests per
second, not hundreds of thousands. Put it behind a CDN or a load balancer if it
faces the public internet.

---

## Requirements

| Requirement | Version | Why |
|---|---|---|
| **bash** | **5.3+** | Namerefs, `read -N`, `${var,,}`, `EPOCHSECONDS`, dynamic file descriptors |
| **socat** | **1.8.0+** | Listener, `fork`, `max-children`, OpenSSL integration |
| curl | 8.0.0+ | Optional — only for `--proxy-target`, and only checked then |

Nothing else. No python, no perl, no awk in the request path — just bash, socat,
and the handful of coreutils (`cat`, `head`, `tail`, `stat`) that exist
everywhere a shell does.

Both versions are checked at startup, and the server tells you exactly how to
install what's missing rather than failing halfway through a request.

### Installing

```bash
# macOS — /bin/bash is 3.2 from 2007 and Apple will never update it
brew install bash socat

# Debian / Ubuntu
sudo apt update && sudo apt install bash socat

# Fedora / RHEL
sudo dnf install bash socat

# Arch
sudo pacman -S bash socat

# Alpine
apk add bash socat
```

Check what you have:

```bash
bash --version | head -1     # need 5.3 or newer
socat -V | head -2           # need 1.8.0 or newer
```

**On macOS you must name the new interpreter explicitly**, because `./http-server.sh`
and `/bin/bash` both resolve to the ancient one:

```bash
/opt/homebrew/bin/bash http-server.sh --port 8080 --static-dir ./public   # Apple silicon
/usr/local/bin/bash    http-server.sh --port 8080 --static-dir ./public   # Intel
```

Or put the new bash first on `PATH` and use the shebang:

```bash
export PATH="/opt/homebrew/bin:$PATH"
./http-server.sh --port 8080 --static-dir ./public
```

If your distribution only packages socat 1.7.x, build 1.8 from
[dest-unreach.org/socat](http://www.dest-unreach.org/socat/), or run with
`--skip-socat-version-check` and accept that TLS options may behave differently.

---

## Cheat sheet

| I want to… | Add this |
|---|---|
| Serve a folder | `./http-server.sh -p 8080 -s ./public` |
| Serve only to this machine | `--bind 127.0.0.1` |
| Serve over HTTPS | `--tls-cert cert.pem --tls-key key.pem` |
| Require a client certificate | `--tls-ca ca.pem --tls-verify-client` |
| Add API endpoints | `-rh ./handler.sh` |
| Make handlers fast | define `handle_request` inside the handler |
| Send unmatched requests to an app | `-r http://127.0.0.1:3000` |
| Get JSON access logs | `--enable-tracing --trace-file access.ndjson` |
| Log headers and bodies too | `--enable-full-tracing` |
| Handle more concurrent clients | `--max-connections 256` |
| Run more handlers at once | `--pool-size 32` |
| Refuse symlinked content | `--deny-symlinks` |
| Use a different index page | `--index-file home.html` |
| Cap upload size | `--max-body-size 65536` |
| Close connections immediately | `--disable-keep-alive` |

Short flags: `-p` port, `-s` static dir, `-b` bind, `-c` max connections,
`-rb` / `-wb` socket buffers, `-rh` request handler, `-r` proxy target.

Everyday one-liners:

```bash
# is it up?
curl -sf localhost:8080/ >/dev/null && echo up || echo down

# what is it actually sending?
curl -v localhost:8080/ 2>&1 | grep '^<'

# stop it
pkill -f 'LISTEN:8080'

# watch errors as they happen
tail -f access.ndjson | jq -c 'select(.status >= 400)'
```

---

## Options

### Required

| Option | Description |
|---|---|
| `-p, --port <port>` | TCP port to listen on |
| `-s, --static-dir <dir>` | Directory served as static content |

### Listener

| Option | Default | Description |
|---|---|---|
| `-b, --bind <address>` | `0.0.0.0` | Interface to bind |
| `-c, --max-connections <n>` | `64` | Simultaneous connections |
| `-rb, --read-buffer <bytes>` | `65536` | Socket receive buffer |
| `-wb, --write-buffer <bytes>` | `65536` | Socket send buffer |

### TLS — optional, off by default

| Option | Description |
|---|---|
| `--tls-cert <file>` | PEM certificate. Supplying this switches the listener to HTTPS |
| `--tls-key <file>` | PEM private key (defaults to the certificate file) |
| `--tls-ca <file>` | CA bundle used to verify client certificates |
| `--tls-verify-client` | Require a valid client certificate (mTLS); needs `--tls-ca` |

### Timeouts

Each phase of a request is bounded on the clock, not merely per read.

| Option | Default | Description |
|---|---|---|
| `--keep-alive-timeout <sec>` | `15` | Idle wait for the next request on a live connection |
| `--header-timeout <sec>` | `10` | Deadline for the whole header block |
| `--request-timeout <sec>` | `30` | Deadline for one complete request including its body |

A per-read timeout bounds one read and nothing more. A client that sends a
single header every few seconds never trips it, so on its own it lets a
connection be held open indefinitely at almost no cost — a slow-drip variant of
slowloris. The header and request deadlines are wall-clock: every read inside a
phase gets only the time still remaining, so the total is bounded however the
bytes are spread out.

`--request-timeout` also caps how long an upstream may take under
`--proxy-target`.

### Keep-alive

| Option | Default | Description |
|---|---|---|
| `--max-keepalive-requests <n>` | `100` | Requests per connection before closing |
| `--disable-keep-alive` | off | Answer everything with `Connection: close` |

### Content

| Option | Default | Description |
|---|---|---|
| `--index-file <name>` | `index.html` | Directory index filename |
| `--max-body-size <bytes>` | `10485760` | Largest accepted request body |
| `--deny-symlinks` | off | Refuse symlinked files, and files under symlinked directories |

### Dynamic requests

| Option | Default | Description |
|---|---|---|
| `-rh, --request-handler <path>` | none | Executable run when no static file matches |
| `--pool-size <n>` | `8` | Pre-forked handler workers, `0` disables pooling (max 127) |
| `--handler-mode <mode>` | `auto` | `auto` loads a handler defining `handle_request` into each worker; `exec` always forks and execs |
| `-r, --proxy-target <url>` | none | Upstream origin when no static file matches |

### Observability

| Option | Default | Description |
|---|---|---|
| `--enable-tracing` | off | One NDJSON record per request: status, sizes, service time |
| `--enable-full-tracing` | off | Also record request headers and textual bodies |
| `--trace-file <path>` | `trace.log` | Trace destination (NDJSON) |

### Hardening

Follows the OWASP Secure Headers baseline by default. Policies that can break
ordinary content are offered rather than imposed — a header that forces you to
disable the whole set is worse than one you turn on deliberately.

| Option | Default | Description |
|---|---|---|
| `--server-tokens <mode>` | `off` | `off` sends `Server: bash-httpd`, `on` adds the version, `none` omits the header |
| `--no-security-headers` | off | Drop the baseline entirely (for use behind a proxy that sets its own) |
| `--csp <policy>` | none | `Content-Security-Policy` for all responses |
| `--cross-origin-resource-policy <v>` | none | `Cross-Origin-Resource-Policy`; `same-origin` breaks cross-origin asset serving |
| `--hsts-max-age <sec>` | `31536000` | `Strict-Transport-Security` age when TLS is on; `0` disables |
| `--verbose-errors` | off | Return the rejection reason to the client as well as logging it |
| `--max-connections-per-ip <n>` | `0` | Cap concurrent connections from one address; `0` is unlimited |
| `--tls-min-version <v>` | `TLS1.3` | Lowest TLS version accepted |
| `--tls-ciphers <list>` | OpenSSL default | OpenSSL cipher list |

Sent on every response unless `--no-security-headers`:

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
X-Permitted-Cross-Domain-Policies: none
Cross-Origin-Opener-Policy: same-origin-allow-popups
Permissions-Policy: accelerometer=(), camera=(), geolocation=(), gyroscope=(),
                    magnetometer=(), microphone=(), payment=(), usb=()
Strict-Transport-Security: max-age=31536000        [TLS only]
```

Error responses additionally carry `Content-Security-Policy: default-src 'none'`
and `Cache-Control: no-store`.

**TLS 1.3 only, by default.** Everything below it is refused, TLS 1.2 included.
That rules out clients older than roughly 2019 — Chrome and Firefox got 1.3 in
2018, Safari in 2019, OpenSSL in 1.1.1. If you have to serve something older,
`--tls-min-version TLS1.2` lowers the floor and warns that it did.

**Rejection reasons are logged, not returned.** A client gets
`400 Bad Request`; the trace record gets `"reason":"missing Host header"`.
Telling an attacker exactly which check failed maps your parser for them.
`--verbose-errors` opts back in for development.

### Performance

| Option | Default | Description |
|---|---|---|
| `--file-cache-seconds <n>` | `0` | Remember file size and mtime for up to n seconds per connection; `0` reads them every request |

### Other

| Option | Description |
|---|---|
| `--skip-socat-version-check` | Bypass the socat 1.8.0 requirement |
| `--skip-curl-version-check` | Bypass the curl 8.0.0 requirement |
| `-V, --version` | Print the version |
| `-h, --help` | Show help |

---

## Examples

Every example below is complete and runnable, and every handler in them has
been run against the server.

Two things that apply throughout: **handler files must be executable**
(`chmod +x handler.sh`) — the server refuses to start otherwise and says so —
and on macOS you prefix each `./http-server.sh` with `/opt/homebrew/bin/bash`.

### 1. Serve the current directory

```bash
./http-server.sh --port 8080 --static-dir .
```

### 2. Serve only to localhost

Bind to the loopback interface so nothing outside the machine can reach it.

```bash
./http-server.sh --port 8080 --static-dir ./public --bind 127.0.0.1
```

### 3. A single-page app, where every path falls back to index.html

`spa-handler.sh`:

```bash
#!/usr/bin/env bash
# Anything that isn't a real file lands here; hand back the app shell.
printf 'Status: 200 OK\r\n'
printf 'Content-Type: text/html; charset=utf-8\r\n'
printf '\r\n'
cat "$DOCUMENT_ROOT/index.html"
```

Run it:

```bash
./http-server.sh --port 8080 --static-dir ./dist --request-handler ./spa-handler.sh
```

### 4. Use a different index file

```bash
./http-server.sh --port 8080 --static-dir ./site --index-file home.html
```

### 5. A hardened static host

Localhost-only, no symlinks followed, small bodies, short keep-alive.

```bash
./http-server.sh \
  --port 8080 \
  --bind 127.0.0.1 \
  --static-dir ./public \
  --deny-symlinks \
  --max-body-size 65536 \
  --keep-alive-timeout 5 \
  --max-keepalive-requests 50 \
  --max-connections 32
```

### 6. HTTPS with a self-signed certificate

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
        -keyout key.pem -out cert.pem -subj '/CN=localhost'

./http-server.sh --port 8443 --static-dir ./public \
            --tls-cert cert.pem --tls-key key.pem

curl -k https://localhost:8443/
```

### 7. HTTPS with Let's Encrypt certificates

certbot writes a combined chain; point `--tls-cert` at the full chain.

```bash
./http-server.sh --port 443 --static-dir ./public \
  --tls-cert /etc/letsencrypt/live/example.com/fullchain.pem \
  --tls-key  /etc/letsencrypt/live/example.com/privkey.pem
```

### 8. Mutual TLS — require a client certificate

```bash
./http-server.sh --port 8443 --static-dir ./public \
  --tls-cert server-cert.pem \
  --tls-key  server-key.pem \
  --tls-ca   client-ca.pem \
  --tls-verify-client

curl --cert client.pem --key client-key.pem -k https://localhost:8443/
```

Requests without a certificate signed by `client-ca.pem` never reach the server.

### 9. Hello world handler

The simplest possible dynamic endpoint.

`hello.sh`:

```bash
#!/usr/bin/env bash
printf 'Status: 200 OK\r\n'
printf 'Content-Type: text/plain\r\n'
printf '\r\n'
printf 'Hello from %s\n' "$PATH_INFO"
```

Run it:

```bash
./http-server.sh -p 8080 -s ./public -rh ./hello.sh
curl localhost:8080/anything      # Hello from /anything
```

### 10. A JSON API — the fast, poolable form

Defining `handle_request` lets each worker load the file once instead of
exec'ing it per request. This is the form you want for anything under load.

`api.sh`:

```bash
#!/usr/bin/env bash
# Everything out here runs ONCE per worker.
readonly STARTED_AT="$EPOCHSECONDS"

reply() {
  printf 'Status: %s\r\nContent-Type: application/json\r\n\r\n%s' "$1" "$2"
}

handle_request() {
  case "$REQUEST_METHOD $PATH_INFO" in
    "GET /api/health")  reply '200 OK' '{"status":"ok"}' ;;
    "GET /api/uptime")  reply '200 OK' "{\"seconds\":$(( EPOCHSECONDS - STARTED_AT ))}" ;;
    *)                  reply '404 Not Found' '{"error":"not found"}' ;;
  esac
}
```

Run it:

```bash
./http-server.sh -p 8080 -s ./public -rh ./api.sh --pool-size 16
curl localhost:8080/api/health
```

### 11. Read a POST body

The body arrives on stdin.

`echo.sh`:

```bash
#!/usr/bin/env bash
handle_request() {
  local body
  body="$(cat)"
  printf 'Status: 200 OK\r\nContent-Type: text/plain\r\n\r\n'
  printf 'method=%s bytes=%s\n%s\n' "$REQUEST_METHOD" "$CONTENT_LENGTH" "$body"
}
```

Run it:

```bash
./http-server.sh -p 8080 -s ./public -rh ./echo.sh
curl -X POST -d 'hello world' localhost:8080/echo
```

### 12. Parse the query string

`query.sh`:

```bash
#!/usr/bin/env bash
handle_request() {
  declare -A params=()
  local pair key value
  local IFS='&'
  for pair in $QUERY_STRING; do
    key="${pair%%=*}"; value="${pair#*=}"
    value="${value//+/ }"
    params["$key"]="$value"
  done

  printf 'Status: 200 OK\r\nContent-Type: text/plain\r\n\r\n'
  printf 'name=%s age=%s\n' "${params[name]:-anon}" "${params[age]:-?}"
}
```

Run it:

```bash
./http-server.sh -p 8080 -s ./public -rh ./query.sh
curl 'localhost:8080/hi?name=ada&age=36'      # name=ada age=36
```

### 13. Path routing, including path parameters

`routes.sh`:

```bash
#!/usr/bin/env bash
reply() { printf 'Status: %s\r\nContent-Type: application/json\r\n\r\n%s' "$1" "$2"; }

handle_request() {
  case "$PATH_INFO" in
    /users)        reply '200 OK' '{"users":["ada","alan"]}' ;;
    /users/*/pets) reply '200 OK' "{\"owner\":\"$(basename "$(dirname "$PATH_INFO")")\"}" ;;
    /users/*)      reply '200 OK' "{\"user\":\"${PATH_INFO##*/}\"}" ;;
    *)             reply '404 Not Found' '{"error":"no route"}' ;;
  esac
}
```

Run it:

```bash
curl localhost:8080/users/ada          # {"user":"ada"}
curl localhost:8080/users/ada/pets     # {"owner":"ada"}
```

### 14. Status codes, redirects and custom headers

Emit any header you like — the server only overrides the framing ones.

`headers.sh`:

```bash
#!/usr/bin/env bash
handle_request() {
  case "$PATH_INFO" in
    /old)
      printf 'Status: 301 Moved Permanently\r\n'
      printf 'Location: /new\r\n\r\n'
      ;;
    /teapot)
      printf "Status: 418 I'm a teapot\r\n\r\nshort and stout\n"
      ;;
    /login)
      printf 'Status: 200 OK\r\n'
      printf 'Set-Cookie: session=abc123; HttpOnly; SameSite=Strict; Path=/\r\n'
      printf 'Content-Type: text/plain\r\n\r\nlogged in\n'
      ;;
    *)
      printf 'Status: 204 No Content\r\n\r\n'
      ;;
  esac
}
```

### 15. Load configuration once per worker

Anything outside `handle_request` is paid for once at worker startup, not per
request. This is the reason to use the function form.

`config-handler.sh`:

```bash
#!/usr/bin/env bash
# Read once per worker, not once per request.
declare -A SETTINGS=()
while IFS='=' read -r key value; do
  [[ -z "$key" || "$key" == \#* ]] && continue
  SETTINGS["$key"]="$value"
done < /etc/myapp.conf

handle_request() {
  printf 'Status: 200 OK\r\nContent-Type: text/plain\r\n\r\n'
  printf 'greeting=%s\n' "${SETTINGS[greeting]:-hello}"
}
```

### 16. Serve a generated file, or stream a large one

`report.sh`:

```bash
#!/usr/bin/env bash
handle_request() {
  printf 'Status: 200 OK\r\n'
  printf 'Content-Type: text/csv; charset=utf-8\r\n'
  printf 'Content-Disposition: attachment; filename="report.csv"\r\n'
  printf '\r\n'
  printf 'id,name\n'
  printf '%s,user%s\n' 1 1
  printf '%s,user%s\n' 2 2
}
```

`Content-Length` is computed for you, so streaming a multi-megabyte file works
without you counting a single byte.

### 17. Kubernetes liveness and readiness probes

`probes.sh`:

```bash
#!/usr/bin/env bash
READY_FLAG=/tmp/app-ready

handle_request() {
  case "$PATH_INFO" in
    /healthz) printf 'Status: 200 OK\r\n\r\nok\n' ;;
    /readyz)
      if [[ -e "$READY_FLAG" ]]; then
        printf 'Status: 200 OK\r\n\r\nready\n'
      else
        printf 'Status: 503 Service Unavailable\r\n\r\nstarting\n'
      fi
      ;;
    *) printf 'Status: 404 Not Found\r\n\r\n' ;;
  esac
}
```

### 18. A handler in another language

The handler is just an executable — it does not have to be bash. Non-bash
handlers always use the exec path.

`handler.py`:

```python
#!/usr/bin/env python3
import os, sys, json
print("Status: 200 OK\r")
print("Content-Type: application/json\r")
print("\r")
print(json.dumps({"path": os.environ["PATH_INFO"], "body": sys.stdin.read()}))
```

Run it:

```bash
./http-server.sh -p 8080 -s ./public --request-handler ./handler.py
```

### 19. Reverse proxy to an application

Static files are served directly; everything else goes upstream.

```bash
./http-server.sh --port 8080 --static-dir ./public \
            --proxy-target http://127.0.0.1:3000
```

### 20. Static assets in front, API behind

```bash
./http-server.sh --port 8080 \
            --static-dir ./dist \
            --request-handler ./api.sh \
            --pool-size 16 \
            --max-connections 128
```

Lookup order is: real file → handler → 404.

### 21. Structured access logs

Tracing emits **one JSON object per line** (NDJSON) — built for tooling, not
for reading. Each record is written after the response, so it carries the
status, the byte count and the service time in a single entry.

```bash
./http-server.sh -p 8080 -s ./public --enable-tracing --trace-file ./trace.ndjson
```

```json
{"ts":"2026-07-27T18:53:26.585Z","dur_us":4018,"pid":60028,"remote":"127.0.0.1","method":"GET","target":"/a.txt?q=1","proto":"HTTP/1.1","status":200,"bytes":6,"req_bytes":0,"host":"localhost:8080","ua":"curl/8.21.0","referer":""}
```

| Field | Meaning |
|---|---|
| `ts` | ISO 8601 UTC with milliseconds |
| `dur_us` | Service time in microseconds, request line to last byte |
| `pid` | Connection process, so you can group a keep-alive session |
| `remote` | Client address |
| `method` `target` `proto` | Request line, target capped at 512 bytes |
| `status` | Numeric, not a string — no parsing needed |
| `bytes` / `req_bytes` | Response and request body sizes |
| `host` `ua` `referer` | Common headers, capped at 256 bytes each |

`--enable-full-tracing` adds a `headers` object and, for textual requests, a
`body` string (binary is marked, not dumped).

Because it is NDJSON it goes straight into the usual tools:

```bash
# slowest requests
jq -s 'sort_by(-.dur_us) | .[:10] | .[] | "\(.dur_us)us \(.status) \(.target)"' -r trace.ndjson

# error rate and p95 latency
jq -s '{errors: (map(select(.status >= 500)) | length),
        total: length,
        p95_us: (map(.dur_us) | sort | .[(length * 0.95 | floor)])}' trace.ndjson

# live tail of failures only
tail -f trace.ndjson | jq -c 'select(.status >= 400)'

# top clients
jq -r .remote trace.ndjson | sort | uniq -c | sort -rn | head
```

Records never reach the disk on the request path: connections write them to a
FIFO that a dedicated process drains. See
[how concurrency works](#how-concurrency-works).

### 22. Run under systemd

```ini
# /etc/systemd/system/bash-httpd.service
[Unit]
Description=bash-httpd
After=network.target

[Service]
ExecStart=/usr/bin/bash /opt/http-server-script/http-server.sh \
          --port 8080 --static-dir /srv/www --request-handler /srv/api.sh
Restart=on-failure
User=www-data
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now bash-httpd
```

### 23. Run in a container

```dockerfile
FROM alpine:latest
RUN apk add --no-cache bash socat
COPY http-server.sh /usr/local/bin/http-server.sh
COPY public/ /srv/www/
RUN chmod +x /usr/local/bin/http-server.sh
EXPOSE 8080
CMD ["bash", "/usr/local/bin/http-server.sh", "--port", "8080", "--static-dir", "/srv/www"]
```

```bash
docker build -t bash-httpd . && docker run -p 8080:8080 bash-httpd
```

Check that Alpine's bash is 5.3+; if not, pin a newer base image.

### 24. Benchmark it

```bash
# throughput and latency
wrk -t4 -c32 -d10s --latency http://127.0.0.1:8080/

# compare handler forms: exec-per-request vs loaded-once
./http-server.sh -p 8081 -s ./public -rh ./hello.sh --pool-size 8 &   # script form
./http-server.sh -p 8082 -s ./public -rh ./api.sh   --pool-size 8 &   # function form
wrk -t4 -c16 -d10s http://127.0.0.1:8081/api/health
wrk -t4 -c16 -d10s http://127.0.0.1:8082/api/health

# without wrk
ab -c 16 -n 2000 http://127.0.0.1:8080/
```

### 25. HTTP basic authentication

`auth.sh`:

```bash
#!/usr/bin/env bash
# Realistically you would read this from a file or the environment.
readonly EXPECTED="Basic $(printf 'admin:secret' | base64)"

deny() {
  printf 'Status: 401 Unauthorized\r\n'
  printf 'WWW-Authenticate: Basic realm="restricted"\r\n\r\n'
  printf 'unauthorized\n'
}

handle_request() {
  if [[ "${HTTP_AUTHORIZATION:-}" != "$EXPECTED" ]]; then
    deny
    return
  fi
  printf 'Status: 200 OK\r\nContent-Type: text/plain\r\n\r\nwelcome\n'
}
```

Run it:

```bash
./http-server.sh -p 8080 -s ./public -rh ./auth.sh
curl -u admin:secret localhost:8080/private
```

Comparing the header as a whole string is deliberate — it avoids decoding
attacker-supplied base64 in shell.

### 26. CORS preflight and headers

`cors.sh`:

```bash
#!/usr/bin/env bash
readonly ALLOWED_ORIGIN="https://app.example.com"

cors_headers() {
  printf 'Access-Control-Allow-Origin: %s\r\n' "$ALLOWED_ORIGIN"
  printf 'Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n'
  printf 'Access-Control-Allow-Headers: Content-Type, Authorization\r\n'
  printf 'Access-Control-Max-Age: 600\r\n'
}

handle_request() {
  if [[ "$REQUEST_METHOD" == "OPTIONS" ]]; then
    printf 'Status: 204 No Content\r\n'
    cors_headers
    printf '\r\n'
    return
  fi
  printf 'Status: 200 OK\r\nContent-Type: application/json\r\n'
  cors_headers
  printf '\r\n{"ok":true}'
}
```

Note the server answers `OPTIONS` on *static* files itself; a handler only sees
preflights for paths with no matching file.

### 27. Restrict access by client address

`allowlist.sh`:

```bash
#!/usr/bin/env bash
handle_request() {
  case "$REMOTE_ADDR" in
    127.0.0.1|10.*|192.168.*)
      printf 'Status: 200 OK\r\nContent-Type: text/plain\r\n\r\ninternal\n' ;;
    *)
      printf 'Status: 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nnope\n' ;;
  esac
}
```

This is a coarse filter, not a security boundary — anything in front of the
server can set the source address. Use a firewall for the real thing.

### 28. Control caching per path

Static files get `Cache-Control: public, max-age=3600`, an `ETag` and a
`Last-Modified` automatically, so conditional requests just work:

```bash
etag=$(curl -sI localhost:8080/app.js | tr -d '\r' | awk -F': ' 'tolower($1)=="etag"{print $2}')
curl -s -o /dev/null -w '%{http_code}\n' -H "If-None-Match: $etag" localhost:8080/app.js   # 304
```

For different policies per path, answer from a handler:

`cache.sh`:

```bash
#!/usr/bin/env bash
handle_request() {
  case "$PATH_INFO" in
    /assets/*)  printf 'Status: 200 OK\r\nCache-Control: public, max-age=31536000, immutable\r\n\r\n' ;;
    /api/*)     printf 'Status: 200 OK\r\nCache-Control: no-store\r\n\r\n{"ok":true}' ;;
    *)          printf 'Status: 200 OK\r\nCache-Control: no-cache\r\n\r\n' ;;
  esac
}
```

### 29. Accept a file upload

Request bodies are read through bash, so this suits small payloads. Anything
large belongs behind `--proxy-target`.

`upload.sh`:

```bash
#!/usr/bin/env bash
handle_request() {
  if [[ "$REQUEST_METHOD" != "POST" ]]; then
    printf 'Status: 405 Method Not Allowed\r\nAllow: POST\r\n\r\n'
    return
  fi
  local destination="/tmp/upload.$$"
  cat >"$destination"
  printf 'Status: 201 Created\r\nContent-Type: application/json\r\n\r\n'
  printf '{"stored":"%s","bytes":%s}' "$destination" "$CONTENT_LENGTH"
}
```

Run it:

```bash
./http-server.sh -p 8080 -s ./public -rh ./upload.sh --max-body-size 1048576
curl -X POST --data-binary @notes.txt localhost:8080/upload
```

### 30. Run several sites at once

One process per site, each with its own root and port:

```bash
./http-server.sh -p 8081 -s ./site-a --trace-file ./a.ndjson --enable-tracing &
./http-server.sh -p 8082 -s ./site-b --trace-file ./b.ndjson --enable-tracing &
```

Put a real reverse proxy in front to route by hostname:

```nginx
server {
    server_name a.example.com;
    location / { proxy_pass http://127.0.0.1:8081; }
}
server {
    server_name b.example.com;
    location / { proxy_pass http://127.0.0.1:8082; }
}
```

### 31. Restart it without dropping the port

`restart.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
PORT=8080
PIDFILE=/tmp/http-server.pid

[[ -f "$PIDFILE" ]] && kill "$(cat "$PIDFILE")" 2>/dev/null || true

./http-server.sh -p "$PORT" -s ./public &
echo $! > "$PIDFILE"

until curl -sf "http://127.0.0.1:${PORT}/" >/dev/null; do sleep 0.1; done
echo "listening on ${PORT}"
```

The listener sets `SO_REUSEADDR`, so a restart does not have to wait out
`TIME_WAIT`.

### 32. Turn the access log into a live dashboard

```bash
# requests per second, updated each second
tail -f access.ndjson | jq -r .ts | uniq -c

# slowest ten requests so far
jq -s 'sort_by(-.dur_us)[:10] | .[] | "\(.dur_us)us \(.status) \(.target)"' -r access.ndjson

# status code breakdown
jq -r .status access.ndjson | sort -n | uniq -c

# bytes served per client
jq -r '[.remote, .bytes] | @tsv' access.ndjson \
  | awk '{sum[$1] += $2} END {for (c in sum) print sum[c], c}' | sort -rn
```

### 33. Use it as a CI fixture with a health gate

`ci-test.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

./http-server.sh -p 8080 -s ./fixtures --disable-keep-alive &
SERVER=$!
trap 'kill $SERVER 2>/dev/null' EXIT

for _ in {1..50}; do
  curl -sf http://127.0.0.1:8080/health.json >/dev/null && break
  sleep 0.2
done

npm test
```

### 34. Confirm it is actually safe

```bash
./test/pentest.sh
```

---

## Writing a request handler

Any executable will do — it needs the executable bit set (`chmod +x`) and
nothing else. The request arrives in CGI-style environment variables, the body
on stdin. Write an optional header block, a blank line, then your payload.

### Handler environment

| Variable | Description |
|---|---|
| `REQUEST_METHOD` | `GET`, `POST`, … |
| `REQUEST_URI` | Raw request target, query string included |
| `PATH_INFO` | Decoded, normalised path |
| `QUERY_STRING` | Everything after the first `?` |
| `CONTENT_TYPE` / `CONTENT_LENGTH` | Body metadata |
| `SERVER_PROTOCOL` | `HTTP/1.1` or `HTTP/1.0` |
| `REMOTE_ADDR` | Client address |
| `DOCUMENT_ROOT` | Value of `--static-dir` |
| `HTTP_*` | Every request header, uppercased, `-` → `_` |

Handlers on the exec path run under `env -i`, so they see exactly these
variables and nothing from the server's own environment.

### Two forms

**Script form** — the file writes a response when executed. Simple, works with
any language, but costs a fork *and* an exec *and* an interpreter start per
request.

**Function form** — the file defines `handle_request` and does nothing at top
level. Each worker loads it once and then calls the function: one cheap fork per
request, no exec. Worth **~1.7× the throughput and half the p99**.

The form is detected automatically. Anything that doesn't cleanly define
`handle_request` keeps the exec path, so existing handlers are unaffected.
Force the old behaviour with `--handler-mode exec`.

Two things to know about the function form:

- Code outside the function runs once per worker. That's the point — it's where
  config parsing, lookup tables and long-lived connections belong.
- `handle_request` runs in a subshell, so whatever it assigns is discarded when
  the request ends. A handler cannot leak state into the worker, corrupt the
  next request, or kill the worker by calling `exit`.

### Framing is not your problem

`Content-Length`, `Transfer-Encoding` and `Connection` headers emitted by a
handler are discarded and recomputed by the server. This is deliberate: a
handler that miscounts its own body would desynchronise a keep-alive connection
and turn every later request on it into a smuggling opportunity. Emit whatever
else you like — status, content type, cookies, cache headers.

---

## How concurrency works

Two independent layers, because they solve different problems.

**Connections** are handled by socat, which forks one process per connection and
caps the total at `--max-connections`. Each connection process owns its socket
for its whole lifetime, including every keep-alive request on it.

**Handlers** run in a pool of long-lived workers, sized by `--pool-size`.
Workers are forked once at startup and stay warm, which also bounds how many
handlers can run at once — backpressure a fork-per-request server doesn't have.

The interesting part is how a connection finds an idle worker with no scheduler
process in the middle:

```
                   ┌──────────────────────────────────────┐
                   │  tokens  (FIFO of one-byte tickets)  │
                   └──┬────────────────────────────┬──────┘
       claim one byte │                            │ worker returns its byte
                      ▼                            │   once the reply is out
   ┌───────────────────────┐    job record   ┌─────┴──────────┐
   │  connection process   │ ──────────────► │  worker N      │
   │  (forked by socat)    │                 │  (pre-forked)  │
   │                       │ ◄────────────── │                │
   └───────────────────────┘   reply on the  └────────────────┘
                               connection's
                               private FIFO
```

Idle workers are published as single-byte tokens on a shared FIFO. A connection
blocks reading exactly one byte; that byte identifies the worker it just
claimed, and the kernel guarantees only one reader gets it. The connection
writes the job to that worker's private request FIFO — one reader, so the
record can never be split — and blocks on its own reply FIFO.

The single-byte detail is load-bearing. Bash reads a pipe one byte at a time, so
several workers blocked on one shared queue would interleave bytes from the same
record and shred it. A one-byte read cannot be split, which is what makes the
whole arrangement work without locks.

**Tracing** is a third process, for the same reason. Connections never touch
the log file: they format a record into a single line and write it to a FIFO
that one dedicated `cat` drains into the file.

```
  connection ─┐
  connection ─┼──► trace FIFO ──► drain process ──► trace.ndjson
  connection ─┘    (one write        (sole writer)
                    per record)
```

Two properties fall out of that. Request handling never waits on disk. And
because a single process owns the file, records cannot interleave there — the
only ordering risk left is at the FIFO, which is why records are capped below
`PIPE_BUF` (4 KB), the size the kernel guarantees to write atomically. A record
that would exceed it is replaced by a short one flagged `"truncated":true`
rather than allowed to tear.

Failure modes are handled rather than hoped away:

- A worker returns its own token, so a client that disappears mid-request cannot
  shrink the pool.
- Reply FIFOs are opened read-write, which never blocks, so a vanished client
  cannot wedge a worker.
- A worker that hits an error still replies and still returns its token; it
  never dies and takes its slot with it.
- If no worker can be claimed within five seconds, the connection runs the
  handler itself. Saturation degrades, it never fails.

---

## Performance and tuning

`wrk -t4 -c16 -d6s`, keep-alive on, requests per second:

| scenario | macOS arm64 | Linux arm64 |
|---|---|---|
| static, text (27 B) | 1289 | 2220 |
| static, text, `--file-cache-seconds 5` | 6497 | 3931 |
| static, binary (4 KB) | 871 | 1767 |
| 404 (no filesystem access) | 8642 | 5302 |
| dynamic, function handler | 1980 | 1717 |
| static, tracing enabled | 1221 | 1801 |

And with keep-alive off, one connection per request:

| scenario | macOS arm64 | Linux arm64 |
|---|---|---|
| static, text | 293 | 555 |
| dynamic, function handler | 203 | 406 |

The `--file-cache-seconds` row is the best case for it: the same file, requested
repeatedly on one connection. A first page load fetching twenty different assets
sees almost none of that gain.

Host: M1, containers limited to `--cpus 4`. Reproduce with
[example 24](#24-benchmark-it).

Service time on a single warm connection, which strips out client and
concurrency effects:

| | macOS arm64 | Linux arm64 |
|---|---|---|
| 404 | 0.62 ms | 0.91 ms |
| static, text | 4.11 ms | 1.75 ms |
| dynamic, function handler | 2.61 ms | 2.49 ms |

### The one thing to understand

**Process spawns dominate everything.** A `fork` costs roughly 0.7 ms on macOS
and a `fork`+`exec` about 3 ms; Linux is several times cheaper at both. Every
number above follows from how many spawns a request needs:

| path | spawns per request |
|---|---|
| 404 | 0 |
| dynamic, function-form handler | 1 (the handler subshell) |
| static, text file | 1 (`stat`, for `ETag` and `Last-Modified`) |
| static, binary file | 2 (`stat` + `cat`) |
| dynamic, script-form handler | 2, plus a whole interpreter start |

Two consequences that surprise people:

- **Dynamic can outrun static.** A function-form handler needs no `stat`,
  because reading its reply also measures it. A static file still has to ask
  the filesystem for a modification time.
- **A binary file costs one spawn more than a text file of the same size.**
  Bash cannot hold a NUL byte in a variable, so anything containing one is
  streamed with `cat` rather than sent from memory. HTML, CSS, JS and JSON take
  the cheaper path.

Payload size barely matters by comparison — a 64 KB file and a 27 byte file
cost nearly the same.

### Tuning checklist

Roughly in order of how much they matter:

1. **Leave keep-alive on.** Turning it off costs a connection fork on every
   single request. This dwarfs every other setting here.
2. **Write handlers in the function form.** Defining `handle_request` removes
   an interpreter start per request. Worth ~5x on macOS, ~1.2x on Linux — so
   it matters far more if you develop or deploy on a Mac.
3. **Raise `--max-connections`** if clients are queuing. The default of 64 is
   conservative; connections are cheap once established, and each one is
   already capped by `--max-keepalive-requests`.
4. **Size `--pool-size` to your handler, not your traffic.** It bounds how many
   handlers run at once. Match it to what your handler contends for — a
   database, a lock, a rate limit — rather than setting it as high as it goes.
5. **Serve text where you can.** Pre-compressed assets, JSON over binary
   formats: they take the no-spawn path.
6. **Keep `--max-body-size` tight.** Request bodies are read through bash a
   byte at a time, so large uploads are genuinely slow. Response bodies of any
   size are fast; the asymmetry is real. If you need to accept large uploads,
   put them behind `--proxy-target`.
7. **Consider `--file-cache-seconds`** if you serve a fixed set of files. The
   one remaining process spawn on the static path is the `stat` that produces
   `ETag` and `Last-Modified`; caching it is worth roughly 5x on macOS and 1.8x
   on Linux for repeat requests to the same file over one connection. The trade
   is real and it is why this is off by default: a file rewritten inside the
   window is served with the previous validator, so a client can cache a stale
   copy for as long as your `Cache-Control` allows. Set it to a second or two,
   or leave it off if content changes underneath you.
8. **Turn tracing off when you do not need it.** It costs about 4% on macOS and
   19% on Linux — writing the log is off the request path, but building each
   JSON record is not.
9. **Terminate TLS elsewhere if you are latency-sensitive.** Plain HTTP hands
   the accepted socket straight to the server process; TLS cannot, so it costs
   an extra relaying process per connection on top of the handshake.

### Where the remaining cost is

The last spawn on the static path is the `stat` that produces `ETag` and
`Last-Modified`. Removing it would mean caching file metadata and accepting
that a file modified inside the cache window is served with a stale validator.
That is a trade rather than a free win, so the server does not make it for you.

If you need static files faster than this, the honest answer is a CDN or a
reverse proxy in front — which is where a server like this belongs anyway.

---

## Testing

```bash
./test/pentest.sh
```

Starts a throwaway server and attacks it. 135 checks; each names what it
expected and what it got, and the suite exits non-zero on any failure, so it
drops straight into CI. It writes its own handler fixtures, so it needs nothing
but `http-server.sh`.

It passes on macOS and inside Linux containers alike (checks that have nothing
to test against — the old-bash gate on a machine with only a current bash, TLS
without openssl — report themselves as skipped rather than passing quietly).

| Group | What it tries |
|---|---|
| Path traversal | `../`, percent-encoded, double-encoded, mixed-case, backslash variants |
| NUL & control bytes | Truncation attacks against dotfiles and the document root |
| Command injection | Shell metacharacters in paths and headers, with a canary file that appears if any is ever evaluated |
| Request smuggling | CL.TE, TE.CL, duplicate and conflicting framing headers, obfuscated `Transfer-Encoding`, obsolete line folding |
| Response splitting | CRLF injection through the query string and header values |
| Resource limits | Oversized request lines, header floods, oversized bodies, slowloris |
| Access control | Dotfiles, symlink escapes, `TRACE`, `CONNECT`, write methods |
| Conformance | Host handling, versions, absolute-form targets, `OPTIONS *`, `HEAD`, conditional GET, byte ranges, `100-continue` |
| Keep-alive | Pipelining and exact body consumption — the check that catches desynchronisation |
| Handler isolation | Framing headers stripped, load spread across workers, workers surviving between requests |
| Handler modes | Function-form handlers load once and keep their state; exec mode refuses a handler it cannot run |
| OWASP headers | The baseline is present, the version is not advertised, breaking policies are not imposed, errors carry a deny-all CSP |
| OWASP options | `--csp`, `--cross-origin-resource-policy`, `--server-tokens` and `--no-security-headers` all take effect; a newline in a policy is refused |
| Error disclosure | Clients get the status only; the reason reaches the log, including for malformed requests |
| Transport security | The TLS floor and HSTS are applied; a client capped below the floor cannot fetch |
| Resource limits | One address cannot take every connection slot, and slots are released |
| Metadata cache | A cached validator still refreshes after its window, and conditional requests still work |
| Tracing | Every request produces one valid JSON record with status, sizes and timing; a request with no `Referer` is still logged; enabling tracing does not swallow stderr |
| Trace integrity | 40 concurrent writers produce no torn record; the drain runs as a separate process and is reaped on shutdown |
| TLS | HTTPS serves content, cleartext to the TLS port leaks nothing |
| CLI | Every validation path and error message |
| socat gate | Outdated and unparseable versions are refused |

---

## Troubleshooting

**`bash 5.3 or newer is required, but this is bash 3.2.57`**
macOS bash. `brew install bash`, then run the script as
`/opt/homebrew/bin/bash http-server.sh …`.

**`socat is not installed, or not on PATH`**
Install it — the error message lists the command for your platform.

**`socat 1.8.0 or newer is required`**
Upgrade socat, or pass `--skip-socat-version-check` if your 1.7.x build is
known good.

**`this socat build was compiled without OpenSSL support`**
Your socat has no TLS. Reinstall a build with OpenSSL, or drop `--tls-cert`.

**Handler returns 502**
It exited non-zero and produced no output. Run it by hand:
`PATH_INFO=/api/health REQUEST_METHOD=GET ./handler.sh </dev/null`.

**Handler returns an empty 200**
It defines `handle_request` but was forced onto the exec path, or it writes
nothing. Drop `--handler-mode exec`.

**Connections hang or are refused under load**
You're at `--max-connections`. Raise it, and confirm keep-alive is on —
`--disable-keep-alive` burns a connection slot per request.

**Port already in use**
socat prints the bind error to stderr. Pick another port or free that one.

**I need to serve a site with inline scripts and the CSP breaks it**
No CSP is applied to content by default, precisely because it would. If you set
`--csp`, you own tuning it for your content.

**Scanners flag the server for disclosing its version**
It does not by default — `Server: bash-httpd` carries no version. If you see
one, something set `--server-tokens on`.

**Anyone can reach an endpoint I meant to protect**
There is no built-in authentication, authorisation or rate limiting. Add it in
a handler — see [basic auth](#25-http-basic-authentication) — or put the server
behind something that provides it. `--bind 127.0.0.1` restricts it to the local
machine, and [address filtering](#27-restrict-access-by-client-address) is a
coarse filter, not a security boundary.

**A file outside the document root is being served**
Symlinks inside the root are followed by default, matching nginx. Pass
`--deny-symlinks` to refuse symlinked files and files reached through
symlinked directories. Path traversal itself is always blocked; this is only
about links the document root deliberately contains.

**An uploaded file arrives corrupted, or a byte is missing**
Request bodies are read through bash, which cannot hold a NUL byte in a
variable, so NUL bytes are dropped from request bodies. Text uploads are fine;
binary ones are not. Use `--proxy-target` and let an upstream take the body.
Response bodies are unaffected — those are byte-exact, including binaries.

**Large uploads are slow**
Same cause: bash reads a socket a byte at a time, so request bodies scale
poorly. Responses of any size are fast. Keep `--max-body-size` tight and route
real uploads to an upstream.

**Connections pile up from a client that never finishes a request**
That is what `--header-timeout` and `--request-timeout` are for, and they are
on by default at 10s and 30s. Lower them if you are under pressure. Combine
with `--max-connections-per-ip` so one address cannot occupy many slots at once.

**`--proxy-target` refuses to start, complaining about curl**
curl 8.0.0 or newer is required on that path, because it handles responses from
the upstream. The error prints the install command for your platform. Nothing
else in the server needs curl, so the check only runs when `--proxy-target` is
set; `--skip-curl-version-check` bypasses it.

**Throughput is poor and clients open a new connection each time**
A connection costs a process. Keep-alive amortises that over many requests;
without it every request pays for one. Check the client is not sending
`Connection: close`, and that `--disable-keep-alive` is not set.

**HTTPS is slower than HTTP for the same file**
Beyond the handshake, TLS also costs an extra process per connection: socat has
to stay in the data path to run the session, so it cannot hand the socket
straight to the server the way it does for plain HTTP. Terminate TLS at a
reverse proxy if that matters.

---

## License

Apache License 2.0. See [LICENSE](LICENSE).
