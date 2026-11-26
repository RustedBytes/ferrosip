#!/usr/bin/env bash
# Test PKI for local TLS runs, all signed by one CA:
#   server.pem    127.0.0.1 / localhost — server *and* client auth (proxy, mTLS)
#   b.test.pem    DNS:b.test            — second identity for SNI selection tests
#   other.test.pem DNS:other.test       — wrong name, for hostname-verification tests
#   hss.ims.test.pem DNS:hss.ims.test   — the HSS of the IMS scenario (Diameter over TLS)
# Usage: etc/tls/gen-certs.sh [outdir]   (default: etc/tls; created if missing)
set -euo pipefail

die() { echo "gen-certs.sh: $*" >&2; exit 2; }
case "${1:-}" in
  -h | --help) sed -n '2,7s/^# \{0,1\}//p' "$0"; exit 0 ;;
esac
command -v openssl >/dev/null || die "openssl not found"
d=${1:-$(dirname "$0")}
mkdir -p "$d"
cd "$d"

# openssl prints progress on stderr: keep it quiet, but show it on failure.
ossl() {
  local err
  err=$(openssl "$@" 2>&1 >/dev/null) || die "openssl $1 failed:"$'\n'"$err"
}

ossl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
  -keyout ca.key.pem -out ca.pem -subj "/CN=ferrosip test CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash"

issue() { # name cn san
  ossl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$1.key.pem" -out "$1.csr" -subj "/CN=$2"
  ossl x509 -req -in "$1.csr" -CA ca.pem -CAkey ca.key.pem -CAcreateserial -days 365 \
    -extfile <(printf "%s\n" "subjectAltName=$3" "extendedKeyUsage=serverAuth,clientAuth" \
      "keyUsage=critical,digitalSignature" "basicConstraints=critical,CA:FALSE" \
      "subjectKeyIdentifier=hash" "authorityKeyIdentifier=keyid,issuer") \
    -out "$1.pem"
  rm -f "$1.csr"
}
issue server localhost "IP:127.0.0.1,DNS:localhost"
issue b.test b.test "DNS:b.test"
issue other.test other.test "DNS:other.test"
issue hss.ims.test hss.ims.test "DNS:hss.ims.test"
rm -f ca.srl
echo "wrote $(pwd)/{ca,server,b.test,other.test,hss.ims.test}.pem (+ .key.pem)"
