#!/usr/bin/env bash
# Classical certificate chains for C1 (mutual TLS: CA -> server cert + client cert).
#   certs/make_classical_certs.sh               # ecdsa-p256 (default)
#   certs/make_classical_certs.sh rsa2048
# Output: certs/out/<alg>/{ca.pem,ca.key,server.pem,server.key,client.pem,client.key}
# PQ chains (Dilithium) for C2 use the same file layout: certs/out/dilithium3/... (Jose's script).
set -euo pipefail
ALG=${1:-ecdsa-p256}
OUT="$(cd "$(dirname "$0")" && pwd)/out/$ALG"
mkdir -p "$OUT"; cd "$OUT"
case $ALG in
  ecdsa-p256) newkey() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; } ;;
  rsa2048)    newkey() { openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1" 2>/dev/null; } ;;
  *) echo "unknown alg $ALG (ecdsa-p256 | rsa2048)"; exit 2 ;;
esac
DAYS=365
newkey ca.key
openssl req -x509 -new -key ca.key -sha256 -days $DAYS -subj "/CN=CPS Modbus Test CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca.pem
for who in server client; do
  newkey $who.key
  openssl req -new -key $who.key -subj "/CN=modbus-$who" -out $who.csr
  if [ $who = server ]; then
    ext="subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth"
  else
    ext="extendedKeyUsage=clientAuth"
  fi
  openssl x509 -req -in $who.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days $DAYS -sha256 \
    -extfile <(printf "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\n$ext\n") -out $who.pem 2>/dev/null
  rm $who.csr
done
rm -f ca.srl
echo "certs in $OUT:"; for f in ca.pem server.pem client.pem; do printf "  %-11s %5d bytes (DER %d)\n" $f $(wc -c <$f) $(openssl x509 -in $f -outform DER | wc -c); done
