#!/bin/sh
# Disposable synthetic keys only; the destination must be an empty test directory.
set -eu
test "$#" -eq 1
test -d "$1"
test -z "$(find "$1" -mindepth 1 -maxdepth 1 -print -quit)"
cd "$1"
umask 077
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 2 \
  -subj /CN=h454-test-root -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign,cRLSign >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout trusted.key -out trusted.csr \
  -subj /CN=brc-agent.internal >/dev/null 2>&1
printf 'subjectAltName=DNS:brc-agent.internal\nextendedKeyUsage=serverAuth\n' > trusted.ext
openssl x509 -req -in trusted.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out trusted.crt -days 1 -extfile trusted.ext >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout wrong.key -out wrong.csr \
  -subj /CN=wrong.invalid >/dev/null 2>&1
printf 'subjectAltName=DNS:wrong.invalid\nextendedKeyUsage=serverAuth\n' > wrong.ext
openssl x509 -req -in wrong.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out wrong.crt -days 1 -extfile wrong.ext >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -keyout fake.key -out fake.crt -days 1 \
  -subj /CN=brc-agent.internal -addext subjectAltName=DNS:brc-agent.internal \
  -addext basicConstraints=critical,CA:TRUE >/dev/null 2>&1
cp ca.crt relay-ca.pem
chmod 644 ca.crt relay-ca.pem trusted.key trusted.crt wrong.key wrong.crt fake.key fake.crt
printf 'SYNTHETIC_CERTIFICATES=PASS\n'
