#!/usr/bin/env bash
set -euo pipefail

uname="$1"
nkey="$2"

curl --silent "https://github.com/${uname}.keys" |
    sed -n "${nkey}p" |
    ssh-keygen -f /dev/stdin -e -m PKCS8 |
    openssl pkeyutl -encrypt -pubin -inkey /dev/stdin -in <(echo "$*") -out /dev/stdout |
    base64
