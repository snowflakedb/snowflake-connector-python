#!/bin/bash

# GPG setup script for creating unique GPG home directory

setup_gpg_home() {
  # Create unique GPG home directory
  export GNUPGHOME="${THIS_DIR}/.gnupg_$$_$(date +%s%N)_${BUILD_NUMBER:-}"
  mkdir -p "$GNUPGHOME"
  chmod 700 "$GNUPGHOME"

  cleanup_gpg() {
    if [[ -n "$GNUPGHOME" && -d "$GNUPGHOME" ]]; then
      rm -rf "$GNUPGHOME"
    fi
  }
  trap cleanup_gpg EXIT
}

setup_gpg_home
