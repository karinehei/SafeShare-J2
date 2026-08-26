#!/bin/sh
# Install official J2 0.1.0 (macOS Apple Silicon) from GitHub Releases.
#
# Source of truth (do not substitute an unofficial URL):
#   https://j2-lang.org/download.html
#   https://github.com/JasnamSinghArora/j2/releases/tag/v0.1.0
#
# Asset: j2-0.1.0-aarch64-apple-darwin.tar.gz
# SHA-256: 6fda8338791730cf7937362acd03e29247719e65785458e62988e1789c842e75
#
# The bundled ./install.sh is from that tarball after the checksum passes.
# This script does not curl | sh an installer from a raw gist.

set -eu

if [ "$(uname -s)" != "Darwin" ] || [ "$(uname -m)" != "arm64" ]; then
    echo "J2 0.1.0 is published only for macOS on Apple Silicon (aarch64-apple-darwin)." >&2
    echo "This runner is $(uname -s)/$(uname -m)." >&2
    exit 1
fi

J2_TAG="v0.1.0"
J2_ASSET="j2-0.1.0-aarch64-apple-darwin.tar.gz"
J2_SHA256="6fda8338791730cf7937362acd03e29247719e65785458e62988e1789c842e75"
J2_URL="https://github.com/JasnamSinghArora/j2/releases/download/${J2_TAG}/${J2_ASSET}"

WORKDIR="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/j2-install"
PREFIX="${J2_PREFIX:-${HOME}/.j2}"
BINDIR="${J2_BINDIR:-${HOME}/.local/bin}"

mkdir -p "$WORKDIR" "$BINDIR"
cd "$WORKDIR"

echo "Downloading ${J2_URL}"
curl -fsSL -o "$J2_ASSET" "$J2_URL"

actual=$(shasum -a 256 "$J2_ASSET" | awk '{print $1}')
if [ "$actual" != "$J2_SHA256" ]; then
    echo "SHA-256 mismatch for ${J2_ASSET}" >&2
    echo "expected: ${J2_SHA256}" >&2
    echo "actual:   ${actual}" >&2
    exit 1
fi

tar xzf "$J2_ASSET"
cd j2-0.1.0-aarch64-apple-darwin

# Documented overrides: J2_PREFIX and J2_BINDIR (j2-lang.org/download.html).
J2_PREFIX="$PREFIX" J2_BINDIR="$BINDIR" ./install.sh

if [ ! -x "${BINDIR}/j2" ]; then
    echo "install.sh did not place an executable j2 at ${BINDIR}/j2" >&2
    exit 1
fi

if [ -n "${GITHUB_PATH:-}" ]; then
    echo "$BINDIR" >> "$GITHUB_PATH"
fi

echo "J2 installed to ${PREFIX}; command at ${BINDIR}/j2"
