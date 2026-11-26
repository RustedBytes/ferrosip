#!/usr/bin/env bash
# Build Kamailio from its GitHub sources for the benchmark (bench/kamailio/run.sh).
#
#   bench/kamailio/build.sh                 # KAMAILIO_VERSION=6.1.5 into target/kamailio-6.1.5
#   KAMAILIO_VERSION=6.1.4 bench/kamailio/build.sh
#
# Builds the core and Kamailio's default module set (none need external
# libraries; the benchmark loads tm, sl, usrloc and registrar) with the
# flags of Kamailio's own Makefile (-O2) and MEMDBG=0: a plain source build
# turns on memory debugging (DBG_SR_MEMORY, DBG_*_MALLOC: file/line kept
# for every allocation), which made stateless replies ~3x slower on a
# GitHub runner. Production builds use MEMDBG=0. The memory manager (TLSF)
# is chosen at run time with -x/-X. Needs gcc, make, bison, flex; ~80 s on
# 4 vCPUs.
# Prints the install prefix; run.sh takes it as KAMAILIO_PREFIX.
set -euo pipefail
cd "$(dirname "$0")/../.."
VER=${KAMAILIO_VERSION:-6.1.5}
PREFIX=$(realpath -m "${KAMAILIO_PREFIX:-target/kamailio-$VER}")
SRC=$(realpath -m "target/kamailio-src-$VER")

built() { [ -x "$PREFIX/sbin/kamailio" ] && "$PREFIX/sbin/kamailio" -V | grep -q "kamailio $VER " && ! "$PREFIX/sbin/kamailio" -V | grep -q DBG_SR_MEMORY; }
if built; then
  echo "$PREFIX"   # already built
  exit 0
fi
if [ ! -d "$SRC/.git" ]; then
  rm -rf "$SRC"
  git clone -q --depth 1 --branch "$VER" https://github.com/kamailio/kamailio.git "$SRC" >&2
fi
J=$(nproc)
make -C "$SRC" -s cfg PREFIX="$PREFIX" MEMDBG=0 >&2
make -C "$SRC" -s -j"$J" all >&2
make -C "$SRC" -s install >&2
"$PREFIX/sbin/kamailio" -V | head -2 >&2
built || { echo "build check failed (version or memory debugging)" >&2; exit 1; }
echo "$PREFIX"
