#!/usr/bin/env bash
set -euo pipefail

lane_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cache_root=${V17_BCHN_ASSAY_CACHE:-"${lane_root}/.local/bchn-v29-assay"}
mkdir -p -- "$cache_root"
cache_root=$(cd -- "$cache_root" && pwd)
source_archive="${cache_root}/bitcoin-cash-node-v29.0.0.tar.gz"
source_root="${cache_root}/bitcoin-cash-node-29.0.0"
build_root="${cache_root}/build"
cmake_archive="${cache_root}/cmake-4.1.2-linux-x86_64.tar.gz"
cmake_root="${cache_root}/cmake-4.1.2-linux-x86_64"
boost_archive="${cache_root}/boost-1.91.0-2-x86_64.pkg.tar.zst"
boost_root="${cache_root}/boost-1.91.0-2"

bchn_url=https://github.com/bitcoin-cash-node/bitcoin-cash-node/archive/refs/tags/v29.0.0.tar.gz
bchn_sha256=0dbc86a416e376a4b3813004e7aa493d7a4473467f32a5f5909a7408a4a3b2e4
cmake_url=https://github.com/Kitware/CMake/releases/download/v4.1.2/cmake-4.1.2-linux-x86_64.tar.gz
cmake_sha256=773cc679c3a7395413bd096523f8e5d6c39f8718af4e12eb4e4195f72f35e4ab
boost_url=https://archive.archlinux.org/packages/b/boost/boost-1.91.0-2-x86_64.pkg.tar.zst
boost_sha256=58a6ba3b464ff63993829684251c3adf72f71374da1f3151b2033471de08322a

verify_sha256() {
  local expected=$1
  local file=$2
  printf '%s  %s\n' "$expected" "$file" | sha256sum --check --status
}

download_once() {
  local url=$1
  local expected=$2
  local destination=$3
  if [[ -f "$destination" ]]; then
    if ! verify_sha256 "$expected" "$destination"; then
      printf 'refusing mismatched cached archive: %s\n' "$destination" >&2
      exit 1
    fi
    return
  fi
  local partial="${destination}.partial"
  curl --fail --location --show-error --silent "$url" --output "$partial"
  if ! verify_sha256 "$expected" "$partial"; then
    printf 'downloaded archive failed SHA-256 verification: %s\n' "$url" >&2
    exit 1
  fi
  mv -- "$partial" "$destination"
}

download_once "$bchn_url" "$bchn_sha256" "$source_archive"
if [[ ! -d "$source_root" ]]; then
  tar -xzf "$source_archive" -C "$cache_root" \
    --exclude='bitcoin-cash-node-29.0.0/src/test/data/vmb_tests' \
    --exclude='bitcoin-cash-node-29.0.0/src/bench/data'
fi

# Refuse a modified extracted engine. The archive pin authenticates the whole
# download; these checks protect the runtime semantic seam across cached runs.
verify_sha256 aa6b6f2d98d0227da543d0217debc0b7e17fba3338f0c63dfe9e08eface90776 "${source_root}/src/script/interpreter.cpp"
verify_sha256 d21f220750d2209c5298bc45d63a4b2b220e0c1d3e76e9bf8cf5065d1f88fab8 "${source_root}/src/script/script_metrics.h"
verify_sha256 6aa86ab30bfcb94523c87c6e7c9de0ffe71ffa9b312f5120d51b2bdf24f40ad5 "${source_root}/src/script/vm_limits.h"
verify_sha256 d256c7396ce6303247c4cec4e85c07e2a483f8ef11a9ca2fafbde17090271df8 "${source_root}/src/script/script_flags.h"
verify_sha256 a4b0778268aa7d881f078a1fb513e134c5b696dc0bd7842baaa26df5d0036f26 "${source_root}/src/script/script_execution_context.cpp"
verify_sha256 08697beb9b46ce2b1c8ddf792ae94aae0178c73f66dfb3ee2d50a84b6dbd6475 "${source_root}/src/script/script_execution_context.h"
verify_sha256 948927425735b08472a2b819b2a7ba601256ce2891dd7714f50da0b77de671f9 "${source_root}/src/primitives/transaction.cpp"
verify_sha256 20fc50c36c58a8bcc93ca0c5b40b6f96b541e7a3593f87a3b70b8a0752d690fb "${source_root}/src/primitives/token.cpp"
verify_sha256 c5e807c612ec53d88cd76fdf401c548cfbbb198b179d0d44ebb5c3565bd662ca "${source_root}/src/consensus/consensus.h"

if command -v cmake >/dev/null 2>&1; then
  cmake_bin=$(command -v cmake)
else
  if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
    printf 'cmake >= 3.19 is required on non-Linux-x86_64 hosts\n' >&2
    exit 1
  fi
  download_once "$cmake_url" "$cmake_sha256" "$cmake_archive"
  if [[ ! -x "${cmake_root}/bin/cmake" ]]; then
    tar -xzf "$cmake_archive" -C "$cache_root"
  fi
  cmake_bin="${cmake_root}/bin/cmake"
fi

boost_include=/usr/include
if [[ ! -f "${boost_include}/boost/version.hpp" ]]; then
  if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
    printf 'Boost >= 1.73 development headers are required\n' >&2
    exit 1
  fi
  download_once "$boost_url" "$boost_sha256" "$boost_archive"
  if [[ ! -f "${boost_root}/usr/include/boost/version.hpp" ]]; then
    mkdir -p -- "$boost_root"
    tar --extract --zstd --file "$boost_archive" --directory "$boost_root"
  fi
  boost_include="${boost_root}/usr/include"
fi

boost_library_dir=${V17_BCHN_BOOST_LIBRARY_DIR:-/usr/lib}
if [[ ! -e "${boost_library_dir}/libboost_chrono.so" || \
      ! -e "${boost_library_dir}/libboost_filesystem.so" ]]; then
  printf 'Boost chrono/filesystem libraries are required (set V17_BCHN_BOOST_LIBRARY_DIR)\n' >&2
  exit 1
fi
# BCHN configures a small nested native build for secp256k1's gen_context.
# Environment hints reach both that configure and the outer configure; a
# cache-only -DBoost_INCLUDE_DIR would not reach the nested build.
export BOOST_INCLUDEDIR="$boost_include"
export BOOST_LIBRARYDIR="$boost_library_dir"

"$cmake_bin" -Wno-dev -S "$source_root" -B "$build_root" \
  -DCMAKE_BUILD_TYPE=Release \
  -DBoost_INCLUDE_DIR="$boost_include" \
  -DCMAKE_PROJECT_INCLUDE="${lane_root}/tools/bchn-v29-assay/inject.cmake" \
  -DV17_BCHN_ASSAY_SOURCE="${lane_root}/tools/bchn-v29-assay/bchn_v29_assay.cpp" \
  -DBUILD_BITCOIN_DAEMON=OFF \
  -DBUILD_BITCOIN_WALLET=OFF \
  -DBUILD_BITCOIN_ZMQ=OFF \
  -DBUILD_BITCOIN_CLI=OFF \
  -DBUILD_BITCOIN_TX=OFF \
  -DBUILD_BITCOIN_QT=OFF \
  -DBUILD_BITCOIN_SEEDER=OFF \
  -DBUILD_LIBBITCOINCONSENSUS=OFF \
  -DENABLE_TEST=OFF \
  -DENABLE_DBUS_NOTIFICATIONS=OFF \
  -DENABLE_QRCODE=OFF \
  -DENABLE_UPNP=OFF \
  -DENABLE_NATPMP=OFF

# The first native configure can leave a CMakeCache without a generated
# Makefile if a prerequisite was unavailable. Re-run the generated native
# configure deterministically; this is cheap and makes the cache self-healing.
touch "${build_root}/config/run_native_cmake.sh"

"$cmake_bin" --build "$build_root" --target v17-bchn-v29-assay \
  --parallel "${V17_BCHN_ASSAY_JOBS:-4}"

touch "${cache_root}/built.stamp"
printf '%s\n' "${build_root}/bin/v17-bchn-v29-assay"
