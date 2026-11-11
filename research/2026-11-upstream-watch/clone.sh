#!/bin/sh
# Sparse, shallow clones of the three C/C++ package indexes into .cache/ (only the files indexes.py reads).
set -eu
cd "$(dirname "$0")" && mkdir -p .cache && cd .cache
clone() {
  repo=$1 dir=$2; shift 2
  [ -d "$dir" ] || git clone -q --depth 1 --filter=blob:none --no-checkout "https://github.com/$repo.git" "$dir"
  git -C "$dir" sparse-checkout init --no-cone
  printf '%s\n' "$@" > "$dir/.git/info/sparse-checkout"
  git -C "$dir" checkout -q
  echo "$dir $(git -C "$dir" rev-parse --short HEAD) $(git -C "$dir" log -1 --format=%cs)"
}
clone microsoft/vcpkg vcpkg '/ports/*/portfile.cmake' '/ports/*/vcpkg.json' '/versions/baseline.json'
clone bazelbuild/bazel-central-registry bcr '/modules/*/metadata.json' '/modules/*/*/source.json'
clone conan-io/conan-center-index cci '/recipes/*/*/conandata.yml' '/recipes/*/config.yml'
