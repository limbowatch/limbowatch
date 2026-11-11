# Upstream-watch: C/C++ dependencies and advisories without a package (November 2026)

Phase 6, step 0 (FINDINGS [F-135](../../docs/FINDINGS.md#f-135), [F-136](../../docs/FINDINGS.md#f-136), question Q26). Measurements only, no product code.

| Script | Question | Output |
|---|---|---|
| `clone.sh` | sparse, shallow clones of microsoft/vcpkg, bazel-central-registry and conan-center-index | `.cache/` |
| `indexes.py` | which upstream repo each vcpkg port, BCR module and conan-center recipe builds from | `.cache/indexes.json` |
| `libraries.py` | which limbo advisories without a package are about those libraries, and whether their patched versions are tags upstream (`git ls-remote`, no API quota) | `libraries.json` |
| `survey.py` | how 85 C/C++ projects take in dependencies, and what the watcher could know about each | `survey.json` |

Run from the repo root, in order: `research/2026-11-upstream-watch/clone.sh`, then `uv run research/2026-11-upstream-watch/<script>.py`. `survey.py` needs an authenticated `gh` for the search; the token is never printed.

## Results (2026-11-10/11)

**Package indexes.** 2,437 of 2,917 vcpkg ports, 1,284 of 1,400 BCR modules and 1,641 of 1,977 conan-center recipes name an upstream forge repo: 3,661 repos, 3,620 on GitHub.

**Limbo advisories without a package that are about libraries.** 1,472 of the feed's 14,785 package-less records (10%) come from 95 repos that one of the indexes builds from: FreeRDP 338, ImageMagick 116, libheif 90, vim 82, OpenEXR 73, bacnet-stack 60, Fast DDS 36, git 32, Exiv2 32, libyang 31.

**Their fixes as tags.** For 1,207 of the 1,472 every patched version is a tag (1,663 patched versions exactly, as `1.2.3` or `v1.2.3`; 284 by the numbers in the tag, as in `bacnet-stack-1.6.0` or `release-22.1.8`); for 102 some are; 83 have none; 68 give no patched version; 12 repos have no tags. The misses include ImageMagick 6 fixes (released from ImageMagick/ImageMagick6), `0.27.5 RC1` against the tag `v0.27.5-RC1`, and patched "versions" that are commit hashes.

**How projects take in dependencies** (25 most-starred C++ repos, 25 most-starred C repos, 35 random repos with 200-2,000 stars pushed in 2026):

| Method | Projects | Dependencies | Upstream and version/commit known |
|---|---:|---:|---:|
| vendored copy (license file under `third_party/` etc.) | 22 | 153 | 0 (version unknown) |
| CMake FetchContent | 17 | 75 | 35 |
| git submodule | 17 | 300 | 296 (commit) |
| CMake ExternalProject | 13 | 58 | 5 |
| `vcpkg.json` | 5 | 114 | 41 (through the port; version needs the baseline) |
| `MODULE.bazel` | 5 | 163 | 158 (through BCR) |
| Bazel `http_archive` (also wrappers) | 4 | 325 | 182 |
| CPM, meson wraps | 3 | 13 | 1 |

44 of the 85 projects declare no dependencies in these forms (the Linux kernel, FFmpeg, nginx, stb, imgui use system libraries or none). 14 of the 85 depend on an upstream that has records in the limbo feed (protobuf, fmt, gRPC, c-ares, xz, libpng, harfbuzz, nghttp2, PCRE2, cpp-httplib, capstone, …).

**Checking a commit against a fix.** A commits-only clone (`git clone --bare --filter=tree:0`) is 0.4 MB (zlib) to 22 MB (gRPC) and takes under 3 s; `git merge-base --is-ancestor <fix tag> <commit>` then answers exactly, with no API quota and on any host. GitHub's compare API answers the same (`behind`, `ahead`, `identical`; base the fix tag) at one request per pair. OSV's `/v1/query` and `/v1/querybatch` accept `{"commit": …}`: zlib at v1.2.11 returns 6 CVEs, at v1.3.1 4.

Data: vcpkg (MIT), bazel-central-registry (Apache-2.0) and conan-center-index (MIT) build files; advisory facts from the limbo feed and GitHub (CC BY 4.0); project files from public GitHub repos, read for counting only.
