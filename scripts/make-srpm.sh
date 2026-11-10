#!/usr/bin/env bash
# 一键打 exvia SRPM：git archive 出源码 → rpmbuild -bs。
# 用法：bash scripts/make-srpm.sh        （需干净工作树；源码 tar 取自 HEAD；产物路径在最后输出）
# 可选：RPM_TOPDIR=/path 覆盖 rpmbuild 顶层目录（默认 ~/rpmbuild）。
#
# 不带 vendor：构建期经 crates.io（或镜像）在线解析依赖，--locked 钉住
# Cargo.lock。地板工具链见 Cargo.toml 的 rust-version（msrv-1.82 分支为 1.82）。
set -euo pipefail
cd "$(dirname "$0")/.."

command -v rpmbuild >/dev/null 2>&1 || { echo "错误：缺 rpmbuild（dnf install rpm-build）"; exit 1; }
command -v cargo >/dev/null 2>&1 || { echo "错误：缺 cargo（dnf install cargo）"; exit 1; }
[[ -z $(git status --porcelain) ]] || { echo "错误：工作树不干净（tar 取自 HEAD），先提交"; exit 1; }

V="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
TARBALL="exvia-$V.tar.gz"
TOP="${RPM_TOPDIR:-$HOME/rpmbuild}"

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
git archive --prefix="exvia-$V/" HEAD | tar -x -C "$STAGE"

mkdir -p "$TOP/SOURCES" "$TOP/SPECS"
tar -czf "$TOP/SOURCES/$TARBALL" -C "$STAGE" "exvia-$V"
cp exvia.spec "$TOP/SPECS/"
rpmbuild -bs --define "_topdir $TOP" "$TOP/SPECS/exvia.spec"
