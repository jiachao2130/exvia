# Copyright (c) 2026 Jia Chao
# exvia is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

# exvia 构建脚本。
# check  : cargo fmt --check && cargo clippy -D warnings && cargo test --locked
# msrv   : 用地板工具链（见 Cargo.toml rust-version）做编译级检查
# e2e    : 端到端回归（release 二进制 + 独立端口/目录）
# srpm   : 一键打 RPM 源码包（scripts/make-srpm.sh，产物 srpm 路径见脚本输出）
# ci     : 门禁合集 = check + msrv（push 前过一遍）

VERSION ?= $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)

.PHONY: check msrv e2e srpm ci

check:
	cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace --locked

msrv:
	cargo +$$(sed -n 's/^rust-version = "\(.*\)"/\1/p' Cargo.toml | head -1) check --workspace --locked

e2e:
	cargo build --release && ./scripts/e2e.sh

srpm:
	bash scripts/make-srpm.sh

ci: check msrv
	@echo "=> ci gate passed"
