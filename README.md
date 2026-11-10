# exvia

自托管的远程运维工具。被管机无需公网地址、无需开放任何入站端口，由常驻程序向中继建立出站连接，即可获得终端、文件传输与端口转发能力，使用方式与 ssh 对齐。Rust 实现，一个仓库产出三个二进制，共享同一协议库。

exvia 由三个组件组成：

- **exvia-relay** —— 公网中继：登记在线机器、撮合会话、转发加密流量。按不可信组件设计，可部署于不完全受信的环境。
- **exvia-agent** —— 被管机常驻程序：仅发起出站连接，本机不监听任何端口；提供交互终端、文件传输与端口转发服务。
- **exvia** —— 操作者命令行客户端：日常运维入口，负责签发会话票据。

## 安全设计

- **端到端加密**：会话内容由 Noise 协议（XX 模式，X25519 + ChaCha20-Poly1305）在 agent 与 CLI 之间加密，中继只搬运密文，读不到任何会话明文。
- **授权不依赖中继**：每条会话由 CLI 用长期 ed25519 私钥签发一次性票据（绑定机器标识、会话号、对端公钥、有效期、随机数），中继只能原样透传；agent 依据 enroll 时固化在本机的可信 CLI 公钥白名单独立验签，白名单之外的签名一律拒绝。
- **三处指纹固定**：中继证书指纹（注册/登录时带外核对）、会话对端公钥指纹（首连记录，变更即拒绝）、机器标识即身份公钥指纹。全部不依赖第三方 CA，中间人会在任一处暴露。

## 易用性

- 命令与 ssh 习惯对齐：`exec` / `shell` / `put` / `get` / `forward -L -R`，支持多机批量执行与分发。
- 被管机 enroll 一次后常驻在线，断线按指数退避自动重连，无需人工干预。
- 滚动升级窗口内新旧版本可混跑（minor 相差不超过 1），升级不必停全量。
- `exvia-agent install` 直接输出可落盘的 systemd unit；机器别名、TOFU 台账、shell 补全（bash/zsh/fish）等本地便利机制齐备。

## 功能

- 反向注册：一次性令牌 enroll，ed25519 挑战签名认证，断线指数退避重连（1s→60s±20%）。
- 交互终端：真 PTY（vim/htop/resize 正常），退出码透传。
- 命令执行：stdout/stderr 分通道、`--timeout <秒>` 超时 kill（CLI 侧另有僵死逃生口）、退出码透传；直接执行 argv 不经远端 shell，管道/组合命令显式 `sh -c`；`exec -t` 强制命令走远端 PTY（ssh -t 语义，单机，退出码与超时语义不变）。
- 文件传输：60000B 分块 + SHA-256 校验 + ACK 流控 + 临时文件原子落盘；单文件支持 `--resume` 断点续传（分片记在目标旁边，按内容哈希区分，收尾仍以整文件 SHA-256 为准）。`put` 自动遍历目录源（`-r` 仅为兼容保留）、`get -r` 递归整棵树，均一次会话传完：保留权限位与 mtime、还原空目录、不跟随符号链接、丢弃 setuid/setgid，接收端独立校验路径不越界。put 支持多源与通配符（`put box1 '*.log' dist/`，大文件传输 stderr 显示进度）；`get` 支持远端尾分量通配（`get box1 'logs/*.log' out/`，agent 匹配后落本地目录，无匹配报错）。
- TCP 转发：`-L 本地端口:目标:端口` 多并发，`-L/-R` 均可重复（一条命令多条隧道，全部绑定成功才进入转发）；`-R [绑定地址:]端口:目标:端口` 反向（ssh -R 语义，默认绑 127.0.0.1）。
- 批量执行：`exvia exec m1,m2,m3 -- cmd` 逗号分隔多机并发，输出带机器前缀，逐机回报退出码；`put m1,m2 ...` 同一组源并发分发到每台（逐机汇总，任一失败整体非零）。
- 用户与授权：admin 令牌 + 用户名/密码（argon2id）；用户↔机器授权表，会话级鉴权。
- 会话治理：`exvia sessions` 列出在线会话（admin 看全量，普通用户只看自己的），`exvia close <sid>` 终止；CLI 掉线时桥接自动取消。
- 白名单运行期扩容：`exvia trust list|add|rm <machine> [公钥]` 经 Trust 会话让 agent 改写本地白名单（0600、tmp+fsync+rename 原子落盘），从白名单内 CLI 发起，无需重新 enroll；拒绝删除最后一把钥匙（否则没人能再进去），上限 64。
- 可观测性：独立指标端点，默认关闭；`--metrics-listen` 开启后提供 Prometheus 文本格式 `/metrics` 与 `/healthz`；只允许绑定回环地址（非回环直接启动失败，远程查看走 ssh 隧道），`--metrics-token` 为可选加固（常数时间比较）。
- 审计：中继记录会话（用户/机器/类型/字节数/时长），`exvia-relay audit` 查询；`exvia-relay export --format csv|jsonl [--since --until --user --machine --limit --out]` 导出（时间接受 epoch 秒或 `YYYY-MM-DD`）；保留期默认 90 天可配，每日自动清理 + WAL checkpoint。
- 机器引用：`exvia ls` 会把 machine_id→主机名落盘为本地缓存，之后命令可直接用主机名或 machine_id 前缀（歧义一律报错，不猜）。
- 分组：机器标签，`exvia ls --tag <tag>`。
- 机器别名：本机 `exvia alias add <名字> <machine_id>`，之后所有命令可用短名；`exvia ls` 显示 ALIAS 列。
- CLI 侧台账与补全：`exvia known add/list/rm` 管理对端公钥 TOFU 台账——`add` 用 agent enroll 输出里给出的现成命令在首连前预置公钥（首连改为核对预置值，不再信任中继介绍），`rm` 重置对某台机器的信任（不再需要手删文件）；`exvia completion bash|zsh|fish` 输出静态补全脚本。
- 服务化：systemd unit（`exvia-agent install`），开机自启、崩溃拉起。
- 凭证生命周期：自签证书默认有效期 3650 天（`--cert-validity-days`，仅作用于新证书），到期前 30 天启动告警；管理员令牌超过 365 天提示轮换。两者都不强制过期——自托管单点半夜失效等于把人锁在门外，判断权留给运维。
- 版本协同：三个二进制均支持 `--version`；中继与 agent 允许相邻小版本共存（N 与 N-1 互通，不兼容时给出明确升级提示），滚动升级不会一刀切断线。

## 快速上手

```sh
# 0. 每一台操作者机器先生成长期 CLI 身份，并取得公钥（每台不同）
exvia pubkey                       # 输出 ed25519 公钥，写入 cli-identity.json (0600)
#     注意：CLI 身份长期固定；换机器/重装后把新公钥补进 agent 白名单（优先由白名单内 CLI 执行 `trust add` 在线扩容，无需重新 enroll）

# 1. 中继（公网 VPS）—— 证书 CN/SAN 与 WS 路径部署可配置，三端必须一致
exvia-relay serve --listen 0.0.0.0:8443 --data-dir /var/lib/exvia-relay \
    --cert-name cdn.example.com --ws-prefix /api/v2/sync
#   首次启动打印 证书指纹 与 管理员令牌（亦存于 data-dir/admin-token.txt）

# 2. 被管机 —— --trusted-cli-key 可重复；不配 = 拒绝所有会话（fail-closed）
exvia-relay token create --data-dir /var/lib/exvia-relay      # 签发一次性令牌
exvia-agent enroll --server wss://<中继地址>:8443 \
    --token <令牌> --fingerprint <证书指纹> \
    --ws-prefix /api/v2/sync \
    --trusted-cli-key <CLI_A 公钥> --trusted-cli-key <CLI_B 公钥>
exvia-agent install --identity /var/lib/exvia-agent/identity.json | sudo tee /etc/systemd/system/exvia-agent.service
sudo systemctl enable --now exvia-agent

# 3. 操作者 —— 登录令牌/密码可用 `-` 交互输入或 EXVIA_TOKEN / EXVIA_PASSWORD 环境变量
exvia login --server wss://<中继地址>:8443 --token <管理员令牌> --fingerprint <指纹> \
    --ws-prefix /api/v2/sync
exvia ls                                        # 复制完整 machine_id
exvia alias add box1 <machine_id>               # 配好别名后不必再输 32 位长串
exvia shell box1                                # 交互 PTY（vim/htop/resize 正常）
exvia exec box1 -- uname -a
exvia exec -t box1 -- vim /etc/hosts           # 强制 PTY（ssh -t 语义，单机）
exvia exec box1,box2 -- uname -r               # 逗号分隔多机并发批量执行
exvia put box1 <本地> <远端>
exvia put box1 '*.log' dist/                   # 多源/通配符（目录目标走树协议）
exvia put box1,box2 firmware.bin dist/         # 多机分发：同一组源并发传到每台，逐机汇总
exvia get box1 'logs/*.log' out/               # 远端尾分量通配：agent 匹配，结果落 out/
exvia put box1 --resume <本地> <远端>           # 断线后接着传，不从头再来
exvia forward -L 8222:localhost:22 box1         # 之后 ssh -p 8222 即达目标机 sshd
exvia forward -R 9000:127.0.0.1:80 box1         # 物料下发：目标机访问其 9000 端口即达操作者侧 80 端口的服务
```

用户与授权：

```sh
exvia-relay user add --username bob --password ... --role user
exvia-relay auth grant --username bob --machine-id <machine_id>
exvia-relay audit
exvia login --server ... --user bob --password ... --fingerprint ...
```

新操作者机器的完整接入步骤（CLI 身份 → 被管机信任 → 中继授权 → 登录）见运维手册的[「新增一台操作者机器」](docs/operations.md)一节。

会话与白名单：

```sh
exvia sessions                     # SID / MACHINE_ID / USER / KIND / AGE（普通用户只看自己）
exvia close <sid>                  # 立刻终止该会话，桥接随即取消
exvia trust list box1              # 查看 agent 当前信任的 CLI 公钥
exvia trust add box1 "$(exvia pubkey)"   # 新机器加入，无需重新 enroll
exvia trust rm  box1 <旧公钥>       # 撤销（最后一把会被拒绝删除）
```

## 构建

```sh
cargo build --release          # 当前平台，产出三个二进制（exvia / exvia-agent / exvia-relay）
scripts/e2e.sh                 # 一键端到端回归（53 项，独立端口/目录，不碰现有配置）
```

RPM 源码包：`make srpm`（产物在 `dist/`，含 spec；构建依赖见 spec 的 BuildRequires）。

## 发布

推送 `v*` tag 自动触发发布流水线：x86_64 / aarch64 / loongarch64 三个架构的
静态 musl 构建（无 glibc 依赖，任意同架构 Linux 直接运行）→ RPM 三件套 +
src.rpm + 裸二进制 tar.gz，汇入同一个 GitHub Release。x86_64 与 aarch64 在
原生 runner 上跑全量单测与 53 项 e2e 回归；loongarch64 为交叉构建，附
qemu 冒烟。日常门禁（fmt/clippy/单测，stable + 最低工具链双腿）见
`.github/workflows/ci.yml`。

## 文档

- [需求说明书](docs/requirements.md)
- [概要设计说明书](docs/design.md)（威胁模型、安全与不可探测性）
- [运维手册](docs/operations.md)（部署、日常管理、升级、故障排查）
- [变更记录](CHANGELOG.md)

## 安全边界

- 本工具用于管理员对自有或已获明确授权的机器运维；部署前提是对目标机与中继具有管理权限。
- 隐蔽性指流量层面（加密、标准协议外形、可在部署期配置的证书 CN/SAN 与 WS 路径）；出口处"存在一条到中继的加密长连接"无法隐藏。默认路径 `/_exvia` 与默认证书名 `localhost` 只用于开发环境，生产必须三端一致地改掉，否则 TLS 扫描与路径探测仍能识别出服务类型。
- agent 的 `--trusted-cli-key` 白名单是会话授权的最终依据；它随 enroll 固化在身份文件里，中继无法改写。新增操作者可用白名单内的既有 CLI 执行 `exvia trust add` 在线扩容（受信方才能改受信方，中继无参与权），其余情况需重新 enroll。
- 主机层隐藏（进程/文件隐藏、对抗 EDR）明确不做。

## 许可

[MulanPSL-2.0](LICENSE)（木兰宽松许可证，第 2 版）。不引入 GPL/AGPL 代码；RustDesk/frp 等仅借鉴协议设计。
