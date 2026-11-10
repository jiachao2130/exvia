# exvia 运维手册

三个组件的部署、日常管理与故障排查。设计与安全模型见[概要设计](design.md)，本文只讲"怎么跑起来、怎么管、坏了怎么查"。

## 角色与网络要求

| 组件 | 跑在哪 | 网络要求 |
|---|---|---|
| exvia-relay | 公网 VPS（可以完全不可信） | 入站放行一个 TCP 端口（默认 8443） |
| exvia-agent | 被管机 | 出站能达中继那一个端口即可（TLS 长连接），不开任何入站 |
| exvia（CLI） | 操作者本机 | 出站能达中继即可 |

agent 与 CLI 之间不直连：所有流量经中继搬运，且端到端加密（Noise XX），中继读不到会话内容。被管机不需要公网地址、不需要开端口，这是本工具能在受限网络工作的前提。

## 部署中继

```sh
./exvia-relay serve --listen 0.0.0.0:8443 --data-dir /var/lib/exvia-relay \
    --cert-name cdn.example.com --ws-prefix /api/v2/sync
```

首次启动自动生成自签证书并打印两样东西：证书指纹（SHA-256，发给所有 agent 和 CLI 用于固定）和管理员令牌（同时落盘 `admin-token.txt`，权限 600）。注意默认 `--listen 127.0.0.1:8443` 只监听本机，公网部署必须显式指定 `0.0.0.0`。

生产部署要改两项：`--cert-name` 决定自签证书的 CN/SAN，`--ws-prefix` 决定两个 WS 路由（`<prefix>/agent`、`<prefix>/cli`）。默认值 `localhost` / `/_exvia` 是开发默认值，固定值可被 TLS 扫描与路径探测直接识别。三端（relay / agent enroll / CLI login）必须使用完全一致的前缀；改前缀后所有 agent 需重新 enroll（前缀固化在身份文件里）。

systemd 单元参考（`exvia-relay` 无 install 子命令，手写一份即可）：

```ini
[Unit]
Description=exvia relay
After=network-online.target

[Service]
ExecStart=/usr/local/bin/exvia-relay serve --listen 0.0.0.0:8443 --data-dir /var/lib/exvia-relay --cert-name cdn.example.com --ws-prefix /api/v2/sync
Restart=always
RestartSec=5
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

数据目录内容：`relay.db`（机器/用户/授权/会话/审计）、`relay-cert.pem`、`relay-key.pem`（私钥，务必 600）、`relay-cert.json`（证书元数据：CN 与到期时间）、`admin-token.txt`。备份即备份整个目录；热备可用 `sqlite3 relay.db ".backup backup.db"`。审计默认保留 90 天（`--audit-retention-days` 可调，0 表示不清理），每日自动清理过期行并做 WAL checkpoint。

### 证书有效期与轮换

新生成的证书默认有效期 **3650 天**（`--cert-validity-days` 可改，最小 1 天）。这个参数只作用于**新生成**的证书：已有 `relay-cert.pem` 不会因为改参数被重建——否则每次调参都静默换指纹，把所有客户端踢下线。到期时间记在 `relay-cert.json`，中继启动时若剩余不足 30 天或已过期会打 warn。

**续期**（必然换指纹，必然要重新固定）：

```sh
# 1. 停中继，备份，删掉证书与私钥（元数据文件可留作记录）
systemctl stop exvia-relay
cp -a /var/lib/exvia-relay /var/lib/exvia-relay.bak
rm /var/lib/exvia-relay/relay-cert.pem /var/lib/exvia-relay/relay-key.pem
# 2. 起中继，记下新指纹
systemctl start exvia-relay && journalctl -u exvia-relay -n 20 | grep -i fingerprint
# 3. 每台 agent 用新指纹重新 enroll；每台 CLI 重新 login
```

没有"不停机换证书"的路径：TLS 用固定指纹而不是 CA 链，新旧两张证书不可能同时被同一份配置接受。这不影响会话安全（内层 Noise 与 ed25519 票据才是身份根基，TLS 只是第一道门），但它是**运维动作**，请排进维护窗口。

顺带说明一个刻意的取舍：证书**过期后指纹固定仍然通过**（自写验证器只比对指纹，不校验 notAfter）。这样证书过期不会在某个凌晨把整个集群锁在门外，代价是"过期"本身不构成强制轮换。可观测性由启动告警和 `relay-cert.json` 提供，判断权留给运维。

### 管理员令牌轮换

`admin-token.txt` 里的令牌**不会自动过期**（自托管单点，半夜失效等于把人锁在门外）。偏移量记在库里，超过 365 天启动时打 warn：

```sh
exvia-relay token rotate-admin --data-dir /var/lib/exvia-relay   # 立即作废旧令牌，打印新的
```

轮换后所有用旧令牌登录的 CLI 会话不受影响（会话令牌是独立的 7 天凭据），但重新 `login` 必须用新令牌。

## 部署被管机（agent）

流程如下：中继签发一次性令牌 → agent 注册 → 装成系统服务。

```sh
# 1. 在中继上（或用中继的数据目录副本）签发令牌，用后即废
exvia-relay token create --data-dir /var/lib/exvia-relay --label "web-1"

# 2. 先拿到每台操作者机器的 CLI 公钥（在各自机器上执行 exvia pubkey）
#    CLI 身份长期固定在 cli-identity.json（0600），重装/换机后公钥会变

# 3. 在被管机上注册（指纹来自中继首次启动的输出）
exvia-agent enroll --server wss://relay.example.com:8443 \
    --token <令牌> --fingerprint <证书指纹> --ws-prefix /api/v2/sync \
    --trusted-cli-key <CLI_A 的 ed25519 公钥> \
    --trusted-cli-key <CLI_B 的 ed25519 公钥>
#    --trusted-cli-key 可重复；身份默认落盘 /var/lib/exvia-agent/identity.json（0600），--identity 可改
#    不配任何白名单 = fail-closed，agent 会拒绝一切会话邀请（enroll 时打印警告）
#
#    enroll 成功的输出里含本机 machine_id 与 Noise 静态公钥（x25519_b64），并附一条
#    可直接复制的预置命令：exvia known add <machine_id> <x25519_pub>
#    在首连前的操作者 CLI 上执行它即完成预置锚定——之后首连核对的是预置值，
#    不再信任中继的介绍（TOFU 首连窗口被带外关闭，详见下面 known 一节）

# 4. 装 systemd 服务（install 输出可直接落盘的完整 unit：ExecStart 绑定 --identity
#    绝对路径、User= 取执行 install 的当前用户；相对路径会按当前目录转绝对）
exvia-agent install --identity /var/lib/exvia-agent/identity.json | sudo tee /etc/systemd/system/exvia-agent.service
sudo systemctl enable --now exvia-agent
```

unit 加固刻意保守：只保留 `NoNewPrivileges=true`，不加 `PrivateTmp` / `ProtectHome` / `ProtectSystem`——文件传输要写真实路径（含 `/home` 下的任意目标目录），文件系统视图隔离会让 `put`/`get` 写不进部署目标，全路径运维能力优先。

运行期行为：断线指数退避重连（1s→60s，带抖动）；每 30s 心跳，中继 90s 判死；证书指纹不符会直接拒绝连接（防中间人）。

重装 / 换身份：直接对已注册的机器重新 enroll 会被拒绝，这是为了防止身份被冒领顶替。正确顺序：

```sh
exvia-relay machine del <machine_id>   # 中继删除机器及授权关系（审计历史保留）
rm /var/lib/exvia-agent/identity.json  # agent 端清掉旧身份
exvia-agent enroll ...                 # 重新注册（别忘了重新带上全部 --trusted-cli-key）
```

新增操作者 / 轮换 CLI 身份：白名单随 enroll 固化在 agent 身份文件里，中继无权改写。两条路：

1. **运行期扩容（推荐，不用重装）**——在白名单内的既有 CLI 上执行：

```sh
exvia trust list <machine>                 # 当前受信的 CLI 公钥
exvia trust add <machine> "$(exvia pubkey)" # 把新机器的公钥加进去，立即生效
exvia trust rm  <machine> <旧公钥>          # 撤销；拒绝删除最后一把钥匙（删完就没人进得去了）
```

   Trust 会话由 CLI 发起、agent 本地执行：写 `trusted-cli.json`（0600，tmp + fsync + rename 原子落盘，重启后仍生效），不重启 agent、不经中继授权。上限 64 把。撤销某人后他再开会话会被 agent 验签拒绝（`signer not in trusted cli allowlist`）。

2. **重新 enroll**——适用于钥匙全丢、或要顺带换 agent 身份：`machine del <machine_id>` → 删 `identity.json` → `enroll`（别忘带全部 `--trusted-cli-key`）。

只改 `client.json` 或只在 relay 上授权是不生效的：信任锚在被管机本地，这是设计选择。

> **信任是传递的，这一点必须心里有数。** 任何一把已在白名单里的钥匙都能 `trust add` 新钥匙——没有"审批人"这一层。好处是扩容不需要重启 agent、不需要碰中继；代价是**一把钥匙泄露 = 攻击者可以给自己登记一把长期有效的钥匙**，而且在你发现之前他不会走。`trust rm` 撤销后对方的下一次会话即被验签拒绝，但没有任何机制能阻止他在撤销前先加一把自己的。
>
> 因此：CLI 私钥（`cli-identity.json`）按"能登所有机器的通行证"来保管。一旦怀疑泄露，处置顺序是
>
> 1. **先撤**：从每台机器的白名单里 `trust rm` 掉那把公钥（拿不到 CLI 就用第三台机器加进去，或到机器上直接编辑 `trusted-cli.json`）。
> 2. **再核**：`exvia trust list <machine>` 逐台过一遍，确认没有多出来的钥匙；agent 日志里搜 `allowlist action=add`，看有没有你没做过的操作（日志带 `key=<前12字符>` 便于比对）。
> 3. **换身份**：`exvia logout` 后删掉 `cli-identity.json` 重新生成，新公钥重新登记。
> 4. **如果连中继也怀疑**：`exvia-relay token rotate-admin`、给所有用户改密码（`exvia-relay user passwd`），并检查 `exvia-relay audit` 里的 `denied/*` 与异常来源。
>
> 另外，agent 日志里的 `claimed_user=` 是 **CLI 在票据里自报**的用户名：该字段在签名覆盖范围内，中继改不了；但 agent 只证明"这把白名单钥匙报了这名"，不证明名字对应哪个人（它不认识 CLI 那边的用户体系）。授权依据始终是 ed25519 签名，排查时不要拿这个字段当实名证据。

## 操作者（CLI）

```sh
# 管理员：令牌登录；普通用户：用户名/密码
exvia pubkey                           # 首次生成/查看长期 CLI 身份，交给 agent enroll
exvia login --server wss://relay.example.com:8443 --token <管理员令牌> --fingerprint <指纹> \
    --ws-prefix /api/v2/sync
exvia login --server ... --user bob --password ... --fingerprint <指纹> --ws-prefix /api/v2/sync
```

`--token` / `--password` 支持三种给法：直接给值、给 `-` 走交互隐藏输入、或留空读 `EXVIA_TOKEN` / `EXVIA_PASSWORD` 环境变量，避免凭证进 shell history 和进程列表。

登录与接入的公网加固（中继侧固定上限，无需配置）：连续密码错误按用户名分桶递增延迟（60s 窗口内第 n 次失败延迟 n 秒、封顶 5s），且查无此人的用户名也付同价 argon2 校验（响应时间不透存在性）；未认证连接每 IP 最多 16 条、全局 128 条，超限直接 429 不升级 WS（agent 认证后即释放配额，常驻连接不受影响）；WS 控制消息单帧上限 1MB（控制面都是小 JSON，审计导出走 relay 本地子命令不经 WS）。

机器别名（省掉 32 位 machine_id）：`exvia alias add <名字> <完整 machine_id>` 把映射写进本机 `aliases.json`（0600，纯本地、离线可用、不需要登录），之后所有带机器参数的命令（`exec` / `shell` / `ping` / `put` / `get` / `forward`）都能直接写名字，`exvia ls` 会多一列 `ALIAS` 显示已配置的名字。管理命令：`exvia alias list` / `exvia alias rm <名字>`。

```sh
exvia alias add web-1 3b07c2d94e1a8f6b4c5d90e2f8a1b6c0
exvia exec web-1 -- uname -a
exvia alias rm web-1
```

解析顺序是本地别名精确匹配 → 完整 machine_id → 本机机器缓存（`machines.json`）里的 ID 唯一前缀 / 主机名（大小写不敏感）→ 别名表内 ID 的唯一前缀 → 报错；未知名字会直接失败并列出已知机器，不会把名字当 ID 发给中继后报一句含糊的"机器不在线"。缓存由每次 `exvia ls` 自动落盘（Linux `~/.config/exvia/machines.json`，macOS `~/Library/Application Support/exvia/machines.json`，纯 id→主机名映射、无密钥），所以 `exvia exec box1 -- ...` 直接写主机名也可以。解析命中时静默使用结果，不再向 stderr 回显映射；需要核对别名指向时用 `exvia alias list`。歧义一律报错、不猜。别名表只存 machine_id、不含任何密钥；`--encrypt` 加密配置时也不受影响。别名指向的是机器身份：agent 重装导致 machine_id 变化后需重新 `alias add`（缓存会在下次 `ls` 时自动刷新）。

登录后落盘的内容（Linux `~/.config/exvia/`，macOS `~/Library/Application Support/exvia/`，均 0600）：`cli-identity.json`（长期 ed25519/x25519 身份，签发会话票据用）、`client.json`（中继地址、指纹、WS 前缀、会话令牌）和 `known_agents.json`（见过的对端机器公钥）。明文密码不落盘——用户名/密码登录只保存中继签发的会话令牌（7 天有效，过期重新 login 即可）。

> 私钥千万别外发：`cli-identity.json` 与 agent 的 `identity.json` 里 `ed_seed_b64` / `x25519_b64` 存的都是私钥，名字里没有 `priv` 是历史命名。给 agent 配白名单只能用 `exvia pubkey` 输出的 ed25519 公钥；把身份文件里的 `x25519_b64` 当公钥贴进 `--trusted-cli-key` 不会生效，还会泄露私钥。`cli-identity.json` 是 CLI 身份的单一真相源，`client.json` 里的同名字段只是历史冗余副本；升级或只拷贝 `client.json` 时会自动迁移对齐，不用手工改。

默认配置明文落盘（靠 0600 权限保护）。若担心磁盘被窃取，登录时加 `--encrypt`：会话令牌与 CLI 私钥会用口令加密（argon2id 派生密钥 + AES-256-GCM）封进 `client.json` 的 `sealed` 字段。代价是之后每条命令都要输一次配置口令；口令没有找回机制，忘了只能重新 `exvia login`（不加 `--encrypt` 即回到明文配置）。`server`/`fingerprint` 保持明文，便于诊断。

CLI 与目标 agent 之间同样固定公钥（TOFU）：首次会话记住对端公钥，之后不符即拒绝。用 `exvia known list` 查看台账、`exvia known rm <别名或id>` 重置对某台机器的信任（仅在确认目标机重装过身份时才这么做）。

预置锚（推荐）：TOFU 的首连窗口本要靠"信任中继的介绍"记账，这一步可以带外关闭——agent `enroll` 成功的输出里带一条现成的 `exvia known add <machine_id> <x25519_pub>`，在首连前的 CLI 上原样执行它，即把对端公钥预置进 `known_agents.json`（0600，纯本地）。之后首连核对的是预置值，不符即拒；预置值与既有 TOFU 记录相同时幂等（提示 `already anchored`），不同则拒绝并提示先 `known rm`，绝不静默覆盖。

常用命令：

```sh
exvia ls [--tag prod]                 # 在线列表（普通用户只看被授权的机器）
exvia ping <machine_id>               # 连通性与 RTT
exvia shell <machine_id>              # 交互终端（真 PTY）
exvia exec <machine_id> -- <命令...>  # 执行命令，退出码透传
exvia exec -t <machine_id> -- <命令...>  # 命令进远端 PTY（ssh -t 语义；单机）
exvia exec m1,m2,m3 -- <命令...>      # 批量执行（逗号分隔多机，并发；输出带 [机器] 前缀，末尾逐机 rc）
exvia put <machine_id> <本地> <远端>   # 上传（SHA-256 校验 + 临时文件原子落盘）
exvia put <machine_id> <本地目录>/*.log <远端目录>/  # 多源/通配符上传（不引号由 shell 展开；引号则 CLI 展开，仅支持 * 与 ?）
exvia put m1,m2 <本地...> <远端>      # 多机分发（同一组源并发传到每台；输出带 [机器] 前缀，逐机汇总）
exvia get <machine_id> <远端> <本地>   # 下载（同样校验；>1MiB 时 stderr 显示进度）
exvia get <machine_id> '远端目录/*.log' <本地目录>/  # 远端尾分量通配（agent 匹配，结果落本地目录）
exvia put --resume <machine_id> <本地> <远端>  # 断点续传（复用上次中断留下的分片）
exvia get --resume <machine_id> <远端> <本地>  # 断点续传（下载方向）
exvia put <machine_id> <本地目录>/ <远端目录>/  # 传整棵树（put 的目录源自动递归，无需 -r）
exvia get -r <machine_id> <远端目录> <本地目录>  # 递归下载整棵树（get 需显式 -r）

# 路径写法约定（与交互 shell 的 cwd 约定一致）：
#   远端相对路径与 ~/ 都以 agent 运行用户的家目录为基准，如
#   exvia get worktop Downloads/f.rpm ./        # 取 worktop 家目录下的文件
#   exvia put worktop f.rpm ~/                 # 传进家目录
# get 的本地目标是目录（已存在或以 / 结尾）时自动补上远端文件名；
# put 的远端目标以 / 结尾时视为目录，自动补上本地文件名（scp 习惯）
exvia forward -L 8222:localhost:22 <machine_id>
#    之后本机 ssh -p 8222 即达目标机的 sshd；Ctrl-C 退出
#    -L/-R 均可重复（-L a -L b 一条命令多条隧道；全部绑定成功才进入转发）
exvia forward -R [绑定地址:]绑定端口:目标地址:目标端口 <machine_id>
#    反向转发（ssh -R 语义）：被管机上有人连这个端口时，流量经隧道回到操作者
#    机器，由 CLI 拨向目标。典型用途：物料下发——目标机 `curl 127.0.0.1:9000`
#    即取到操作者侧仓库/制品服务。Ctrl-C 退出并解除被管机侧监听。
#
#    安全默认：绑定地址缺省 127.0.0.1。绑非环回地址（如 0.0.0.0）会把操作者侧
#    服务暴露给被管机所在局域网，确有需要请显式指定；被管机只能打到 CLI 指定
#    的这一个目标端点，拿不到隧道之外的任何访问能力。
exvia known list                      # 本机记录的对端机器公钥（TOFU 台账，纯本地）
exvia known add <别名或id> <x25519公钥b64>  # 首连前预置对端公钥（现成命令在 agent enroll 输出里）
exvia known rm <别名或id>             # 删除一条记录（重置对那台机器的 TOFU 信任）
exvia completion bash|zsh|fish        # 输出 shell 补全脚本（静态，子命令一级）
```

`exec` 直接执行 argv，不经远端 shell：`exvia exec box -- 'a && b'` 会把整串当成一个程序名报 `cannot start`。要管道、`&&`、通配展开、重定向，显式走 `exvia exec box -- sh -c 'a && b'`；交互登录 shell 用 `exvia shell`。

`put` 的 `-r` 是兼容旧脚本的空操作（目录源本来就会自动递归，多源可混文件与目录）；`get` 传目录则必须显式 `-r`。

`-L` 转发不在会话列表里：它没有常驻中继会话，每条过路连接才产生一个短暂的 `Tcpfwd` 会话，转发生命周期由本地 `exvia forward` 进程持有，用 Ctrl-C 结束（`exvia close` 管不到它）。`-R` 相反，有一个常驻会话，列表里显示为 `TcpfwdReverse`，可以被 `exvia close` 终止。

目录整树传输（put 遇目录源自动触发，get 需显式 `-r`）与 `scp -r` / `rsync -a` 的差异，值得先看一眼再上手：

- **整棵树走一次会话**，不是每文件一次握手；清单在端到端加密通道内传输，中继看不到路径。
- **保留权限位（低 9 位）与 mtime**，空目录也会被还原（包括挖在中间的空目录）。
- **不继承 setuid/setgid/sticky**。跨机器复制一个 setuid 程序等于把对端的提权路径搬过来，这一位默认丢弃。
- **符号链接不跟随、也不传输**（避免逃逸与目录环）；fifo/socket/设备文件跳过。跳过了多少会在结束时提示 `note: skipped N symlink(s)...`，别以为传全了。
- **接收端做路径校验，不信任发送端**：拒绝 `..`、绝对路径、盘符前缀；每一级祖先和目标自身都不允许是符号链接（防止目标机预先放一个 `sub -> /etc` 让写入穿出去）。
- 中断会留下部分已完成的文件（每个文件都是先写临时文件再原子改名，不会出现半截文件）；整树传输不支持断点续传，重跑即覆盖。单文件的 `--resume` 见下一节。
- 传输完整性靠 Noise AEAD 逐块校验，不再逐文件算 SHA-256（大目录下省一遍读盘）。
- **整树传输需要两端同版本**。滚动升级期间若 CLI 已是新版、目标 agent 还是旧版，`put` 目录会以"对端不认识该控制帧"失败（不会静默写坏）；等 agent 升上来再用，或先用 `tar` + 单文件 `put` 过渡。

### 断点续传（单文件）

```sh
exvia put --resume <machine_id> <本地> <远端>
exvia get --resume <machine_id> <远端> <本地>
```

- 中断后重跑同一命令**加上 `--resume`** 即从断点继续；不加就清空重来。`--resume` 只对单文件有效：与 `-r` 同用、或多源/目录源同用都会直接报错拒绝，不会静默忽略。
- 断点记在目标旁边的分片文件里：上传侧 `<远端名>.exvia-part-<内容 SHA-256 前 16 位>`，下载侧 `<本地名>.exvia-part`。分片名带内容哈希（上传侧），换了内容就不会误用上一次的半截文件。
- 续传会先重读一遍已有前缀来续算整文件 SHA-256（摘要状态没法落盘），大文件会多花一次顺序读的时间，但仍远少于重传。
- 两边对不上时自己回退，不拼内容：进程被硬杀可能在分片尾部留下半个分块，这时先丢掉一个分块再续；本地分片根本不是这份文件的前缀（内容换过），就整段丢弃从头传。`--resume` 因此可以无脑重跑。
- 收尾仍以整文件 SHA-256 为准：拼接错了就在最后失败并丢弃分片，**不会**留下"看起来传完了"的文件。下载侧只有校验通过才把分片改名成正式文件。
- 成功的传输会顺手清掉同一目标遗留的陈旧分片；要手工清理就是 `rm <目标>.exvia-part*`。
- 与 `-r` 一样需要两端同版本：对端是旧版时 `--resume` 会在 10 秒后报 `timed out waiting for resume handshake`，去掉 `--resume` 重跑即可。

### exec -t、远端通配与多机分发

```sh
exvia exec -t <machine_id> -- <命令...>             # 命令进远端 PTY（ssh -t 语义）
exvia get <machine_id> '远端目录/*.log' <本地目录>/  # 远端尾分量通配（引号防 shell 展开）
exvia put m1,m2 <本地...> <远端>                    # 同一组源并发分发到多台
```

- `exec -t`（对标 `ssh -t`）：跑的是指定命令而非登录 shell，但 CRLF、TERM、窗口 resize 语义与 `shell` 一致（全屏程序也能跑）；命令退出码透传，`--timeout` 语义不变（到点杀掉命令回 124）。本地 stdin 是 tty 时自动进 raw mode，管道输入照常可用；PTY 的 `\r\n` 输出原样透传。PTY 语义只对单机有意义，与多目标组合会明确报错。**需要两端同版本**：旧版 agent 会忽略这条请求，退化成开一个登录 shell（不执行命令）——滚动升级期间注意。
- `get` 远端通配：远端路径的最后一个分量可以是 `*` / `?`，由 agent 在父目录内匹配（与 put 侧本地展开同一套语义：不匹配点开头的隐藏文件、不跨目录层级），匹配结果按既有树下载路径回传、落进本地目录；无匹配明确报错、非零退出。字面路径（不含通配符）行为不变。旧版 agent 不认识该请求，会对原始串做目录扫描而报 "cannot read"——失败可见，不会静默整目录下载。
- put 多机分发：`m1,m2` 把同一组源并发传到每台机器（每机独立 put 会话，复用既有传输引擎），输出行带 `[机器] ` 前缀，末尾逐机汇总（`m1: ok` / `m2: failed: ...`），任一失败整体退出码 1；单机写法行为不变。`shell` 刻意不做多机：交互终端共用一个本地 tty 的语义是混乱的（输出交错、Ctrl-C 广播），确有需要就开多个终端。

## 新增一台操作者机器

一台全新的笔记本/工作站要接入环境，按下述顺序完成身份、信任、授权三件事，最后登录：

1. 新机器上 `exvia pubkey` 生成 CLI 身份，记下输出的 ed25519 公钥。
2. **被管机侧**信任这把公钥：由已在某台被管机白名单内的既有 CLI 执行 `exvia trust add <machine> "<新公钥>"`（立即生效，不重启 agent）。
3. **中继侧**建账号并授权：`exvia-relay user add --username <U> --password ... --role user`（已有账号跳过），`exvia-relay auth grant --username <U> --machine-id <ID>`（admin 账号可跳过授权这步）。
4. 新机器 `exvia login ...` 登录即可使用。

缺一步的典型症状，便于对号入座：只做了 1 和 2 缺 3——`exvia ls` 只有表头（普通用户只列被授权的机器，授权为空时不打印任何提示行）；只做了 1 和 3 缺 2——ls 能看到机器，但会话被拒 `signer not in trusted cli allowlist`。授权（grant/revoke）即时生效，客户端无需重新登录。

## 日常管理

```sh
exvia-relay token create|list|revoke <ID>    # 注册令牌：签发 / 查看 / 作废
exvia-relay token rotate-admin               # 轮换管理员令牌（旧的立即作废）
exvia-relay user add|list|del                # 用户管理（argon2id 存储密码）
exvia-relay user passwd --username U --password 新密码   # 改密（旧会话全部吊销，授权关系保留）
exvia-relay user logout --username U         # 吊销某用户全部会话令牌（强制重新登录）
exvia logout                                 # CLI 登出：吊销中继侧会话 + 清空本地令牌（身份密钥保留）
exvia-relay auth grant|revoke|list           # 用户↔机器授权（grant/revoke 即时生效，客户端无需重新登录）
exvia-relay machine tag <id> lab,web         # 打标签
exvia-relay machine del <id>                 # 删除机器（见上文重装流程）
exvia-relay audit [--limit 50]               # 审计
```

审计字段：时间、用户、机器、会话类型、字节数、时长。字节方向约定：UP = agent→CLI（命令输出、文件下载），DOWN = CLI→agent（命令输入、文件上传）。登录失败、未授权会话也会记录（`denied/login`、`denied/<类型>`）。

连续输错密码有递增延迟惩罚（60 秒滑动窗口内逐次加秒，上限 5 秒，按"该用户名"和"全局"两个桶取最大值——换用户名绕不过去），暴力破解在审计里一目了然。**被拒绝的登录会明确回 `invalid credentials`**，不会让客户端干等到超时（这条路径曾经会因为"发完就断连"丢掉拒绝帧，排障时别把"超时"当成网络问题）。

### 会话治理

```sh
exvia sessions        # SID / MACHINE_ID / USER / KIND / AGE（admin 看全量，普通用户只看自己的）
exvia close <sid>     # 立即终止该会话，桥接随即取消，agent 侧子进程随连接关闭而退出
```

`KIND` 取值：`Exec` / `Pty` / `File` / `Tcpfwd` / `TcpfwdReverse` / `Trust` / `Echo`（`exvia ping` 会话活跃时出现）。CLI 进程崩溃或被 Ctrl-C 时，中继侧桥接会自动取消，不会留下悬挂会话。

### 审计导出

```sh
exvia-relay export --data-dir /var/lib/exvia-relay --format csv  --out /tmp/audit.csv
exvia-relay export --data-dir /var/lib/exvia-relay --format jsonl --since 2026-01-01 --until 2026-02-01 \
    --user bob --machine <machine_id> --limit 5000
```

时间参数接受 epoch 秒或 `YYYY-MM-DD`（UTC，含当天 00:00:00 起）。`--since/--until` 可单用可组合，结果按时间升序；不给 `--out` 就打到 stdout，可直接管道给分析脚本。CSV 字段：`ts,iso,user,machine,kind,bytes_up,bytes_down,duration_ms`。

### 指标端点（可选，默认关闭）

```sh
exvia-relay serve ... --metrics-listen 127.0.0.1:9101
```

独立端口、独立监听器，与业务端口分开，不给外部探测多一条路径。`GET /metrics` 返回 Prometheus 文本格式，`GET /healthz` 返回 `ok`。指标：`exvia_up`、`exvia_uptime_seconds`、`exvia_machines_online`、`exvia_sessions_active`、`exvia_sessions_pending`、`exvia_reverse_streams`、`exvia_build_info{version}`。**只允许绑定回环地址**，绑定非回环地址直接启动失败（fail-closed，不允许把内部状态暴露到任何非回环面）；远程查看走 ssh 隧道。`--metrics-token` 是回环之上的可选加固，带 token 时用 `Authorization: Bearer <token>` 且为常数时间比较。指标端口被占等绑定失败同样拒绝启动，不允许静默降级为无指标运行。

## 升级

版本兼容按**窗口**判定（`exvia_proto::version_compatible`，三端共用一份实现）：major 必须相同，minor 相差不超过 1，且双方都不低于 `0.1`（`MIN_COMPAT_MINOR`）。也就是 `0.1` 与 `0.2` 可以混跑；0.1 是首个对外发布，窗口下限就定在这儿，将来协议真的不兼容了再抬这个常量并写进变更说明。patch 号不参与判定。agent 的 Hello、CLI 的 Login 都上报实时版本，中继据此拒绝不兼容端并给出"对端比本地老/新"的提示；`Kick` 带机器可读的 `KickCode`（takeover / version / reconnect / unknown），不靠 reason 文案匹配。旧端不带 `code` 字段时 agent 按文案兜底。

混跑窗口的意义是滚动升级不必一刀切：先升级 relay（旧 agent/CLI 仍在窗口内，不掉线），再逐台升 agent、最后升 CLI。跨窗口才需要停机，且只需在跨窗口的那一步停；跨窗口时所有 agent 要用 `--trusted-cli-key` 重新 enroll。

三个二进制都支持 `--version`，升级前先核对三端实际版本，比翻日志快。

relay 收到 SIGTERM（`systemctl stop/restart`）会优雅收尾：停止接入新连接、通知在线 agent 断开重连、等在途会话收尾（上限 10 秒，超时强走）再做 WAL checkpoint，退出码 0。`systemctl restart` 时不会硬砍在途传输，在途会话被礼貌切断，agent 会自动重连回来。协议里有 `Logout` 控制消息；旧版中继不识别该消息时 `exvia logout` 会报错、吊销不生效，升级时一并替换中继。

反向转发 `-R` 要求三端都是含此功能的版本：旧版中继收到 `-R` 的 CreateSession 会回 `消息解析失败: unknown variant \`tcpfwd_reverse\``，命令干净失败，不影响 `-L` 等既有功能；旧版 agent 收到 TcpfwdReverse 会话则在该会话内失败、连接不受影响。另一条只在异常场景可达的路径：若 agent 向旧版中继发出 `reverse_open`（要求 -R 会话已建立，正常操作不会发生），中继会因消息无法识别断开该 agent 连接（旧中继对 agent 侧不可解析消息一律断开，新中继则忽略），agent 走自动重连。

```sh
make srpm                     # 一键生成 RPM 源码包（产物在 dist/）
# 或手工：cargo build --release 后替换三端二进制，重启 exvia-agent / exvia-relay 服务
```

## 容量参考（本机回环实测，非跨公网实测）

以下数字来自真实二进制在本机拉起 1 个中继 + 12 个 agent 的回环压测。每一条都是一次完整的 `exvia exec`（进程启动 → TLS → 登录 → 票据 → 会话 → 执行 → 拆除），因此数字包含客户端进程开销（同机基线 `exvia --version` 约 3ms）。

一台 12 核机器（loopback，12 agent）实测：

| 并发 | p50 | p95 | max | 吞吐 |
|---|---|---|---|---|
| 1 | 6.1ms | 6.6ms | 6.6ms | 162 ops/s |
| 8 | 10.7ms | 14.4ms | 15.8ms | 502 ops/s |
| 32 | 19.9ms | 48.1ms | 56.4ms | 565 ops/s |

同期中继 CPU 约 37%（单核占比），RSS 7→12MB，每个 agent RSS≈9MB；50MiB 文件上传 108MiB/s、下载 135MiB/s（loopback，SHA-256 校验一致）。

读法：延迟随并发近似线性上升但斜率很低，吞吐在 8 并发后进入平台区——瓶颈是"每命令一个进程"的客户端开销，不是中继。真实跨公网时链路 RTT 才是主导项（此前在 200ms RTT 的公网链路上，一次 exec 端到端约 80–170ms）。中继是单进程异步的，内存随在线 agent 数与在途会话数增长，量级是 MB/百连接。

## 故障排查

agent 反复重连失败，看 agent 日志里的拒绝原因：

| 现象 | 原因与处置 |
|---|---|
| `already registered` | 重复 enroll。走上面的重装流程 |
| 握手/证书错误 | 指纹抄错，或中继换过证书。核对 `--fingerprint` |
| `protocol version mismatch` / kicked with an upgrade hint | 三端版本不一致，统一升级 |
| 一直退避重连、无拒绝信息 | 网络不通：中继端口未放行、防火墙、地址写错，或三端 `--ws-prefix` 不一致 |
| `ticket signature invalid: signer not in trusted cli allowlist` | 该 CLI 的 `exvia pubkey` 没写进目标 agent 的 `--trusted-cli-key`；或 CLI 重装导致身份变了。补白名单并重新 enroll |
| `no trusted cli pubkey configured` | enroll 时没带 `--trusted-cli-key`，agent 处于 fail-closed 状态 |
| `ticket nonce replay` / `ticket expired` | 同一票据被复用或两端时钟偏差过大；报错里直接给出 `agent_now` 与 `expires_at`（过期类还附 `skew ≈ Ns`），两者差值即时钟偏差，据此核对 NTP 与会话重试逻辑 |

机器列表显示离线：进程在但连接断了——中继 90 秒无心跳才判离线，稍等再看；或出站被防火墙掐断（`systemctl status exvia-agent` + agent 日志确认）。

`exvia ls` 只有表头、没有任何机器行：登录是成功的，但当前账号名下没有一台被授权机器——普通用户只列被授权的机器（admin 才看全量），授权为空时不打印提示行。找管理员 `exvia-relay auth grant`；授权即时生效，不用重新登录。

会话打不开，CLI 的拒绝信息含义不同：

- `machine offline`——agent 掉线；
- `permission denied: user X is not authorized for machine Y`——找管理员 `auth grant`；
- `timed out waiting for session ready` / `agent rejected the session`——agent 在线但会话没建起来，看 agent 日志（多为版本不一致）；
- `session not ready: ticket verification failed: ...`——agent 独立验签拒绝了邀请，按上面的白名单/时钟条目排查；这是预期的安全行为，不要通过关闭验签来"修好"。

登录类报错现在都是"说人话"的，不用再猜：

| 现象 | 含义 |
|---|---|
| `not logged in: no config at <路径>` | 这个 `HOME` 没登录过（或配置被删）。按提示跑 `exvia login ...` |
| `login failed: invalid credentials` | 令牌/密码错。管理员令牌被 `token rotate-admin` 轮换过的话，旧令牌立即失效 |
| `connection failed (...): HTTP error: 200 OK` | 多半是 `--ws-prefix` 和 relay 不一致：relay 把它当普通页面返回了 200。报错里会直接点明这一条 |
| `plaintext ws:// rejected` | 必须用 `wss://`，否则证书指纹固定形同虚设 |

开调试日志：三端都认 `RUST_LOG` 环境变量，如 `RUST_LOG=exvia=debug`（或 `trace`）。

relay 进程退出码 2、随即被 systemd 拉起：状态锁毒化——持锁期间有 bug 触发了 panic，全局状态被判定不可信，进程拒绝带病运行主动退出（systemd `Restart=always` 负责拉起恢复）。查 relay 日志定位触发 panic 的路径。

直接查库：`sqlite3 /var/lib/exvia-relay/relay.db`。表结构简单直白：`machines` / `users` / `machine_auth` / `sessions` / `audit` / `tokens`。

## 安全边界

- 仅用于管理员对自有或已获明确授权的机器运维。
- 隐蔽性指流量层面（TLS + 标准 WebSocket 外形、端到端加密、无特征指纹）；"存在一条到中继的加密长连接"这件事本身无法隐藏。
- 主机层隐藏（进程/文件隐藏、对抗 EDR）明确不做。
- **未认证连接有 15 秒绝对期限**：CLI 连上后必须在 15s 内完成 Login，agent 必须在 15s 内完成 Hello 签名，否则断开。这是绝对期限而非空闲超时——持续发垃圾帧也续不了期，避免一堆"连上不说话"的连接占着名额并消耗 argon2 校验。正常握手在 2s 内完成（含公网 RTT），15s 对慢链路仍有充足余量；若你的线路 RTT 超过 7s，先治网络而不是调大这个值。
- 中继可见的元数据：谁在何时连了哪台机器、会话类型、字节数、时长。这些不加密（中继要靠它们撮合与会话治理）；命令内容、文件内容、路径清单都在 Noise 通道内，中继读不到。
