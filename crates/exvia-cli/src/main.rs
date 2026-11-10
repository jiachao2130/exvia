// Copyright (c) 2026 Jia Chao
// exvia is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! exvia 命令行客户端

mod client;
mod config;
mod raw;

use std::time::Duration;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "exvia", about = "exvia remote ops client", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// log in to relay (admin token or user/password)
    Login {
        /// relay address, e.g. wss://relay.example.com:8443
        #[arg(long)]
        server: String,
        /// pass `-` to prompt (no echo), or use env EXVIA_TOKEN
        #[arg(long, group = "cred")]
        token: Option<String>,
        #[arg(long, group = "cred")]
        user: Option<String>,
        /// pass `-` to prompt (no echo), or use env EXVIA_PASSWORD
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        fingerprint: String,
        /// ws path prefix (must match relay --ws-prefix, default /_exvia)
        #[arg(long, default_value = "/_exvia")]
        ws_prefix: String,
        /// encrypt local config with a passphrase (each command then prompts)
        #[arg(long)]
        encrypt: bool,
    },
    /// print this CLI's ed25519 public key (for the agent allowlist)
    Pubkey,
    /// log out (revoke relay session token, clear local credentials, keep identity key)
    Logout,
    /// list online machines
    Ls {
        #[arg(long)]
        tag: Option<String>,
    },
    /// echo channel connectivity test
    Ping {
        machine_id: String,
        #[arg(long, default_value_t = 4)]
        count: u32,
    },
    /// open an interactive shell on the machine
    Shell { machine_id: String },
    /// run a command on one machine, or on several: `m1,m2,m3` (aliases/ids mixed)
    Exec {
        machine_id: String,
        /// remote command timeout in seconds; agent kills the child and returns 124
        #[arg(long, value_name = "SECS")]
        timeout: Option<u64>,
        /// force the command to run in a remote PTY (ssh -t semantics); single machine only
        #[arg(short = 't', long)]
        pty: bool,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        cmd: Vec<String>,
    },
    /// upload files/directories to one machine, or to several: `m1,m2` (same
    /// sources sent concurrently; summary per machine, exit 1 if any fails)
    Put {
        machine_id: String,
        /// one or more local sources; a trailing `*`/`?` wildcard in the last path
        /// component is expanded CLI-side (no `**`, no character classes)
        #[arg(num_args = 1.., required = true)]
        local: Vec<String>,
        /// remote destination path (acts as a directory for multiple sources)
        remote: String,
        /// kept for compatibility; directories are always walked, sources may mix
        /// files and directories (preserves mode and mtime; symlinks are not followed)
        #[arg(short = 'r', long)]
        recursive: bool,
        /// continue an interrupted upload (reuses the partial file left on the machine)
        #[arg(long)]
        resume: bool,
    },
    /// download a file from the machine
    Get {
        machine_id: String,
        /// remote path; a trailing `*`/`?` wildcard downloads all matches on the
        /// machine into `local` (used as a directory; quoted to keep the shell out)
        remote: String,
        local: String,
        /// recurse into a directory (preserves mode and mtime; symlinks are not followed)
        #[arg(short = 'r', long)]
        recursive: bool,
        /// continue an interrupted download (reuses the local partial file)
        #[arg(long)]
        resume: bool,
    },
    /// port forward (-L local / -R reverse); each may repeat, all run concurrently
    Forward {
        machine_id: String,
        /// -L: local port:target host:target port; listen locally, forward via agent (repeatable)
        #[arg(short = 'L')]
        l_specs: Vec<String>,
        /// -R: [bind addr:]bind port:target host:target port; agent listens, CLI dials the target (repeatable)
        #[arg(short = 'R')]
        r_specs: Vec<String>,
    },
    /// manage machine aliases (local, offline, no login needed)
    Alias {
        #[command(subcommand)]
        cmd: AliasCmd,
    },
    /// list active sessions on the relay (admin sees all users)
    Sessions,
    /// terminate an active session by sid
    Close {
        /// session id from `exvia sessions`
        sid: u64,
    },
    /// manage the trusted CLI allowlist on a machine
    Trust {
        #[command(subcommand)]
        cmd: TrustCmd,
    },
    /// manage locally recorded agent keys (TOFU); `known add` presets a key
    /// before first contact (anchor from the agent's enroll output, closing
    /// the TOFU window out-of-band); `known rm` resets a stale record after
    /// an agent reinstall, the next session re-records the key
    Known {
        #[command(subcommand)]
        cmd: KnownCmd,
    },
    /// print a static completion script (subcommand level); source it,
    /// e.g. `source <(exvia completion bash)`
    Completion {
        /// shell to generate for
        #[arg(value_enum)]
        shell: ShellKind,
    },
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum ShellKind {
    Bash,
    Zsh,
    Fish,
}

#[derive(Subcommand)]
enum KnownCmd {
    /// list recorded agent keys (machine id, key fingerprint, first-seen time)
    List,
    /// preset the recorded key for a machine (alias or id) before the first
    /// session; the first contact then verifies against the preset value
    /// instead of trusting the relay's introduction (TOFU window closed
    /// out-of-band). The agent prints the ready-made command on enroll.
    Add {
        target: String,
        /// agent x25519 static pubkey, b64 (from the enroll output)
        pubkey_b64: String,
    },
    /// remove the recorded key for a machine (alias or id); the next session
    /// re-records whatever key it presents (TOFU reset)
    Rm { target: String },
}

#[derive(Subcommand)]
enum TrustCmd {
    /// show the keys the machine accepts
    List { machine_id: String },
    /// allow one more CLI public key (current one must already be allowed)
    Add {
        machine_id: String,
        /// CLI ed25519 public key, b64 (from `exvia pubkey` on that machine)
        pubkey: String,
    },
    /// revoke a CLI public key (the last remaining key cannot be removed)
    Rm { machine_id: String, pubkey: String },
}

#[derive(Subcommand)]
enum AliasCmd {
    /// bind alias -> machine_id (see `exvia ls` for the full ID)
    Add { name: String, machine_id: String },
    /// remove an alias
    Rm { name: String },
    /// list configured aliases
    List,
}

// 凭证优先走交互输入/环境变量，避免进入 shell history 与进程参数列表
fn resolve_secret(
    value: Option<String>,
    env: &str,
    prompt: &str,
) -> anyhow::Result<Option<String>> {
    match value {
        Some(v) if v == "-" => {
            Ok(Some(rpassword::prompt_password(prompt).map_err(|e| {
                anyhow::anyhow!("failed to read secret: {e}")
            })?))
        }
        Some(v) => Ok(Some(v)),
        None => Ok(std::env::var(env).ok().filter(|v| !v.is_empty())),
    }
}

fn resolve_machine(input: &str) -> anyhow::Result<String> {
    let map = config::load_aliases()?;
    let cache = config::load_machine_cache();
    // 解析命中即静默使用结果（不回显）；歧义/未知仍由 resolver 报错并列出候选
    let (id, _) = config::resolve_machine_with_cache(input, &map, &cache)?;
    Ok(id)
}

// 尾分量通配（`*`/`?`、仅最后一个路径分量）与 agent get 侧的匹配共用
// `exvia_proto::tree::glob_match` 这一份实现。

/// 展开一个源参数：字面路径存在（或不含通配符）时原样返回；含 `*`/`?` 且字面
/// 不存在时按最后一个分量展开，结果为空即明确报错。
fn expand_source(src: &str) -> anyhow::Result<Vec<String>> {
    if !src.contains('*') && !src.contains('?') {
        return Ok(vec![src.to_string()]);
    }
    if std::fs::symlink_metadata(src).is_ok() {
        // 字面路径存在（文件名里真有 *）：不当通配符处理
        return Ok(vec![src.to_string()]);
    }
    let (dir, pat) = match src.rsplit_once('/') {
        Some((d, p)) => (d, p),
        None => ("", src),
    };
    if dir.contains('*') || dir.contains('?') {
        anyhow::bail!("wildcards are only supported in the last path component: {src}");
    }
    let mut hits: Vec<String> = Vec::new();
    let rd = std::fs::read_dir(if dir.is_empty() { "." } else { dir })
        .map_err(|e| anyhow::anyhow!("no files match {src}: cannot scan {dir}: {e}"))?;
    for entry in rd.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // 与 shell 一致：`*` 不匹配点开头的隐藏文件
        if name.starts_with('.') && !pat.starts_with('.') {
            continue;
        }
        if exvia_proto::tree::glob_match(pat, &name) {
            hits.push(if dir.is_empty() {
                name.into_owned()
            } else {
                format!("{dir}/{name}")
            });
        }
    }
    hits.sort();
    if hits.is_empty() {
        anyhow::bail!("no files match: {src}");
    }
    Ok(hits)
}

/// put 的全部本地源：逐个做通配展开（多源里每个参数都可以带尾部通配）。
fn expand_put_sources(args: &[String]) -> anyhow::Result<Vec<String>> {
    let mut out = Vec::new();
    for a in args {
        out.extend(expand_source(a)?);
    }
    Ok(out)
}

/// 解析逗号分隔的多目标列表（trim、跳过空段）；重复目标直接报错。同一台机器
/// 开两个并发会话时，CLI 侧的流配对按对端公钥暂存（client.rs 的 stray_streams
/// 按公钥键控），同机两会话公钥相同会互相认领错流，必须在发起任何会话前拒绝。
fn parse_targets(machine_id: &str) -> anyhow::Result<Vec<&str>> {
    let mut targets: Vec<&str> = Vec::new();
    for t in machine_id
        .split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
    {
        if targets.contains(&t) {
            anyhow::bail!("duplicate target: {t}");
        }
        targets.push(t);
    }
    if targets.is_empty() {
        anyhow::bail!("no target machine given");
    }
    Ok(targets)
}

/// 批量目标先全量解析：任一目标解析失败即整批拒绝（零会话发起）。
/// 逐个"边解析边 spawn"会把已发起的前几个会话丢在半路，与 parse_targets
/// "发起前拒绝"的承诺冲突；解析必须先于一切会话完成。返回按原顺序的
/// (原目标名, 机器 id) 列表，输出前缀仍用原目标名。
fn resolve_targets(
    targets: &[&str],
    resolve: impl Fn(&str) -> anyhow::Result<String>,
) -> anyhow::Result<Vec<(String, String)>> {
    targets
        .iter()
        .map(|t| Ok(((*t).to_string(), resolve(t)?)))
        .collect()
}

// 记录时间只做人话化的相对时长，不做日历运算（没有 chrono 依赖）
fn ago(secs: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let delta = now.saturating_sub(secs);
    if delta < 60 {
        format!("{delta}s ago")
    } else if delta < 3600 {
        format!("{}m ago", delta / 60)
    } else if delta < 86400 {
        format!("{}h ago", delta / 3600)
    } else {
        format!("{}d ago", delta / 86400)
    }
}

// 简化取舍：静态补全——手写字符串常量，不引 clap_complete；
// 只做子命令一级 + 常用 flag，参数级补全按需再手写。
const COMPLETION_BASH: &str = r#"# exvia completion -- statically generated, subcommand-level completion (not auto-updated between releases)
# usage: source <(exvia completion bash)  or append this output to ~/.bashrc
_exvia_completions() {
    local cur
    cur="${COMP_WORDS[COMP_CWORD]}"
    if [[ $COMP_CWORD -eq 1 ]]; then
        COMPREPLY=($(compgen -W "login pubkey logout ls ping shell exec put get forward alias sessions close trust known completion" -- "$cur"))
        return 0
    fi
    case "${COMP_WORDS[1]}" in
        login) COMPREPLY=($(compgen -W "--server --token --user --password --fingerprint --ws-prefix --encrypt" -- "$cur")) ;;
        ls) COMPREPLY=($(compgen -W "--tag" -- "$cur")) ;;
        ping) COMPREPLY=($(compgen -W "--count" -- "$cur")) ;;
        exec) COMPREPLY=($(compgen -W "--timeout --pty" -- "$cur")) ;;
        put|get) COMPREPLY=($(compgen -W "-r --recursive --resume" -- "$cur")) ;;
        forward) COMPREPLY=($(compgen -W "-L -R" -- "$cur")) ;;
        alias) COMPREPLY=($(compgen -W "add rm list" -- "$cur")) ;;
        trust) COMPREPLY=($(compgen -W "list add rm" -- "$cur")) ;;
        known) COMPREPLY=($(compgen -W "list add rm" -- "$cur")) ;;
        completion) COMPREPLY=($(compgen -W "bash zsh fish" -- "$cur")) ;;
    esac
}
complete -F _exvia_completions exvia
"#;

const COMPLETION_ZSH: &str = r#"#compdef exvia
# exvia completion -- statically generated, subcommand-level completion (put in fpath or source directly)
_exvia() {
    local -a cmds
    cmds=('login:log in to relay' 'pubkey:print the CLI public key' 'logout:revoke the session'
          'ls:list online machines' 'ping:echo channel test' 'shell:interactive shell'
          'exec:run a command' 'put:upload files' 'get:download files' 'forward:port forward'
          'alias:manage aliases' 'sessions:list relay sessions' 'close:terminate a session'
          'trust:manage the agent allowlist' 'known:manage recorded agent keys'
          'completion:print a completion script')
    if (( CURRENT == 2 )); then
        _describe -t exvia-cmds 'exvia command' cmds
        return
    fi
    local -a flags
    case ${words[2]} in
        login) flags=(--server --token --user --password --fingerprint --ws-prefix --encrypt) ;;
        ls) flags=(--tag) ;;
        ping) flags=(--count) ;;
        exec) flags=(--pty --timeout) ;;
        put|get) flags=(-r --recursive --resume) ;;
        forward) flags=(-L -R) ;;
        alias) flags=('add:bind alias' 'rm:remove alias' 'list:list aliases') ;;
        trust) flags=('list:show keys' 'add:allow a key' 'rm:revoke a key') ;;
        known) flags=('list:list recorded keys' 'add:preset a key before first contact' 'rm:remove a recorded key') ;;
        completion) flags=(bash zsh fish) ;;
        *) return 0 ;;
    esac
    _describe -t exvia-flags 'argument' flags
}
_exvia "$@"
"#;

const COMPLETION_FISH: &str = r#"# exvia completion -- statically generated, subcommand-level completion (save as ~/.config/fish/completions/exvia.fish)
complete -c exvia -n '__fish_use_subcommand' -a 'login pubkey logout ls ping shell exec put get forward alias sessions close trust known completion'
complete -c exvia -n '__fish_seen_subcommand_from login' -l server -l token -l user -l password -l fingerprint -l ws-prefix -l encrypt
complete -c exvia -n '__fish_seen_subcommand_from ls' -l tag
complete -c exvia -n '__fish_seen_subcommand_from ping' -l count
complete -c exvia -n '__fish_seen_subcommand_from exec' -l timeout -l pty -s t
complete -c exvia -n '__fish_seen_subcommand_from put' -s r -l recursive -l resume
complete -c exvia -n '__fish_seen_subcommand_from get' -s r -l recursive -l resume
complete -c exvia -n '__fish_seen_subcommand_from forward' -l L -l R
complete -c exvia -n '__fish_seen_subcommand_from alias' -a 'add rm list'
complete -c exvia -n '__fish_seen_subcommand_from trust' -a 'list add rm'
complete -c exvia -n '__fish_seen_subcommand_from known' -a 'list add rm'
complete -c exvia -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish'
"#;

fn completion_script(shell: ShellKind) -> &'static str {
    match shell {
        ShellKind::Bash => COMPLETION_BASH,
        ShellKind::Zsh => COMPLETION_ZSH,
        ShellKind::Fish => COMPLETION_FISH,
    }
}

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "exvia=info,warn".into()),
        )
        .init();
    let cli = Cli::parse();
    if let Err(e) = run(cli.cmd).await {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

async fn run(cmd: Cmd) -> anyhow::Result<()> {
    match cmd {
        Cmd::Login {
            server,
            token,
            user,
            password,
            fingerprint,
            ws_prefix,
            encrypt,
        } => {
            let fingerprint = exvia_proto::tls::normalize_fingerprint(&fingerprint)?;
            let token = resolve_secret(token, "EXVIA_TOKEN", "admin/session token: ")?;
            let password = resolve_secret(password, "EXVIA_PASSWORD", "password: ")?;
            if user.is_some() && password.is_none() {
                anyhow::bail!("--user requires --password (or - for prompt / EXVIA_PASSWORD)");
            }
            // 身份固定：每次 login 换密钥会让 agent 白名单失效
            let (ed_seed_b64, x25519_b64) = config::load_or_create_identity()?;
            let cfg = config::ClientConfig {
                server,
                fingerprint,
                token,
                user,
                pass: password,
                ed_seed_b64,
                x25519_b64,
                ws_prefix: Some(ws_prefix),
            };
            let (_conn, session_token) = client::connect_and_login(&cfg).await?;
            let mut saved = cfg.clone();
            // 凭证不落盘：只存签发的会话令牌（7 天有效）
            saved.pass = None;
            if let Some(t) = session_token {
                saved.token = Some(t);
            }
            if encrypt {
                saved.save_encrypted()?;
            } else {
                saved.save()?;
            }
            println!(
                "logged in, config saved to {}",
                config::config_path().display()
            );
            if encrypt {
                println!("config encrypted with a passphrase; each command will prompt for it");
            }
        }
        Cmd::Pubkey => {
            println!("{}", config::current_pubkey()?);
        }
        Cmd::Logout => {
            let (cfg, pass) = config::ClientConfig::load_with_pass()?;
            let Some(_) = &cfg.token else {
                println!("not logged in (no local session token)");
                return Ok(());
            };
            // 先吊销中继会话再清本地；顺序反了会留下中继侧仍有效的会话
            let (conn, _) = client::connect_and_login(&cfg).await?;
            conn.logout().await?;
            let mut cleared = cfg.clone();
            cleared.token = None;
            config::ClientConfig::save_after_logout(&cleared, pass.as_deref())?;
            println!("logged out");
        }
        Cmd::Ls { tag } => {
            let cfg = config::ClientConfig::load()?;
            let (conn, _) = client::connect_and_login(&cfg).await?;
            let machines = conn.list_machines().await?;
            // 记住最近一次结果，后续可以按主机名或 ID 前缀引用机器
            let cache: config::MachineCache = machines
                .iter()
                .map(|m| (m.machine_id.clone(), m.hostname.clone()))
                .collect();
            config::save_machine_cache(&cache);
            let aliases = config::load_aliases()?;
            let mut by_id: std::collections::BTreeMap<String, Vec<String>> = Default::default();
            for (name, id) in &aliases {
                by_id.entry(id.clone()).or_default().push(name.clone());
            }
            println!(
                "{:<34} {:<16} {:<10} {:<8} {:<8} {:<6} {:<12} {:<14} LAST_SEEN",
                "MACHINE_ID", "HOSTNAME", "OS", "ARCH", "VERSION", "ONLINE", "TAGS", "ALIAS"
            );
            for m in machines {
                if let Some(t) = &tag {
                    if !m.tags.split(',').any(|x| x.trim() == t) {
                        continue;
                    }
                }
                println!(
                    "{:<34} {:<16} {:<10} {:<8} {:<8} {:<6} {:<12} {:<14} {}",
                    m.machine_id,
                    m.hostname,
                    m.os,
                    m.arch,
                    m.version,
                    if m.online { "●" } else { "○" },
                    m.tags,
                    by_id
                        .get(&m.machine_id)
                        .map(|v| v.join(","))
                        .unwrap_or_default(),
                    m.last_seen_secs_ago
                        .map(|s| format!("{s}s ago"))
                        .unwrap_or_else(|| "-".into()),
                );
            }
        }
        Cmd::Ping { machine_id, count } => {
            if count == 0 {
                anyhow::bail!("count must be at least 1");
            }
            let machine_id = resolve_machine(&machine_id)?;
            let cfg = config::ClientConfig::load()?;
            let (conn, _) = client::connect_and_login(&cfg).await?;
            let rtts = conn.ping(&machine_id, count).await?;
            for (i, rtt) in rtts.iter().enumerate() {
                println!("seq={i} time={:.2}ms", rtt.as_secs_f64() * 1000.0);
            }
            let avg = rtts.iter().sum::<Duration>() / rtts.len() as u32;
            println!(
                "--- {} echo stats --- sent {} received {} avg {:.2}ms",
                machine_id,
                rtts.len(),
                rtts.len(),
                avg.as_secs_f64() * 1000.0
            );
        }
        Cmd::Shell { machine_id } => {
            let machine_id = resolve_machine(&machine_id)?;
            let cfg = config::ClientConfig::load()?;
            let (conn, _) = client::connect_and_login(&cfg).await?;
            let code = conn.shell(&machine_id).await?;
            std::process::exit(code);
        }
        Cmd::Exec {
            machine_id,
            timeout,
            pty,
            cmd,
        } => {
            if cmd.is_empty() {
                anyhow::bail!(
                    "usage: exvia exec <machine>[,machine2...] [--timeout N] -- <command...>"
                );
            }
            if timeout == Some(0) {
                anyhow::bail!("--timeout must be at least 1 second");
            }
            let targets = parse_targets(&machine_id)?;
            let cfg = config::ClientConfig::load()?;
            let (conn, _) = client::connect_and_login(&cfg).await?;
            if let [only] = &targets[..] {
                // 单目标：完全沿用既有路径（输出无前缀、直接透传退出码），脚本兼容
                let machine_id = resolve_machine(only)?;
                let code = if pty {
                    // -t：命令进远端 PTY（ssh -t 语义），退出码与超时语义不变
                    conn.exec_pty(&machine_id, &cmd, timeout).await?
                } else {
                    conn.exec(&machine_id, &cmd, timeout).await?
                };
                std::process::exit(code);
            }
            if pty {
                // 交互 PTY 的输出/控制字符语义只对单机有意义，批量场景明确拒绝
                anyhow::bail!("-t runs on a single machine; drop -t or split the targets");
            }
            // 多目标：并发独立 exec 会话（复用现有引擎），输出行加 [别名] 前缀；
            // 末尾逐机汇总 rc，任一非零则整体退出码为 1。--timeout 按每会话生效。
            // 目标先全量解析（任一失败→整批拒绝，零会话发起），再并发 spawn。
            let resolved = resolve_targets(&targets, resolve_machine)?;
            let mut handles = Vec::new();
            for (name, machine_id) in resolved {
                let conn = conn.clone();
                let cmd = cmd.clone();
                handles.push((
                    name.clone(),
                    tokio::spawn(async move {
                        conn.exec_labeled(&machine_id, &cmd, timeout, &name).await
                    }),
                ));
            }
            let mut any_nonzero = false;
            for (name, h) in handles {
                let rc = match h.await {
                    Ok(r) => r,
                    Err(e) => Err(anyhow::anyhow!("exec task failed: {e}")),
                };
                match rc {
                    Ok(0) => println!("{name}: rc=0"),
                    Ok(code) => {
                        println!("{name}: rc={code}");
                        any_nonzero = true;
                    }
                    Err(e) => {
                        // 某目标连接失败不中断其他目标：记 rc=255 风格的错误行
                        eprintln!("[{name}] session failed: {e:#}");
                        println!("{name}: rc=255");
                        any_nonzero = true;
                    }
                }
            }
            std::process::exit(if any_nonzero { 1 } else { 0 });
        }
        Cmd::Put {
            machine_id,
            local,
            remote,
            recursive,
            resume,
        } => {
            if recursive && resume {
                anyhow::bail!("--resume is only for single files; drop -r or drop --resume");
            }
            let sources = expand_put_sources(&local)?;
            if resume && sources.len() > 1 {
                anyhow::bail!(
                    "--resume is only for single files; pass one source or drop --resume"
                );
            }
            // 目标解析（含去重）放在登录/建会话之前：重复目标必须零会话拒绝
            let targets = parse_targets(&machine_id)?;
            let cfg = config::ClientConfig::load()?;
            let (conn, _) = client::connect_and_login(&cfg).await?;
            // 单个普通文件源走既有非递归快速路径（含 --resume，行为不变）；
            // 目录与多源合并成一棵清单树走一次会话（同名文件冲突即报错）。
            let single_file = sources.len() == 1
                && !std::fs::symlink_metadata(&sources[0])
                    .map(|m| m.is_dir())
                    .unwrap_or(false);
            // --resume 只对单文件有意义；目录/多源走整树重传，先拒绝而不是
            // 默默把 resume 丢掉——静默忽略会让用户误以为断点被接上
            if resume && !single_file {
                anyhow::bail!(
                    "--resume is only for single files; \
                     directory and multi-source transfers re-walk from scratch, drop --resume"
                );
            }
            if let [only] = &targets[..] {
                // 单目标：完全沿用既有路径（输出无前缀、无汇总行），脚本兼容
                let machine_id = resolve_machine(only)?;
                if single_file {
                    conn.put(&machine_id, &sources[0], &remote, resume).await?;
                    println!("uploaded: {} -> {machine_id}:{remote}", sources[0]);
                } else {
                    let (files, bytes, stats) =
                        conn.put_tree(&machine_id, &sources, &remote).await?;
                    if stats.any() {
                        eprintln!("note: {stats}");
                    }
                    println!(
                        "uploaded: {} -> {machine_id}:{remote} ({files} files, {} MiB)",
                        sources.join(", "),
                        bytes / (1024 * 1024)
                    );
                }
                return Ok(());
            }
            // 多目标：同一组源并发传到每台机器（每机独立 put 会话，参照批量 exec 的
            // Connection Clone + 并发），输出行加 [别名] 前缀；末尾逐机汇总，
            // 任一失败整体退出码 1。目标先全量解析（任一失败→整批拒绝，零会话发起），
            // 再并发 spawn。
            let resolved = resolve_targets(&targets, resolve_machine)?;
            let mut handles = Vec::new();
            for (name, machine_id) in resolved {
                let conn = conn.clone();
                let sources = sources.clone();
                let remote = remote.clone();
                handles.push((
                    name.clone(),
                    tokio::spawn(async move {
                        let done: anyhow::Result<String> = if single_file {
                            conn.put_labeled(&machine_id, &sources[0], &remote, resume, &name)
                                .await?;
                            Ok(format!("uploaded: {} -> {machine_id}:{remote}", sources[0]))
                        } else {
                            let (files, bytes, stats) = conn
                                .put_tree_labeled(&machine_id, &sources, &remote, &name)
                                .await?;
                            if stats.any() {
                                eprintln!("[{name}] note: {stats}");
                            }
                            Ok(format!(
                                "uploaded: {} -> {machine_id}:{remote} ({files} files, {} MiB)",
                                sources.join(", "),
                                bytes / (1024 * 1024)
                            ))
                        };
                        // 完成行也带前缀：多机并发时区分来源
                        println!("[{name}] {}", done?);
                        Ok::<(), anyhow::Error>(())
                    }),
                ));
            }
            let mut any_failed = false;
            for (name, h) in handles {
                match h.await {
                    Ok(Ok(())) => println!("{name}: ok"),
                    Ok(Err(e)) => {
                        println!("{name}: failed: {e:#}");
                        any_failed = true;
                    }
                    Err(e) => {
                        println!("{name}: failed: put task failed: {e}");
                        any_failed = true;
                    }
                }
            }
            std::process::exit(if any_failed { 1 } else { 0 });
        }
        Cmd::Get {
            machine_id,
            remote,
            local,
            recursive,
            resume,
        } => {
            let machine_id = resolve_machine(&machine_id)?;
            if recursive && resume {
                anyhow::bail!("--resume is only for single files; drop -r or drop --resume");
            }
            let has_glob = remote.contains('*') || remote.contains('?');
            if has_glob && resume {
                anyhow::bail!(
                    "--resume is only for single files; drop the wildcard or drop --resume"
                );
            }
            let cfg = config::ClientConfig::load()?;
            let (conn, _) = client::connect_and_login(&cfg).await?;
            if has_glob {
                // 远端尾分量通配：agent 在父目录内匹配，结果按树下载路径落进 local/（目录）
                let (files, bytes) = conn.get_glob(&machine_id, &remote, &local).await?;
                println!(
                    "downloaded: {machine_id}:{remote} -> {local} ({files} files, {} MiB)",
                    bytes / (1024 * 1024)
                );
            } else if recursive {
                let (files, bytes) = conn.get_recursive(&machine_id, &remote, &local).await?;
                println!(
                    "downloaded: {machine_id}:{remote} -> {local} ({files} files, {} MiB)",
                    bytes / (1024 * 1024)
                );
            } else {
                conn.get(&machine_id, &remote, &local, resume).await?;
                println!("downloaded: {machine_id}:{remote} -> {local}");
            }
        }
        Cmd::Forward {
            machine_id,
            l_specs,
            r_specs,
        } => {
            let machine_id = resolve_machine(&machine_id)?;
            let cfg = config::ClientConfig::load()?;
            let (conn, _) = client::connect_and_login(&cfg).await?;
            tokio::select! {
                // forward_multi 内部先全部解析+绑定、全成才进入转发循环
                r = conn.forward_multi(&machine_id, &l_specs, &r_specs) => r?,
                _ = tokio::signal::ctrl_c() => { println!("\nstopped"); }
            }
        }
        Cmd::Sessions => {
            let cfg = config::ClientConfig::load()?;
            let (conn, _) = client::connect_and_login(&cfg).await?;
            let sessions = conn.list_sessions().await?;
            if sessions.is_empty() {
                println!("no active sessions");
            } else {
                println!(
                    "{:<22} {:<34} {:<12} {:<16} AGE",
                    "SID", "MACHINE_ID", "USER", "KIND"
                );
                let aliases = config::load_aliases()?;
                let mut by_id: std::collections::HashMap<String, Vec<String>> = Default::default();
                for (name, id) in &aliases {
                    by_id.entry(id.clone()).or_default().push(name.clone());
                }
                for s in sessions {
                    let alias = by_id
                        .get(&s.machine_id)
                        .map(|v| format!(" ({})", v.join(",")))
                        .unwrap_or_default();
                    println!(
                        "{:<22} {:<34} {:<12} {:<16} {}s{}",
                        s.sid, s.machine_id, s.user, s.kind, s.age_secs, alias
                    );
                }
            }
        }
        Cmd::Close { sid } => {
            let cfg = config::ClientConfig::load()?;
            let (conn, _) = client::connect_and_login(&cfg).await?;
            conn.close_session(sid).await?;
            println!("session {sid} closed");
        }
        Cmd::Trust { cmd } => {
            let (machine_id, action, key, verb) = match &cmd {
                TrustCmd::List { machine_id } => (machine_id.clone(), "list", None, "allowlist"),
                TrustCmd::Add { machine_id, pubkey } => {
                    (machine_id.clone(), "add", Some(pubkey.clone()), "added")
                }
                TrustCmd::Rm { machine_id, pubkey } => {
                    (machine_id.clone(), "rm", Some(pubkey.clone()), "removed")
                }
            };
            let machine_id = resolve_machine(&machine_id)?;
            let cfg = config::ClientConfig::load()?;
            let (conn, _) = client::connect_and_login(&cfg).await?;
            let keys = conn.trust(&machine_id, action, key.as_deref()).await?;
            match verb {
                "allowlist" => {
                    if keys.is_empty() {
                        println!("no trusted cli keys (all sessions are rejected)");
                    } else {
                        for k in keys {
                            println!("{k}");
                        }
                    }
                }
                other => {
                    println!("{other}; {} keys now trusted:", keys.len());
                    for k in keys {
                        println!("  {k}");
                    }
                }
            }
        }
        Cmd::Alias { cmd } => match cmd {
            AliasCmd::Add { name, machine_id } => {
                config::alias_add(&name, &machine_id)?;
                println!("saved alias {name} -> {machine_id}");
                println!("use it directly: exvia exec {name} -- <command>");
            }
            AliasCmd::Rm { name } => {
                if config::alias_remove(&name)? {
                    println!("removed alias {name}");
                } else {
                    println!("alias {name} not found");
                }
            }
            AliasCmd::List => {
                let map = config::load_aliases()?;
                if map.is_empty() {
                    println!(
                        "no aliases configured; add one with exvia alias add <name> <machine_id>"
                    );
                } else {
                    println!("{:<20} MACHINE_ID", "ALIAS");
                    for (name, id) in map {
                        println!("{:<20} {}", name, id);
                    }
                }
            }
        },
        Cmd::Known { cmd } => {
            match cmd {
                // 纯本地操作：不登录、不联网，只读写 known_agents.json（0600）
                KnownCmd::List => {
                    let known = config::load_known_agents()?;
                    if known.is_empty() {
                        println!(
                            "no known agents recorded; a machine's key is recorded on the first session (TOFU)"
                        );
                    } else {
                        let aliases = config::load_aliases()?;
                        let mut by_id: std::collections::BTreeMap<&str, Vec<&str>> =
                            Default::default();
                        for (name, id) in &aliases {
                            by_id.entry(id).or_default().push(name.as_str());
                        }
                        println!(
                            "{:<20} {:<34} {:<23} RECORDED",
                            "ALIAS", "MACHINE_ID", "KEY FINGERPRINT"
                        );
                        for (id, entry) in &known {
                            println!(
                                "{:<20} {:<34} {:<23} {}",
                                by_id
                                    .get(id.as_str())
                                    .map(|v| v.join(","))
                                    .unwrap_or_else(|| "-".into()),
                                id,
                                config::key_fingerprint(&entry.pubkey_b64),
                                entry.first_seen.map(ago).unwrap_or_else(|| "-".into()),
                            );
                        }
                    }
                }
                // 预置信任锚同为纯本地操作：写入 known_agents.json（0600），
                // 之后首连核对预置值，不再信任中继的介绍
                KnownCmd::Add { target, pubkey_b64 } => {
                    let machine_id = resolve_machine(&target)?;
                    let key = config::normalize_agent_pubkey(&pubkey_b64)?;
                    if config::known_agent_anchor(&machine_id, &key)? {
                        println!(
                            "anchored known agent {machine_id} (fingerprint {})",
                            config::key_fingerprint(&key)
                        );
                        println!(
                            "the first session verifies against this key instead of trusting the relay's introduction"
                        );
                    } else {
                        println!("already anchored");
                    }
                }
                KnownCmd::Rm { target } => {
                    // 支持别名或完整 id：先按别名解析，不是别名就当 id 用
                    let aliases = config::load_aliases()?;
                    let id = aliases
                        .get(target.as_str())
                        .cloned()
                        .unwrap_or_else(|| target.clone());
                    match config::known_agent_remove(&id)? {
                        true => {
                            let note = if id == target {
                                String::new()
                            } else {
                                format!(" (alias {target})")
                            };
                            println!("removed known agent {id}{note}");
                            println!(
                                "the next session re-records whatever key it presents (TOFU reset)"
                            );
                        }
                        false => anyhow::bail!("no known agent recorded for {target}"),
                    }
                }
            }
        }
        Cmd::Completion { shell } => {
            print!("{}", completion_script(shell));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_targets_resolve_all_or_reject_with_zero_sessions() {
        // 模拟目标表：web-1/db-1 可解析，其余按 resolver 的既有文案报未知
        let known = ["web-1", "db-1"];
        let resolve = |t: &str| -> anyhow::Result<String> {
            match known.contains(&t) {
                true => Ok(format!("id-{t}")),
                false => anyhow::bail!(
                    "unknown machine {t:?}: not a machine_id, configured alias, hostname, or unique id prefix"
                ),
            }
        };
        // 全部可解析：按原顺序返回 (原目标名, 机器 id)，输出前缀仍用原目标名
        assert_eq!(
            resolve_targets(&["web-1", "db-1"], resolve).unwrap(),
            vec![
                ("web-1".to_string(), "id-web-1".to_string()),
                ("db-1".to_string(), "id-db-1".to_string()),
            ]
        );
        // 任一未知：整批拒绝且无部分结果——解析先于一切 spawn 完成，
        // 因此已发起会话为零，也不会有任何 [别名] 前缀的输出残留
        let err = resolve_targets(&["web-1", "no-such"], resolve)
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown machine"), "{err}");
    }

    #[test]
    fn expand_source_keeps_literal_and_expands_tail_wildcards() {
        let dir = std::env::temp_dir().join(format!(
            "exvia-glob-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.log"), "a").unwrap();
        std::fs::write(dir.join("b.log"), "b").unwrap();
        std::fs::write(dir.join("c.txt"), "c").unwrap();
        std::fs::write(dir.join(".hidden"), "h").unwrap();
        std::fs::write(dir.join("weird*"), "w").unwrap();
        let d = dir.to_string_lossy().into_owned();

        // 字面路径存在（哪怕名字里真有 *）：不当通配符处理
        assert_eq!(
            expand_source(&format!("{d}/weird*")).unwrap(),
            vec![format!("{d}/weird*")]
        );
        // 尾部通配展开：字典序、不混入隐藏文件与其它后缀
        assert_eq!(
            expand_source(&format!("{d}/*.log")).unwrap(),
            vec![format!("{d}/a.log"), format!("{d}/b.log")]
        );
        assert_eq!(
            expand_source(&format!("{d}/?.log")).unwrap(),
            vec![format!("{d}/a.log"), format!("{d}/b.log")]
        );
        // 无匹配 → 明确报错，不静默当字面路径
        let err = expand_source(&format!("{d}/*.zip"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("no files match"), "{err}");
        // 中间分量通配 → 报错（只支持尾部分量）
        let err = expand_source(&format!("{d}/*/a.log"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("last path component"), "{err}");
        // 不含通配符的缺失路径：原样带回，交给后续存在性检查
        assert_eq!(
            expand_source(&format!("{d}/missing.bin")).unwrap(),
            vec![format!("{d}/missing.bin")]
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn parse_targets_rejects_duplicates_and_keeps_single_target() {
        // 单目标不受影响（trim/空段语义与原先一致）
        assert_eq!(parse_targets("m1").unwrap(), vec!["m1"]);
        assert_eq!(parse_targets(" m1 , m2 ").unwrap(), vec!["m1", "m2"]);
        assert_eq!(parse_targets("m1,,m2,").unwrap(), vec!["m1", "m2"]);
        // 重复目标：报错带目标名，发生在任何会话发起之前
        let err = parse_targets("m1,m1").unwrap_err().to_string();
        assert!(err.contains("duplicate target: m1"), "{err}");
        let err = parse_targets("m1, m2 ,m1").unwrap_err().to_string();
        assert!(err.contains("duplicate target: m1"), "{err}");
        // 空列表语义保持
        assert!(parse_targets("").is_err());
        assert!(parse_targets(" , ").is_err());
    }

    #[test]
    fn completion_scripts_cover_subcommands() {
        for script in [
            completion_script(ShellKind::Bash),
            completion_script(ShellKind::Zsh),
            completion_script(ShellKind::Fish),
        ] {
            assert!(
                script.contains("statically generated"),
                "header comment missing"
            );
            for cmd in ["exec", "forward", "known", "completion", "put", "trust"] {
                assert!(script.contains(cmd), "{cmd} missing from script");
            }
        }
    }
}
