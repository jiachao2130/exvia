// Copyright (c) 2026 Jia Chao
// exvia is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! exvia 被控端：仅出站连接、注册上线、会话执行。

mod agent;
mod conn;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "exvia-agent", about = "exvia agent", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// enroll once with a one-time token
    Enroll {
        /// relay address, e.g. wss://relay.example.com:8443
        #[arg(long)]
        server: String,
        #[arg(long)]
        token: String,
        /// relay certificate fingerprint (SHA-256 hex, printed by serve at startup)
        #[arg(long)]
        fingerprint: String,
        #[arg(long, default_value = "/var/lib/exvia-agent/identity.json")]
        identity: PathBuf,
        /// trusted CLI ed25519 pubkey (b64, repeatable; get via `exvia pubkey`)
        /// no key configured: agent rejects all sessions (fail-closed)
        #[arg(long = "trusted-cli-key")]
        trusted_cli_keys: Vec<String>,
        /// ws path prefix (must match relay --ws-prefix)
        #[arg(long, default_value = "/_exvia")]
        ws_prefix: String,
    },
    /// run as a daemon (load local identity, reconnect on disconnect)
    Run {
        #[arg(long, default_value = "/var/lib/exvia-agent/identity.json")]
        identity: PathBuf,
    },
    /// print a ready-to-use systemd unit (ExecStart pins this --identity path)
    Install {
        /// identity path embedded into the generated unit; `run`'s default
        /// (/var/lib/exvia-agent/identity.json) is NOT assumed, pass it explicitly
        #[arg(long)]
        identity: PathBuf,
    },
}

fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "exvia_agent=info,warn".into()),
        )
        .init();
    let cli = Cli::parse();
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let r = match cli.cmd {
        Cmd::Enroll {
            server,
            token,
            fingerprint,
            identity,
            trusted_cli_keys,
            ws_prefix,
        } => rt.block_on(agent::enroll(
            &server,
            &token,
            &fingerprint,
            &identity,
            &trusted_cli_keys,
            &ws_prefix,
        )),
        Cmd::Run { identity } => rt.block_on(agent::run(&identity)),
        Cmd::Install { identity } => {
            print_unit(&identity);
            Ok(())
        }
    };
    if let Err(e) = r {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn print_unit(identity: &PathBuf) {
    print!("{}", systemd_unit(identity));
}

// 简化取舍：用户名解析——env 优先（交互 shell 必有），缺失时按 getuid 查
// /etc/passwd（systemd/cron 等无 USER 的环境兜底）；只覆盖 Linux/Unix，unit
// 本就是 Linux 部署产物，Windows 不在此列。
fn current_user() -> String {
    for var in ["USER", "LOGNAME"] {
        if let Ok(u) = std::env::var(var) {
            if !u.is_empty() {
                return u;
            }
        }
    }
    let uid = unsafe { libc::getuid() };
    let uid = uid.to_string();
    // /etc/passwd 七段：name:passwd:uid:gid:gecos:home:shell
    if let Ok(passwd) = std::fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let mut f = line.splitn(7, ':');
            let name = match f.next() {
                Some(n) if !n.is_empty() => n,
                _ => continue,
            };
            if f.nth(1).unwrap_or("") == uid {
                return name.to_string();
            }
        }
    }
    format!("uid-{uid}")
}

/// 单元必须可直接落盘使用：ExecStart 显式带 --identity（run 的缺省路径未必是
/// 部署者选的），User= 取当前用户（缺了 systemd 默认以 root 跑）。相对路径按
/// 当前目录转绝对（systemd 的工作目录是 /，相对路径会指错）。
fn systemd_unit(identity: &PathBuf) -> String {
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "/usr/local/bin/exvia-agent".into());
    let identity = if identity.is_absolute() {
        identity.display().to_string()
    } else {
        std::path::absolute(identity)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| identity.display().to_string())
    };
    let user = current_user();
    format!(
        r#"[Unit]
Description=exvia agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart={exe} run --identity {identity}
User={user}
Restart=always
RestartSec=3
# hardening: NoNewPrivileges only. exvia is a full operations tool: file transfer
# and exec must write arbitrary real paths (incl. /home, /etc), so filesystem-wide
# read-only sandboxing (ProtectSystem=full) is deliberately not applied — write
# reach across the whole filesystem wins over that hardening layer.
NoNewPrivileges=true
ReadWritePaths=/var/lib/exvia-agent

[Install]
WantedBy=multi-user.target"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 单元加固意图：保留 NoNewPrivileges，放弃 ProtectSystem=full
    /// （它把 /usr /boot /etc 变只读，与 put/exec 的全路径写能力矛盾）。
    /// 注释里可以解释取舍，但不得再出现 ProtectSystem 指令行。
    /// 另外断言单元可直接使用：ExecStart 带 --identity、User= 当前用户。
    #[test]
    fn unit_keeps_no_new_privileges_and_drops_protect_system() {
        let unit = systemd_unit(&PathBuf::from("/home/chao/exvia/agent/identity.json"));
        assert!(unit.contains("NoNewPrivileges=true"));
        assert!(
            !unit.lines().any(|l| l.starts_with("ProtectSystem")),
            "ProtectSystem directive must be gone (comment may still mention it)"
        );
        assert!(unit.contains("ReadWritePaths=/var/lib/exvia-agent"));
        assert!(unit.contains("[Unit]"));
        assert!(unit.contains("[Install]"));
        assert!(unit.contains("WantedBy=multi-user.target"));
        // User= 行存在且取当前用户名（缺了 systemd 会默认以 root 跑）
        let user_line = unit
            .lines()
            .find(|l| l.starts_with("User="))
            .expect("User= line missing");
        assert_eq!(user_line, format!("User={}", current_user()));
        // ExecStart 显式带 --identity（run 的缺省路径不一定是部署者选的）
        let exec_line = unit
            .lines()
            .find(|l| l.starts_with("ExecStart="))
            .expect("ExecStart line missing");
        assert!(
            exec_line.contains(" run --identity /home/chao/exvia/agent/identity.json"),
            "{exec_line}"
        );
    }

    /// 相对 --identity 按 cwd 转绝对：systemd 的工作目录是 /，相对路径会指错。
    #[test]
    fn unit_absolutizes_relative_identity_path() {
        let unit = systemd_unit(&PathBuf::from("agent/identity.json"));
        let exec_line = unit
            .lines()
            .find(|l| l.starts_with("ExecStart="))
            .expect("ExecStart line missing");
        let abs = std::path::absolute("agent/identity.json").unwrap();
        assert!(
            exec_line.contains(&format!("--identity {}", abs.display())),
            "{exec_line}"
        );
    }
}
