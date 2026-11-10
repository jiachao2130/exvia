// Copyright (c) 2026 Jia Chao
// exvia is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 目录树传输的路径安全规则。
//!
//! 目录传输是唯一一种"发送端指定落盘路径"的场景，因此路径校验必须两端都做：
//! 发送端负责生成规范路径，接收端负责**不信任地**再校验一次。历史上多数
//! tar/zip 类漏洞都出在"只校验一次"或"解压时才校验"。

use crate::frame::{read_frame, write_frame, Frame, FrameKind};
use crate::msgs::{CtrlMsg, TreeEntry};
use std::path::{Path, PathBuf};

/// 校验一个目录传输里声明的相对路径，返回归一化后的形式。
///
/// 接受：`a`、`a/b`、`./a/b`、`a//b`（空段与 `.` 会被折叠）。
/// 拒绝：空串、绝对路径、含 `..` 分量、含 NUL、Windows 盘符前缀、只剩空段。
pub fn safe_rel_path(input: &str) -> Result<String, &'static str> {
    if input.is_empty() {
        return Err("empty path");
    }
    if input.contains('\0') {
        return Err("path contains NUL");
    }
    // 绝对路径：Unix 风格与 Windows 风格都拒。目录传输的路径永远相对传输根。
    if input.starts_with('/') || input.starts_with('\\') {
        return Err("absolute path not allowed");
    }
    // 盘符前缀（`C:` / `c:\`）在 Unix agent 上会被当成普通文件名，
    // 但会让同一份清单在跨平台解释上产生歧义，直接拒绝。
    let bytes = input.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        return Err("drive-letter path not allowed");
    }

    let mut out = String::with_capacity(input.len());
    for seg in input.split('/') {
        match seg {
            "" | "." => continue,
            ".." => return Err("parent traversal not allowed"),
            s => {
                if !out.is_empty() {
                    out.push('/');
                }
                out.push_str(s);
            }
        }
    }
    if out.is_empty() {
        return Err("path has no component");
    }
    Ok(out)
}

/// 把已校验的相对路径解析到根目录下。
///
/// 调用方仍需自行确认没有符号链接逃逸——本函数只保证路径字符串本身不越界。
pub fn join_under(root: &Path, rel: &str) -> Result<PathBuf, &'static str> {
    let safe = safe_rel_path(rel)?;
    let p = root.join(safe);
    // 归一化后再断言：即使 join 的行为在某个平台上出乎意料，也拦得住。
    if !p.starts_with(root) {
        return Err("resolved path escapes root");
    }
    Ok(p)
}

// 简化取舍：极简 glob——只支持最后一个路径分量里的 `*` 与 `?`（无 `**`、无字符类、
// 不跨 `/`），覆盖 `put 'logs/*.log' dest/` 这类高频用法；更复杂的模式请交给 shell 展开。
/// 单分量通配匹配：`*` 匹配任意序列（含空），`?` 匹配单个字符，其余按字面。
///
/// 只做字符级的模式比对：调用方须传入单个路径分量（不得含 `/`），且自行决定
/// 是否放行点开头的隐藏文件（CLI put / agent get 两侧的展开逻辑已各自处理）。
pub fn glob_match(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    let (mut pi, mut ni) = (0usize, 0usize);
    let (mut star, mut star_ni) = (None::<usize>, 0usize);
    while ni < n.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            pi += 1;
            star_ni = ni;
        } else if let Some(s) = star {
            pi = s + 1;
            star_ni += 1;
            ni = star_ni;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// 遍历时被跳过的条目统计，供命令行提示"有些东西没传"。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ScanStats {
    pub symlinks: usize,
    pub special: usize,
    pub unreadable: usize,
}

impl ScanStats {
    pub fn any(&self) -> bool {
        self.symlinks + self.special + self.unreadable > 0
    }
}

impl std::fmt::Display for ScanStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "skipped {} symlink(s), {} special file(s), {} unreadable",
            self.symlinks, self.special, self.unreadable
        )
    }
}

/// 递归扫描目录，产出按路径字典序排列的条目清单（**不含 root 自身**）。
///
/// 安全约定：
/// - 符号链接一律不跟随（`symlink_metadata`），既防逃逸也防目录环；
/// - fifo/socket/设备文件跳过，传过去没有意义且可能阻塞读取；
/// - 权限位只保留 `0o777`，**不继承 setuid/setgid/sticky**——跨机器复制
///   setuid 程序等于把对端的提权路径搬过来。
pub fn collect_tree(root: &Path) -> std::io::Result<(Vec<TreeEntry>, ScanStats)> {
    let mut out = Vec::new();
    let mut stats = ScanStats::default();
    walk(root, "", &mut out, &mut stats)?;
    Ok((out, stats))
}

fn walk(
    dir: &Path,
    prefix: &str,
    out: &mut Vec<TreeEntry>,
    stats: &mut ScanStats,
) -> std::io::Result<()> {
    let mut entries: Vec<_> = match std::fs::read_dir(dir) {
        Ok(rd) => rd.filter_map(|e| e.ok()).collect(),
        Err(_) => {
            stats.unreadable += 1;
            return Ok(());
        }
    };
    // 排序保证清单顺序确定：同样的目录在任何机器上产出同样的序列，
    // 便于比对与复现问题。
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let rel = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}/{name}")
        };
        let path = entry.path();
        let Ok(md) = std::fs::symlink_metadata(&path) else {
            stats.unreadable += 1;
            continue;
        };
        let ft = md.file_type();
        if ft.is_symlink() {
            stats.symlinks += 1;
            continue;
        }
        if ft.is_dir() {
            out.push(TreeEntry {
                rel: rel.clone(),
                dir: true,
                size: 0,
                mode: mode_of(&md),
                mtime: mtime_of(&md),
            });
            walk(&path, &rel, out, stats)?;
        } else if ft.is_file() {
            out.push(TreeEntry {
                rel,
                dir: false,
                size: md.len(),
                mode: mode_of(&md),
                mtime: mtime_of(&md),
            });
        } else {
            stats.special += 1;
        }
    }
    Ok(())
}

/// 把清单里的相对路径解析成落盘位置，并堵死符号链接逃逸。
///
/// 字符串层已经由 [`safe_rel_path`] 拦掉 `..` 与绝对路径；这里再检查**每一级祖先**
/// 以及**目标自身**不是符号链接。否则对方可以预先放一个 `root/sub -> /etc`，
/// 随后写 `sub/passwd` 就落到 root 之外了；目标自身是链接时，
/// `create_dir_all` 与 `chmod` 同样会顺着链接跑到外面。
///
/// 威胁模型边界：防护目标是"中继/对端不可信"（清单由远端下发），**不防**"本机
/// 并发进程攻击传输根目录"——下面的逐级检查与后续 `create_dir_all`/写盘之间存在
/// check-then-use（TOCTOU）窗口，本机攻击者可在检查通过后替换路径组件；
/// 那属于本地同权限面的问题，不在本函数的防护范围内。
pub fn resolve_target(root: &Path, rel: &str) -> anyhow::Result<PathBuf> {
    use anyhow::Context as _;
    let target = join_under(root, rel).map_err(|e| anyhow::anyhow!("unsafe path {rel:?}: {e}"))?;
    let parent = target
        .parent()
        .with_context(|| format!("no parent for {}", target.display()))?;
    let rel_parent = parent.strip_prefix(root).unwrap_or(Path::new(""));
    let mut cur = root.to_path_buf();
    for seg in rel_parent.components() {
        cur.push(seg);
        match std::fs::symlink_metadata(&cur) {
            Ok(md) if md.file_type().is_symlink() => {
                anyhow::bail!("refusing to write through symlink: {}", cur.display());
            }
            Ok(_) => {}
            // 剩下的路径都还不存在，交给 create_dir_all；后续祖先不会是链接。
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(e) => return Err(e).with_context(|| format!("stat {}", cur.display())),
        }
    }
    // 目标本身也必须检查：`create_dir_all` 对指向目录的符号链接会静默成功，
    // 后续 chmod/utimes 就作用在链接目标上了。
    if let Ok(md) = std::fs::symlink_metadata(&target) {
        if md.file_type().is_symlink() {
            anyhow::bail!("refusing to replace symlink: {}", target.display());
        }
    }
    Ok(target)
}

/// 清单条目的权限位：只保留 `0o777`，不继承 setuid/setgid/sticky
///（与 [`collect_tree`] 同一规则，供 put/get 的通配展开共用）。
#[cfg(unix)]
pub fn mode_of(md: &std::fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(md.permissions().mode() & 0o777)
}

/// 非 Unix 平台没有权限位语义，条目不带 mode。
#[cfg(not(unix))]
pub fn mode_of(_md: &std::fs::Metadata) -> Option<u32> {
    None
}

/// 清单条目的 mtime（Unix 秒）。
pub fn mtime_of(md: &std::fs::Metadata) -> Option<i64> {
    md.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
}

/// 还原权限位（只接受 `0o777` 内的位，其它一律忽略）。
#[cfg(unix)]
pub fn apply_mode(path: &Path, mode: Option<u32>) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let Some(m) = mode else { return Ok(()) };
    let m = m & 0o777;
    if m == 0 {
        return Ok(());
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(m))
}

#[cfg(not(unix))]
pub fn apply_mode(_path: &Path, _mode: Option<u32>) -> std::io::Result<()> {
    Ok(())
}

/// 还原 mtime（Unix 秒）。`UTIME_OMIT` 让 atime 保持原样，
/// 避免"读一遍文件就把 atime 改了"的副作用。
#[cfg(unix)]
pub fn apply_mtime(path: &Path, mtime: Option<i64>) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;
    let Some(secs) = mtime else { return Ok(()) };
    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let times = [
        libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        },
        libc::timespec {
            tv_sec: secs as libc::time_t,
            tv_nsec: 0,
        },
    ];
    // SAFETY: 路径与 times 数组都是本栈上有效的 C 布局数据，调用期间不释放。
    let rc = unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), times.as_ptr(), 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
pub fn apply_mtime(_path: &Path, _mtime: Option<i64>) -> std::io::Result<()> {
    Ok(())
}

/// 目录树接收中正在写的一个文件。落盘前先写临时文件（`{target}.exvia-tmp-{pid}-{seq}`），
/// 校验通过才 rename，避免中断留下半截内容覆盖掉原有文件。
struct IncomingFile {
    path: std::path::PathBuf,
    temp: std::path::PathBuf,
    file: tokio::fs::File,
    expect: u64,
    got: u64,
    mode: Option<u32>,
    mtime: Option<i64>,
}

impl IncomingFile {
    /// 校验大小、落盘、还原属性。失败时删掉临时文件，绝不留半截文件。
    ///
    /// `verb` 是 rename 失败报错里的动词（agent 视角 "write" / CLI 视角 "save"，
    /// 两侧既有文案逐字节保留）；`warn` 是元数据还原失败的上报通道（agent 走
    /// tracing 日志，CLI 打 stderr），还原失败不让整个传输失败。
    async fn finish(self, verb: &str, warn: &mut (dyn FnMut(&str) + Send)) -> anyhow::Result<u64> {
        if self.expect != 0 && self.got != self.expect {
            let _ = tokio::fs::remove_file(&self.temp).await;
            anyhow::bail!(
                "size mismatch for {}: expected {}, got {}",
                self.path.display(),
                self.expect,
                self.got
            );
        }
        // sync 后即可 rename（fd 仍开着，POSIX 允许；随 self 在函数尾部关闭）
        self.file.sync_all().await?;
        if let Err(e) = std::fs::rename(&self.temp, &self.path) {
            let _ = std::fs::remove_file(&self.temp);
            anyhow::bail!("{verb} file failed: {}: {e}", self.path.display());
        }
        // 属性还原失败不该让整个传输失败：内容已经正确落盘，只是元数据没跟上。
        if let Err(e) = apply_mode(&self.path, self.mode) {
            warn(&format!("chmod {} failed: {e}", self.path.display()));
        }
        if let Err(e) = apply_mtime(&self.path, self.mtime) {
            warn(&format!("utimes {} failed: {e}", self.path.display()));
        }
        Ok(self.got)
    }
}

impl Drop for IncomingFile {
    /// 兜底清理：没走完 `finish`（未 rename 成功）的临时文件随自身 drop 删除。
    /// 该命名不匹配分片清理规则（`is_part_of`），残留会随反复失败持续积累。
    /// 成功路径 rename 后临时名已不存在，这里的 remove 静默失败，无副作用。
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.temp);
    }
}

/// 目录树接收的共用帧循环：CLI `put` → agent 与 agent `get` → CLI 是同一份
/// 帧协议（`TreeEntryMeta` 划界、数据块跟随文件条目、`TreeDone` 收尾），本函数
/// 是两端等价实现的唯一一份，防逃逸（[`resolve_target`]）与临时文件语义逐行为一致。
///
/// 调用方各自保留的差异（文案与通道逐字节不变）：
/// - `peer`：断连报错里的对端称谓（agent 视角 "peer"，CLI 视角 "agent"）；
/// - `verb`：写盘失败报错里的动词（见 [`IncomingFile::finish`]）；
/// - `warn`：文件元数据还原失败的上报通道；
/// - `on_close`：收到对端 Close 帧时的翻译（agent 忽略 reason 直接报中止，
///   CLI 透传 agent 的 reason，两侧文案不同）。
///
/// 返回 (文件数, 字节数, 目录属性清单)；目录 mode/mtime 由调用方在收尾时按
/// 由深到浅还原（子项写入会刷新父目录 mtime）。任何失败路径都不留临时文件
///（见 [`IncomingFile`] 的 Drop）。
pub async fn recv_tree_frames<S>(
    io: &mut S,
    root: &Path,
    peer: &str,
    verb: &str,
    warn: &mut (dyn FnMut(&str) + Send),
    on_close: impl FnOnce(Frame) -> anyhow::Error + Send,
) -> anyhow::Result<(
    u64,
    u64,
    Vec<(std::path::PathBuf, Option<u32>, Option<i64>)>,
)>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt as _;
    let mut cur: Option<IncomingFile> = None;
    let mut dirs: Vec<(std::path::PathBuf, Option<u32>, Option<i64>)> = Vec::new();
    let mut files = 0u64;
    let mut bytes = 0u64;
    let mut seq = 0u64;

    let result: anyhow::Result<()> = loop {
        let Some(frame) = read_frame(io).await? else {
            break Err(anyhow::anyhow!("{peer} closed during transfer"));
        };
        match frame.kind {
            FrameKind::Data => {
                let Some(f) = cur.as_mut() else {
                    break Err(anyhow::anyhow!("data frame before any file entry"));
                };
                f.file.write_all(&frame.payload).await?;
                f.got += frame.payload.len() as u64;
                bytes += frame.payload.len() as u64;
            }
            FrameKind::Ctrl => match frame.ctrl_msg()? {
                CtrlMsg::TreeEntryMeta { entry } => {
                    // 上一个文件以"下一个条目"为边界，这里收尾。
                    if let Some(f) = cur.take() {
                        f.finish(verb, warn).await?;
                        files += 1;
                    }
                    let target = resolve_target(root, &entry.rel)?;
                    if entry.dir {
                        std::fs::create_dir_all(&target).map_err(|e| {
                            anyhow::anyhow!("cannot create {}: {e}", target.display())
                        })?;
                        dirs.push((target, entry.mode, entry.mtime));
                    } else {
                        let parent = target.parent().unwrap_or(root).to_path_buf();
                        std::fs::create_dir_all(&parent).map_err(|e| {
                            anyhow::anyhow!("cannot create {}: {e}", parent.display())
                        })?;
                        seq += 1;
                        let temp = target
                            .with_extension(format!("exvia-tmp-{}-{seq}", std::process::id()));
                        let file = tokio::fs::File::create(&temp).await.map_err(|e| {
                            anyhow::anyhow!("cannot create {}: {e}", temp.display())
                        })?;
                        cur = Some(IncomingFile {
                            path: target,
                            temp,
                            file,
                            expect: entry.size,
                            got: 0,
                            mode: entry.mode,
                            mtime: entry.mtime,
                        });
                    }
                }
                CtrlMsg::TreeDone => {
                    if let Some(f) = cur.take() {
                        f.finish(verb, warn).await?;
                        files += 1;
                    }
                    break Ok(());
                }
                _ => {}
            },
            FrameKind::Close => break Err(on_close(frame)),
            FrameKind::Shutdown => {}
        }
    };
    result?;
    Ok((files, bytes, dirs))
}

/// 目录树发送的共用帧循环：CLI `put` → agent 与 agent `get` → CLI 用同一套帧序
/// （条目元数据划界、数据块跟随、`TreeDone` 收尾），这里是唯一一份实现。
///
/// `entries` 是 (清单条目, 内容根)：文件内容按 `root.join(&entry.rel)` 打开；
/// 一个根下可以有多条清单（多源 `put`），同名冲突由调用方在收集阶段解决。
/// `on_chunk(files, bytes)` 在每块数据发出后回调，供调用方打进度；不需要时传
/// `|_, _| {}`。返回 (文件数, 字节数)；收尾的 Close 回执由调用方读取并判定。
pub async fn send_tree_frames<S>(
    io: &mut S,
    entries: &[(TreeEntry, PathBuf)],
    mut on_chunk: impl FnMut(u64, u64),
) -> anyhow::Result<(u64, u64)>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncReadExt as _;
    let mut buf = vec![0u8; crate::FILE_CHUNK];
    let mut files = 0u64;
    let mut bytes = 0u64;
    for (entry, root) in entries {
        write_frame(
            io,
            &Frame::ctrl(&CtrlMsg::TreeEntryMeta {
                entry: entry.clone(),
            })?,
        )
        .await?;
        if entry.dir {
            continue;
        }
        let p = root.join(&entry.rel);
        let mut f = tokio::fs::File::open(&p)
            .await
            .map_err(|e| anyhow::anyhow!("cannot open {}: {e}", p.display()))?;
        files += 1;
        loop {
            let n = f.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            write_frame(io, &Frame::data(buf[..n].to_vec())).await?;
            bytes += n as u64;
            on_chunk(files, bytes);
        }
    }
    write_frame(io, &Frame::ctrl(&CtrlMsg::TreeDone)?).await?;
    Ok((files, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_and_normalizes_plain_relative_paths() {
        assert_eq!(safe_rel_path("a").unwrap(), "a");
        assert_eq!(safe_rel_path("a/b/c.txt").unwrap(), "a/b/c.txt");
        assert_eq!(safe_rel_path("./a/b").unwrap(), "a/b");
        assert_eq!(safe_rel_path("a//b///c").unwrap(), "a/b/c");
        // 结尾斜杠不产生空段
        assert_eq!(safe_rel_path("a/b/").unwrap(), "a/b");
    }

    #[test]
    fn rejects_traversal_and_absolute_paths() {
        for bad in [
            "",
            "..",
            "../etc/passwd",
            "a/../../etc/passwd",
            "a/..",
            "/etc/passwd",
            "\\windows\\system32",
            "C:/windows",
            "c:\\windows",
            "a\0b",
            ".",
            "././",
            "//",
        ] {
            assert!(safe_rel_path(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn join_under_stays_inside_root() {
        let root = Path::new("/srv/dest");
        assert_eq!(join_under(root, "a/b").unwrap(), Path::new("/srv/dest/a/b"));
        assert!(join_under(root, "../etc/passwd").is_err());
        assert!(join_under(root, "/etc/passwd").is_err());
    }

    #[test]
    fn real_world_tar_slip_payloads_are_rejected() {
        // 经典 tar-slip 变体：先跳到父目录再绕回来
        for bad in ["foo/../../bar", "a/./../../b", "./../x", "a/b/../../../etc"] {
            assert!(safe_rel_path(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn dots_that_are_not_traversal_stay_literal() {
        // `....` 与 `...` 是合法文件名，不是 `..` 分量；拒绝它们会误伤真实文件
        assert_eq!(safe_rel_path("....//x").unwrap(), "..../x");
        assert_eq!(safe_rel_path("...").unwrap(), "...");
        assert_eq!(safe_rel_path("a..b").unwrap(), "a..b");
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "exvia-tree-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn collect_tree_is_sorted_and_relative() {
        let root = tmpdir("collect");
        std::fs::create_dir_all(root.join("b/sub")).unwrap();
        std::fs::create_dir_all(root.join("a")).unwrap();
        std::fs::write(root.join("b/sub/x.txt"), b"hello").unwrap();
        std::fs::write(root.join("a/y.txt"), b"yy").unwrap();
        std::fs::write(root.join("z.txt"), b"z").unwrap();

        let (entries, stats) = collect_tree(&root).unwrap();
        assert!(!stats.any(), "{stats}");
        let rels: Vec<&str> = entries.iter().map(|e| e.rel.as_str()).collect();
        // 深度优先 + 同层字典序
        assert_eq!(
            rels,
            vec!["a", "a/y.txt", "b", "b/sub", "b/sub/x.txt", "z.txt"]
        );
        // 目录条目不携带 size，文件携带真实大小
        assert!(entries[0].dir);
        assert_eq!(entries[0].size, 0);
        assert_eq!(entries[1].size, 2);
        assert!(!entries[1].dir);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn collect_tree_skips_symlinks_and_special_files() {
        let root = tmpdir("links");
        std::fs::write(root.join("real.txt"), b"r").unwrap();
        // 指向父目录的符号链接：若被跟随会无限递归
        std::os::unix::fs::symlink(&root, root.join("loop")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", root.join("outside")).unwrap();

        let (entries, stats) = collect_tree(&root).unwrap();
        let rels: Vec<&str> = entries.iter().map(|e| e.rel.as_str()).collect();
        assert_eq!(rels, vec!["real.txt"], "symlinks must not be followed");
        assert_eq!(stats.symlinks, 2);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn resolve_target_refuses_symlinked_ancestor_and_symlinked_target() {
        let root = tmpdir("resolve");
        let outside = tmpdir("outside");
        // root/sub -> outside：写 sub/x 会落到根之外
        std::os::unix::fs::symlink(&outside, root.join("sub")).unwrap();

        let err = resolve_target(&root, "sub/x.txt").unwrap_err().to_string();
        assert!(err.contains("symlink"), "{err}");
        // 目标自身是链接时同样拒绝：create_dir_all 会静默跟随
        let err = resolve_target(&root, "sub").unwrap_err().to_string();
        assert!(err.contains("symlink"), "{err}");
        // 正常路径不受影响
        assert!(resolve_target(&root, "ok/x.txt").is_ok());
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[cfg(unix)]
    #[test]
    fn apply_mode_and_mtime_roundtrip() {
        use std::os::unix::fs::MetadataExt;
        let root = tmpdir("meta");
        let f = root.join("m.bin");
        std::fs::write(&f, b"x").unwrap();
        apply_mode(&f, Some(0o751)).unwrap();
        apply_mtime(&f, Some(1_600_000_000)).unwrap();

        let md = std::fs::metadata(&f).unwrap();
        assert_eq!(md.mode() & 0o777, 0o751);
        assert_eq!(md.mtime(), 1_600_000_000);

        // setuid/setgid 位不该被还原：只取低 9 位
        apply_mode(&f, Some(0o4755)).unwrap();
        let md = std::fs::metadata(&f).unwrap();
        assert_eq!(md.mode() & 0o7000, 0, "setuid must not be restored");
        assert_eq!(md.mode() & 0o777, 0o755);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn mode_of_and_mtime_of_read_entry_metadata() {
        let f = tmpdir("entry-meta").join("f.bin");
        std::fs::write(&f, b"x").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o640)).unwrap();
        let md = std::fs::metadata(&f).unwrap();
        assert_eq!(mode_of(&md), Some(0o640));
        // setuid 位不进清单：条目只带 0o777 内的位
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o4755)).unwrap();
        let md = std::fs::metadata(&f).unwrap();
        assert_eq!(mode_of(&md), Some(0o755));
        // mtime 是当前时刻附近的 Unix 秒
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let mtime = mtime_of(&md).unwrap();
        assert!((mtime - now).abs() < 60, "mtime {mtime} vs now {now}");
    }

    // 单分量通配（CLI put 本地展开 / agent get 远端匹配共用一份实现）：
    // `*` 任意序列、`?` 精确单字符、按字符而非字节比对
    #[test]
    fn glob_match_covers_tail_component_semantics() {
        assert!(glob_match("*.log", "a.log"));
        assert!(glob_match("*", "anything.txt"));
        assert!(glob_match("a*c", "abc"));
        assert!(glob_match("a*c", "ac")); // * 允许匹配空序列
        assert!(!glob_match("*.log", "a.log.gz"));
        // `?` 精确匹配单个字符
        assert!(glob_match("app-?.log", "app-1.log"));
        assert!(!glob_match("app-?.log", "app-12.log"));
        assert!(!glob_match("a*", "b"));
        // 多字节文件名按字符（而非字节）匹配，`?` 精确吃一个字符
        assert!(glob_match("报表-*.log", "报表-202611.log"));
        assert!(glob_match("周?.log", "周日.log"));
        assert!(!glob_match("周?.log", "周一补.log"));
        assert!(glob_match("é?", "éc"));
    }

    // 目录树接收中途失败（对端断连）时，已开的 `{target}.exvia-tmp-*` 必须被删掉：
    // 该命名不匹配分片清理规则，残留会随反复失败持续积累
    #[tokio::test]
    async fn recv_tree_frames_removes_temp_file_when_transfer_fails_midway() {
        use crate::frame::write_frame;

        let root = tmpdir("recv-tree");
        let (mut io, mut peer) = tokio::io::duplex(64 * 1024);
        let dst = root.clone();
        let task = tokio::spawn(async move {
            let mut warn = |_: &str| {};
            recv_tree_frames(&mut io, &dst, "peer", "write", &mut warn, |_frame| {
                anyhow::anyhow!("peer aborted transfer")
            })
            .await
        });

        // 声明一个 100 字节的文件，只送 10 字节就断开
        write_frame(
            &mut peer,
            &Frame::ctrl(&CtrlMsg::TreeEntryMeta {
                entry: TreeEntry {
                    rel: "f.bin".into(),
                    dir: false,
                    size: 100,
                    mode: None,
                    mtime: None,
                },
            })
            .unwrap(),
        )
        .await
        .unwrap();
        write_frame(&mut peer, &Frame::data(vec![b'x'; 10]))
            .await
            .unwrap();
        drop(peer);

        assert!(
            task.await.unwrap().is_err(),
            "mid-transfer disconnect must fail"
        );
        let left: Vec<String> = std::fs::read_dir(&root)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(left.is_empty(), "temp files left behind: {left:?}");
        let _ = std::fs::remove_dir_all(&root);
    }
}
