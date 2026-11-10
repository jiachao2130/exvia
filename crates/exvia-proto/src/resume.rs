// Copyright (c) 2026 Jia Chao
// exvia is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 断点续传的分片文件命名与续传点选择。
//!
//! 分片一律落在目标文件旁边（`<目标名>.exvia-part[-<内容哈希前缀>]`），成功后才原子改名：
//! - `put`：分片名带内容 SHA-256 前缀，不同内容的半截文件不会互相复用；
//! - `get`：CLI 在拿到远端 sha 之前就要决定起点，故不带哈希，靠传输末尾的整文件校验兜底。
//!
//! 这两条都只影响“复用哪一段”，不影响正确性：整文件 SHA-256 不匹配就丢弃分片，
//! 绝不会把半截内容改名成正式文件。

use std::path::{Path, PathBuf};

/// 分片文件名的公共前缀。
fn part_prefix(dest: &Path) -> String {
    let name = dest
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_string());
    format!("{name}.exvia-part")
}

/// 分片文件路径。`tag`（通常是用内容哈希）会先过滤成 `[A-Za-z0-9]` 再截断，
/// 防止对端送来的字符串里带 `/` 或 `..` 把分片写到别的目录去。
pub fn part_path(dest: &Path, tag: Option<&str>) -> PathBuf {
    let prefix = part_prefix(dest);
    let name = match tag.map(short_tag).filter(|t| !t.is_empty()) {
        Some(t) => format!("{prefix}-{t}"),
        None => prefix,
    };
    dest.with_file_name(name)
}

fn short_tag(tag: &str) -> String {
    tag.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(16)
        .collect::<String>()
        .to_ascii_lowercase()
}

/// 分片能否复用：非空且不超过目标长度。超长或空的分片返回 0（从头传）。
pub fn resume_from(existing_len: Option<u64>, total: u64) -> u64 {
    match existing_len {
        Some(n) if n > 0 && n <= total => n,
        _ => 0,
    }
}

/// 读出 `upto` 字节并返回 `(实际读到的字节数, 哈希)`。
///
/// 续传要把已有的前缀并进整文件 SHA-256，而摘要状态无法跨进程传递，只能重读一遍。
/// 文件比 `upto` 短时第一个返回值会小于 `upto`，调用方据此判断分片是否可用。
pub async fn hash_prefix(path: &Path, upto: u64) -> anyhow::Result<(u64, sha2::Sha256)> {
    use sha2::{Digest, Sha256};
    use tokio::io::AsyncReadExt as _;
    let mut f = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    let mut read: u64 = 0;
    while read < upto {
        let want = ((upto - read) as usize).min(buf.len());
        let n = f.read(&mut buf[..want]).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        read += n as u64;
    }
    Ok((read, hasher))
}

/// `candidate` 是否属于 `dest` 的分片（用于清理同目录下的陈旧分片）。
///
/// 必须精确匹配 [`part_path`] 能产生的两种形态：`{name}.exvia-part` 与
/// `{name}.exvia-part-{tag}`（tag 是 `short_tag` 的产物：1..=16 个小写字母数字）。
/// 裸前缀匹配会把 `data.exvia-part-old.md` 这类真实用户文件一并删掉。
pub fn is_part_of(dest: &Path, candidate: &Path) -> bool {
    let Some(name) = candidate.file_name() else {
        return false;
    };
    let lossy = name.to_string_lossy();
    let Some(rest) = lossy.strip_prefix(part_prefix(dest).as_str()) else {
        return false;
    };
    match rest.strip_prefix('-') {
        // 无 tag 形态
        None => rest.is_empty(),
        Some(tag) => {
            !tag.is_empty()
                && tag.len() <= 16
                && tag
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn part_path_keeps_destination_directory() {
        let dest = Path::new("/var/tmp/a/big.iso");
        assert_eq!(
            part_path(dest, Some("deadbeefcafebabe00112233")),
            Path::new("/var/tmp/a/big.iso.exvia-part-deadbeefcafebabe")
        );
        assert_eq!(
            part_path(dest, None),
            Path::new("/var/tmp/a/big.iso.exvia-part")
        );
    }

    #[test]
    fn part_tag_is_sanitized() {
        // 对端送来的 tag 不可信：路径分隔符与 `..` 都不能改变落盘位置。
        let dest = Path::new("/data/f");
        let p = part_path(dest, Some("../../etc/passwd"));
        assert_eq!(p.parent(), Some(Path::new("/data")));
        assert!(p
            .file_name()
            .unwrap()
            .to_string_lossy()
            .ends_with("etcpasswd"));
    }

    #[test]
    fn resume_point_matrix() {
        assert_eq!(resume_from(Some(0), 100), 0, "空分片没有意义");
        assert_eq!(resume_from(None, 100), 0);
        assert_eq!(resume_from(Some(40), 100), 40);
        assert_eq!(resume_from(Some(100), 100), 100, "完整分片可直接收尾");
        assert_eq!(resume_from(Some(101), 100), 0, "超长分片必须重来");
        assert_eq!(resume_from(Some(10), 0), 0, "空文件不存在续传");
    }

    #[test]
    fn part_matching_is_scoped_to_destination() {
        let dest = Path::new("/d/a.bin");
        assert!(is_part_of(dest, Path::new("/d/a.bin.exvia-part")));
        assert!(is_part_of(
            dest,
            Path::new("/d/a.bin.exvia-part-0123456789abcdef")
        ));
        assert!(!is_part_of(dest, Path::new("/d/b.bin.exvia-part")));
        assert!(!is_part_of(dest, Path::new("/d/a.bin")));
    }

    #[test]
    fn part_matching_requires_exact_part_shape() {
        let dest = Path::new("/d/a.bin");
        // 两种合法分片形态：无 tag 与内容哈希 tag
        assert!(is_part_of(dest, Path::new("/d/a.bin.exvia-part")));
        assert!(is_part_of(
            dest,
            Path::new("/d/a.bin.exvia-part-0123456789abcdef")
        ));
        assert!(is_part_of(dest, Path::new("/d/a.bin.exvia-part-ab12cd34")));
        // 裸前缀匹配会误删真实用户文件
        assert!(!is_part_of(dest, Path::new("/d/a.bin.exvia-part-old.md")));
        assert!(!is_part_of(dest, Path::new("/d/a.bin.exvia-partX")));
        assert!(!is_part_of(dest, Path::new("/d/a.bin.exvia.part")));
        // tag 段必须符合 short_tag 的落盘规则：1..=16 个小写字母数字
        assert!(!is_part_of(dest, Path::new("/d/a.bin.exvia-part-")));
        assert!(!is_part_of(
            dest,
            Path::new("/d/a.bin.exvia-part-ABCDEF0123456789")
        ));
        assert!(!is_part_of(
            dest,
            Path::new("/d/a.bin.exvia-part-0123456789abcdef0")
        ));
        assert!(!is_part_of(dest, Path::new("/d/a.bin.exvia-part-a.b")));
    }

    /// 不变式：`part_path` 的任何产物（含不可信 tag 被过滤后的形态）都必须被
    /// `is_part_of` 识别，否则成功收尾后会漏掉本该清理的陈旧分片。
    #[test]
    fn part_path_output_is_always_matched_by_is_part_of() {
        let dest = Path::new("/d/a.bin");
        for tag in [
            None,
            Some("deadbeefcafebabe00112233"),
            Some("../etc/passwd"),
            Some("--x"),
            Some("!!!"),
        ] {
            let p = part_path(dest, tag);
            assert!(is_part_of(dest, &p), "{} should be recognized", p.display());
        }
    }
}
