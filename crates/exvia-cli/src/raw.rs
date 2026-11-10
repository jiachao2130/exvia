// Copyright (c) 2026 Jia Chao
// exvia is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 终端 raw mode（RAII，Drop 还原）

pub struct RawGuard {
    original: libc::termios,
}

impl RawGuard {
    pub fn enable() -> anyhow::Result<Self> {
        unsafe {
            // 非 tty（管道/重定向）跳过 raw mode，保留流水线可测试性
            if libc::isatty(0) != 1 {
                return Ok(Self {
                    original: std::mem::zeroed(),
                });
            }
            let mut original: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(0, &mut original) != 0 {
                anyhow::bail!("tcgetattr failed (stdin is not a tty?)");
            }
            let mut raw = original;
            libc::cfmakeraw(&mut raw);
            // 保留 OPOST（输出后处理），让 \n 正常换行
            raw.c_oflag |= libc::OPOST;
            if libc::tcsetattr(0, libc::TCSANOW, &raw) != 0 {
                anyhow::bail!("tcsetattr failed");
            }
            Ok(Self { original })
        }
    }
}

impl Drop for RawGuard {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(0, libc::TCSANOW, &self.original);
        }
    }
}
