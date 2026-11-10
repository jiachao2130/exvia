// Copyright (c) 2026 Jia Chao
// exvia is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 身份密钥：ed25519（对中继签名认证）+ x25519（Noise DH）。
//!
//! enroll / login 时一次生成，本地落盘 0600；没有导出与同步逻辑，
//! 丢了就重新注册（对中继而言是一台"新机器"）。

use std::path::Path;

use base64::Engine;
use ed25519_dalek::Signer;
use rand::RngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

use crate::Result;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// 私密文件落盘（0600，父目录自动创建）：创建时即设 0600 避免权限窗口，
/// 写完再收紧一次，覆盖文件已存在时带着旧宽松权限的情况。
pub fn write_private(path: &Path, content: &str) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    use std::io::Write as _;
    let mut f = std::fs::OpenOptions::new();
    f.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        f.mode(0o600);
    }
    f.open(path)?.write_all(content.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// 角色无关的身份密钥（agent / cli 共用一套结构）。
#[derive(Clone)]
pub struct Identity {
    signing: ed25519_dalek::SigningKey,
    x_static: XStaticSecret,
}

impl Identity {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);

        let mut x = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut x);
        let x_static = XStaticSecret::from(x);

        Self { signing, x_static }
    }

    /// 机器标识：ed25519 公钥 SHA-256 的前 16 字节 hex（32 字符）。
    pub fn machine_id(&self) -> String {
        let vk = self.signing.verifying_key();
        let hash = Sha256::digest(vk.as_bytes());
        hex::encode(&hash[..16])
    }

    pub fn ed25519_pub_b64(&self) -> String {
        B64.encode(self.signing.verifying_key().as_bytes())
    }

    /// x25519 静态公钥（b64），Noise XX 对端身份 + 指纹固定的对象。
    pub fn x25519_pub_b64(&self) -> String {
        let pk = XPublicKey::from(&self.x_static);
        B64.encode(pk.as_bytes())
    }

    pub fn x25519_pub(&self) -> [u8; 32] {
        *XPublicKey::from(&self.x_static).as_bytes()
    }

    pub fn x25519_private(&self) -> [u8; 32] {
        self.x_static.to_bytes()
    }

    /// 对消息做 ed25519 签名（b64），用于挑战应答。
    pub fn sign_b64(&self, msg: &[u8]) -> String {
        B64.encode(self.signing.sign(msg).to_bytes())
    }

    pub fn verify_b64(pub_b64: &str, msg: &[u8], sig_b64: &str) -> Result<()> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let pub_bytes = B64.decode(pub_b64)?;
        let vk = VerifyingKey::from_bytes(
            pub_bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid public key length"))?,
        )?;
        let sig = Signature::from_slice(&B64.decode(sig_b64)?)?;
        vk.verify(msg, &sig)
            .map_err(|_| anyhow::anyhow!("signature verification failed"))
    }

    /// 导出为两段 b64（ed25519 种子 / x25519 私钥），供身份文件嵌入。
    pub fn export_parts(&self) -> (String, String) {
        (
            B64.encode(self.signing.to_bytes()),
            B64.encode(self.x_static.to_bytes()),
        )
    }

    pub fn import_parts(ed_seed_b64: &str, x25519_b64: &str) -> Result<Self> {
        let seed: [u8; 32] = B64
            .decode(ed_seed_b64)?
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid ed25519 seed length"))?;
        let x: [u8; 32] = B64
            .decode(x25519_b64)?
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid x25519 private key length"))?;
        Ok(Self {
            signing: ed25519_dalek::SigningKey::from_bytes(&seed),
            x_static: XStaticSecret::from(x),
        })
    }
}

/// 指纹：字节流的 SHA-256 hex（证书指纹 / 对端公钥指纹统一用它）。
pub fn fingerprint(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let id = Identity::generate();
        let msg = b"challenge nonce";
        let sig = id.sign_b64(msg);
        Identity::verify_b64(&id.ed25519_pub_b64(), msg, &sig).unwrap();
        assert!(Identity::verify_b64(&id.ed25519_pub_b64(), b"tampered", &sig).is_err());
    }
}
