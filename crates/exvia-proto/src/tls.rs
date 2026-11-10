// Copyright (c) 2026 Jia Chao
// exvia is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! TLS：中继自签证书 + 两端指纹固定（不依赖第三方 CA）。
//!
//! - 中继首次启动生成自签证书并持久化，指纹打印出来供注册/登录时比对
//! - agent / cli 用 `pinned_client_config` 固定中继证书指纹，
//!   任何指纹不符的连接立即失败（比公共 CA 校验更强的中间人防护）

use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ServerConfig};

use crate::keys::fingerprint;
use crate::Result;

/// 证书旁挂的元数据。用于回答"这张证书什么时候到期"——
/// 手写 X.509 解析只为一个字段不值当，且容易在边界格式上出错。
///
/// 老部署没有这个文件：那时证书是"永不过期"的（rcgen 默认到 4096 年），
/// 读到 `None` 就当作"未知"，不做任何提醒。
const CERT_META_FILE: &str = "relay-cert.json";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CertMeta {
    /// 生成时间 / 到期时间，Unix 秒
    pub not_before: i64,
    pub not_after: i64,
    /// 证书里的 CN/SAN，轮换后变化便于追溯
    pub subject: String,
}

impl CertMeta {
    /// 距到期还有多少天；负数表示已过期。
    pub fn days_left(&self, now: i64) -> i64 {
        (self.not_after - now) / 86_400
    }

    /// 到期提醒文案。30 天内或已过期才返回内容。
    pub fn warning(&self, now: i64) -> Option<String> {
        let days = self.days_left(now);
        if days < 0 {
            return Some(format!(
                "relay certificate EXPIRED {} day(s) ago: TLS pinning still works, but plan a rotation \
                 (bump --cert-validity-days, replace relay-cert.pem/relay-key.pem, then re-pin every CLI and agent)",
                -days
            ));
        }
        if days <= 30 {
            return Some(format!(
                "relay certificate expires in {days} day(s): rotation changes the fingerprint and \
                 requires re-pinning every CLI and agent"
            ));
        }
        None
    }
}

fn read_meta(data_dir: &Path) -> Option<CertMeta> {
    let raw = std::fs::read_to_string(data_dir.join(CERT_META_FILE)).ok()?;
    serde_json::from_str(&raw).ok()
}

fn write_meta(data_dir: &Path, meta: &CertMeta) -> std::io::Result<()> {
    let path = data_dir.join(CERT_META_FILE);
    let body = serde_json::to_vec_pretty(meta).unwrap_or_default();
    // 与其它私密文件一致：先写临时文件再改名，避免半截 JSON
    let tmp = data_dir.join(format!("{CERT_META_FILE}.tmp"));
    {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new();
        f.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            f.mode(0o644);
        }
        let mut f = f.open(&tmp)?;
        f.write_all(&body)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, &path)
}

/// 证书与到期信息。`meta` 为 None 表示老部署（没有元数据文件）。
pub struct LoadedCert {
    pub certs: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
    pub fingerprint: String,
    pub meta: Option<CertMeta>,
}

/// 生成（或加载）中继自签证书。
///
/// `cert_name` 部署可配置，避免 TLS 扫描器靠 CN/SAN 直接判定服务身份；
/// 已有证书文件保持原样加载，不受改名影响。
///
/// `validity_days` 只影响**新生成**的证书；已有证书不会因为参数变化被重建，
/// 否则每次调参都会静默换指纹、把所有客户端踢下线。
pub fn load_or_create_cert(
    data_dir: &Path,
    cert_name: &str,
    validity_days: u32,
) -> Result<LoadedCert> {
    let cert_name = cert_name.trim();
    if cert_name.is_empty() || cert_name.len() > 253 || cert_name.contains('\0') {
        anyhow::bail!("invalid cert name (1..=253 chars, no NUL)");
    }
    if validity_days == 0 {
        anyhow::bail!("cert validity must be at least 1 day");
    }
    let cert_path = data_dir.join("relay-cert.pem");
    let key_path = data_dir.join("relay-key.pem");
    if cert_path.exists() && key_path.exists() {
        let cert_pem = std::fs::read(&cert_path)?;
        let key_pem = std::fs::read(&key_path)?;
        let certs = rustls_pemfile::certs(&mut &cert_pem[..])
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if certs.is_empty() {
            anyhow::bail!("cert file empty: {}", cert_path.display());
        }
        let fp = fingerprint(&certs[0]);
        let key = rustls_pemfile::private_key(&mut &key_pem[..])?
            .ok_or_else(|| anyhow::anyhow!("private key file empty: {}", key_path.display()))?;
        return Ok(LoadedCert {
            certs,
            key,
            fingerprint: fp,
            meta: read_meta(data_dir),
        });
    }
    std::fs::create_dir_all(data_dir)?;
    let key_pair = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::new(vec![cert_name.to_string()])?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cert_name);
    // 有效期：从当前时刻起算。留 1 小时 backdate 容忍时钟偏差，
    // 否则明显偏慢的机器会因为 not_before 在未来而拒绝这张证书。
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::hours(1);
    params.not_after = now + time::Duration::days(validity_days as i64);
    let cert = params.self_signed(&key_pair)?;
    std::fs::write(&cert_path, cert.pem())?;
    use std::io::Write as _;
    let mut kf = std::fs::OpenOptions::new();
    kf.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        kf.mode(0o600);
    }
    kf.open(&key_path)?
        .write_all(key_pair.serialize_pem().as_bytes())?;
    let der = cert.der();
    let fp = fingerprint(der.as_ref());
    let certs = vec![der.clone()];
    let key = PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        key_pair.serialize_der(),
    ));
    let meta = CertMeta {
        not_before: params.not_before.unix_timestamp(),
        not_after: params.not_after.unix_timestamp(),
        subject: cert_name.to_string(),
    };
    if let Err(e) = write_meta(data_dir, &meta) {
        // 元数据只是运维便利信息，写不进去不该让中继起不来
        tracing::warn!("cannot write {CERT_META_FILE}: {e}");
    }
    Ok(LoadedCert {
        certs,
        key,
        fingerprint: fp,
        meta: Some(meta),
    })
}

/// 校验并规范化中继证书指纹：剥掉分隔符等非 hex 字符，要求剩余恰为 64 位
/// （SHA-256），统一小写返回。agent enroll 与 CLI login 共用同一规则。
pub fn normalize_fingerprint(fp: &str) -> anyhow::Result<String> {
    let cleaned: String = fp.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if cleaned.len() != 64 {
        anyhow::bail!("invalid fingerprint (expected 64 hex chars): {fp}");
    }
    Ok(cleaned.to_lowercase())
}

/// 服务端 TLS 配置（不要求客户端证书；客户端身份由挑战签名完成）。
pub fn server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>> {
    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(Arc::new(cfg))
}

/// 客户端 TLS 配置：固定服务器证书指纹（TOFU/带外比对），不做 CA 链校验。
pub fn pinned_client_config(cert_fingerprint_hex: &str) -> Result<Arc<ClientConfig>> {
    let verifier = PinVerifier {
        fp: cert_fingerprint_hex.to_lowercase(),
    };
    let cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// 指纹固定验证器：证书 SHA-256（hex）与预期一致才放行。
#[derive(Debug)]
struct PinVerifier {
    fp: String,
}

impl rustls::client::danger::ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let got = fingerprint(end_entity.as_ref());
        if got == self.fp {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "relay cert fingerprint mismatch (expected {}, got {got})",
                self.fp
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(days: i64, now: i64) -> CertMeta {
        CertMeta {
            not_before: now - 86_400,
            not_after: now + days * 86_400,
            subject: "cdn.example.com".into(),
        }
    }

    #[test]
    fn cert_expiry_warning_only_near_or_past_the_deadline() {
        let now = 1_800_000_000;
        // 一年、一个月零一天：不吵
        assert!(meta(365, now).warning(now).is_none());
        assert!(meta(31, now).warning(now).is_none());
        // 30 天以内开始提醒，文案要带天数
        let w = meta(30, now).warning(now).expect("should warn at 30 days");
        assert!(w.contains("expires in 30 day"), "{w}");
        assert!(meta(1, now).warning(now).is_some());
        // 已过期：说清楚"已过期多久"以及指纹仍可用
        let w = meta(-5, now)
            .warning(now)
            .expect("should warn when expired");
        assert!(w.contains("EXPIRED 5 day"), "{w}");
        assert!(w.contains("pin"), "{w}");
    }

    #[test]
    fn days_left_rounds_toward_zero_not_up() {
        let now = 1_800_000_000;
        // 差 1 小时到期：算 0 天，仍进提醒分支
        let m = CertMeta {
            not_before: now - 86_400,
            not_after: now + 3_600,
            subject: "x".into(),
        };
        assert_eq!(m.days_left(now), 0);
        assert!(m.warning(now).is_some());
    }

    // enroll/login 输入的指纹允许带分隔符、大小写混排：剥非 hex 后须恰为 64 位
    #[test]
    fn normalize_fingerprint_strips_separators_and_rejects_wrong_length() {
        let hex = "a1b2c3d4".repeat(8); // 64 hex chars
                                        // 冒号分隔 + 大写 → 统一小写
        let dashed: String = (0..hex.len() / 2)
            .map(|i| hex[i * 2..i * 2 + 2].to_ascii_uppercase())
            .collect::<Vec<_>>()
            .join(":");
        assert_eq!(normalize_fingerprint(&dashed).unwrap(), hex);
        // 非 hex 字符（z、空格）被剥掉，不影响判定
        assert_eq!(normalize_fingerprint(&format!(" {hex} ")).unwrap(), hex);
        // 长度不对（差一位、空串）一律拒绝
        assert!(normalize_fingerprint(&hex[..63]).is_err());
        assert!(normalize_fingerprint("").is_err());
    }
}
