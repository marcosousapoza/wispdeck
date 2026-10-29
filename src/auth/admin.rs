use std::{
    collections::HashMap,
    env,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;

use crate::config::storage::{load_toml, save_toml};

const CREDENTIALS_FILE: &str = "admin-credentials.toml";

#[derive(Serialize, Deserialize)]
struct AdminCredentials {
    password_hash: String,
    changed_unix_seconds: u64,
}

struct Session {
    csrf: String,
    expires: Instant,
    generation: u64,
}
struct FailedLogin {
    attempts: u32,
    blocked_until: Option<Instant>,
}

#[derive(Clone)]
pub struct AdminAuth {
    inner: Arc<Mutex<AdminAuthInner>>,
    credentials_path: PathBuf,
    session_duration: Duration,
}

struct AdminAuthInner {
    password_hash: String,
    generation: u64,
    sessions: HashMap<String, Session>,
    failures: HashMap<String, FailedLogin>,
}

#[derive(Clone)]
pub struct VerifiedSession {
    pub csrf: String,
}

impl AdminAuth {
    pub async fn initialize(data_dir: &Path, session_minutes: u64) -> Result<Self> {
        let path = data_dir.join(CREDENTIALS_FILE);
        let credentials = match load_toml::<AdminCredentials>(&path).await {
            Ok(credentials) => credentials,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                let password = env::var("WISP_ADMIN_PASSWORD").context(
                    "administrator credentials do not exist; set nonempty WISP_ADMIN_PASSWORD for first startup",
                )?;
                validate_password(&password)?;
                let credentials = new_credentials(&password)?;
                save_toml(&path, &credentials, true).await?;
                credentials
            }
            Err(error) => return Err(error).context("load administrator credentials"),
        };
        PasswordHash::new(&credentials.password_hash).map_err(|error| {
            anyhow::anyhow!("invalid persisted administrator password hash: {error}")
        })?;
        Ok(Self {
            inner: Arc::new(Mutex::new(AdminAuthInner {
                password_hash: credentials.password_hash,
                generation: 0,
                sessions: HashMap::new(),
                failures: HashMap::new(),
            })),
            credentials_path: path,
            session_duration: Duration::from_secs(session_minutes * 60),
        })
    }

    pub async fn login(
        &self,
        password: &str,
        source: &str,
    ) -> Result<Option<(String, VerifiedSession)>> {
        let hash = {
            let mut inner = self.inner.lock().await;
            let failure = inner
                .failures
                .entry(source.to_owned())
                .or_insert(FailedLogin {
                    attempts: 0,
                    blocked_until: None,
                });
            if failure
                .blocked_until
                .is_some_and(|until| until > Instant::now())
            {
                return Ok(None);
            }
            inner.password_hash.clone()
        };
        let valid = verify_hash(&hash, password);
        let mut inner = self.inner.lock().await;
        if !valid {
            let failure = inner
                .failures
                .entry(source.to_owned())
                .or_insert(FailedLogin {
                    attempts: 0,
                    blocked_until: None,
                });
            failure.attempts = failure.attempts.saturating_add(1);
            if failure.attempts >= 5 {
                failure.blocked_until = Some(Instant::now() + Duration::from_secs(60));
            }
            return Ok(None);
        }
        inner.failures.remove(source);
        let token = random_token();
        let csrf = random_token();
        let generation = inner.generation;
        inner.sessions.insert(
            token.clone(),
            Session {
                csrf: csrf.clone(),
                expires: Instant::now() + self.session_duration,
                generation,
            },
        );
        Ok(Some((token, VerifiedSession { csrf })))
    }

    pub async fn verify(&self, token: &str) -> Option<VerifiedSession> {
        let mut inner = self.inner.lock().await;
        let generation = inner.generation;
        inner.sessions.retain(|_, session| {
            session.expires > Instant::now() && session.generation == generation
        });
        inner.sessions.get(token).map(|session| VerifiedSession {
            csrf: session.csrf.clone(),
        })
    }

    pub async fn verify_csrf(&self, token: &str, supplied: &str) -> bool {
        self.verify(token)
            .await
            .is_some_and(|session| constant_time_equal(&session.csrf, supplied))
    }

    pub async fn logout(&self, token: &str) {
        self.inner.lock().await.sessions.remove(token);
    }

    pub async fn change_password(&self, current: &str, new_password: &str) -> Result<bool> {
        let current_hash = self.inner.lock().await.password_hash.clone();
        if !verify_hash(&current_hash, current) {
            return Ok(false);
        }
        validate_password(new_password)?;
        let credentials = new_credentials(new_password)?;
        save_toml(&self.credentials_path, &credentials, true).await?;
        let mut inner = self.inner.lock().await;
        inner.password_hash = credentials.password_hash;
        inner.generation = inner.generation.wrapping_add(1);
        inner.sessions.clear();
        Ok(true)
    }
}

pub async fn reset_password(data_dir: &Path, password: &str) -> Result<()> {
    validate_password(password)?;
    save_toml(
        &data_dir.join(CREDENTIALS_FILE),
        &new_credentials(password)?,
        true,
    )
    .await
}

fn validate_password(password: &str) -> Result<()> {
    ensure!(
        password.len() >= 12,
        "administrator password must contain at least 12 characters"
    );
    ensure!(password.len() <= 1024, "administrator password is too long");
    ensure!(
        !password.trim().is_empty(),
        "administrator password must not be blank"
    );
    Ok(())
}

fn argon2() -> Result<Argon2<'static>> {
    let params = Params::new(19_456, 2, 1, None)
        .map_err(|error| anyhow::anyhow!("invalid Argon2 parameters: {error}"))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

fn new_credentials(password: &str) -> Result<AdminCredentials> {
    let mut salt_bytes = [0_u8; 16];
    rand::rng().fill_bytes(&mut salt_bytes);
    let salt = SaltString::encode_b64(&salt_bytes)
        .map_err(|error| anyhow::anyhow!("salt encoding failed: {error}"))?;
    let password_hash = argon2()?
        .hash_password(password.as_bytes(), &salt)
        .map_err(|error| anyhow::anyhow!("password hashing failed: {error}"))?
        .to_string();
    Ok(AdminCredentials {
        password_hash,
        changed_unix_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    })
}

fn verify_hash(encoded: &str, password: &str) -> bool {
    let Ok(hash) = PasswordHash::new(encoded) else {
        return false;
    };
    argon2().is_ok_and(|a| a.verify_password(password.as_bytes(), &hash).is_ok())
}

fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
fn constant_time_equal(left: &str, right: &str) -> bool {
    left.as_bytes().ct_eq(right.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn existing_credentials_ignore_bootstrap_environment() {
        let directory = tempfile::tempdir().unwrap();
        reset_password(directory.path(), "correct horse battery")
            .await
            .unwrap();
        unsafe { env::set_var("WISP_ADMIN_PASSWORD", "different bootstrap password") };
        let auth = AdminAuth::initialize(directory.path(), 30).await.unwrap();
        assert!(
            auth.login("correct horse battery", "test")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            auth.login("different bootstrap password", "other")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn changing_password_invalidates_sessions() {
        let directory = tempfile::tempdir().unwrap();
        reset_password(directory.path(), "correct horse battery")
            .await
            .unwrap();
        let auth = AdminAuth::initialize(directory.path(), 30).await.unwrap();
        let (token, _) = auth
            .login("correct horse battery", "test")
            .await
            .unwrap()
            .unwrap();
        assert!(
            auth.change_password("correct horse battery", "new correct horse battery")
                .await
                .unwrap()
        );
        assert!(auth.verify(&token).await.is_none());
    }

    #[tokio::test]
    async fn csrf_is_bound_to_the_session() {
        let directory = tempfile::tempdir().unwrap();
        reset_password(directory.path(), "correct horse battery")
            .await
            .unwrap();
        let auth = AdminAuth::initialize(directory.path(), 30).await.unwrap();
        let (token, session) = auth
            .login("correct horse battery", "test")
            .await
            .unwrap()
            .unwrap();
        assert!(auth.verify_csrf(&token, &session.csrf).await);
        assert!(!auth.verify_csrf(&token, "not-the-token").await);
    }
}
