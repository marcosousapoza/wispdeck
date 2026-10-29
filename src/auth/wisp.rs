use std::{
    collections::HashMap,
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, ensure};
use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHasher, SaltString},
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::config::storage::{load_toml, save_toml};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WispUser {
    pub username: String,
    pub enabled: bool,
}

#[derive(Default, Deserialize, Serialize)]
struct UserFile {
    users: Vec<WispUser>,
}

#[derive(Default, Deserialize, Serialize)]
struct SecretFile {
    password_hashes: HashMap<String, String>,
}

#[derive(Clone)]
pub struct WispUsers {
    users: Arc<RwLock<Vec<WispUser>>>,
    secrets: Arc<RwLock<HashMap<String, String>>>,
    users_path: PathBuf,
    secrets_path: PathBuf,
}

impl WispUsers {
    pub async fn load(data_dir: &Path) -> Result<Self> {
        let users_path = data_dir.join("wisp-users.toml");
        let secrets_path = data_dir.join("wisp-user-secrets.toml");
        let users = load_or_default::<UserFile>(&users_path).await?.users;
        let secrets = load_or_default::<SecretFile>(&secrets_path)
            .await?
            .password_hashes;
        Ok(Self {
            users: Arc::new(RwLock::new(users)),
            secrets: Arc::new(RwLock::new(secrets)),
            users_path,
            secrets_path,
        })
    }

    pub async fn list(&self) -> Vec<WispUser> {
        self.users.read().await.clone()
    }

    pub async fn enabled_password_hashes(&self) -> HashMap<String, String> {
        let users = self.users.read().await;
        let secrets = self.secrets.read().await;
        users
            .iter()
            .filter(|user| user.enabled)
            .filter_map(|user| {
                secrets
                    .get(&user.username)
                    .map(|password| (user.username.clone(), password.clone()))
            })
            .collect()
    }

    pub async fn add_or_reset(&self, username: String, password: String) -> Result<()> {
        validate_username(&username)?;
        validate_password(&password)?;
        let mut users = self.users.write().await;
        let mut secrets = self.secrets.write().await;
        if let Some(user) = users.iter_mut().find(|user| user.username == username) {
            user.enabled = true;
        } else {
            users.push(WispUser {
                username: username.clone(),
                enabled: true,
            });
            users.sort_by(|a, b| a.username.cmp(&b.username));
        }
        let mut salt_bytes = [0_u8; 16];
        rand::rng().fill_bytes(&mut salt_bytes);
        let salt = SaltString::encode_b64(&salt_bytes)
            .map_err(|error| anyhow::anyhow!("salt encoding failed: {error}"))?;
        let params = Params::new(19_456, 2, 1, None)
            .map_err(|error| anyhow::anyhow!("invalid Argon2 parameters: {error}"))?;
        let hash = Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password(password.as_bytes(), &salt)
            .map_err(|error| anyhow::anyhow!("password hashing failed: {error}"))?
            .to_string();
        secrets.insert(username, hash);
        persist(&self.users_path, &self.secrets_path, &users, &secrets).await
    }

    pub async fn disable(&self, username: &str) -> Result<bool> {
        let mut users = self.users.write().await;
        let Some(user) = users.iter_mut().find(|user| user.username == username) else {
            return Ok(false);
        };
        user.enabled = false;
        let secrets = self.secrets.read().await;
        persist(&self.users_path, &self.secrets_path, &users, &secrets).await?;
        Ok(true)
    }

    pub async fn remove(&self, username: &str) -> Result<bool> {
        let mut users = self.users.write().await;
        let original = users.len();
        users.retain(|user| user.username != username);
        if original == users.len() {
            return Ok(false);
        }
        let mut secrets = self.secrets.write().await;
        secrets.remove(username);
        persist(&self.users_path, &self.secrets_path, &users, &secrets).await?;
        Ok(true)
    }
}

async fn persist(
    users_path: &Path,
    secrets_path: &Path,
    users: &[WispUser],
    secrets: &HashMap<String, String>,
) -> Result<()> {
    save_toml(
        secrets_path,
        &SecretFile {
            password_hashes: secrets.clone(),
        },
        true,
    )
    .await?;
    save_toml(
        users_path,
        &UserFile {
            users: users.to_vec(),
        },
        false,
    )
    .await
}

async fn load_or_default<T: serde::de::DeserializeOwned + Default>(path: &Path) -> Result<T> {
    match load_toml(path).await {
        Ok(value) => Ok(value),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == ErrorKind::NotFound) =>
        {
            Ok(T::default())
        }
        Err(error) => Err(error).with_context(|| format!("load {}", path.display())),
    }
}

fn validate_username(value: &str) -> Result<()> {
    ensure!(
        (1..=64).contains(&value.len()),
        "username must contain 1..=64 characters"
    );
    ensure!(
        value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'@')),
        "username contains unsupported characters"
    );
    Ok(())
}
fn validate_password(value: &str) -> Result<()> {
    ensure!(
        (12..=255).contains(&value.len()),
        "Wisp password must contain 12..=255 bytes"
    );
    Ok(())
}
