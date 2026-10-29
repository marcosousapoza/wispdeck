use anyhow::{Context, Result};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
};
use tokio::fs;

use super::{Config, validation::validate};

pub async fn load_or_create(data_dir: &Path) -> Result<Config> {
    fs::create_dir_all(data_dir)
        .await
        .with_context(|| format!("create {}", data_dir.display()))?;
    let path = data_dir.join("config.toml");
    match load_toml(&path).await {
        Ok(config) => {
            validate(&config)?;
            Ok(config)
        }
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == ErrorKind::NotFound) =>
        {
            let config = Config::default();
            save_toml(&path, &config, false).await?;
            Ok(config)
        }
        Err(error) => Err(error).context("load configuration"),
    }
}

pub async fn load_toml<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).await?;
    toml::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}

pub async fn save_toml<T: Serialize>(path: &Path, value: &T, secret: bool) -> Result<()> {
    let bytes = toml::to_string_pretty(value)?.into_bytes();
    atomic_write(path, &bytes, secret).await
}

pub async fn atomic_write(path: &Path, bytes: &[u8], secret: bool) -> Result<()> {
    let parent = path.parent().context("file has no parent directory")?;
    fs::create_dir_all(parent).await?;
    let temporary = temporary_path(path);
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        options.mode(if secret { 0o600 } else { 0o640 });
    }
    let mut file = options.open(&temporary).await?;
    use tokio::io::AsyncWriteExt;
    file.write_all(bytes).await?;
    file.sync_all().await?;
    drop(file);
    fs::rename(&temporary, path).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            path,
            std::fs::Permissions::from_mode(if secret { 0o600 } else { 0o640 }),
        )
        .await?;
    }
    Ok(())
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_owned();
    value.push(format!(".tmp.{}", uuid::Uuid::new_v4()));
    PathBuf::from(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn toml_round_trip_is_atomic() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        let config = Config::default();
        save_toml(&path, &config, false).await.unwrap();
        let loaded: Config = load_toml(&path).await.unwrap();
        assert_eq!(loaded.policy.allowed_ports, vec![465, 587, 993]);
        assert!(!directory.path().read_dir().unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".tmp.")
        }));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn secret_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("secret.toml");
        save_toml(&path, &Config::default(), true).await.unwrap();
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
