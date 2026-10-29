use std::{collections::HashMap, sync::Arc};

use serde::Serialize;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Clone, Serialize)]
pub struct SessionView {
    pub id: String,
    pub user: String,
    pub peer: String,
    pub streams: usize,
}

struct SessionEntry {
    view: SessionView,
    cancel: CancellationToken,
}

#[derive(Default)]
pub struct SessionRegistry {
    inner: RwLock<HashMap<String, SessionEntry>>,
}

pub struct SessionGuard {
    id: String,
    registry: Arc<SessionRegistry>,
}

impl SessionGuard {
    pub fn id(&self) -> &str {
        &self.id
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        let id = self.id.clone();
        let registry = Arc::clone(&self.registry);
        tokio::spawn(async move {
            registry.inner.write().await.remove(&id);
        });
    }
}

impl SessionRegistry {
    pub async fn register(
        self: &Arc<Self>,
        user: String,
        peer: String,
    ) -> (SessionGuard, CancellationToken) {
        let id = Uuid::new_v4().to_string();
        let cancel = CancellationToken::new();
        self.inner.write().await.insert(
            id.clone(),
            SessionEntry {
                view: SessionView {
                    id: id.clone(),
                    user,
                    peer,
                    streams: 0,
                },
                cancel: cancel.clone(),
            },
        );
        (
            SessionGuard {
                id,
                registry: Arc::clone(self),
            },
            cancel,
        )
    }

    pub async fn list(&self) -> Vec<SessionView> {
        self.inner
            .read()
            .await
            .values()
            .map(|entry| entry.view.clone())
            .collect()
    }

    pub async fn stream_opened(&self, id: &str) {
        if let Some(entry) = self.inner.write().await.get_mut(id) {
            entry.view.streams += 1;
        }
    }

    pub async fn stream_closed(&self, id: &str) {
        if let Some(entry) = self.inner.write().await.get_mut(id) {
            entry.view.streams = entry.view.streams.saturating_sub(1);
        }
    }

    pub async fn disconnect(&self, id: &str) -> bool {
        if let Some(entry) = self.inner.read().await.get(id) {
            entry.cancel.cancel();
            true
        } else {
            false
        }
    }

    pub async fn disconnect_user(&self, user: &str) {
        for entry in self
            .inner
            .read()
            .await
            .values()
            .filter(|entry| entry.view.user == user)
        {
            entry.cancel.cancel();
        }
    }
}
