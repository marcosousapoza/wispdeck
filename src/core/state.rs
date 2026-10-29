use std::{collections::VecDeque, path::PathBuf, sync::Arc, time::Instant};

use tokio::sync::{RwLock, Semaphore};

use crate::{
    auth::{admin::AdminAuth, wisp::WispUsers},
    config::Config,
    core::{metrics::Metrics, sessions::SessionRegistry},
    protocol::{BackendInfo, ProtocolBackend},
};

pub struct AppState {
    pub data_dir: PathBuf,
    pub started: Instant,
    pub config: RwLock<Config>,
    pub metrics: Arc<Metrics>,
    pub sessions: Arc<SessionRegistry>,
    pub admin_auth: AdminAuth,
    pub wisp_users: WispUsers,
    pub client_slots: Arc<Semaphore>,
    pub dial_slots: Arc<Semaphore>,
    pub recent_errors: RwLock<VecDeque<String>>,
    pub backend: BackendInfo,
    pub protocol_backend: Arc<dyn ProtocolBackend>,
}

impl AppState {
    pub async fn record_error(&self, message: impl Into<String>) {
        let mut errors = self.recent_errors.write().await;
        if errors.len() == 20 {
            errors.pop_back();
        }
        errors.push_front(message.into());
    }
}
