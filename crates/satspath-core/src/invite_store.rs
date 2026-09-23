//! Persistent storage for SatsPath invites and claim notifications.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::profile::{ClaimNotification, InviteRecord, InviteStatus};
use crate::validation::assert_no_private_material;

pub const INVITES_FILE: &str = "invites.json";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct InviteStorage {
    #[serde(default)]
    invites: HashMap<String, InviteRecord>,
    #[serde(default)]
    notifications: Vec<ClaimNotification>,
}

/// Thread-safe and persistent invite store for daemon and CLI operations.
#[derive(Debug, Clone)]
pub struct InviteStore {
    path: PathBuf,
    storage: InviteStorage,
}

impl InviteStore {
    /// Open the invite store located at `home/invites.json`.
    pub fn open(home: &Path) -> Result<Self> {
        fs::create_dir_all(home).with_context(|| format!("creating dir {}", home.display()))?;
        let path = home.join(INVITES_FILE);
        let storage = if path.exists() {
            let data = fs::read_to_string(&path)
                .with_context(|| format!("reading invites file {}", path.display()))?;
            serde_json::from_str(&data)
                .with_context(|| format!("parsing invites json from {}", path.display()))?
        } else {
            InviteStorage::default()
        };

        Ok(Self { path, storage })
    }

    /// Persist the invite storage to disk atomically with owner-only permissions.
    pub fn save(&self) -> Result<()> {
        let json = serde_json::to_string_pretty(&self.storage)
            .context("serializing invite storage to JSON")?;
        assert_no_private_material(&json)?;

        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;

        let mut rand_bytes = [0u8; 16];
        secp256k1::rand::RngCore::fill_bytes(&mut secp256k1::rand::thread_rng(), &mut rand_bytes);
        let tmp_path = parent.join(format!(".tmp-invites-{}", hex::encode(rand_bytes)));

        #[cfg(unix)]
        {
            use std::fs::OpenOptions;
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&tmp_path)?;
            file.write_all(json.as_bytes())?;
            file.sync_all()?;
        }
        #[cfg(not(unix))]
        {
            fs::write(&tmp_path, json.as_bytes())?;
        }

        fs::rename(&tmp_path, &self.path)
            .with_context(|| format!("renaming tmp file to {}", self.path.display()))?;
        Ok(())
    }

    /// Insert or update an invite record in the store.
    pub fn insert(&mut self, record: InviteRecord) -> Result<()> {
        self.storage
            .invites
            .insert(record.invite_id.clone(), record);
        self.save()
    }

    /// Retrieve an invite by its unique ID.
    /// If the invite was Created but its expiry has passed, returns with Expired status.
    pub fn get(&self, invite_id: &str) -> Option<InviteRecord> {
        let record = self.storage.invites.get(invite_id)?.clone();
        let now = chrono::Utc::now().timestamp();
        if record.status == InviteStatus::Created && now >= record.expires_at {
            let mut expired = record;
            expired.status = InviteStatus::Expired;
            Some(expired)
        } else {
            Some(record)
        }
    }

    /// Find all invite records matching a given identifier hash.
    pub fn get_by_identifier_hash(&self, identifier_hash: &str) -> Vec<InviteRecord> {
        let now = chrono::Utc::now().timestamp();
        self.storage
            .invites
            .values()
            .filter(|r| r.identifier_hash == identifier_hash)
            .map(|r| {
                let mut record = r.clone();
                if record.status == InviteStatus::Created && now >= record.expires_at {
                    record.status = InviteStatus::Expired;
                }
                record
            })
            .collect()
    }

    /// List all invite records, evaluating and updating any expired invites.
    pub fn list(&mut self) -> Result<Vec<InviteRecord>> {
        let now = chrono::Utc::now().timestamp();
        let mut modified = false;

        for record in self.storage.invites.values_mut() {
            if record.status == InviteStatus::Created && now >= record.expires_at {
                record.status = InviteStatus::Expired;
                modified = true;
            }
        }

        if modified {
            self.save()?;
        }

        let mut list: Vec<_> = self.storage.invites.values().cloned().collect();
        list.sort_by_key(|b| std::cmp::Reverse(b.created_at));
        Ok(list)
    }

    /// Claim an invite with the receiver's published public profile key.
    /// Transitions status from Created -> ClaimedWithPublicProfile and generates a notification.
    pub fn claim(&mut self, invite_id: &str, claimed_profile_pubkey: &str) -> Result<InviteRecord> {
        let now = chrono::Utc::now().timestamp();
        let record = self
            .storage
            .invites
            .get_mut(invite_id)
            .ok_or_else(|| anyhow::anyhow!("invite '{}' not found", invite_id))?;

        if now >= record.expires_at {
            record.status = InviteStatus::Expired;
            let _ = self.save();
            anyhow::bail!("invite has expired");
        }

        if record.status == InviteStatus::ClaimedWithPublicProfile {
            anyhow::bail!("invite has already been claimed");
        }

        if record.status == InviteStatus::Cancelled {
            anyhow::bail!("invite has been cancelled");
        }

        record.status = InviteStatus::ClaimedWithPublicProfile;
        record.claimed_at = Some(now);
        record.claimed_profile_pubkey = Some(claimed_profile_pubkey.to_string());

        let notification = ClaimNotification {
            notification_id: uuid::Uuid::new_v4().to_string(),
            invite_id: invite_id.to_string(),
            identifier_hash: record.identifier_hash.clone(),
            display_hint: record.display_hint.clone(),
            amount_sats: record.amount_sats,
            claimed_at: now,
            claimed_profile_pubkey: claimed_profile_pubkey.to_string(),
            read: false,
        };
        self.storage.notifications.push(notification);

        let updated = record.clone();
        self.save()?;
        Ok(updated)
    }

    /// Cancel an active, unclaimed invite.
    pub fn cancel(&mut self, invite_id: &str) -> Result<InviteRecord> {
        let record = self
            .storage
            .invites
            .get_mut(invite_id)
            .ok_or_else(|| anyhow::anyhow!("invite '{}' not found", invite_id))?;

        if record.status == InviteStatus::ClaimedWithPublicProfile {
            anyhow::bail!("cannot cancel an already claimed invite");
        }

        record.status = InviteStatus::Cancelled;
        let updated = record.clone();
        self.save()?;
        Ok(updated)
    }

    /// Retrieve all notifications (sender notifications for claimed invites).
    pub fn notifications(&self) -> &[ClaimNotification] {
        &self.storage.notifications
    }

    /// Mark a specific notification as read.
    pub fn mark_notification_read(&mut self, notification_id: &str) -> Result<()> {
        let n = self
            .storage
            .notifications
            .iter_mut()
            .find(|n| n.notification_id == notification_id)
            .ok_or_else(|| anyhow::anyhow!("notification '{}' not found", notification_id))?;
        n.read = true;
        self.save()
    }

    /// Mark all notifications as read.
    pub fn mark_all_notifications_read(&mut self) -> Result<()> {
        for n in &mut self.storage.notifications {
            n.read = true;
        }
        self.save()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create_invite_record;

    #[test]
    fn test_invite_store_lifecycle() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let mut store = InviteStore::open(temp_dir.path())?;

        let invite = create_invite_record(
            "alice@example.com",
            50_000,
            Some("Dinner".into()),
            "sender-fp-123".into(),
            3600,
        );
        let id = invite.invite_id.clone();
        store.insert(invite)?;

        // Verify retrieval
        let retrieved = store.get(&id).expect("invite should exist");
        assert_eq!(retrieved.status, InviteStatus::Created);
        assert_eq!(retrieved.amount_sats, 50_000);

        // Claim invite
        let claimed = store.claim(&id, "receiver_pubkey_hex_0123")?;
        assert_eq!(claimed.status, InviteStatus::ClaimedWithPublicProfile);
        assert_eq!(
            claimed.claimed_profile_pubkey.as_deref(),
            Some("receiver_pubkey_hex_0123")
        );
        assert!(claimed.claimed_at.is_some());

        // Verify notification was created
        let notification_id = {
            let notifications = store.notifications();
            assert_eq!(notifications.len(), 1);
            assert_eq!(notifications[0].invite_id, id);
            assert_eq!(notifications[0].amount_sats, 50_000);
            assert!(!notifications[0].read);
            notifications[0].notification_id.clone()
        };

        // Marking read
        store.mark_notification_read(&notification_id)?;
        assert!(store.notifications()[0].read);

        // Cannot claim again
        assert!(store.claim(&id, "other_pubkey").is_err());

        // Reopen store from disk
        let mut reopened = InviteStore::open(temp_dir.path())?;
        let re_retrieved = reopened.get(&id).expect("should exist in file");
        assert_eq!(re_retrieved.status, InviteStatus::ClaimedWithPublicProfile);
        assert_eq!(reopened.notifications().len(), 1);
        assert!(reopened.notifications()[0].read);

        let list = reopened.list()?;
        assert_eq!(list.len(), 1);

        Ok(())
    }

    #[test]
    fn test_expired_invite_handling() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let mut store = InviteStore::open(temp_dir.path())?;

        // Create an already-expired invite (ttl = -10s)
        let invite = create_invite_record(
            "expired@example.com",
            10_000,
            None,
            "sender-fp-456".into(),
            -10,
        );
        let id = invite.invite_id.clone();
        store.insert(invite)?;

        // Get should report Expired
        let retrieved = store.get(&id).expect("should exist");
        assert_eq!(retrieved.status, InviteStatus::Expired);

        // Claiming should fail with expired error
        assert!(store.claim(&id, "some_pubkey").is_err());

        // List should update record to Expired
        let list = store.list()?;
        assert_eq!(list[0].status, InviteStatus::Expired);

        Ok(())
    }
}
