//! Uniffi based bindings for the `matrix-sdk-crypto` crate.
//!
//! This crate can be used to introduce E2EE support into an existing Matrix
//! client or client library in any of the language targets Uniffi supports.

#![warn(missing_docs)]

mod backup_recovery_key;
mod device;
mod error;
mod logger;
mod machine;
mod responses;
mod users;
mod verification;

use std::{collections::HashMap, convert::TryFrom, sync::Arc};

pub use backup_recovery_key::{
    BackupRecoveryKey, DecodeError, MegolmV1BackupKey, PassphraseInfo, PkDecryptionError,
};
pub use device::Device;
pub use error::{
    CryptoStoreError, DecryptionError, KeyImportError, SecretImportError, SignatureError,
};
pub use logger::{set_logger, Logger};
pub use machine::{KeyRequestPair, OlmMachine};
use matrix_sdk_common::instant::Instant;
pub use responses::{
    BootstrapCrossSigningResult, DeviceLists, KeysImportResult, OutgoingVerificationRequest,
    Request, RequestType, SignatureUploadRequest, UploadSigningKeysRequest,
};
use ruma::{DeviceId, DeviceKeyAlgorithm, RoomId, UserId};
pub use users::UserIdentity;
pub use verification::{
    CancelInfo, ConfirmVerificationResult, QrCode, RequestVerificationResult, Sas, ScanResult,
    StartSasResult, Verification, VerificationRequest,
};

/// Struct collecting data that is important to migrate to the rust-sdk
pub struct MigrationData {
    /// The pickled version of the Olm Account
    account: PickledAccount,
    /// The list of pickleds Olm Sessions.
    sessions: Vec<PickledSession>,
    /// The list of Megolm inbound group sessions.
    inbound_group_sessions: Vec<PickledInboundGroupSession>,
    /// The Olm pickle key that was used to pickle all the Olm objects.
    pickle_key: String,
    /// The backup version that is currently active.
    backup_version: Option<String>,
    // The backup recovery key, as a base64 encoded string.
    backup_recovery_key: Option<String>,
    /// The private cross signing keys.
    cross_signing: CrossSignignKeys,
    /// The list of users that the Rust SDK should track.
    tracked_users: Vec<String>,
}

/// Struct holding the private cross signing keys as base64 encoded strings.
pub struct CrossSignignKeys {
    /// The private part of the master key.
    master_key: Option<String>,
    /// The private part of the self-signing key.
    self_signing_key: Option<String>,
    /// The private part of the user-signing key.
    user_signing_key: Option<String>,
}

/// A pickled version of an `Account`.
///
/// Holds all the information that needs to be stored in a database to restore
/// an account.
pub struct PickledAccount {
    /// The user id of the account owner.
    pub user_id: String,
    /// The device id of the account owner.
    pub device_id: String,
    /// The pickled version of the Olm account.
    pub pickle: String,
    /// Was the account shared.
    pub shared: bool,
    /// The number of uploaded one-time keys we have on the server.
    pub uploaded_signed_key_count: i64,
}

/// A pickled version of a `Session`.
///
/// Holds all the information that needs to be stored in a database to restore
/// a Session.
pub struct PickledSession {
    /// The pickle string holding the Olm Session.
    pub pickle: String,
    /// The curve25519 key of the other user that we share this session with.
    pub sender_key: String,
    /// Was the session created using a fallback key.
    pub created_using_fallback_key: bool,
    /// The relative time elapsed since the session was created.
    pub creation_time: String,
    /// The relative time elapsed since the session was last used.
    pub last_use_time: String,
}

/// A pickled version of an `InboundGroupSession`.
///
/// Holds all the information that needs to be stored in a database to restore
/// an InboundGroupSession.
pub struct PickledInboundGroupSession {
    /// The pickle string holding the InboundGroupSession.
    pub pickle: String,
    /// The public curve25519 key of the account that sent us the session
    pub sender_key: String,
    /// The public ed25519 key of the account that sent us the session.
    pub signing_key: HashMap<String, String>,
    /// The id of the room that the session is used in.
    pub room_id: String,
    /// The list of claimed ed25519 that forwarded us this key. Will be empty if
    /// we directly received this session.
    pub forwarding_chains: Vec<String>,
    /// Flag remembering if the session was directly sent to us by the sender
    /// or if it was imported.
    pub imported: bool,
    /// Flag remembering if the session has been backed up.
    pub backed_up: bool,
}

/// Error type for the migration process.
#[derive(thiserror::Error, Debug)]
pub enum MigrationError {
    /// Generic catch all error variant.
    #[error("error migrating database: {message}")]
    Generic {
        /// The error message
        message: String,
    },
}

impl From<anyhow::Error> for MigrationError {
    fn from(e: anyhow::Error) -> MigrationError {
        MigrationError::Generic { message: e.to_string() }
    }
}

/// TODO
pub fn migrate(
    mut data: MigrationData,
    path: &str,
    passphrase: Option<String>,
) -> Result<(), anyhow::Error> {
    use matrix_sdk_crypto::{
        olm::PrivateCrossSigningIdentity,
        store::{Changes as RustChanges, CryptoStore, RecoveryKey},
    };
    use matrix_sdk_sled::CryptoStore as SledStore;
    use tokio::runtime::Runtime;
    use vodozemac::{
        megolm::InboundGroupSession,
        olm::{Account, Session},
        Curve25519PublicKey,
    };
    use zeroize::Zeroize;

    let store = SledStore::open_with_passphrase(path, passphrase.as_deref())?;
    let runtime = Runtime::new()?;

    let user_id: Arc<UserId> = parse_user_id(&data.account.user_id)?.into();
    let device_id: Box<DeviceId> = data.account.device_id.into();
    let device_id: Arc<DeviceId> = device_id.into();

    let account = Account::from_libolm_pickle(&data.account.pickle, &data.pickle_key)?;
    let pickle = account.pickle();

    let identity_keys = Arc::new(account.identity_keys());

    let pickled_account = matrix_sdk_crypto::olm::PickledAccount {
        user_id: parse_user_id(&data.account.user_id)?,
        device_id: device_id.as_ref().to_owned(),
        pickle,
        shared: data.account.shared,
        uploaded_signed_key_count: data.account.uploaded_signed_key_count as u64,
    };

    let account = matrix_sdk_crypto::olm::ReadOnlyAccount::from_pickle(pickled_account)?;

    let mut sessions = Vec::new();

    for session_pickle in data.sessions {
        let pickle =
            Session::from_libolm_pickle(&session_pickle.pickle, &data.pickle_key)?.pickle();

        let pickle = matrix_sdk_crypto::olm::PickledSession {
            pickle,
            sender_key: Curve25519PublicKey::from_base64(&session_pickle.sender_key)?,
            created_using_fallback_key: session_pickle.created_using_fallback_key,
            creation_time: Instant::now(),
            // TODO pass the last use time from the kotlin side instead of using
            // last use time.
            last_use_time: Instant::now(),
        };

        let session = matrix_sdk_crypto::olm::Session::from_pickle(
            user_id.clone(),
            device_id.clone(),
            identity_keys.clone(),
            pickle,
        );

        sessions.push(session);
    }

    let mut inbound_group_sessions = Vec::new();

    for session in data.inbound_group_sessions {
        let pickle =
            InboundGroupSession::from_libolm_pickle(&session.pickle, &data.pickle_key)?.pickle();

        let pickle = matrix_sdk_crypto::olm::PickledInboundGroupSession {
            pickle,
            sender_key: session.sender_key,
            signing_key: session
                .signing_key
                .into_iter()
                .map(|(k, v)| Ok((DeviceKeyAlgorithm::try_from(k)?, v)))
                .collect::<Result<_, anyhow::Error>>()?,
            room_id: RoomId::parse(session.room_id)?,
            forwarding_chains: session.forwarding_chains,
            imported: session.imported,
            backed_up: session.backed_up,
            history_visibility: None,
        };

        let session = matrix_sdk_crypto::olm::InboundGroupSession::from_pickle(pickle)?;

        inbound_group_sessions.push(session);
    }

    let recovery_key =
        data.backup_recovery_key.map(|k| RecoveryKey::from_base64(k.as_str())).transpose()?;

    let cross_signing = PrivateCrossSigningIdentity::empty((*user_id).into());
    runtime.block_on(cross_signing.import_secrets_unchecked(
        data.cross_signing.master_key.as_deref(),
        data.cross_signing.self_signing_key.as_deref(),
        data.cross_signing.user_signing_key.as_deref(),
    ))?;

    data.cross_signing.master_key.zeroize();
    data.cross_signing.self_signing_key.zeroize();
    data.cross_signing.user_signing_key.zeroize();

    let tracked_users = data
        .tracked_users
        .into_iter()
        .map(|u| Ok(((parse_user_id(&u)?), true)))
        .collect::<Result<Vec<(Box<UserId>, bool)>, anyhow::Error>>()?;

    let tracked_users: Vec<(&UserId, bool)> =
        tracked_users.iter().map(|(u, d)| (&**u, *d)).collect();

    runtime.block_on(store.save_tracked_users(tracked_users.as_slice()))?;

    let changes = RustChanges {
        account: Some(account),
        private_identity: Some(cross_signing),
        sessions,
        inbound_group_sessions,
        recovery_key,
        backup_version: data.backup_version,
        ..Default::default()
    };

    Ok(runtime.block_on(store.save_changes(changes))?)
}

/// Callback that will be passed over the FFI to report progress
pub trait ProgressListener {
    /// The callback that should be called on the Rust side
    ///
    /// # Arguments
    ///
    /// * `progress` - The current number of items that have been handled
    ///
    /// * `total` - The total number of items that will be handled
    fn on_progress(&self, progress: i32, total: i32);
}

/// An event that was successfully decrypted.
pub struct DecryptedEvent {
    /// The decrypted version of the event.
    pub clear_event: String,
    /// The claimed curve25519 key of the sender.
    pub sender_curve25519_key: String,
    /// The claimed ed25519 key of the sender.
    pub claimed_ed25519_key: Option<String>,
    /// The curve25519 chain of the senders that forwarded the Megolm decryption
    /// key to us. Is empty if the key came directly from the sender of the
    /// event.
    pub forwarding_curve25519_chain: Vec<String>,
}

/// Struct representing the state of our private cross signing keys, it shows
/// which private cross signing keys we have locally stored.
#[derive(Debug, Clone)]
pub struct CrossSigningStatus {
    /// Do we have the master key.
    pub has_master: bool,
    /// Do we have the self signing key, this one is necessary to sign our own
    /// devices.
    pub has_self_signing: bool,
    /// Do we have the user signing key, this one is necessary to sign other
    /// users.
    pub has_user_signing: bool,
}

/// A struct containing private cross signing keys that can be backed up or
/// uploaded to the secret store.
pub struct CrossSigningKeyExport {
    /// The seed of the master key encoded as unpadded base64.
    pub master_key: Option<String>,
    /// The seed of the self signing key encoded as unpadded base64.
    pub self_signing_key: Option<String>,
    /// The seed of the user signing key encoded as unpadded base64.
    pub user_signing_key: Option<String>,
}

/// Struct holding the number of room keys we have.
pub struct RoomKeyCounts {
    /// The total number of room keys.
    pub total: i64,
    /// The number of backed up room keys.
    pub backed_up: i64,
}

/// Backup keys and information we load from the store.
pub struct BackupKeys {
    /// The recovery key as a base64 encoded string.
    pub recovery_key: String,
    /// The version that is used with the recovery key.
    pub backup_version: String,
}

impl TryFrom<matrix_sdk_crypto::store::BackupKeys> for BackupKeys {
    type Error = ();

    fn try_from(keys: matrix_sdk_crypto::store::BackupKeys) -> Result<Self, Self::Error> {
        Ok(Self {
            recovery_key: keys.recovery_key.ok_or(())?.to_base64(),
            backup_version: keys.backup_version.ok_or(())?,
        })
    }
}

impl From<matrix_sdk_crypto::store::RoomKeyCounts> for RoomKeyCounts {
    fn from(count: matrix_sdk_crypto::store::RoomKeyCounts) -> Self {
        Self { total: count.total as i64, backed_up: count.backed_up as i64 }
    }
}

impl From<matrix_sdk_crypto::CrossSigningKeyExport> for CrossSigningKeyExport {
    fn from(e: matrix_sdk_crypto::CrossSigningKeyExport) -> Self {
        Self {
            master_key: e.master_key.clone(),
            self_signing_key: e.self_signing_key.clone(),
            user_signing_key: e.user_signing_key.clone(),
        }
    }
}

impl From<CrossSigningKeyExport> for matrix_sdk_crypto::CrossSigningKeyExport {
    fn from(e: CrossSigningKeyExport) -> Self {
        matrix_sdk_crypto::CrossSigningKeyExport {
            master_key: e.master_key,
            self_signing_key: e.self_signing_key,
            user_signing_key: e.user_signing_key,
        }
    }
}

impl From<matrix_sdk_crypto::CrossSigningStatus> for CrossSigningStatus {
    fn from(s: matrix_sdk_crypto::CrossSigningStatus) -> Self {
        Self {
            has_master: s.has_master,
            has_self_signing: s.has_self_signing,
            has_user_signing: s.has_user_signing,
        }
    }
}

fn parse_user_id(user_id: &str) -> Result<Box<UserId>, CryptoStoreError> {
    UserId::parse(user_id).map_err(|e| CryptoStoreError::InvalidUserId(user_id.to_owned(), e))
}

#[allow(warnings)]
mod generated {
    use super::*;
    include!(concat!(env!("OUT_DIR"), "/olm.uniffi.rs"));
}

pub use generated::*;
