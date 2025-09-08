#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

use std::sync::{Arc, Mutex};

pub use cryptoki;
pub use r2d2;

use cryptoki::{
    context::{Function, Pkcs11},
    error::RvError,
    session::{Session, SessionState, UserType},
    slot::{Limit, Slot},
    types::AuthPin,
};
use r2d2::{CustomizeConnection, ManageConnection, NopConnectionCustomizer};

/// Alias for this crate's instance of r2d2's Pool
pub type Pool = r2d2::Pool<SessionManager>;
/// Alias for this crate's instance of r2d2's PooledSession
pub type PooledSession = r2d2::PooledConnection<SessionManager>;

/// Manager holding all information necessary for opening new connections
#[derive(Debug, Clone)]
pub struct SessionManager {
    pkcs11: Pkcs11,
    slot: Slot,
    session_state: SessionState,
}

/// Session types, holding the pin for the authenticated sessions
#[derive(Debug, Clone)]
pub enum SessionAuth {
    /// [SessionState::RoPublic]
    RoPublic,
    /// [SessionState::RoUser]
    RoUser(AuthPin),
    /// [SessionState::RwPublic]
    RwPublic,
    /// [SessionState::RwUser]
    RwUser(AuthPin),
    /// [SessionState::RwSecurityOfficer]
    RwSecurityOfficer(AuthPin),
}

/// Mandatory connection customizer for logins
#[derive(Debug, Clone)]
struct LoginCustomizer {
    auth_pin: AuthPin,
    user_type: UserType,
    active_sessions: Arc<Mutex<u32>>,
}

impl SessionAuth {
    fn as_state(&self) -> SessionState {
        match self {
            Self::RoPublic => SessionState::RoPublic,
            Self::RoUser(_) => SessionState::RoUser,
            Self::RwPublic => SessionState::RwPublic,
            Self::RwUser(_) => SessionState::RwUser,
            Self::RwSecurityOfficer(_) => SessionState::RwSecurityOfficer,
        }
    }

    /// Returns the correct customizer to use for the specified session auth
    pub fn into_customizer(self) -> Box<dyn CustomizeConnection<Session, cryptoki::error::Error>> {
        match self {
            Self::RoPublic | Self::RwPublic => Box::new(NopConnectionCustomizer),
            Self::RoUser(auth_pin) | Self::RwUser(auth_pin) => Box::from(LoginCustomizer {
                auth_pin,
                user_type: UserType::User,
                active_sessions: Default::default(),
            }),
            Self::RwSecurityOfficer(auth_pin) => Box::from(LoginCustomizer {
                auth_pin,
                user_type: UserType::So,
                active_sessions: Default::default(),
            }),
        }
    }
}

impl SessionManager {
    /// # Example
    /// ```no_run
    ///  # use r2d2_cryptoki::{*, cryptoki::{context::*, types::AuthPin}};
    ///  let pkcs11 = Pkcs11::new("libsofthsm2.so").unwrap();
    ///  pkcs11 .initialize(CInitializeArgs::OsThreads).unwrap();
    ///  let slots = pkcs11.get_slots_with_token().unwrap();
    ///  let slot = slots.first().unwrap();
    ///  let manager = SessionManager::new(pkcs11, *slot, &SessionAuth::RwUser(AuthPin::new("abcd".to_string())));
    /// ```
    pub fn new(pkcs11: Pkcs11, slot: Slot, session_auth: &SessionAuth) -> Self {
        Self {
            pkcs11,
            slot,
            session_state: session_auth.as_state(),
        }
    }

    /// Returns the maximum number of sessions supported by the HSM.
    ///
    /// Arguments:
    /// * `maximum`: A maximum number of sessions as `max_size` can return u32::max_value() which is probably more than what your application should use.
    ///
    /// # Example
    /// ```no_run
    ///  # use r2d2_cryptoki::{*, cryptoki::{context::*, types::AuthPin}};
    ///  # let pkcs11 = Pkcs11::new("libsofthsm2.so").unwrap();
    ///  # pkcs11.initialize(CInitializeArgs::OsThreads);
    ///  # let slots = pkcs11.get_slots_with_token().unwrap();
    ///  # let slot = slots.first().unwrap();
    ///  # let session_auth = SessionAuth::RwUser(AuthPin::new("fedcba".to_string()));
    ///  # let manager = SessionManager::new(pkcs11, *slot, &session_auth);
    ///  let pool_builder = Pool::builder().connection_customizer(session_auth.into_customizer());
    ///  let pool_builder = if let Some(max_size) = manager.max_size(100).unwrap() {
    ///     pool_builder.max_size(max_size)
    ///  } else {
    ///     pool_builder
    ///  };
    ///  let pool = pool_builder.build(manager).unwrap();
    /// ```
    pub fn max_size(&self, maximum: u32) -> Result<Option<u32>, cryptoki::error::Error> {
        let token_info = self.pkcs11.get_token_info(self.slot)?;
        let limit = token_info.max_session_count();
        let res = match limit {
            Limit::Max(m) => Some(m.try_into().unwrap_or(u32::MAX)),
            Limit::Unavailable => None,
            Limit::Infinite => Some(u32::MAX),
        };
        Ok(if let Some(true) = res.map(|r| r > maximum) {
            Some(maximum)
        } else {
            res
        })
    }
}

impl ManageConnection for SessionManager {
    type Connection = Session;

    type Error = cryptoki::error::Error;

    fn connect(&self) -> Result<Self::Connection, Self::Error> {
        let session = match self.session_state {
            SessionState::RoPublic | SessionState::RoUser => {
                self.pkcs11.open_ro_session(self.slot)?
            }
            SessionState::RwPublic | SessionState::RwUser | SessionState::RwSecurityOfficer => {
                self.pkcs11.open_rw_session(self.slot)?
            }
        };
        Ok(session)
    }

    fn is_valid(&self, session: &mut Self::Connection) -> Result<(), Self::Error> {
        let actual_state = session.get_session_info()?.session_state();
        if actual_state != self.session_state {
            Err(Self::Error::Pkcs11(
                RvError::UserNotLoggedIn,
                Function::GetSessionInfo,
            ))
        } else {
            Ok(())
        }
    }

    fn has_broken(&self, _session: &mut Self::Connection) -> bool {
        // TODO find a way to check session state without reaching out to the HSM
        false
    }
}

impl CustomizeConnection<Session, cryptoki::error::Error> for LoginCustomizer {
    fn on_acquire(&self, session: &mut Session) -> Result<(), cryptoki::error::Error> {
        let mutex = self.active_sessions.clone();
        let mut active = mutex.lock().unwrap_or_else(|e| e.into_inner());

        // Login is global, once a session logs in, all sessions are logged in https://stackoverflow.com/a/40225885.
        if *active == 0 {
            match session.login(self.user_type, Some(&self.auth_pin)) {
                // Can happen with poisoned mutex
                Err(cryptoki::error::Error::Pkcs11(
                    RvError::UserAlreadyLoggedIn,
                    Function::Login,
                )) => {}
                res => res?,
            };
        };

        // Increase after login to prefer login too many over too few
        *active += 1;

        Ok(())
    }

    fn on_release(&self, _: Session) {
        let mutex = self.active_sessions.clone();
        let mut active = mutex.lock().unwrap_or_else(|e| e.into_inner());
        if *active > 0 {
            *active -= 1;
        }
    }
}

#[cfg(test)]
mod test {
    use std::{env, fs, path::Path, time::Duration};

    use cached::proc_macro::{cached, once};
    use cryptoki::{
        context::CInitializeArgs,
        mechanism::Mechanism,
        object::{Attribute, KeyType, ObjectClass},
    };
    use r2d2::PooledConnection;

    use super::*;

    #[derive(Clone, Hash, PartialEq, Eq)]
    struct Config {
        max_sessions: Option<u32>,
        label: Vec<u8>,
    }

    // Using cached to create only one pkcs11 ojbect, otherwise it segfaults.
    #[once(sync_writes = true)]
    fn default_pkcs11() -> Pkcs11 {
        env::set_var("SOFTHSM2_CONF", "./test/softhsm2.conf");
        let tokens_path = Path::new("./test/softhsm/tokens");
        if tokens_path.exists() {
            fs::remove_dir_all(tokens_path.to_str().unwrap()).unwrap();
        }
        fs::create_dir_all(tokens_path.to_str().unwrap()).unwrap();

        let pkcs11 = Pkcs11::new("libsofthsm2.so").expect("Could not use pkcs11 library");
        pkcs11
            .initialize(CInitializeArgs::OsThreads)
            .expect("Could not initialize pkcs11");
        pkcs11
    }

    #[cached(sync_writes = true)]
    fn default_token(pin: String) -> (Pkcs11, Slot) {
        let pkcs11 = default_pkcs11();
        let slot = {
            let slots = pkcs11
                .get_slots_with_token()
                .expect("Could not get slots with token");
            *slots.first().expect("Could not find a slot")
        };
        pkcs11
            .init_token(slot, &pin.clone().into(), "token")
            .expect("Could not initialize token");
        let session = pkcs11.open_rw_session(slot).unwrap();
        session
            .login(cryptoki::session::UserType::So, Some(&pin.clone().into()))
            .unwrap();
        session.init_pin(&pin.into()).unwrap();

        (pkcs11, slot)
    }

    fn default_setup(config: Config) -> Pool {
        let pin_string = "abcde".to_string();
        let pin = AuthPin::new(pin_string.clone());
        let (pkcs11, slot) = default_token(pin_string);

        let login = SessionAuth::RwUser(pin);
        let manager = SessionManager::new(pkcs11, slot, &login);
        let pool_builder = Pool::builder().connection_customizer(login.into_customizer());
        let pool_builder = if let Some(m) = config.max_sessions {
            pool_builder.max_size(m)
        } else {
            pool_builder
        };
        let pool = pool_builder.build(manager).unwrap();

        let mechanism = Mechanism::EccKeyPairGen;
        let pub_key_template = vec![
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Derive(true),
            Attribute::KeyType(KeyType::EC),
            Attribute::Verify(true),
            Attribute::EcParams(vec![
                0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
            ]),
            Attribute::Label(config.label.clone()),
        ];
        let priv_key_template = vec![
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Derive(true),
            Attribute::Sign(true),
            Attribute::Label(config.label),
        ];

        // sometimes raises an GeneralError
        backoff::retry(
            backoff::backoff::Constant::new(Duration::from_millis(25)),
            || {
                Ok(pool.get().unwrap().generate_key_pair(
                    &mechanism,
                    &pub_key_template,
                    &priv_key_template,
                )?)
            },
        )
        .unwrap();
        pool
    }

    fn sign(config: &Config, session: &PooledConnection<SessionManager>) -> Vec<u8> {
        let template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Label(config.label.clone()),
        ];
        let objects = session.find_objects(&template).unwrap();
        let private = objects.first().unwrap();
        session
            .sign(&Mechanism::Ecdsa, *private, "test_data".as_bytes())
            .unwrap()
    }
    fn verify(config: &Config, session: PooledConnection<SessionManager>, signature: &[u8]) {
        let template = vec![
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::Label(config.label.clone()),
        ];
        let objects = session.find_objects(&template).unwrap();
        let public = objects.first().unwrap();
        session
            .verify(
                &Mechanism::Ecdsa,
                *public,
                "test_data".as_bytes(),
                signature,
            )
            .unwrap();
    }

    #[test]
    fn basic() {
        let config = Config {
            max_sessions: None,
            label: "basic".into(),
        };
        let pool = default_setup(config.clone());
        let sig = sign(&config, &pool.get().unwrap());
        verify(&config, pool.get().unwrap(), &sig);
    }

    fn basic_test(config: &Config, pool1: Pool) {
        let pool2 = pool1.clone();
        let config1 = config.clone();
        let config2 = config.clone();
        loom::thread::spawn(move || {
            let sig = sign(&config1, &pool1.get().unwrap());
            verify(&config1, pool1.get().unwrap(), &sig);
        });
        let sig = sign(&config2, &pool2.get().unwrap());
        verify(&config2, pool2.get().unwrap(), &sig);
    }

    #[test]
    fn basic_concurrency() {
        loom::model(|| {
            let config = Config {
                max_sessions: None,
                label: "basic_concurrency".into(),
            };
            let pool1 = default_setup(config.clone());
            basic_test(&config, pool1);
        });
    }

    #[test]
    fn max_one_session() {
        loom::model(|| {
            let config = Config {
                max_sessions: Some(1),
                label: "max_one_session".into(),
            };
            let pool1 = default_setup(config.clone());
            basic_test(&config, pool1);
        });
    }

    #[test]
    fn multiple_operations_per_session() {
        loom::model(|| {
            let config = Config {
                max_sessions: Some(1),
                label: "multiple_operations_per_session".into(),
            };
            let config2 = config.clone();
            let pool1 = default_setup(config.clone());
            let pool2 = pool1.clone();
            loom::thread::spawn(move || {
                let session = pool1.get().unwrap();
                let sig = sign(&config, &session);
                verify(&config, session, &sig);
            });
            let session = pool2.get().unwrap();
            let sig = sign(&config2, &session);
            verify(&config2, session, &sig);
        });
    }
}
