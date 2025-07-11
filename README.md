# `r2d2` adaptor for `cryptoki`

[![Crates.io](https://img.shields.io/crates/v/r2d2-cryptoki.svg)](https://crates.io/crates/r2d2-cryptoki)
[![Documentation](https://docs.rs/r2d2-cryptoki/badge.svg)](https://docs.rs/r2d2-cryptoki/)

Session pool manager for [cryptoki](https://github.com/parallaxsecond/rust-cryptoki/).

Cryptoki has a single login state for all sessions.
Only when all sessions are closed, a login is needed again.
This library requires a `ConnectionCustomizer` on the pool to ensure login is only done when needed.
The `SessionAuth` can be converted into the appropriate `ConnectionCustomizer`.

## Example

```rust no_run
use r2d2_cryptoki::{*, cryptoki::{context::*, types::AuthPin}};

let pkcs11 = Pkcs11::new("libsofthsm2.so").unwrap();
pkcs11.initialize(CInitializeArgs::OsThreads).unwrap();
let slots = pkcs11.get_slots_with_token().unwrap();
let slot = slots.first().unwrap();
let session_auth = SessionAuth::RwUser(AuthPin::new("fedcba".to_string()));
let manager = SessionManager::new(pkcs11, *slot, &session_auth);

let pool = let pool_builder = Pool::builder().connection_customizer(session_auth.into_customizer()).unwrap();

let session = pool.get().unwrap();
println!("{:?}", session.get_session_info().unwrap());
```
