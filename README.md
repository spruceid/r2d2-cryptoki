# `r2d2` adaptor for `cryptoki`

[![Crates.io](https://img.shields.io/crates/v/r2d2-cryptoki.svg)](https://crates.io/crates/r2d2-cryptoki)
[![Documentation](https://docs.rs/r2d2-cryptoki/badge.svg)](https://docs.rs/r2d2-cryptoki/)

Session pool manager for [cryptoki](https://github.com/parallaxsecond/rust-cryptoki/).

## Example

```rust no_run
use r2d2_cryptoki::{*, cryptoki::{context::*, types::AuthPin}};

let pkcs11 = Pkcs11::new("libsofthsm2.so").unwrap();
pkcs11.initialize(CInitializeArgs::OsThreads).unwrap();
let slots = pkcs11.get_slots_with_token().unwrap();
let slot = slots.first().unwrap();
let manager = SessionManager::new(pkcs11, *slot, SessionType::RwUser(AuthPin::new("fedcba".to_string())));

let pool = r2d2::Pool::builder().build(manager).unwrap();

let session = pool.get().unwrap();
println!("{:?}", session.get_session_info().unwrap());
```
