//! Web authentication library.
//!
//! This crate provides authentication for web applications.
//!
//! # Features
//!
//! ## Storage Backends
//!
//! - `postgres`: Enable PostgreSQL integration.
//!
//! ## Web Frameworks
//!
//! - `axum`: Enable Axum integration.
//!
//! ## Hash Algorithms
//!
//! This library supports multiple hash algorithms
//! but is currently configured to use only `argon2`.
//! In the future, the list of supported hashing algorithms
//! may change. Either because better algorithms are added,
//! or because existing algorithms are found to be insecure.
//! The default set always only includes safe algorithms.
//!
//! However, to keep support for algorithms currently in use within your project,
//! you can enable a specific `hash-algorithm-vN` feature.
//! This forces the inclusion of older hashing algorithms,
//! even if they maybe deemed less secure in the future.
//! By doing this, you keep support for older hashing algorithms,
//! and while also gaining increased security for new logins
//! through the use of newer algorithms.
//!
//! Note that only one of these features can be enabled;
//! they are not additive.
//!
//! New projects can simply pin the latest algorithm set version.
//!
//! - `hash-algorithms-v1`: argon2

#![forbid(unsafe_code)]

mod backend;
mod user;
mod session;
mod password;
mod hash_utils;
pub use backend::{Backend, CookieSessionBackend};
pub use user::User;
pub use session::{Session, SessionId, SessionFields};
pub use password::{HashedPassword, ValidPassword, BadPassword, Authenticated, MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH};

mod func;

#[cfg(feature = "postgres")]
mod postgres;

#[cfg(feature = "axum")]
pub mod axum;
