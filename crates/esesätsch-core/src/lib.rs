//! Core library for the esesätsch SSH server.
//!
//! This crate is OS-agnostic: it does not spawn shells or touch the local
//! authentication system. OS-level behaviour is injected through traits
//! (see `auth`, `pty`, `user_ctx` in later plans).

#![doc(html_root_url = "https://docs.rs/esesaetsch-core/0.1.0")]

pub mod auth;
pub mod cert;
pub mod config;
pub mod crypto;
pub mod error;
pub mod hostkey;
pub mod logging;

pub use error::Error;
