//! `ferrum-ops` — the operation registry (spec §5.2).
//!
//! This crate is the security model made concrete. Every privileged action the
//! panel can take is a named entry in one table, and reaching it requires:
//!
//! 1. a **name that exists** in the registry — an unknown name is not "run
//!    something else", it is `FER-1504`;
//! 2. an **[`AuthContext`] that the agent re-validates against the database**,
//!    not merely the one the web process asserted (spec §12 rule 4);
//! 3. a **permission** the operation declares up front;
//! 4. an **input that deserialises into the operation's typed struct**, where
//!    every field is a validated newtype (spec §12 rule 3).
//!
//! Only after all four does any code run. Because inputs are enums and newtypes
//! rather than strings, and because execution goes through
//! [`ferrum_distro::Cmd`]'s argv arrays, there is no path from an API request to
//! a shell.

pub mod acme;
pub mod adminer;
pub mod alerts;
pub mod backup;
pub mod cert;
pub mod cron;
pub mod db;
pub mod dns;
pub mod fpm;
pub mod harden;
pub mod fsops;
pub mod fwops;
pub mod metrics;
pub mod nodeapp;
pub mod panel;
pub mod php;
pub mod plan;
pub mod posture;
pub mod provision;
pub mod quota;
pub mod registry;
pub mod services;
pub mod sftp;
pub mod site;
pub mod slices;
pub mod stack;
pub mod svc;
pub mod sys;
pub mod tls;
pub mod waf;

pub use registry::{Execution, OpContext, OpRegistry, Operation, Services, TypedOperation};
