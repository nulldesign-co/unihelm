//! Typed identifiers.
//!
//! The panel deals in a lot of integer ids; making them distinct types means a
//! `UserId` can never silently be used where a `SiteId` is expected, which is the
//! cheapest possible defence against cross-tenant bugs.

use std::fmt;

use serde::{Deserialize, Serialize};

macro_rules! id_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub i64);

        impl $name {
            pub const fn new(v: i64) -> Self { Self(v) }
            pub const fn get(self) -> i64 { self.0 }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl From<i64> for $name {
            fn from(v: i64) -> Self { Self(v) }
        }

        impl From<$name> for i64 {
            fn from(v: $name) -> i64 { v.0 }
        }
    };
}

id_type!(
    /// A panel account: admin, reseller or customer.
    UserId
);
id_type!(
    /// One plan instance owned by a customer; the unit that holds sites and dbs
    /// and maps to exactly one Linux user (spec §6.1).
    SubscriptionId
);
id_type!(
    /// A hosted site.
    SiteId
);
id_type!(
    /// A plan definition owned by an admin or reseller.
    PlanId
);

/// Task ids are UUIDs, not row ids: the agent hands one back before the row is
/// visible to the web process, and they show up in log lines and URLs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TaskId(pub uuid::Uuid);

impl TaskId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }
    pub const fn get(self) -> uuid::Uuid {
        self.0
    }
}

impl Default for TaskId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for TaskId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl std::str::FromStr for TaskId {
    type Err = uuid::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(uuid::Uuid::parse_str(s)?))
    }
}
