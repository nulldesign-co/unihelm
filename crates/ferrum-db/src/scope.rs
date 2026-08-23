//! Turning a [`TenantScope`] into a query filter.
//!
//! There is deliberately **no** "build a WHERE clause from a string" helper here.
//! Each repository matches on [`ScopeFilter`] and writes the handful of literal
//! queries it needs, so no column name or predicate is ever assembled at runtime.

use ferrum_core::TenantScope;

/// The scope reduced to what a query actually needs to bind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeFilter {
    /// Admin: no restriction.
    All,
    /// Everything under one reseller. Resolving which customers those are is a
    /// join the repository writes explicitly.
    Reseller(i64),
    /// One customer and all of their subscriptions.
    Customer(i64),
    /// A single subscription, plus the customer that owns it — carried so a
    /// scoped query never has to join back to find out who the tenant is.
    Subscription {
        subscription_id: i64,
        customer_id: i64,
    },
}

impl ScopeFilter {
    pub fn from_scope(scope: &TenantScope) -> Self {
        match scope {
            TenantScope::Global => ScopeFilter::All,
            TenantScope::Reseller { reseller_id } => ScopeFilter::Reseller(reseller_id.get()),
            TenantScope::Customer { customer_id } => ScopeFilter::Customer(customer_id.get()),
            TenantScope::Subscription {
                subscription_id,
                customer_id,
            } => ScopeFilter::Subscription {
                subscription_id: subscription_id.get(),
                customer_id: customer_id.get(),
            },
        }
    }

    pub const fn is_unrestricted(self) -> bool {
        matches!(self, ScopeFilter::All)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_core::{SubscriptionId, UserId};

    #[test]
    fn every_scope_maps_to_a_filter() {
        assert_eq!(
            ScopeFilter::from_scope(&TenantScope::Global),
            ScopeFilter::All
        );
        assert_eq!(
            ScopeFilter::from_scope(&TenantScope::Customer {
                customer_id: UserId(4)
            }),
            ScopeFilter::Customer(4)
        );
        assert_eq!(
            ScopeFilter::from_scope(&TenantScope::Subscription {
                subscription_id: SubscriptionId(9),
                customer_id: UserId(4),
            }),
            ScopeFilter::Subscription {
                subscription_id: 9,
                customer_id: 4
            }
        );
    }

    #[test]
    fn only_global_is_unrestricted() {
        assert!(ScopeFilter::All.is_unrestricted());
        assert!(!ScopeFilter::Customer(1).is_unrestricted());
        assert!(!ScopeFilter::Reseller(1).is_unrestricted());
        assert!(
            !ScopeFilter::Subscription {
                subscription_id: 1,
                customer_id: 1
            }
            .is_unrestricted()
        );
    }
}
