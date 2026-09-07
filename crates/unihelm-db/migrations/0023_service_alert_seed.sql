-- Retire migration 0011's `service_down`/`nginx` seed (spec §11.11).
--
-- 0011 armed a service rule for nginx on every install, on the reasoning that
-- nginx down means every site on the box is down. That reasoning holds only on
-- a machine that runs nginx. On one that does not — an Apache box, or a fresh
-- server before anything is installed — the rule is a lie with a delay on it:
-- `service_is_down` counts only Inactive and Failed, so `not_found` reads as
-- fine and the alerts page shows the rule "Armed" and quiet. Install nginx
-- later for five minutes of testing, stop it, and the panel fires an alert from
-- a rule the operator never created and cannot find a reason for. A service
-- rule now gets armed when the service is actually installed
-- (`unihelm_ops::alerts::arm_service_rule`), which is the only moment the panel
-- knows the machine runs it.
--
-- ## Why the predicate is this long
--
-- Deleting a row an operator has invested in would be the worse defect. Every
-- clause is one way the row could be theirs rather than 0011's:
--
--   * `threshold = 1.0 AND enabled = 1` — the seed's own values, so a rule
--     re-thresholded or switched off is not this row;
--   * `created_at = updated_at` — never edited since it was written; every
--     write through `set_alert_rule` moves `updated_at`;
--   * `created_at IN (…)` — written by the *same statement* as 0011's other two
--     seeds. SQLite freezes `now` for the duration of a statement, so the three
--     seeded rows share a timestamp to the second, and a rule the operator
--     added later does not. This is what separates the seed from an identical
--     nginx rule somebody typed in themselves;
--   * `NOT EXISTS (…)` — nothing has ever fired against it. An event means
--     somebody has seen this rule work, and possibly acknowledged it.
--
-- Anything that fails one of those clauses stays exactly as it is. The cost of
-- being wrong in that direction is one rule an operator can now delete from the
-- panel, which is the other half of this change.
DELETE FROM alert_rules
 WHERE kind = 'service_down'
   AND target = 'nginx'
   AND threshold = 1.0
   AND enabled = 1
   AND created_at = updated_at
   AND created_at IN (
           SELECT created_at
             FROM alert_rules
            WHERE target IS NULL
              AND kind IN ('disk_pct', 'cert_expiry_days')
       )
   AND NOT EXISTS (
           SELECT 1
             FROM alert_events
            WHERE alert_events.rule_id = alert_rules.id
       );
