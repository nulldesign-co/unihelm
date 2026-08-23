//! Generates `docs/api/errors.md` from the error taxonomy.
//!
//! The docs page and the code cannot drift, because one is produced from the
//! other and a test compares them (spec §10.5, §16.10).
//!
//! Run: `cargo run -p ferrum-core --bin gen-error-docs > docs/api/errors.md`

fn main() {
    print!("{}", ferrum_core::error::docs_table());
}
