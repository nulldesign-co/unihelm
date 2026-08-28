//! Shell completions (spec §11.20).
//!
//! Generated from the same [`Cli`] the binary parses with, so a subcommand
//! cannot exist without being completable — the alternative, a hand-written
//! completion file, is wrong the day after it is written.
//!
//! The subcommand is hidden because it is plumbing for the packaging, not
//! something an operator browses to. Packagers call:
//!
//! ```text
//! ferrum completions bash > /usr/share/bash-completion/completions/ferrum
//! ferrum completions zsh  > /usr/share/zsh/site-functions/_ferrum
//! ferrum completions fish > /usr/share/fish/vendor_completions.d/ferrum.fish
//! ```

use std::io::Write;

use clap::CommandFactory;
use clap_complete::Shell;

use crate::cli::{Cli, CompletionShell};

/// Write a completion script for one shell.
pub fn generate(shell: CompletionShell, out: &mut dyn Write) {
    let mut command = Cli::command();
    let name = command.get_name().to_string();
    let shell = match shell {
        CompletionShell::Bash => Shell::Bash,
        CompletionShell::Zsh => Shell::Zsh,
        CompletionShell::Fish => Shell::Fish,
    };
    clap_complete::generate(shell, &mut command, name, out);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn script(shell: CompletionShell) -> String {
        let mut buffer: Vec<u8> = Vec::new();
        generate(shell, &mut buffer);
        String::from_utf8(buffer).expect("completions are UTF-8")
    }

    #[test]
    fn all_three_shells_get_a_script_that_knows_the_command_tree() {
        for shell in [
            CompletionShell::Bash,
            CompletionShell::Zsh,
            CompletionShell::Fish,
        ] {
            let text = script(shell);
            assert!(text.len() > 500, "{shell:?} produced {} bytes", text.len());
            // A completion that does not know about the command tree is worse
            // than none: it silently offers nothing and looks like a bug in the
            // shell. `json` rather than `--json` because fish writes long
            // options as `-l json`.
            for expected in ["site", "backup", "wordpress", "settings-set", "json"] {
                assert!(
                    text.contains(expected),
                    "{shell:?} completions never mention `{expected}`"
                );
            }
        }
    }

    #[test]
    fn a_new_subcommand_is_completable_without_anybody_writing_it_down() {
        // The reason the script is generated rather than shipped: every group
        // in the tree must appear, including the ones added last.
        let text = script(CompletionShell::Bash);
        for group in [
            "doctor",
            "status",
            "user",
            "ops",
            "site",
            "php",
            "db",
            "backup",
            "cron",
            "dns",
            "firewall",
            "app",
            "wordpress",
            "plan",
            "subscription",
            "stack",
            "task",
            "cert",
            "svc",
            "waf",
            "alert",
            "quota",
            "sftp",
            "security",
        ] {
            assert!(text.contains(group), "bash completions omit `{group}`");
        }
    }

    #[test]
    fn the_completions_subcommand_is_hidden_from_help() {
        // It is plumbing an operator runs once, from a packaging script, so it
        // does not belong in the list of things the panel can do. (It still
        // appears in the generated scripts — clap_complete emits hidden
        // subcommands — which is harmless: completing it is not advertising it.)
        let help = Cli::command().render_help().to_string();
        assert!(
            !help.contains("completions"),
            "the completions subcommand is listed in --help:\n{help}"
        );
    }
}
