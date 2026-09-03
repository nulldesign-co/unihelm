//! What Docker is running on this machine.
//!
//! Read-only, and deliberately so. The panel's whole security model is that a
//! tenant reaches their own files and nothing else, enforced by Linux users,
//! directory modes and per-tenant FPM pools. Docker sits outside all of it: a
//! container started with `-v /:/host` or with the daemon socket mounted is
//! root on the machine, so an operation that starts an arbitrary container is
//! an operation that hands somebody root — through a panel whose entire job is
//! to stop exactly that.
//!
//! Listing is different. It tells an operator what is on their server, which is
//! most of the value and none of the risk, and it is the half that can be built
//! without first answering the socket question. Start, stop and run are
//! deliberately absent until that answer exists; see
//! `docs/roadmap-multi-stack.md`.
//!
//! Nothing here assumes Docker is installed. A machine without it reports
//! `installed: false` and an empty list, because "Docker is not here" is a
//! useful answer and an error is not.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use unihelm_core::{Permission, Result};

use crate::registry::{Execution, OpContext, TypedOperation};

/// Docker's own client, not the daemon socket.
///
/// Shelling out to `docker` rather than speaking to /var/run/docker.sock keeps
/// the panel out of the business of holding a handle that is equivalent to root
/// — and `docker` is what an operator would run themselves, so what the panel
/// reports and what they see agree.
const DOCKER: &str = "docker";

/// Docker is either quick or wedged; a long wait means the daemon is stuck, and
/// a page that hangs is worse than one that says so.
const BUDGET: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Container {
    pub id: String,
    pub name: String,
    pub image: String,
    /// As Docker words it: `Up 3 hours`, `Exited (0) 2 days ago`.
    pub status: String,
    /// Whether it is running right now, derived rather than parsed from prose.
    pub running: bool,
    /// Published ports, as Docker prints them.
    pub ports: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Image {
    pub id: String,
    pub repository: String,
    pub tag: String,
    pub size: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Volume {
    pub name: String,
    pub driver: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct ListInput {}

#[derive(Debug, Serialize)]
pub struct ListOutput {
    /// False when there is no `docker` on the machine at all.
    pub installed: bool,
    /// False when Docker is installed but its daemon is not answering.
    pub daemon_running: bool,
    /// Every container, running or not — a stopped one is still something the
    /// operator has, and hiding it makes the list lie about disk in use.
    pub containers: Vec<Container>,
    pub images: Vec<Image>,
    pub volumes: Vec<Volume>,
    /// What went wrong, when something did, in Docker's own words.
    pub note: Option<String>,
}

/// `docker.list` — containers, images and volumes on this server.
pub struct List;

#[async_trait::async_trait]
impl TypedOperation for List {
    type Input = ListInput;
    type Output = ListOutput;

    const NAME: &'static str = "docker.list";
    // Reading the machine's inventory. The same permission the rest of the
    // server-wide read surface uses.
    const PERMISSION: Permission = Permission::ServerRead;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, _ctx: &OpContext, _input: Self::Input) -> Result<Self::Output> {
        let Ok(docker) = unihelm_distro::exec::resolve_program(DOCKER) else {
            return Ok(ListOutput {
                installed: false,
                daemon_running: false,
                containers: Vec::new(),
                images: Vec::new(),
                volumes: Vec::new(),
                note: Some(
                    "Docker is not installed on this server. `stack.install` can add it.".into(),
                ),
            });
        };
        let docker = docker.to_string_lossy().into_owned();

        // Installed but not answering is a different situation from not
        // installed, and an operator debugging one does not want to be told the
        // other.
        let ping = run_docker(&docker, &["info", "--format", "{{.ServerVersion}}"]).await;
        if ping.is_none() {
            return Ok(ListOutput {
                installed: true,
                daemon_running: false,
                containers: Vec::new(),
                images: Vec::new(),
                volumes: Vec::new(),
                note: Some(
                    "Docker is installed but its daemon is not responding. \
                     `systemctl status docker` will say why."
                        .into(),
                ),
            });
        }

        Ok(ListOutput {
            installed: true,
            daemon_running: true,
            containers: containers(&docker).await,
            images: images(&docker).await,
            volumes: volumes(&docker).await,
            note: None,
        })
    }
}

async fn run_docker(docker: &str, args: &[&str]) -> Option<String> {
    let out = unihelm_distro::Cmd::new(docker)
        .args(args)
        .timeout(BUDGET)
        .run()
        .await
        .ok()?;
    out.success().then(|| out.trimmed_stdout().to_string())
}

/// Docker's Go template output, one record per line, tab-separated.
///
/// `--format` with explicit fields rather than `--format json`: the JSON shape
/// has changed between Docker releases, and a tab-separated template of named
/// fields is the one thing that has been stable across all of them.
fn rows(text: &str, fields: usize) -> Vec<Vec<String>> {
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| {
            let parts: Vec<String> = l.split('\t').map(|p| p.trim().to_string()).collect();
            (parts.len() == fields).then_some(parts)
        })
        .collect()
}

async fn containers(docker: &str) -> Vec<Container> {
    let Some(text) = run_docker(
        docker,
        &[
            "ps",
            "--all",
            "--format",
            "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}",
        ],
    )
    .await
    else {
        return Vec::new();
    };

    rows(&text, 5)
        .into_iter()
        .map(|r| Container {
            // Docker's status prose is localised in some builds, but "Up" as a
            // prefix is emitted by the daemon rather than translated, and it is
            // what `docker ps` filters on internally.
            running: r[3].starts_with("Up"),
            id: r[0].clone(),
            name: r[1].clone(),
            image: r[2].clone(),
            status: r[3].clone(),
            ports: r[4].clone(),
        })
        .collect()
}

async fn images(docker: &str) -> Vec<Image> {
    let Some(text) = run_docker(
        docker,
        &[
            "images",
            "--format",
            "{{.ID}}\t{{.Repository}}\t{{.Tag}}\t{{.Size}}",
        ],
    )
    .await
    else {
        return Vec::new();
    };

    rows(&text, 4)
        .into_iter()
        .map(|r| Image {
            id: r[0].clone(),
            repository: r[1].clone(),
            tag: r[2].clone(),
            size: r[3].clone(),
        })
        .collect()
}

async fn volumes(docker: &str) -> Vec<Volume> {
    let Some(text) = run_docker(
        docker,
        &["volume", "ls", "--format", "{{.Name}}\t{{.Driver}}"],
    )
    .await
    else {
        return Vec::new();
    };

    rows(&text, 2)
        .into_iter()
        .map(|r| Volume {
            name: r[0].clone(),
            driver: r[1].clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A container that is up must be reported as running, and one that is not
    /// must not — the panel's list is the thing an operator decides from.
    #[test]
    fn running_is_derived_from_dockers_own_status_prefix() {
        let text = "abc123\tweb\tnginx:latest\tUp 3 hours\t0.0.0.0:80->80/tcp\n\
                    def456\told\tredis:7\tExited (0) 2 days ago\t\n";
        let found = rows(text, 5);
        assert_eq!(found.len(), 2);
        assert!(found[0][3].starts_with("Up"));
        assert!(!found[1][3].starts_with("Up"));
    }

    /// A stopped container with no published ports still produces its column,
    /// so the record must not be dropped for having an empty field.
    #[test]
    fn a_record_with_empty_trailing_fields_is_kept() {
        let text = "def456\told\tredis:7\tExited (0) 2 days ago\t\n";
        assert_eq!(rows(text, 5).len(), 1, "a stopped container vanished");
    }

    /// Docker prints nothing at all when there is nothing to print, and a blank
    /// line is not a record.
    #[test]
    fn empty_and_ragged_output_produce_no_records() {
        assert!(rows("", 5).is_empty());
        assert!(rows("\n\n  \n", 5).is_empty());
        // A line with the wrong field count is a template that did not render,
        // not a container — inventing one from it would put a phantom in the
        // operator's list.
        assert!(rows("only\ttwo\n", 5).is_empty());
    }

    /// An image name can contain a colon and a slash; splitting on tabs rather
    /// than guessing at the shape is what keeps that intact.
    #[test]
    fn registry_qualified_image_names_survive() {
        let text = "sha256:aa\tregistry.example.com:5000/team/app\tv1.2.3\t120MB\n";
        let found = rows(text, 4);
        assert_eq!(found[0][1], "registry.example.com:5000/team/app");
        assert_eq!(found[0][2], "v1.2.3");
    }
}
