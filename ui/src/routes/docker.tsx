import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Boxes,
  Container,
  HardDrive,
  Layers,
  Play,
  RotateCw,
  ScrollText,
  Square,
  Trash2,
  Plus,
} from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { Dialog } from "@/components/ui/dialog";
import { EmptyState } from "@/components/ui/empty-state";
import { Field, Input, Textarea } from "@/components/ui/input";
import { Menu, MenuItem, MenuSeparator } from "@/components/ui/menu";
import { PageHeader } from "@/components/ui/page-header";
import { SectionHeader } from "@/components/ui/section-header";
import { Select } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { ApiError, api, endpoints, type CreateContainerRequest } from "@/lib/api";
import { staggerStyle } from "@/lib/motion";
import { useSession } from "@/lib/session";
import { cn } from "@/lib/utils";

/**
 * Docker's inventory (`docker.list`), and the lifecycle of what is in it.
 *
 * Five things here are decisions rather than layout:
 *
 * 1. **The controls act on containers; nothing here makes one.** Start, stop,
 *    restart, remove and a log tail, because those are what an operator needs
 *    at 3am and the alternative is an SSH session. No "run", though, and the
 *    callout at the top says why rather than leaving a gap somebody reads as an
 *    oversight: a container can be handed the host's filesystem or the daemon
 *    socket by a single flag, so a form that took run arguments would be a root
 *    shell with a nicer font. The flags on what is listed below were chosen by
 *    whoever created it.
 * 2. **Stopping asks first; starting does not.** The panel did not create most
 *    of what is on this page — a container here may be an nginx serving
 *    somebody's production site, and it looks exactly like one an operator is
 *    finished with. Stop, restart and remove each take something away, so each
 *    names the container and waits. Start takes nothing away, and a dialog in
 *    front of the harmless action is how people learn to click through the one
 *    in front of the harmful one.
 * 3. **"Not installed" and "not answering" are two different pages.** The
 *    operation separates them deliberately, so the UI does too: an absent
 *    Docker is an empty state, because nothing is wrong — the operator simply
 *    has no Docker. A wedged daemon is a warning, because something *is*
 *    wrong and the containers it would have listed are still out there
 *    running. An operator debugging one of those does not want to be told the
 *    other.
 * 4. **The diagnosis is quoted, not paraphrased.** `note` carries the panel's
 *    reason in the words that name the next command — `stack.install`,
 *    `systemctl status docker`. Rewriting it here would be inventing a second
 *    source of truth about a machine this page cannot see. A failed action is
 *    reported the same way: Docker's own sentence, not ours.
 * 5. **Stopped containers are listed.** They are still something the operator
 *    has and still hold their writable layer, so leaving them out would make
 *    the page lie about what is on the disk. The badge follows `running`,
 *    which the server derives once from Docker's own status prefix; nothing
 *    here reads the prose beside it. That prose is localised in some builds,
 *    and a panel that decided "stopped" from a translated word would be wrong
 *    on exactly the machines least able to notice — and now it would also
 *    offer the wrong button, which is how a live container gets a Start it
 *    does not need and a dead one never gets the one it does.
 */
export function DockerPage() {
  const [creating, setCreating] = useState(false);
  const { t } = useTranslation();

  const list = useQuery({ queryKey: ["docker"], queryFn: fetchDockerInventory });

  return (
    <div className="space-y-6">
      <PageHeader
        title={t("docker.title")}
        description={t("docker.subtitle")}
        actions={
          // A re-read, not a control. Docker changes without the panel — the
          // actions on this page invalidate the query themselves, but a
          // container that exited on its own will not — so asking again is how
          // the list catches up with everything nobody here did. Deliberately
          // not a poll: a ten-second shell-out every few seconds is a cost the
          // operator did not ask for on a page they may leave open all day.
          <>
            <Button variant="outline" loading={list.isFetching} onClick={() => void list.refetch()}>
              <RotateCw className="h-4 w-4" aria-hidden />
              {t("docker.refresh")}
            </Button>
            {list.data?.daemon_running ? (
              <Button onClick={() => setCreating(true)}>
                <Plus className="h-4 w-4" aria-hidden />
                {t("docker.create")}
              </Button>
            ) : null}
          </>
        }
      />

      <Callout tone="info" title={t("docker.noRunTitle")}>
        {t("docker.noRun")}
      </Callout>

      <CreateContainerDialog open={creating} onClose={() => setCreating(false)} />

      {list.isPending ? (
        <InventorySkeleton />
      ) : list.error ? (
        <Callout tone="danger">
          {list.error instanceof ApiError ? list.error.message : String(list.error)}
        </Callout>
      ) : (
        <Inventory inventory={list.data!} />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// The operations
// ---------------------------------------------------------------------------

/**
 * `docker.list` and the container lifecycle, typed here rather than in
 * `lib/api.ts`.
 *
 * The shapes mirror `unihelm-ops::docker` field for field. They belong beside
 * `endpoints` with every other operation and should move there once the REST
 * routes land; keeping them local is what let this page be written without
 * editing a file two other pages are being written against.
 */
interface DockerContainer {
  id: string;
  name: string;
  image: string;
  /** Docker's own prose: `Up 3 hours`, `Exited (0) 2 days ago`. */
  status: string;
  /** Decided server-side from the status prefix, so nothing here parses prose. */
  running: boolean;
  /** Published ports as Docker prints them; empty when none are. */
  ports: string;
}

interface DockerImage {
  id: string;
  repository: string;
  tag: string;
  size: string;
}

interface DockerVolume {
  name: string;
  driver: string;
}

interface DockerInventory {
  /** False when there is no `docker` on the machine at all. */
  installed: boolean;
  /** False when Docker is there but its daemon is not answering. */
  daemon_running: boolean;
  containers: DockerContainer[];
  images: DockerImage[];
  volumes: DockerVolume[];
  /** What went wrong, when something did, in the server's own words. */
  note: string | null;
}

interface DockerLogs {
  id: string;
  name: string;
  /** Both output streams, already merged into the order they happened. */
  lines: string[];
}

/** How many lines the log dialog asks for; the agent's own default is the same. */
const LOG_LINES = 200;

/** The three actions that change a container without deleting it. */
type ContainerAction = "start" | "stop" | "restart";

const fetchDockerInventory = () => api.get<DockerInventory>("/api/server/docker");

// Addressed by id, never by name. A name can be moved onto a different
// container by a `docker rename` or a compose recreate between this list being
// drawn and a button being pressed; an id cannot.
const containerAction = (id: string, action: ContainerAction) =>
  api.post<unknown>(`/api/server/docker/containers/${id}/${action}`);

const removeContainer = (id: string) => api.del<unknown>(`/api/server/docker/containers/${id}`);

const fetchContainerLogs = (id: string) =>
  api.get<DockerLogs>(`/api/server/docker/containers/${id}/logs?lines=${LOG_LINES}`);

// ---------------------------------------------------------------------------
// The three answers the operation can give
// ---------------------------------------------------------------------------

/**
 * Create a container.
 *
 * A form rather than a command line, and the fields are the whole of what this
 * panel will pass to Docker. There is no box for extra flags on purpose:
 * `--privileged`, `-v /:/host` and the daemon socket each make a container root
 * on this server, and no allow-list of flags is both short enough to be safe and
 * long enough to be worth having. Anything past this is `docker run` over SSH.
 *
 * The lists are textareas of one entry per line rather than repeating field
 * rows: somebody setting up a container usually has these in front of them
 * already, in exactly this shape, from a compose file or a README.
 */
function CreateContainerDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [image, setImage] = useState("");
  const [name, setName] = useState("");
  const [ports, setPorts] = useState("");
  const [env, setEnv] = useState("");
  const [volumes, setVolumes] = useState("");
  const [restart, setRestart] = useState<CreateContainerRequest["restart"]>("unless-stopped");
  const [error, setError] = useState<string | null>(null);

  const lines = (text: string) =>
    text
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean);

  const create = useMutation({
    mutationFn: () =>
      endpoints.createContainer({
        image: image.trim(),
        name: name.trim(),
        ports: lines(ports).map((line) => {
          const udp = line.endsWith("/udp");
          const [host, container] = line.replace(/\/(udp|tcp)$/, "").split(":");
          return {
            host: Number(host),
            container: Number(container),
            udp,
          };
        }),
        env: lines(env).map((line) => {
          const at = line.indexOf("=");
          return { key: line.slice(0, at), value: line.slice(at + 1) };
        }),
        volumes: lines(volumes).map((line) => {
          const at = line.indexOf(":");
          return { volume: line.slice(0, at), path: line.slice(at + 1) };
        }),
        restart,
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["docker"] });
      onClose();
      setImage("");
      setName("");
      setPorts("");
      setEnv("");
      setVolumes("");
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={t("docker.createTitle")}
      description={t("docker.createHint")}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button
            loading={create.isPending}
            disabled={image.trim() === "" || name.trim() === ""}
            onClick={() => {
              setError(null);
              create.mutate();
            }}
          >
            {t("docker.createConfirm")}
          </Button>
        </>
      }
    >
      {error ? (
        <Callout tone="danger" className="mb-3">
          {error}
        </Callout>
      ) : null}

      <Field label={t("docker.imageField")} htmlFor="dk-image">
        <Input id="dk-image" value={image} onChange={(e) => setImage(e.target.value)} placeholder="nginx:alpine" />
      </Field>
      <p className="-mt-1 mb-3 text-xs text-ink-muted">{t("docker.imageHint")}</p>

      <Field label={t("docker.containerName")} htmlFor="dk-name">
        <Input id="dk-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="web" />
      </Field>
      <p className="-mt-1 mb-3 text-xs text-ink-muted">{t("docker.containerNameHint")}</p>

      <Field label={t("docker.portsLabel")} htmlFor="dk-ports">
        <Textarea id="dk-ports" rows={2} value={ports} onChange={(e) => setPorts(e.target.value)} placeholder="8080:80" />
      </Field>
      <p className="-mt-1 mb-3 text-xs text-ink-muted">{t("docker.portsHint")}</p>

      <Field label={t("docker.envLabel")} htmlFor="dk-env">
        <Textarea id="dk-env" rows={2} value={env} onChange={(e) => setEnv(e.target.value)} placeholder="NODE_ENV=production" />
      </Field>
      <p className="-mt-1 mb-3 text-xs text-ink-muted">{t("docker.envHint")}</p>

      <Field label={t("docker.volumesLabel")} htmlFor="dk-volumes">
        <Textarea id="dk-volumes" rows={2} value={volumes} onChange={(e) => setVolumes(e.target.value)} placeholder="app_data:/var/lib/app" />
      </Field>
      <p className="-mt-1 mb-3 text-xs text-ink-muted">{t("docker.volumesFieldHint")}</p>

      <Field label={t("docker.restartLabel")} htmlFor="dk-restart">
        <Select
          id="dk-restart"
          value={restart}
          onChange={(e) => setRestart(e.target.value as CreateContainerRequest["restart"])}
        >
          <option value="unless-stopped">unless-stopped</option>
          <option value="always">always</option>
          <option value="on-failure">on-failure</option>
          <option value="no">no</option>
        </Select>
      </Field>
    </Dialog>
  );
}

function Inventory({ inventory }: { inventory: DockerInventory }) {
  const { t } = useTranslation();

  // No Docker at all. An empty state rather than an error: the machine is fine,
  // it just has no Docker, and a red banner would send an operator looking for
  // a fault that is not there.
  if (!inventory.installed) {
    return (
      <EmptyState
        icon={<Container aria-hidden />}
        title={t("docker.absentTitle")}
        hint={inventory.note ?? t("docker.absentHint")}
      />
    );
  }

  // Installed and wedged. A warning, because the containers this page cannot
  // list are still running out there — the inventory is missing, not empty.
  if (!inventory.daemon_running) {
    return (
      <Callout tone="warning" title={t("docker.daemonDownTitle")}>
        {/* The agent's own note already carries the remedy, and printing a
            second copy of the same sentence underneath made the page look like
            it had two different things to say. Fall back to our own wording
            only when the agent sent none. */}
        <p>{inventory.note ?? t("docker.daemonDownHint")}</p>
        {inventory.note ? null : <p className="mt-1.5">{t("docker.daemonDownNote")}</p>}
      </Callout>
    );
  }

  const empty =
    inventory.containers.length === 0 &&
    inventory.images.length === 0 &&
    inventory.volumes.length === 0;

  // Working and holding nothing. One empty state, not three: three dashed boxes
  // saying the same thing reads as three failures rather than one clean answer.
  if (empty) {
    return (
      <EmptyState
        icon={<Boxes aria-hidden />}
        title={t("docker.emptyTitle")}
        hint={t("docker.emptyHint")}
      />
    );
  }

  return (
    <>
      <ContainerSection containers={inventory.containers} />
      <ImageSection images={inventory.images} />
      <VolumeSection volumes={inventory.volumes} />
    </>
  );
}

/**
 * Ghosts of the three tables, in the columns they land in.
 *
 * Built on the shared `Table` rather than a copy of its classes, like every
 * other table ghost in the panel, so a change to the card's border or radius
 * reaches the loading state too. The section headings render now and the rows
 * fill in, so the page arrives at its final height once.
 */
function InventorySkeleton() {
  const { t } = useTranslation();
  // The same gate the real rows use. A ghost that draws a verb button the
  // arriving row will not have is a ghost that moves the ⋯ sideways under the
  // pointer, which is the jump this component exists to stop.
  const { user } = useSession();
  const canManage = user?.permissions.includes("server_manage") ?? false;
  return (
    <div role="status" aria-live="polite" className="space-y-6">
      <section className="space-y-3">
        <SectionHeader
          title={t("docker.containersTitle")}
          description={t("docker.containersHint")}
        />
        {/* The same `min-w` as the real table. Without it the ghost lays its
            columns out at one width and the rows arrive at another, which is
            the horizontal version of the jump this component exists to stop. */}
        <Table className="min-w-[780px]">
          <ContainerHead />
          <tbody>
            {Array.from({ length: 3 }, (_, i) => (
              <tr key={i} className="animate-rise-in stagger" style={staggerStyle(i)}>
                <Td>
                  {/* Uneven widths: container names are not all one length, and
                      a perfectly regular ghost reads as a loading graphic. */}
                  <Skeleton className={cn("h-3.5", i % 2 === 0 ? "w-40" : "w-28")} />
                  <Skeleton className="mt-1.5 h-3 w-20" />
                </Td>
                <Td>
                  <Skeleton className="h-3.5 w-32" />
                </Td>
                <Td>
                  <Skeleton className="h-5 w-24 rounded-full" />
                  {/* Two lines, because the real status cell is a badge with
                      Docker's prose under it and it is the cell that sets the
                      row's height. */}
                  <Skeleton className="mt-1 h-3 w-28" />
                </Td>
                <Td>
                  <Skeleton className="h-3.5 w-24" />
                </Td>
                <Td>
                  {/* A button and a ⋯, at the size they arrive at. This is the
                      cell the pointer is already heading for, so it is the one
                      that must not move when the rows land. */}
                  <div className="flex items-center justify-end gap-1">
                    {canManage ? <Skeleton className="h-8 w-20 rounded-lg" /> : null}
                    <Skeleton className="h-8 w-8 rounded-lg" />
                  </div>
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      </section>

      <section className="space-y-3">
        <SectionHeader title={t("docker.imagesTitle")} description={t("docker.imagesHint")} />
        <Table className="min-w-[560px]">
          <ImageHead />
          <tbody>
            {Array.from({ length: 2 }, (_, i) => (
              <tr key={i} className="animate-rise-in stagger" style={staggerStyle(i)}>
                <Td>
                  <Skeleton className={cn("h-3.5", i % 2 === 0 ? "w-48" : "w-32")} />
                  <Skeleton className="mt-1.5 h-3 w-24" />
                </Td>
                <Td>
                  <Skeleton className="h-5 w-16 rounded-full" />
                </Td>
                <Td>
                  <Skeleton className="ms-auto h-3.5 w-14" />
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      </section>

      <section className="space-y-3">
        <SectionHeader title={t("docker.volumesTitle")} description={t("docker.volumesHint")} />
        <Table>
          <VolumeHead />
          <tbody>
            {Array.from({ length: 2 }, (_, i) => (
              <tr key={i} className="animate-rise-in stagger" style={staggerStyle(i)}>
                <Td>
                  <Skeleton className={cn("h-3.5", i % 2 === 0 ? "w-56" : "w-36")} />
                </Td>
                <Td>
                  <Skeleton className="h-3.5 w-16" />
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      </section>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Containers
// ---------------------------------------------------------------------------

/** Named once so the ghost above can borrow the real header rather than guess. */
function ContainerHead() {
  const { t } = useTranslation();
  return (
    <thead>
      <tr>
        <Th>{t("docker.container")}</Th>
        <Th>{t("docker.image")}</Th>
        <Th className="w-48">{t("docker.status")}</Th>
        <Th className="w-56">{t("docker.ports")}</Th>
        <Th className="w-44 text-end">{t("docker.actions")}</Th>
      </tr>
    </thead>
  );
}

function ContainerSection({ containers }: { containers: DockerContainer[] }) {
  const { t } = useTranslation();
  const running = containers.filter((row) => row.running).length;

  // One error sink for the whole table rather than one per row. Docker's
  // failures are sentences — "Cannot connect to the Docker daemon", "container
  // is marked for removal" — and a sentence folded into a table cell is a
  // sentence nobody reads. It carries the container's name, so a row far down
  // a long list is still attributable.
  const [error, setError] = useState<string | null>(null);

  return (
    <section className="space-y-3">
      <SectionHeader
        title={t("docker.containersTitle")}
        description={t("docker.containersHint")}
        // The count belongs in the heading, not in a column total: the table
        // deliberately mixes running and stopped, so how many are actually up
        // is the one thing scanning the rows will not tell you.
        actions={
          containers.length > 0 ? (
            <Badge tone={running > 0 ? "success" : "neutral"} dot>
              {t("docker.runningOf", { running, total: containers.length })}
            </Badge>
          ) : null
        }
      />

      {error ? <Callout tone="danger">{error}</Callout> : null}

      {containers.length === 0 ? (
        <EmptyState
          icon={<Container aria-hidden />}
          title={t("docker.noContainers")}
          hint={t("docker.noContainersHint")}
          className="py-10"
        />
      ) : (
        <Table className="min-w-[780px]">
          <ContainerHead />
          <tbody>
            {containers.map((row, index) => (
              <Tr key={row.id} className="animate-rise-in stagger" style={staggerStyle(index)}>
                <Td className="w-full">
                  <p className="font-mono text-xs break-all text-ink">{row.name}</p>
                  {/* The id, because it is what an operator types into
                      `docker logs` — and the only thing that stays put when
                      two containers share a name across a recreate. */}
                  <p className="tnum mt-0.5 font-mono text-xs text-ink-subtle">{row.id}</p>
                </Td>
                <Td className="font-mono text-xs break-all text-ink-muted">{row.image}</Td>
                <Td>
                  <div className="flex flex-col items-start gap-1">
                    <Badge tone={row.running ? "success" : "neutral"} dot>
                      {row.running ? t("docker.running") : t("docker.stopped")}
                    </Badge>
                    {/* Docker's own prose under the verdict: "Exited (137)" is
                        the difference between a clean stop and an OOM kill, and
                        no badge can carry that. */}
                    <span className="text-xs text-ink-muted">{row.status}</span>
                  </div>
                </Td>
                <Td className="font-mono text-xs break-all text-ink-muted">
                  {row.ports.trim() === "" ? (
                    <span className="text-ink-subtle">{t("docker.noPorts")}</span>
                  ) : (
                    row.ports
                  )}
                </Td>
                <Td>
                  <ContainerActions container={row} onError={setError} />
                </Td>
              </Tr>
            ))}
          </tbody>
        </Table>
      )}
    </section>
  );
}

/** The three actions that want a second thought before they happen. */
type Confirmable = "stop" | "restart" | "remove";

/**
 * One row's controls.
 *
 * The state-changing verb is inline and everything else is behind the ⋯, which
 * is this panel's rule for a table row: three inline buttons per row is a
 * control panel, one ⋯ is a row. Which verb is inline follows the container —
 * Start for a stopped one, Stop for a running one — so the button under the
 * pointer is always the one that changes what the badge beside it says.
 *
 * Remove is offered on both. The agent refuses to remove a running container
 * rather than forcing it, and a menu item that quietly disappeared for running
 * containers would hide that rule instead of teaching it; the confirmation says
 * what will happen and the agent's refusal is the backstop.
 *
 * The four verbs need `server.manage`; the log tail needs only the
 * `server.read` that drew this row. This page sits in the sidebar for anyone
 * who can see the shell, so somebody holding just the read half will reach it —
 * and showing them a Stop that can only ever answer 403 teaches them the panel
 * is broken rather than that they lack the permission. Hidden, not disabled:
 * greying it out promises some toggle ungreys it, and their own role is not one
 * of the things they can toggle. The agent re-checks regardless.
 */
function ContainerActions({
  container,
  onError,
}: {
  container: DockerContainer;
  onError: (message: string | null) => void;
}) {
  const { t } = useTranslation();
  const { user } = useSession();
  const queryClient = useQueryClient();
  const [confirming, setConfirming] = useState<Confirmable | null>(null);
  const [showLogs, setShowLogs] = useState(false);

  const canManage = user?.permissions.includes("server_manage") ?? false;

  const settled = () => {
    setConfirming(null);
    onError(null);
    void queryClient.invalidateQueries({ queryKey: ["docker"] });
  };

  const failed = (e: unknown) => {
    // The dialog closes on the way out. Leaving it up over a message printed
    // behind it would give the operator two places to look and one button that
    // has already had its effect.
    setConfirming(null);
    onError(
      t("docker.actionFailed", {
        name: container.name,
        message: e instanceof ApiError ? e.message : String(e),
      }),
    );
  };

  const act = useMutation({
    mutationFn: (action: ContainerAction) => containerAction(container.id, action),
    onSuccess: settled,
    onError: failed,
  });

  const remove = useMutation({
    mutationFn: () => removeContainer(container.id),
    onSuccess: settled,
    onError: failed,
  });

  const busy = act.isPending || remove.isPending;

  return (
    <div className="flex items-center justify-end gap-1">
      {canManage &&
        (container.running ? (
          <Button
            variant="ghost"
            size="sm"
            disabled={busy}
            loading={act.isPending && act.variables === "stop"}
            onClick={() => setConfirming("stop")}
          >
            <Square className="h-3.5 w-3.5" aria-hidden />
            {t("docker.stop")}
          </Button>
        ) : (
          <Button
            variant="ghost"
            size="sm"
            disabled={busy}
            loading={act.isPending && act.variables === "start"}
            onClick={() => act.mutate("start")}
          >
            <Play className="h-3.5 w-3.5" aria-hidden />
            {t("docker.start")}
          </Button>
        ))}

      <Menu label={t("docker.actionsFor", { name: container.name })}>
        {canManage && container.running ? (
          <MenuItem icon={<RotateCw aria-hidden />} onClick={() => setConfirming("restart")}>
            {t("docker.restart")}
          </MenuItem>
        ) : null}
        <MenuItem icon={<ScrollText aria-hidden />} onClick={() => setShowLogs(true)}>
          {t("docker.logs")}
        </MenuItem>
        {canManage ? (
          <>
            <MenuSeparator />
            <MenuItem danger icon={<Trash2 aria-hidden />} onClick={() => setConfirming("remove")}>
              {t("docker.remove")}
            </MenuItem>
          </>
        ) : null}
      </Menu>

      <LogsDialog container={container} open={showLogs} onClose={() => setShowLogs(false)} />

      <ConfirmDialog
        action={confirming}
        container={container}
        busy={busy}
        onClose={() => setConfirming(null)}
        onConfirm={(action) => (action === "remove" ? remove.mutate() : act.mutate(action))}
      />
    </div>
  );
}

/**
 * The pause in front of stop, restart and remove.
 *
 * One dialog for the three, because the shape of the question is identical and
 * three near-copies would drift apart the first time one of them was reworded.
 * Rendered only while an action is pending confirmation — `Dialog` disappears
 * instantly rather than animating out, so there is no closing frame in which a
 * missing action could show through as the wrong wording.
 */
function ConfirmDialog({
  action,
  container,
  busy,
  onClose,
  onConfirm,
}: {
  action: Confirmable | null;
  container: DockerContainer;
  busy: boolean;
  onClose: () => void;
  onConfirm: (action: Confirmable) => void;
}) {
  const { t } = useTranslation();
  if (action === null) return null;

  return (
    <Dialog
      open
      onClose={onClose}
      title={t(`docker.confirm.${action}.title`, { name: container.name })}
      description={t(`docker.confirm.${action}.hint`)}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button variant="danger" loading={busy} onClick={() => onConfirm(action)}>
            {t(`docker.confirm.${action}.confirm`)}
          </Button>
        </>
      }
    >
      {/* The sentence that matters is about this machine, not about Docker.
          Most of what is on this page was put here by somebody else, and the
          panel genuinely does not know what depends on it. */}
      <p className="text-sm text-ink-muted">{t(`docker.confirm.${action}.body`)}</p>
      {/* The id, because two containers can wear one name across a recreate and
          only this says which one is about to be acted on. */}
      <p className="mt-3 font-mono text-xs break-all text-ink-subtle">{container.id}</p>
    </Dialog>
  );
}

/**
 * The last lines a container has written.
 *
 * Read only while the dialog is open and never on a timer: a tail is a
 * shell-out per request, and a dialog left open on a second monitor should not
 * become a standing load on somebody's server.
 *
 * The lines arrive already merged. Docker keeps a container's stdout and its
 * stderr apart, and most server software logs to stderr, so the agent puts the
 * two back into one order before they get here; nothing on this side sorts,
 * filters or re-reads them.
 */
function LogsDialog({
  container,
  open,
  onClose,
}: {
  container: DockerContainer;
  open: boolean;
  onClose: () => void;
}) {
  const { t } = useTranslation();

  const logs = useQuery({
    queryKey: ["docker-logs", container.id],
    queryFn: () => fetchContainerLogs(container.id),
    enabled: open,
  });

  return (
    <Dialog
      open={open}
      onClose={onClose}
      wide
      title={t("docker.logsTitle", { name: container.name })}
      description={t("docker.logsHint", { lines: LOG_LINES })}
      footer={
        <>
          <Button variant="ghost" loading={logs.isFetching} onClick={() => void logs.refetch()}>
            <RotateCw className="h-3.5 w-3.5" aria-hidden />
            {t("docker.refresh")}
          </Button>
          <Button variant="secondary" onClick={onClose}>
            {t("common.close")}
          </Button>
        </>
      }
    >
      <p className="mb-2 truncate font-mono text-xs text-ink-subtle">{container.id}</p>

      {logs.isPending ? (
        <div className="space-y-2 rounded-lg border border-border bg-canvas p-3">
          <Skeleton className="h-3 w-full" />
          <Skeleton className="h-3 w-5/6" />
          <Skeleton className="h-3 w-2/3" />
          <Skeleton className="h-3 w-3/4" />
        </div>
      ) : logs.error ? (
        <Callout tone="danger">
          {logs.error instanceof ApiError ? logs.error.message : String(logs.error)}
        </Callout>
      ) : (
        <div
          aria-busy={logs.isFetching || undefined}
          className={cn(
            "max-h-[50vh] overflow-y-auto rounded-lg border border-border bg-canvas p-3 font-mono text-xs leading-relaxed",
            // A refetch replaces every line in one frame. Fading the panel out
            // and back is what tells the reader the text they were part-way
            // through is no longer the same text.
            "transition-opacity duration-150",
            logs.isFetching && "opacity-50",
          )}
        >
          {(logs.data?.lines.length ?? 0) === 0 ? (
            // Nothing written is not a failure: a container started seconds ago
            // and one whose logging driver sends its output somewhere else both
            // land here, and the hint says so rather than implying a fault. No
            // second dashed border inside the log panel's own box, and back to
            // the UI face — the mono is for log lines, not for prose.
            <EmptyState
              className="border-0 px-2 py-8 font-sans"
              icon={<ScrollText aria-hidden />}
              title={t("docker.logsEmpty")}
              hint={t("docker.logsEmptyHint")}
            />
          ) : (
            logs.data!.lines.map((line, index) => (
              // Container output is machine text; `break-all` keeps a long
              // stack trace inside the box.
              <div
                key={`${index}-${line}`}
                className="whitespace-pre-wrap break-all text-ink-muted"
              >
                {line}
              </div>
            ))
          )}
        </div>
      )}
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Images
// ---------------------------------------------------------------------------

function ImageHead() {
  const { t } = useTranslation();
  return (
    <thead>
      <tr>
        <Th>{t("docker.repository")}</Th>
        <Th className="w-40">{t("docker.tag")}</Th>
        <Th className="w-28 text-end">{t("docker.size")}</Th>
      </tr>
    </thead>
  );
}

function ImageSection({ images }: { images: DockerImage[] }) {
  const { t } = useTranslation();

  return (
    <section className="space-y-3">
      <SectionHeader title={t("docker.imagesTitle")} description={t("docker.imagesHint")} />
      {images.length === 0 ? (
        <EmptyState
          icon={<Layers aria-hidden />}
          title={t("docker.noImages")}
          hint={t("docker.noImagesHint")}
          className="py-10"
        />
      ) : (
        <Table className="min-w-[560px]">
          <ImageHead />
          <tbody>
            {images.map((row, index) => (
              <Tr
                // Two tags of one image share an id, so the id alone is not an
                // identity here; the pair is.
                key={`${row.id}-${row.repository}:${row.tag}`}
                className="animate-rise-in stagger"
                style={staggerStyle(index)}
              >
                <Td className="w-full">
                  {/* A registry-qualified name carries its own host and port and
                      must break rather than push the size column off the card. */}
                  <p className="font-mono text-xs break-all text-ink">{row.repository}</p>
                  <p className="tnum mt-0.5 font-mono text-xs text-ink-subtle">{row.id}</p>
                </Td>
                <Td className="whitespace-nowrap">
                  {/* Neutral, not accent: `latest` is not a better tag than a
                      pinned one, and a colour would say it was. */}
                  <Badge tone="neutral">{row.tag}</Badge>
                </Td>
                <Td className="tnum text-end whitespace-nowrap text-ink-muted">{row.size}</Td>
              </Tr>
            ))}
          </tbody>
        </Table>
      )}
    </section>
  );
}

// ---------------------------------------------------------------------------
// Volumes
// ---------------------------------------------------------------------------

function VolumeHead() {
  const { t } = useTranslation();
  return (
    <thead>
      <tr>
        <Th>{t("docker.volume")}</Th>
        <Th className="w-40">{t("docker.driver")}</Th>
      </tr>
    </thead>
  );
}

function VolumeSection({ volumes }: { volumes: DockerVolume[] }) {
  const { t } = useTranslation();

  return (
    <section className="space-y-3">
      <SectionHeader title={t("docker.volumesTitle")} description={t("docker.volumesHint")} />
      {volumes.length === 0 ? (
        <EmptyState
          icon={<HardDrive aria-hidden />}
          title={t("docker.noVolumes")}
          hint={t("docker.noVolumesHint")}
          className="py-10"
        />
      ) : (
        <Table>
          <VolumeHead />
          <tbody>
            {volumes.map((row, index) => (
              <Tr key={row.name} className="animate-rise-in stagger" style={staggerStyle(index)}>
                <Td className="w-full font-mono text-xs break-all">{row.name}</Td>
                <Td className="whitespace-nowrap text-ink-muted">{row.driver}</Td>
              </Tr>
            ))}
          </tbody>
        </Table>
      )}
    </section>
  );
}
