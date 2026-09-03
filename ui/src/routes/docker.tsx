import { useQuery } from "@tanstack/react-query";
import { Boxes, Container, HardDrive, Layers, RotateCw } from "lucide-react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader } from "@/components/ui/page-header";
import { SectionHeader } from "@/components/ui/section-header";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { ApiError, api } from "@/lib/api";
import { staggerStyle } from "@/lib/motion";
import { cn } from "@/lib/utils";

/**
 * Docker's inventory (`docker.list`).
 *
 * Four things here are decisions rather than layout:
 *
 * 1. **There is nothing to press.** The panel lists Docker and does not drive
 *    it, and that is said once at the top instead of shown as a row of disabled
 *    Start buttons. A greyed-out control is a promise that some permission
 *    ungreys it; nothing ungreys this one. A container holding the daemon
 *    socket is root on the machine, and the panel exists to keep anybody from
 *    getting there.
 * 2. **"Not installed" and "not answering" are two different pages.** The
 *    operation separates them deliberately, so the UI does too: an absent
 *    Docker is an empty state, because nothing is wrong — the operator simply
 *    has no Docker. A wedged daemon is a warning, because something *is*
 *    wrong and the containers it would have listed are still out there
 *    running. An operator debugging one of those does not want to be told the
 *    other.
 * 3. **The diagnosis is quoted, not paraphrased.** `note` carries the panel's
 *    reason in the words that name the next command — `stack.install`,
 *    `systemctl status docker`. Rewriting it here would be inventing a second
 *    source of truth about a machine this page cannot touch.
 * 4. **Stopped containers are listed.** They are still something the operator
 *    has and still hold their writable layer, so leaving them out would make
 *    the page lie about what is on the disk. The badge follows `running`,
 *    which the server derives once from Docker's own status prefix; nothing
 *    here reads the prose beside it. That prose is localised in some builds,
 *    and a panel that decided "stopped" from a translated word would be wrong
 *    on exactly the machines least able to notice.
 */
export function DockerPage() {
  const { t } = useTranslation();

  const list = useQuery({ queryKey: ["docker"], queryFn: fetchDockerInventory });

  return (
    <div className="space-y-6">
      <PageHeader
        title={t("docker.title")}
        description={t("docker.subtitle")}
        actions={
          // A re-read, not a control. Docker changes without the panel, and no
          // mutation on this page will ever settle and invalidate the query —
          // asking again is the only way this list gets newer. Deliberately not
          // a poll: a ten-second shell-out every few seconds is a cost the
          // operator did not ask for on a page they may leave open all day.
          <Button variant="outline" loading={list.isFetching} onClick={() => void list.refetch()}>
            <RotateCw className="h-4 w-4" aria-hidden />
            {t("docker.refresh")}
          </Button>
        }
      />

      <Callout tone="info" title={t("docker.readOnlyTitle")}>
        {t("docker.readOnly")}
      </Callout>

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
// The operation
// ---------------------------------------------------------------------------

/**
 * `docker.list`, typed here rather than in `lib/api.ts`.
 *
 * The shapes mirror `unihelm-ops::docker::ListOutput` field for field. They
 * belong beside `endpoints` with every other operation and should move there
 * once the REST route lands; keeping them local is what let this page be
 * written without editing a file two other pages are being written against.
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

const fetchDockerInventory = () => api.get<DockerInventory>("/api/server/docker");

// ---------------------------------------------------------------------------
// The three answers the operation can give
// ---------------------------------------------------------------------------

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
        <Table className="min-w-[640px]">
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
      </tr>
    </thead>
  );
}

function ContainerSection({ containers }: { containers: DockerContainer[] }) {
  const { t } = useTranslation();
  const running = containers.filter((row) => row.running).length;

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
      {containers.length === 0 ? (
        <EmptyState
          icon={<Container aria-hidden />}
          title={t("docker.noContainers")}
          hint={t("docker.noContainersHint")}
          className="py-10"
        />
      ) : (
        <Table className="min-w-[640px]">
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
              </Tr>
            ))}
          </tbody>
        </Table>
      )}
    </section>
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
