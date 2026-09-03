import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArchiveRestore, Trash2 } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { PurgeDialog } from "@/components/files/dialogs";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { EmptyState } from "@/components/ui/empty-state";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { ApiError } from "@/lib/api";
import { filesApi, type TrashEntry } from "@/lib/files-api";
import { staggerStyle } from "@/lib/motion";
import { formatBytes } from "@/lib/utils";

/** Shared by the table and its ghost, so the placeholder has the real columns. */
function TrashHead() {
  const { t } = useTranslation();
  return (
    <thead>
      <tr>
        <Th>{t("files.name")}</Th>
        <Th>{t("files.originalPath")}</Th>
        <Th className="w-24 text-end">{t("files.size")}</Th>
        <Th className="w-44">{t("files.deletedAt")}</Th>
        <Th className="w-28">
          <span className="sr-only">{t("files.actions")}</span>
        </Th>
      </tr>
    </thead>
  );
}

/**
 * The bin before it arrives: the real five-column shell rather than the shared
 * list ghost, which promises an avatar-and-pill row this view does not have.
 */
function TrashSkeleton({ rows = 4 }: { rows?: number }) {
  return (
    <div role="status" aria-live="polite">
      <Table className="min-w-[560px]">
        <TrashHead />
        <tbody>
          {Array.from({ length: rows }, (_, i) => (
            <tr key={i} className="animate-rise-in stagger" style={staggerStyle(i)}>
              <Td className="py-2">
                {/* Uneven: real names are not all the same length. */}
                <Skeleton className={i % 2 === 0 ? "h-3.5 w-32" : "h-3.5 w-48"} />
              </Td>
              <Td className="py-2">
                <Skeleton className="h-3 w-40" />
              </Td>
              <Td className="py-2">
                <Skeleton className="ms-auto h-3 w-12" />
              </Td>
              <Td className="py-2">
                <Skeleton className="h-3 w-28" />
              </Td>
              <Td className="py-2">
                <Skeleton className="ms-auto h-8 w-20 rounded-lg" />
              </Td>
            </tr>
          ))}
        </tbody>
      </Table>
    </div>
  );
}

/**
 * The recycle bin (spec §11.7): per-tenant `.trash`, quota-counted, purged
 * automatically after 7 days by the server. This view exists so "I deleted the
 * wrong thing" costs a click instead of a support ticket.
 */
export function TrashView() {
  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const [purging, setPurging] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const trash = useQuery({ queryKey: ["files-trash"], queryFn: filesApi.trash });

  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ["files-trash"] });
    // Restores change the live tree too.
    void queryClient.invalidateQueries({ queryKey: ["files"] });
  };

  const restore = useMutation({
    mutationFn: (name: string) => filesApi.trashRestore(name),
    onSuccess: refresh,
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  const dateFormat = new Intl.DateTimeFormat(i18n.language, {
    dateStyle: "medium",
    timeStyle: "short",
  });

  const entries: TrashEntry[] = trash.data?.entries ?? [];

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-ink-muted">{t("files.trashRetention")}</p>
        <Button
          variant="outline"
          size="sm"
          onClick={() => setPurging(true)}
          disabled={entries.length === 0}
        >
          <Trash2 className="h-3.5 w-3.5" aria-hidden />
          {t("files.purge")}
        </Button>
      </div>

      {error ? <Callout tone="danger">{error}</Callout> : null}

      {trash.isPending ? (
        <TrashSkeleton />
      ) : entries.length === 0 ? (
        <EmptyState
          icon={<Trash2 aria-hidden />}
          title={t("files.trashEmpty")}
          hint={t("files.trashEmptyHint")}
        />
      ) : (
        <Table className="min-w-[560px]">
          <TrashHead />
          <tbody>
            {entries.map((entry, index) => (
              <Tr
                key={entry.name}
                className="animate-rise-in stagger"
                style={staggerStyle(index)}
              >
                <Td className="max-w-0 py-2">
                  <span className="block truncate font-medium text-ink">{entry.name}</span>
                </Td>
                <Td className="max-w-0 py-2">
                  <span className="block truncate font-mono text-xs text-ink-subtle">
                    {entry.original_path ?? "—"}
                  </span>
                </Td>
                <Td className="py-2 text-end text-xs text-ink-muted">
                  {entry.kind === "dir" ? "—" : formatBytes(entry.size, i18n.language)}
                </Td>
                <Td className="whitespace-nowrap py-2 text-xs text-ink-muted">
                  {entry.deleted_at === null || entry.deleted_at === undefined
                    ? "—"
                    : dateFormat.format(new Date(entry.deleted_at * 1000))}
                </Td>
                <Td className="py-2 text-end">
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => restore.mutate(entry.name)}
                    // Every row waits while one restores, but only the row
                    // that was clicked shows the spinner.
                    loading={restore.isPending && restore.variables === entry.name}
                    disabled={restore.isPending}
                  >
                    <ArchiveRestore className="h-3.5 w-3.5" aria-hidden />
                    {t("files.restore")}
                  </Button>
                </Td>
              </Tr>
            ))}
          </tbody>
        </Table>
      )}

      {purging ? <PurgeDialog onClose={() => setPurging(false)} onDone={refresh} /> : null}
    </div>
  );
}
