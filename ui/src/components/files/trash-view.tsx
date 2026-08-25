import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArchiveRestore, Trash2 } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { PurgeDialog } from "@/components/files/dialogs";
import { Button } from "@/components/ui/button";
import { Card, CardBody } from "@/components/ui/card";
import { Spinner } from "@/components/ui/spinner";
import { ApiError } from "@/lib/api";
import { filesApi, type TrashEntry } from "@/lib/files-api";
import { formatBytes } from "@/lib/utils";

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
    mutationFn: (path: string) => filesApi.trashRestore(path),
    onSuccess: refresh,
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  const dateFormat = new Intl.DateTimeFormat(i18n.language, {
    dateStyle: "medium",
    timeStyle: "short",
  });

  const entries: TrashEntry[] = trash.data?.entries ?? [];

  return (
    <Card>
      <CardBody className="pt-4">
        <div className="mb-3 flex items-center justify-between gap-3">
          <p className="text-sm text-ink-muted">{t("files.trashRetention")}</p>
          <Button
            variant="outline"
            size="sm"
            onClick={() => setPurging(true)}
            disabled={entries.length === 0}
          >
            <Trash2 className="h-3.5 w-3.5" />
            {t("files.purge")}
          </Button>
        </div>

        {error ? (
          <p role="alert" className="mb-3 rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
            {error}
          </p>
        ) : null}

        {trash.isPending ? (
          <div className="flex justify-center py-16 text-ink-muted">
            <Spinner className="h-6 w-6" />
          </div>
        ) : entries.length === 0 ? (
          <div className="py-16 text-center">
            <Trash2 className="mx-auto mb-3 h-8 w-8 text-ink-subtle" aria-hidden />
            <p className="text-sm font-medium text-ink">{t("files.trashEmpty")}</p>
            <p className="mt-1 text-sm text-ink-muted">{t("files.trashEmptyHint")}</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[560px] border-collapse text-sm">
              <thead>
                <tr className="border-b border-border text-xs text-ink-muted">
                  <th className="px-2 py-2 text-start font-medium">{t("files.name")}</th>
                  <th className="px-2 py-2 text-start font-medium">{t("files.originalPath")}</th>
                  <th className="w-24 px-2 py-2 text-end font-medium">{t("files.size")}</th>
                  <th className="w-44 px-2 py-2 text-start font-medium">{t("files.deletedAt")}</th>
                  <th className="w-28 px-2 py-2" />
                </tr>
              </thead>
              <tbody>
                {entries.map((entry) => (
                  <tr
                    key={entry.path}
                    className="border-b border-border last:border-b-0 hover:bg-surface-muted"
                  >
                    <td className="max-w-0 px-2 py-2">
                      <span dir="auto" className="block truncate font-medium text-ink">
                        {entry.name}
                      </span>
                    </td>
                    <td className="max-w-0 px-2 py-2">
                      <span dir="ltr" className="block truncate text-start font-mono text-xs text-ink-subtle">
                        {entry.original_path ?? "—"}
                      </span>
                    </td>
                    <td dir="ltr" className="px-2 py-2 text-end tabular-nums text-ink-muted">
                      {entry.kind === "dir" ? "—" : formatBytes(entry.size, i18n.language)}
                    </td>
                    <td className="whitespace-nowrap px-2 py-2 text-ink-muted">
                      {entry.deleted_at === null || entry.deleted_at === undefined
                        ? "—"
                        : dateFormat.format(new Date(entry.deleted_at * 1000))}
                    </td>
                    <td className="px-2 py-2 text-end">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => restore.mutate(entry.path)}
                        disabled={restore.isPending}
                      >
                        <ArchiveRestore className="h-3.5 w-3.5" />
                        {t("files.restore")}
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardBody>

      {purging ? <PurgeDialog onClose={() => setPurging(false)} onDone={refresh} /> : null}
    </Card>
  );
}
