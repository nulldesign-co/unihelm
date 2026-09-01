import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Image, Palette, Trash2, Upload } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Field, Input } from "@/components/ui/input";
import { PageHeader } from "@/components/ui/page-header";
import { Skeleton } from "@/components/ui/skeleton";
import {
  ApiError,
  endpoints,
  type BrandingAssetChange,
  type BrandingAssetKind,
  type BrandingRequest,
  type BrandingSettings,
} from "@/lib/api";
import { assetUrl, useBranding } from "@/lib/branding";
import { staggerStyle } from "@/lib/motion";
import { cn } from "@/lib/utils";

/**
 * White-label branding (spec §11.19).
 *
 * Three things this page is built around:
 *
 * 1. **Empty means "inherit".** Every field falls back to the panel default,
 *    field by field, so a reseller who sets only a logo keeps the panel's name
 *    and colour. Clearing a field is therefore not "set it to empty" but "go
 *    back to inheriting", and the placeholder shows what would be inherited so
 *    the difference is visible rather than explained.
 * 2. **Saving is instant.** Branding is data, not configuration: the response
 *    is 200 with the new values, not a task, because there is nothing to
 *    render or reload. The page invalidates the public branding query so the
 *    colour and the title change under the operator as they save — which is
 *    spec §11.19's "no restart" made visible.
 * 3. **SVG is refused, and the page says why.** Uploads are identified by
 *    their bytes, not their filename, so the file input's `accept` list is a
 *    convenience and the server's answer is the authority. The reason is in
 *    the copy rather than in a tooltip, because "why can I not use my SVG
 *    logo" is otherwise a support ticket.
 */
export function BrandingPage() {
  const { t } = useTranslation();
  const settings = useQuery({
    queryKey: ["branding-settings"],
    queryFn: () => endpoints.brandingSettings(),
  });

  return (
    <div className="space-y-6">
      <PageHeader title={t("branding.title")} description={t("branding.subtitle")} />

      {settings.isPending ? (
        <BrandingSkeleton />
      ) : settings.error ? (
        <Callout tone="danger" title={t("error.title")}>
          {settings.error instanceof ApiError ? settings.error.message : String(settings.error)}
        </Callout>
      ) : (
        <BrandingForm settings={settings.data!} />
      )}
    </div>
  );
}

const ASSET_KINDS: BrandingAssetKind[] = ["logo", "favicon", "login_background"];

/**
 * The swatch a never-branded panel opens on.
 *
 * `<input type="color">` only speaks `#rrggbb`, and `--color-accent` is an
 * oklch token it would refuse, so this one literal cannot be a token. It is a
 * last resort: the picker prefers the colour actually being inherited, which is
 * the same value the text field shows as its placeholder — the two used to
 * disagree, and the swatch was always blue however the panel was branded.
 */
const FALLBACK_SWATCH = "#3b82f6";
const isHex = (value: string) => /^#[0-9a-fA-F]{6}$/.test(value);

/**
 * The two cards' own shape while the settings load.
 *
 * A centred spinner here left the route blank for the whole fetch and then
 * dropped both cards in at once — the largest layout shift in the panel. The
 * ghost fields are the same heights as the real ones, so nothing moves when
 * the answer arrives.
 */
function BrandingSkeleton() {
  return (
    <div role="status" aria-live="polite" className="space-y-6">
      <Card>
        <CardBody className="space-y-5 pt-5">
          <Skeleton className="h-4 w-24" />
          {[0, 1, 2, 3].map((i) => (
            <div key={i} className="animate-rise-in space-y-2 stagger" style={staggerStyle(i)}>
              <Skeleton className="h-3.5 w-32" />
              <Skeleton className="h-9 w-full rounded-lg" />
            </div>
          ))}
          <Skeleton className="h-9 w-36 rounded-lg" />
        </CardBody>
      </Card>

      <Card>
        <CardBody className="space-y-4 pt-5">
          <Skeleton className="h-4 w-20" />
          {ASSET_KINDS.map((kind, i) => (
            <div
              key={kind}
              className="flex animate-rise-in items-center gap-3 rounded-lg border border-border p-3 stagger"
              style={staggerStyle(i)}
            >
              <Skeleton className="h-12 w-12 rounded-lg" />
              <div className="min-w-0 flex-1 space-y-1.5">
                <Skeleton className="h-3.5 w-28" />
                <Skeleton className="h-3 w-20" />
              </div>
              <Skeleton className="h-8 w-28 rounded-lg" />
            </div>
          ))}
        </CardBody>
      </Card>
    </div>
  );
}

function BrandingForm({ settings }: { settings: BrandingSettings }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const own = settings.own;
  const [panelName, setPanelName] = useState(own?.panel_name ?? "");
  const [supportUrl, setSupportUrl] = useState(own?.support_url ?? "");
  const [colour, setColour] = useState(own?.primary_color ?? "");
  const [loginHost, setLoginHost] = useState(own?.login_host ?? "");
  const [pending, setPending] = useState<Partial<Record<BrandingAssetKind, BrandingAssetChange>>>(
    {},
  );

  useEffect(() => {
    setPanelName(settings.own?.panel_name ?? "");
    setSupportUrl(settings.own?.support_url ?? "");
    setColour(settings.own?.primary_color ?? "");
    setLoginHost(settings.own?.login_host ?? "");
    setPending({});
  }, [settings]);

  const save = useMutation({
    mutationFn: () => {
      // An empty text box means "inherit again", which is `clear`, not an
      // empty string — the server would refuse an empty panel name and would
      // store an empty support URL as a broken link.
      const clear: NonNullable<BrandingRequest["clear"]> = [];
      const body: BrandingRequest = {};
      const field = (
        name: "panel_name" | "support_url" | "primary_color" | "login_host",
        value: string,
      ) => {
        if (value.trim() === "") clear.push(name);
        else body[name] = value.trim();
      };
      field("panel_name", panelName);
      field("support_url", supportUrl);
      field("primary_color", colour);
      field("login_host", loginHost);
      if (clear.length > 0) body.clear = clear;
      for (const kind of ASSET_KINDS) {
        const change = pending[kind];
        if (change) body[kind] = change;
      }
      return endpoints.setBranding(body);
    },
    onSuccess: () => {
      setError(null);
      setSaved(true);
      setPending({});
      // Both queries: the settings form and the live branding the shell and
      // the login page read. Invalidating the second is what makes the change
      // visible without a reload.
      void queryClient.invalidateQueries({ queryKey: ["branding-settings"] });
      void queryClient.invalidateQueries({ queryKey: ["branding"] });
      window.setTimeout(() => setSaved(false), 2000);
    },
    onError: (e) => {
      setSaved(false);
      setError(e instanceof ApiError ? e.message : String(e));
    },
  });

  const inherited = settings.resolved;
  // What an empty colour field means here: the value this panel would fall back
  // to. Both the placeholder and the picker read it, so they agree.
  const inheritedColour =
    inherited.primary_color && isHex(inherited.primary_color)
      ? inherited.primary_color
      : FALLBACK_SWATCH;

  return (
    <>
      <Card>
        <CardHeader title={t("branding.identity.title")} description={t("branding.identity.hint")} />
        <CardBody>
          <form
            className="space-y-1"
            onSubmit={(event) => {
              event.preventDefault();
              save.mutate();
            }}
          >
            <Field label={t("branding.panelName")} htmlFor="branding-name">
              <Input
                id="branding-name"
                value={panelName}
                maxLength={64}
                placeholder={inherited.panel_name ?? t("common.appName")}
                onChange={(e) => setPanelName(e.target.value)}
              />
            </Field>

            <Field label={t("branding.supportUrl")} htmlFor="branding-support">
              <Input
                id="branding-support"
                dir="ltr"
                inputMode="url"
                value={supportUrl}
                placeholder={inherited.support_url ?? "https://support.example.com"}
                onChange={(e) => setSupportUrl(e.target.value)}
              />
            </Field>
            <p className="-mt-1 mb-3 text-xs text-ink-muted">{t("branding.supportUrlHint")}</p>

            <Field label={t("branding.primaryColor")} htmlFor="branding-colour">
              <div className="flex items-center gap-2">
                <Input
                  id="branding-colour"
                  dir="ltr"
                  value={colour}
                  placeholder={inheritedColour}
                  onChange={(e) => setColour(e.target.value)}
                />
                {/* A native colour picker that only ever writes `#rrggbb`,
                    which is exactly the grammar the server accepts. `h-9` so it
                    sits on the same baseline as the Input beside it. */}
                <input
                  type="color"
                  aria-label={t("branding.primaryColorPicker")}
                  className="h-9 w-12 shrink-0 cursor-pointer rounded-lg border border-border-strong bg-surface"
                  value={isHex(colour) ? colour : inheritedColour}
                  onChange={(e) => setColour(e.target.value)}
                />
              </div>
            </Field>
            <p className="-mt-1 mb-3 text-xs text-ink-muted">{t("branding.primaryColorHint")}</p>

            <Field label={t("branding.loginHost")} htmlFor="branding-host">
              <Input
                id="branding-host"
                dir="ltr"
                value={loginHost}
                placeholder="panel.example.com"
                onChange={(e) => setLoginHost(e.target.value)}
              />
            </Field>
            <p className="-mt-1 mb-3 text-xs text-ink-muted">{t("branding.loginHostHint")}</p>

            <div className="flex flex-wrap items-center gap-3">
              <Button type="submit" variant="primary" loading={save.isPending}>
                <Palette className="h-4 w-4" aria-hidden />
                {t("branding.save")}
              </Button>
              {/* The page's only success feedback, and it self-clears after two
                  seconds — it arrives with the pop the operator's click earned
                  rather than simply appearing. */}
              {saved ? (
                <Badge tone="success" dot className="animate-pop-in">
                  {t("branding.saved")}
                </Badge>
              ) : null}
              <p className="text-xs text-ink-subtle">{t("branding.noRestart")}</p>
            </div>

            {error ? (
              <Callout tone="danger" className="mt-3">
                {error}
              </Callout>
            ) : null}
          </form>
        </CardBody>
      </Card>

      <Card>
        <CardHeader title={t("branding.images.title")} description={t("branding.images.hint")} />
        <CardBody className="space-y-4">
          <Callout tone="info">{t("branding.svgNote")}</Callout>
          {ASSET_KINDS.map((kind, index) => (
            <AssetRow
              key={kind}
              kind={kind}
              index={index}
              settings={settings}
              pending={pending[kind]}
              onChange={(change) => setPending((current) => ({ ...current, [kind]: change }))}
            />
          ))}
          <p className="text-xs text-ink-subtle">{t("branding.images.applyHint")}</p>
        </CardBody>
      </Card>
    </>
  );
}

function AssetRow({
  kind,
  index,
  settings,
  pending,
  onChange,
}: {
  kind: BrandingAssetKind;
  /** Position in the list, for the staggered entrance. */
  index: number;
  settings: BrandingSettings;
  pending: BrandingAssetChange | undefined;
  onChange: (change: BrandingAssetChange) => void;
}) {
  const { t } = useTranslation();
  const branding = useBranding();
  const input = useRef<HTMLInputElement>(null);
  const [problem, setProblem] = useState<string | null>(null);
  // Reading a two-megabyte file is usually instant and occasionally is not.
  // The button says so rather than looking like a click that did nothing.
  const [reading, setReading] = useState(false);

  const limit = settings.limits.find((l) => l.kind === kind)?.max_bytes ?? 0;
  const stored = settings.resolved.assets.find((a) => a.kind === kind);
  const inherited = stored !== undefined && stored.owner_id !== settings.reseller_id;
  // The image *this* hostname resolves to, which is the one being edited
  // whenever an owner is editing their own branding — the only case this page
  // offers today. An admin editing another reseller's row (`?reseller_id=`, an
  // API-only capability for now) would see their own preview here; the badges
  // below come from `settings`, which is always the edited owner's.
  const preview = assetUrl(branding, kind);

  const pick = async (file: File) => {
    setProblem(null);
    // Checked here as well as on the server, because a 3 MB photograph should
    // not be base64-inflated, uploaded and refused when the browser already
    // knows its size.
    if (file.size > limit) {
      setProblem(t("branding.images.tooLarge", { limit: Math.round(limit / 1024) }));
      return;
    }
    setReading(true);
    try {
      const content = await readBase64(file);
      onChange({ action: "set", content_b64: content });
    } finally {
      setReading(false);
    }
  };

  return (
    <div
      className={cn(
        "animate-rise-in rounded-lg border p-3 transition-colors duration-200 stagger",
        // A staged change is a promise the operator still has to keep, so the
        // whole row carries it — a badge alone left an edited row looking
        // exactly like a saved one, with the Save button a card away.
        pending?.action === "set"
          ? "border-accent/40 bg-accent-soft/40"
          : pending?.action === "clear"
            ? "border-warning/40 bg-warning-soft/40"
            : "border-border",
      )}
      style={staggerStyle(index)}
    >
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <div className="grid h-12 w-12 shrink-0 place-items-center overflow-hidden rounded-lg bg-surface-muted">
          {preview ? (
            // `alt=""` and aria-hidden: the label beside it already names the
            // image, so announcing it twice is noise.
            <img src={preview} alt="" aria-hidden className="max-h-12 max-w-12 object-contain" />
          ) : (
            <Image className="h-5 w-5 text-ink-subtle" aria-hidden />
          )}
        </div>

        <div className="min-w-0 flex-1 basis-32">
          <p className="text-sm font-medium text-ink">{t(`branding.images.${kind}`)}</p>
          <p className="tnum text-xs text-ink-muted">
            {t("branding.images.limit", { limit: Math.round(limit / 1024) })}
          </p>
        </div>

        {/* Badges and buttons travel together so a 375px viewport wraps them as
            one block instead of scattering them over three unpredictable lines. */}
        <div className="flex flex-wrap items-center justify-end gap-x-2 gap-y-1">
          {inherited ? <Badge tone="neutral">{t("branding.images.inherited")}</Badge> : null}
          {pending?.action === "set" ? (
            <Badge tone="accent" dot>
              {t("branding.images.stagedUpload")}
            </Badge>
          ) : null}
          {pending?.action === "clear" ? (
            <Badge tone="warning" dot>
              {t("branding.images.stagedClear")}
            </Badge>
          ) : null}

          <div className="flex items-center gap-1">
            <Button
              variant="ghost"
              size="sm"
              loading={reading}
              onClick={() => input.current?.click()}
            >
              <Upload className="h-3.5 w-3.5" aria-hidden />
              {t("branding.images.upload")}
            </Button>
            <Button
              variant="ghost"
              size="sm"
              disabled={stored === undefined || inherited}
              onClick={() => onChange({ action: "clear" })}
            >
              <Trash2 className="h-3.5 w-3.5" aria-hidden />
              {t("branding.images.clear")}
            </Button>
          </div>
        </div>
      </div>

      <input
        ref={input}
        type="file"
        className="sr-only"
        // A convenience only: the server identifies the file by its bytes, so
        // renaming an SVG to .png changes nothing about whether it is accepted.
        accept="image/png,image/jpeg,image/gif,image/webp,image/x-icon"
        onChange={(event) => {
          const file = event.target.files?.[0];
          // Reset so choosing the same file twice fires `change` again.
          event.target.value = "";
          if (file) void pick(file);
        }}
      />

      {problem ? (
        <p role="alert" className="mt-2 text-xs text-danger">
          {problem}
        </p>
      ) : null}
    </div>
  );
}

/**
 * Read a file as base64, without the `data:` prefix.
 *
 * `FileReader` rather than a dependency: the payload is at most two megabytes
 * and the initial JS budget (spec §3) is 350 KB gzipped, so a base64 library
 * would cost more than the feature.
 */
function readBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(reader.error ?? new Error("could not read the file"));
    reader.onload = () => {
      const result = String(reader.result);
      const comma = result.indexOf(",");
      resolve(comma === -1 ? result : result.slice(comma + 1));
    };
    reader.readAsDataURL(file);
  });
}
