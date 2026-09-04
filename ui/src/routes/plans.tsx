import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  Ban,
  CheckCircle2,
  Globe,
  Pencil,
  Plus,
  Trash2,
  Undo2,
  Users,
  Wallet,
} from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Dialog } from "@/components/ui/dialog";
import { EmptyState } from "@/components/ui/empty-state";
import { Field, Input, Textarea } from "@/components/ui/input";
import { Menu, MenuItem, MenuSeparator } from "@/components/ui/menu";
import { PageHeader } from "@/components/ui/page-header";
import { Select } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { ApiError, endpoints } from "@/lib/api";
import { staggerStyle } from "@/lib/motion";
import {
  limitProblem,
  planDiff,
  plansApi,
  reasonProblem,
  subscriptionsFromSites,
  type CreatePlanRequest,
  type DerivedSubscription,
  type PlanView,
} from "@/lib/plans-api";
import { cn, formatBytes } from "@/lib/utils";

/**
 * Plans, plan assignment and suspension (spec §6.2, §6.4).
 *
 * The two halves of this page have very different risk profiles, and the UI
 * reflects that:
 *
 * - Editing a plan is cheap and reversible. Lowering a limit below what a
 *   tenant already uses is *allowed* on purpose — enforcement happens at create
 *   time, so a downgrade stops growth without knocking anything over — so the
 *   form does not fight it, it just says what will happen.
 * - Suspending a subscription takes live sites off the air. It therefore names
 *   the exact domains that will start serving the maintenance page, and refuses
 *   to proceed without a reason, because the reason is what the customer reads.
 */
export function PlansPage() {
  const { t } = useTranslation();
  const [creating, setCreating] = useState(false);

  const plans = useQuery({ queryKey: ["plans"], queryFn: plansApi.list });

  return (
    <div className="space-y-6">
      <PageHeader
        title={t("plans.title")}
        description={t("plans.subtitle")}
        actions={
          <Button variant="primary" onClick={() => setCreating(true)}>
            <Plus className="h-4 w-4" aria-hidden />
            {t("plans.newPlan")}
          </Button>
        }
      />

      {plans.error ? <ErrorNote error={plans.error} /> : null}

      {plans.isPending ? (
        <PlansTableSkeleton />
      ) : (plans.data?.plans.length ?? 0) === 0 ? (
        <EmptyState
          icon={<Wallet aria-hidden />}
          title={t("plans.empty")}
          hint={t("plans.emptyHint")}
          action={
            <Button variant="primary" onClick={() => setCreating(true)}>
              <Plus className="h-4 w-4" aria-hidden />
              {t("plans.newPlan")}
            </Button>
          }
        />
      ) : (
        <PlansTable plans={plans.data!.plans} />
      )}

      <SubscriptionsCard plans={plans.data?.plans ?? []} />

      <PlanFormDialog open={creating} onClose={() => setCreating(false)} plan={null} />
    </div>
  );
}

function ErrorNote({ error, className }: { error: unknown; className?: string }) {
  return (
    <Callout tone="danger" className={className}>
      {error instanceof ApiError ? error.message : String(error)}
    </Callout>
  );
}

// ---------------------------------------------------------------------------
// Plans
// ---------------------------------------------------------------------------

/** Shared by the table and its skeleton, so the ghost has the real columns. */
function PlansHead() {
  const { t } = useTranslation();
  return (
    <thead>
      <tr>
        <Th>{t("plans.name")}</Th>
        <Th className="text-end">{t("plans.maxSites")}</Th>
        <Th className="text-end">{t("plans.maxDbs")}</Th>
        <Th className="text-end">{t("plans.storage")}</Th>
        <Th>{t("plans.features")}</Th>
        <Th>
          <span className="sr-only">{t("files.actions")}</span>
        </Th>
      </tr>
    </thead>
  );
}

function PlansTable({ plans }: { plans: PlanView[] }) {
  return (
    <Table>
      <PlansHead />
      <tbody>
        {plans.map((plan, index) => (
          <PlanRow key={plan.id} plan={plan} index={index} />
        ))}
      </tbody>
    </Table>
  );
}

/**
 * The plans table before it arrives.
 *
 * A list-shaped ghost promises a list and then a six-column table lands. This
 * keeps the real header and column rhythm, so the only thing that changes when
 * the data comes in is the text.
 */
function PlansTableSkeleton({ rows = 3 }: { rows?: number }) {
  return (
    <div role="status" aria-live="polite">
      <Table>
        <PlansHead />
        <tbody>
          {Array.from({ length: rows }, (_, i) => (
            <tr key={i} className="animate-rise-in stagger" style={staggerStyle(i)}>
              <Td>
                <Skeleton className="h-4 w-40" />
                <Skeleton className="mt-1.5 h-3 w-24" />
              </Td>
              <Td>
                <Skeleton className="ms-auto h-4 w-8" />
              </Td>
              <Td>
                <Skeleton className="ms-auto h-4 w-8" />
              </Td>
              <Td>
                <Skeleton className="ms-auto h-4 w-16" />
              </Td>
              <Td>
                <div className="flex gap-1.5">
                  <Skeleton className="h-5 w-24 rounded-full" />
                  <Skeleton className="h-5 w-16 rounded-full" />
                </div>
              </Td>
              <Td>
                <Skeleton className="ms-auto h-8 w-8 rounded-lg" />
              </Td>
            </tr>
          ))}
        </tbody>
      </Table>
    </div>
  );
}

function PlanRow({ plan, index }: { plan: PlanView; index: number }) {
  const { t, i18n } = useTranslation();
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState(false);

  // The count that gates deletion. Showing it with the disabled action is the
  // difference between "why can't I" and "because these three are on it".
  const inUse = plan.subscriptions > 0;

  return (
    <Tr className="animate-rise-in stagger" style={staggerStyle(index)}>
      <Td>
        <div className="flex items-center gap-2">
          <span className="truncate text-sm font-medium text-ink">{plan.name}</span>
          <Badge tone={plan.owner_user_id === null ? "accent" : "neutral"}>
            {plan.owner_user_id === null ? t("plans.global") : t("plans.owned")}
          </Badge>
        </div>
        <p className="tnum mt-0.5 text-xs text-ink-muted">
          {t("plans.subscriptionsOn", { count: plan.subscriptions })}
        </p>
      </Td>
      <Td className="text-end text-sm">{plan.max_sites}</Td>
      <Td className="text-end text-sm">{plan.max_dbs}</Td>
      <Td className="text-end text-sm whitespace-nowrap">
        {formatBytes(plan.storage_mb * 1024 * 1024, i18n.language)}
      </Td>
      <Td>
        <ul className="flex flex-wrap gap-1.5">
          <Flag on={plan.can_ssh} label={t("plans.canSsh")} />
          <Flag on={plan.can_cron} label={t("plans.canCron")} />
          <Flag on={plan.can_node_apps} label={t("plans.canNodeApps")} />
        </ul>
      </Td>
      <Td className="text-end">
        <Menu label={t("files.actions")}>
          <MenuItem icon={<Pencil aria-hidden />} onClick={() => setEditing(true)}>
            {t("plans.edit")}
          </MenuItem>
          <MenuSeparator />
          {/* A group, not two loose children: `role="menu"` only admits items,
              separators and groups, and the reason belongs to the item above
              it. */}
          <div role="group">
            <MenuItem
              danger
              icon={<Trash2 aria-hidden />}
              disabled={inUse}
              // The reason sits under the item as visible text rather than in a
              // `title`: a tooltip is invisible on a touch screen, and a title
              // on an item that already has a label muddies its accessible name.
              aria-describedby={inUse ? `plan-${plan.id}-blocked` : undefined}
              onClick={() => setDeleting(true)}
            >
              {t("plans.delete")}
            </MenuItem>
            {inUse ? (
              <p
                id={`plan-${plan.id}-blocked`}
                className="px-2.5 pb-1 text-start text-xs text-ink-subtle"
              >
                {t("plans.deleteBlocked")}
              </p>
            ) : null}
          </div>
        </Menu>

        <PlanFormDialog open={editing} onClose={() => setEditing(false)} plan={plan} />
        <DeletePlanDialog open={deleting} onClose={() => setDeleting(false)} plan={plan} />
      </Td>
    </Tr>
  );
}

/** A feature flag, readable without colour: the word says on or off too. */
function Flag({ on, label }: { on: boolean; label: string }) {
  const { t } = useTranslation();
  return (
    <li>
      <Badge tone={on ? "success" : "neutral"} dot={on}>
        {label}
        <span className="opacity-70">{on ? t("plans.flagOn") : t("plans.flagOff")}</span>
      </Badge>
    </li>
  );
}

// ---------------------------------------------------------------------------
// Create / edit
// ---------------------------------------------------------------------------

interface PlanFormState {
  name: string;
  max_sites: string;
  max_dbs: string;
  storage_mb: string;
  can_ssh: boolean;
  can_cron: boolean;
  can_node_apps: boolean;
}

function initialForm(plan: PlanView | null): PlanFormState {
  return plan
    ? {
        name: plan.name,
        max_sites: String(plan.max_sites),
        max_dbs: String(plan.max_dbs),
        storage_mb: String(plan.storage_mb),
        can_ssh: plan.can_ssh,
        can_cron: plan.can_cron,
        can_node_apps: plan.can_node_apps,
      }
    : {
        name: "",
        max_sites: "1",
        max_dbs: "1",
        storage_mb: "1024",
        can_ssh: false,
        // `can_cron` defaults to true on the wire; the form must agree, or a
        // created plan would silently differ from the one that was reviewed.
        can_cron: true,
        can_node_apps: false,
      };
}

function PlanFormDialog({
  open,
  onClose,
  plan,
}: {
  open: boolean;
  onClose: () => void;
  plan: PlanView | null;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [form, setForm] = useState<PlanFormState>(() => initialForm(plan));
  const [error, setError] = useState<string | null>(null);
  // Remount on open so an edit dialog reopened after a cancel shows the stored
  // plan again rather than the abandoned draft.
  const [openedFor, setOpenedFor] = useState<number | null>(null);
  if (open && openedFor !== (plan?.id ?? -1)) {
    setOpenedFor(plan?.id ?? -1);
    setForm(initialForm(plan));
    setError(null);
  }

  const set = <K extends keyof PlanFormState>(key: K, value: PlanFormState[K]) =>
    setForm((current) => ({ ...current, [key]: value }));

  const problems = {
    name: form.name.trim() === "" ? "required" : form.name.trim().length > 64 ? "tooLong" : null,
    max_sites: limitProblem(form.max_sites),
    max_dbs: limitProblem(form.max_dbs),
    storage_mb: limitProblem(form.storage_mb),
  };
  const ready = Object.values(problems).every((p) => p === null);

  const close = () => {
    setOpenedFor(null);
    onClose();
  };

  const save = useMutation({
    mutationFn: async () => {
      const body: CreatePlanRequest = {
        name: form.name.trim(),
        max_sites: Number(form.max_sites.trim()),
        max_dbs: Number(form.max_dbs.trim()),
        storage_mb: Number(form.storage_mb.trim()),
        can_ssh: form.can_ssh,
        can_cron: form.can_cron,
        can_node_apps: form.can_node_apps,
      };
      if (!plan) return plansApi.create(body);
      // PATCH only what moved: an unchanged field left out is a field the
      // server does not have to re-validate, and an audit row that says what
      // actually happened.
      return plansApi.update(plan.id, planDiff(plan, body));
    },
    onSuccess: () => {
      close();
      void queryClient.invalidateQueries({ queryKey: ["plans"] });
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  return (
    <Dialog
      open={open}
      onClose={close}
      title={plan ? t("plans.editTitle", { name: plan.name }) : t("plans.newPlan")}
      description={plan ? t("plans.editHint") : t("plans.newPlanHint")}
      footer={
        <>
          <Button variant="ghost" onClick={close}>
            {t("common.cancel")}
          </Button>
          <Button
            variant="primary"
            disabled={!ready}
            loading={save.isPending}
            onClick={() => {
              setError(null);
              save.mutate();
            }}
          >
            {plan ? t("plans.save") : t("plans.create")}
          </Button>
        </>
      }
    >
      <Field
        label={t("plans.name")}
        htmlFor="plan-name"
        error={problems.name && form.name !== "" ? t(`plans.nameProblem.${problems.name}`) : undefined}
      >
        <Input
          id="plan-name"
          autoFocus
          placeholder="Starter"
          aria-invalid={Boolean(problems.name) && form.name !== ""}
          value={form.name}
          onChange={(event) => set("name", event.target.value)}
        />
      </Field>

      <div className="grid gap-x-3 sm:grid-cols-3">
        <LimitField
          id="plan-max-sites"
          label={t("plans.maxSites")}
          value={form.max_sites}
          problem={problems.max_sites}
          onChange={(v) => set("max_sites", v)}
        />
        <LimitField
          id="plan-max-dbs"
          label={t("plans.maxDbs")}
          value={form.max_dbs}
          problem={problems.max_dbs}
          onChange={(v) => set("max_dbs", v)}
        />
        <LimitField
          id="plan-storage"
          label={t("plans.storageMb")}
          value={form.storage_mb}
          problem={problems.storage_mb}
          onChange={(v) => set("storage_mb", v)}
        />
      </div>

      <fieldset className="mt-1">
        <legend className="block text-sm font-medium text-ink">{t("plans.features")}</legend>
        <Switch
          checked={form.can_ssh}
          onChange={(v) => set("can_ssh", v)}
          label={t("plans.canSsh")}
          description={t("plans.canSshHint")}
        />
        <Switch
          checked={form.can_cron}
          onChange={(v) => set("can_cron", v)}
          label={t("plans.canCron")}
          description={t("plans.canCronHint")}
        />
        <Switch
          checked={form.can_node_apps}
          onChange={(v) => set("can_node_apps", v)}
          label={t("plans.canNodeApps")}
          description={t("plans.canNodeAppsHint")}
        />
      </fieldset>

      {plan ? <p className="mt-3 text-xs text-ink-muted">{t("plans.lowerLimitsNote")}</p> : null}

      {error ? (
        <Callout tone="danger" className="mt-3">
          {error}
        </Callout>
      ) : null}
    </Dialog>
  );
}

function LimitField({
  id,
  label,
  value,
  problem,
  onChange,
}: {
  id: string;
  label: string;
  value: string;
  problem: ReturnType<typeof limitProblem>;
  onChange: (next: string) => void;
}) {
  const { t } = useTranslation();
  return (
    <Field
      label={label}
      htmlFor={id}
      error={problem ? t(`plans.limitProblem.${problem}`) : undefined}
    >
      <Input
        id={id}
        inputMode="numeric"
        aria-invalid={Boolean(problem)}
        value={value}
        onChange={(event) => onChange(event.target.value)}
      />
    </Field>
  );
}

function DeletePlanDialog({
  open,
  onClose,
  plan,
}: {
  open: boolean;
  onClose: () => void;
  plan: PlanView;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);

  const remove = useMutation({
    mutationFn: () => plansApi.remove(plan.id),
    onSuccess: () => {
      onClose();
      void queryClient.invalidateQueries({ queryKey: ["plans"] });
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={t("plans.deleteTitle", { name: plan.name })}
      description={t("plans.deleteHint")}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button
            variant="danger"
            loading={remove.isPending}
            onClick={() => {
              setError(null);
              remove.mutate();
            }}
          >
            {t("plans.deleteConfirm")}
          </Button>
        </>
      }
    >
      {/* Deleting a plan takes nothing offline — the guard lives in the DELETE
          statement itself, so a subscription assigned a moment ago still wins.
          Say so, so the button is not read as more dangerous than it is. */}
      <p className="text-sm text-ink-muted">{t("plans.deleteBody")}</p>
      {error ? <ErrorNote error={error} className="mt-3" /> : null}
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Subscriptions
// ---------------------------------------------------------------------------

/** What this session did, so the list can say something a refetch cannot. */
type LastAction = Record<number, "suspended" | "reinstated">;

/**
 * The receipt for an assignment.
 *
 * An over-limit assignment succeeded, so it is not an error — but it is not
 * plain good news either, and the tone has to say which one the operator is
 * looking at without them re-reading the sentence.
 */
type AssignNote = { tone: "success" | "warning"; text: string };

function SubscriptionsCard({ plans }: { plans: PlanView[] }) {
  const { t } = useTranslation();
  const [lastAction, setLastAction] = useState<LastAction>({});
  const [assigningById, setAssigningById] = useState(false);

  const sites = useQuery({ queryKey: ["sites"], queryFn: endpoints.sites });
  const subscriptions = subscriptionsFromSites(sites.data?.sites ?? []);

  return (
    <Card>
      <CardHeader
        title={t("plans.subscriptions")}
        description={t("plans.subscriptionsHint")}
        action={
          <Button variant="outline" size="sm" onClick={() => setAssigningById(true)}>
            {t("plans.assignById")}
          </Button>
        }
      />
      <CardBody className="space-y-3 pt-0">
        {/* The honest caveat, stated once at the top rather than implied by a
            row that quietly shows less than it seems to. */}
        <Callout tone="info">{t("plans.derivedNotice")}</Callout>

        {sites.error ? <ErrorNote error={sites.error} /> : null}

        {sites.isPending ? (
          <div role="status" aria-live="polite" className="divide-y divide-border">
            {Array.from({ length: 3 }, (_, i) => (
              <div
                key={i}
                className="flex animate-rise-in flex-wrap items-center gap-x-3 gap-y-2 py-3 stagger"
                style={staggerStyle(i)}
              >
                <Skeleton className="h-5 w-32 rounded-full" />
                <div className="min-w-0 flex-1 space-y-1.5">
                  <Skeleton className="h-3.5 w-1/2" />
                  <Skeleton className="h-3 w-1/4" />
                </div>
                <Skeleton className="h-9 w-40 rounded-lg" />
                <Skeleton className="h-9 w-20 rounded-lg" />
                <Skeleton className="h-8 w-8 rounded-lg" />
              </div>
            ))}
          </div>
        ) : subscriptions.length === 0 ? (
          <EmptyState
            icon={<Users aria-hidden />}
            title={t("plans.noSubscriptions")}
            hint={t("plans.noSubscriptionsHint")}
            // The list is derived from sites, so there is nothing to create
            // here — the one thing that *can* be done is reach a subscription
            // the list cannot see, which is exactly what this dialog is for.
            action={
              <Button variant="primary" onClick={() => setAssigningById(true)}>
                {t("plans.assignById")}
              </Button>
            }
          />
        ) : (
          <ul className="divide-y divide-border">
            {subscriptions.map((subscription, index) => (
              <li
                key={subscription.id}
                className="animate-rise-in transition-colors duration-150 stagger hover:bg-surface-muted/60"
                style={staggerStyle(index)}
              >
                <SubscriptionRow
                  subscription={subscription}
                  plans={plans}
                  last={lastAction[subscription.id]}
                  onActed={(action) =>
                    setLastAction((current) => ({ ...current, [subscription.id]: action }))
                  }
                />
              </li>
            ))}
          </ul>
        )}
      </CardBody>

      <AssignByIdDialog
        open={assigningById}
        onClose={() => setAssigningById(false)}
        plans={plans}
      />
    </Card>
  );
}

function SubscriptionRow({
  subscription,
  plans,
  last,
  onActed,
}: {
  subscription: DerivedSubscription;
  plans: PlanView[];
  last?: "suspended" | "reinstated";
  onActed: (action: "suspended" | "reinstated") => void;
}) {
  const { t } = useTranslation();
  const [suspending, setSuspending] = useState(false);
  const [reinstating, setReinstating] = useState(false);

  const all = [...subscription.liveDomains, ...subscription.otherDomains];

  return (
    // The identity and the controls are two wrap units, not seven loose ones:
    // at 375px the row folds into "who" above "what you can do to them" rather
    // than scattering a select, two buttons and a badge across four lines.
    <div className="flex flex-wrap items-center gap-x-3 gap-y-2 py-3">
      <Badge tone="neutral">
        <span>{t("plans.subscriptionShort")}</span>
        <span className="tnum">{subscription.id}</span>
      </Badge>

      <div className="min-w-0 flex-1 basis-40">
        <p className="truncate font-mono text-xs text-ink">
          {all.length === 0 ? "—" : all.join(", ")}
        </p>
        <p className="tnum mt-0.5 text-xs text-ink-subtle">
          {t("plans.liveCount", { count: subscription.liveDomains.length })}
        </p>
      </div>

      {last ? (
        <Badge tone={last === "suspended" ? "danger" : "success"} dot className="animate-pop-in">
          {t(`plans.justAction.${last}`)}
        </Badge>
      ) : null}

      <div className="flex items-start gap-2">
        <AssignInline subscription={subscription} plans={plans} />
        {/* Fixed to the control row's height so the ⋯ trigger centres against
            the select beside it instead of sitting 4px high. */}
        <div className="flex h-9 items-center">
          <Menu label={t("files.actions")}>
            <MenuItem danger icon={<Ban aria-hidden />} onClick={() => setSuspending(true)}>
              {t("plans.suspend")}
            </MenuItem>
            <MenuSeparator />
            <MenuItem icon={<Undo2 aria-hidden />} onClick={() => setReinstating(true)}>
              {t("plans.unsuspend")}
            </MenuItem>
          </Menu>
        </div>
      </div>

      <SuspendDialog
        open={suspending}
        onClose={() => setSuspending(false)}
        subscription={subscription}
        onDone={() => onActed("suspended")}
      />
      <UnsuspendDialog
        open={reinstating}
        onClose={() => setReinstating(false)}
        subscription={subscription}
        onDone={() => onActed("reinstated")}
      />
    </div>
  );
}

function AssignInline({
  subscription,
  plans,
}: {
  subscription: DerivedSubscription;
  plans: PlanView[];
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [planId, setPlanId] = useState("");
  const [note, setNote] = useState<AssignNote | null>(null);
  const [error, setError] = useState<string | null>(null);

  const assign = useMutation({
    mutationFn: () => plansApi.assign(Number(planId), subscription.id),
    onSuccess: (result) => {
      // `over_limit` is the whole reason this response is worth reading: a
      // downgrade is legitimate, but the tenant should not find out at their
      // next site creation.
      setNote(
        result.over_limit
          ? { tone: "warning", text: t("plans.assignedOverLimit", { plan: result.plan_name }) }
          : { tone: "success", text: t("plans.assigned", { plan: result.plan_name }) },
      );
      void queryClient.invalidateQueries({ queryKey: ["plans"] });
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  return (
    <div className="flex min-w-0 flex-col gap-1">
      <div className="flex items-center gap-2">
        {/* The primitive is one height; a bespoke h-8 here left the select
            sitting 4px shorter than the button next to it. */}
        <Select
          className="w-40"
          aria-label={t("plans.assignTo", { id: subscription.id })}
          value={planId}
          onChange={(event) => {
            setPlanId(event.target.value);
            setNote(null);
            setError(null);
          }}
        >
          <option value="">{t("plans.choosePlan")}</option>
          {plans.map((plan) => (
            <option key={plan.id} value={String(plan.id)}>
              {plan.name}
            </option>
          ))}
        </Select>
        <Button
          variant="secondary"
          disabled={planId === ""}
          loading={assign.isPending}
          onClick={() => {
            setError(null);
            assign.mutate();
          }}
        >
          {t("plans.assign")}
        </Button>
      </div>
      {note ? (
        <span
          className={cn(
            "flex items-start gap-1.5 text-xs",
            note.tone === "warning" ? "text-warning" : "text-ink-muted",
          )}
        >
          {note.tone === "warning" ? (
            <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" aria-hidden />
          ) : (
            <CheckCircle2 className="mt-0.5 h-3 w-3 shrink-0 text-success" aria-hidden />
          )}
          {note.text}
        </span>
      ) : null}
      {error ? (
        <span role="alert" className="text-xs text-danger">
          {error}
        </span>
      ) : null}
    </div>
  );
}

function AssignByIdDialog({
  open,
  onClose,
  plans,
}: {
  open: boolean;
  onClose: () => void;
  plans: PlanView[];
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [subscriptionId, setSubscriptionId] = useState("");
  const [planId, setPlanId] = useState("");
  const [note, setNote] = useState<AssignNote | null>(null);
  const [error, setError] = useState<string | null>(null);

  const idInvalid = subscriptionId.trim() !== "" && !/^\d+$/.test(subscriptionId.trim());
  const ready = /^\d+$/.test(subscriptionId.trim()) && planId !== "";

  const assign = useMutation({
    mutationFn: () => plansApi.assign(Number(planId), Number(subscriptionId.trim())),
    onSuccess: (result) => {
      setNote(
        result.over_limit
          ? { tone: "warning", text: t("plans.assignedOverLimit", { plan: result.plan_name }) }
          : { tone: "success", text: t("plans.assigned", { plan: result.plan_name }) },
      );
      void queryClient.invalidateQueries({ queryKey: ["plans"] });
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={t("plans.assignById")}
      description={t("plans.assignByIdHint")}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {t("common.close")}
          </Button>
          <Button
            variant="primary"
            disabled={!ready}
            loading={assign.isPending}
            onClick={() => {
              setError(null);
              setNote(null);
              assign.mutate();
            }}
          >
            {t("plans.assign")}
          </Button>
        </>
      }
    >
      <Field
        label={t("plans.subscriptionId")}
        htmlFor="assign-subscription"
        error={idInvalid ? t("plans.subscriptionIdInvalid") : undefined}
      >
        <Input
          id="assign-subscription"
          inputMode="numeric"
          autoFocus
          aria-invalid={idInvalid}
          value={subscriptionId}
          onChange={(event) => setSubscriptionId(event.target.value)}
        />
      </Field>

      <Field label={t("plans.plan")} htmlFor="assign-plan">
        <Select
          id="assign-plan"
          value={planId}
          onChange={(event) => setPlanId(event.target.value)}
        >
          <option value="">{t("plans.choosePlan")}</option>
          {plans.map((plan) => (
            <option key={plan.id} value={String(plan.id)}>
              {plan.name}
            </option>
          ))}
        </Select>
      </Field>

      {note ? <Callout tone={note.tone}>{note.text}</Callout> : null}
      {error ? <ErrorNote error={error} className="mt-3" /> : null}
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Suspension
// ---------------------------------------------------------------------------

/** `ui/` has no textarea primitive yet, so this wears `Input`'s chrome exactly. */
Textarea.displayName = "Textarea";

/**
 * Suspension, named domain by domain.
 *
 * `subscription.suspend` switches every *active* site of the subscription to
 * the maintenance page, so those domains are the concrete cost of the click and
 * they are listed in full. The reason is mandatory here because it is
 * mandatory on the server and, more to the point, because it is what the
 * customer is shown (spec §6.4).
 */
function SuspendDialog({
  open,
  onClose,
  subscription,
  onDone,
}: {
  open: boolean;
  onClose: () => void;
  subscription: DerivedSubscription;
  onDone: () => void;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);

  const problem = reasonProblem(reason);

  const suspend = useMutation({
    mutationFn: () => plansApi.suspend(subscription.id, reason.trim()),
    onSuccess: () => {
      setReason("");
      onClose();
      onDone();
      void queryClient.invalidateQueries({ queryKey: ["sites"] });
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={t("plans.suspendTitle", { id: subscription.id })}
      description={t("plans.suspendHint")}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button
            variant="danger"
            disabled={problem !== null}
            loading={suspend.isPending}
            onClick={() => {
              setError(null);
              suspend.mutate();
            }}
          >
            {t("plans.suspendConfirm")}
          </Button>
        </>
      }
    >
      {/* The concrete cost of the click, named in full. `subscription.suspend`
          switches exactly the active sites, so exactly those domains are
          promised — no "and others". */}
      <Callout
        tone="danger"
        className="mb-3"
        title={
          <span className="tnum">
            {subscription.liveDomains.length === 0
              ? t("plans.goDarkNone")
              : t("plans.goDark", { count: subscription.liveDomains.length })}
          </span>
        }
      >
        {subscription.liveDomains.length === 0 ? null : (
          // Capped and scrollable: a subscription with thirty live domains
          // otherwise pushes the reason field and the buttons off the screen,
          // which is the one thing this dialog cannot afford to hide.
          <ul className="max-h-40 list-disc space-y-0.5 overflow-y-auto ps-5">
            {subscription.liveDomains.map((domain) => (
              <li key={domain} className="truncate font-mono text-xs">
                {domain}
              </li>
            ))}
          </ul>
        )}
      </Callout>

      {subscription.otherDomains.length > 0 ? (
        <p className="mb-3 text-xs text-ink-muted">
          {t("plans.notServingYet", {
            domains: subscription.otherDomains.join(", "),
          })}
        </p>
      ) : null}

      <Field
        label={t("plans.reason")}
        htmlFor="suspend-reason"
        error={reason !== "" && problem ? t(`plans.reasonProblem.${problem}`) : undefined}
      >
        <Textarea
          id="suspend-reason"
          rows={3}
          autoFocus
          maxLength={600}
          aria-invalid={reason !== "" && problem !== null}
          aria-describedby="suspend-reason-hint"
          placeholder={t("plans.reasonPlaceholder")}
          value={reason}
          onChange={(event) => setReason(event.target.value)}
        />
      </Field>
      <p id="suspend-reason-hint" className="-mt-1 text-xs text-ink-muted">
        {t("plans.reasonHint")}
      </p>

      <p className="mt-3 text-xs text-ink-muted">{t("plans.suspendReversible")}</p>

      {error ? <ErrorNote error={error} className="mt-3" /> : null}
    </Dialog>
  );
}

function UnsuspendDialog({
  open,
  onClose,
  subscription,
  onDone,
}: {
  open: boolean;
  onClose: () => void;
  subscription: DerivedSubscription;
  onDone: () => void;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);

  const unsuspend = useMutation({
    mutationFn: () => plansApi.unsuspend(subscription.id),
    onSuccess: () => {
      onClose();
      onDone();
      void queryClient.invalidateQueries({ queryKey: ["sites"] });
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={t("plans.unsuspendTitle", { id: subscription.id })}
      description={t("plans.unsuspendHint")}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button
            variant="primary"
            loading={unsuspend.isPending}
            onClick={() => {
              setError(null);
              unsuspend.mutate();
            }}
          >
            {t("plans.unsuspendConfirm")}
          </Button>
        </>
      }
    >
      {/* Unsuspending re-renders each vhost from the site's own stored flags,
          so a site the tenant had put in maintenance themselves comes back in
          maintenance. Worth saying, or it reads as a failed unsuspend. */}
      <p className="text-sm text-ink-muted">{t("plans.unsuspendBody")}</p>
      <p className="tnum mt-2 flex items-center gap-2 text-xs text-ink-subtle">
        <Globe className="h-3.5 w-3.5" aria-hidden />
        {t("plans.liveCount", { count: subscription.liveDomains.length })}
      </p>
      {error ? <ErrorNote error={error} className="mt-3" /> : null}
    </Dialog>
  );
}
