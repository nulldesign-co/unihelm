import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Check,
  Copy,
  Database,
  KeyRound,
  Link2,
  Plus,
  RotateCw,
  Terminal,
  Trash2,
  TriangleAlert,
  UserPlus,
} from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Spinner } from "@/components/ui/spinner";
import { ApiError } from "@/lib/api";
import {
  confirmsName,
  copyToClipboard,
  databasesApi,
  dbNameProblem,
  DB_ENGINES,
  grantableUsers,
  type DatabaseRow,
  type DbEngine,
  type DbUserRow,
  type DbUserSecret,
} from "@/lib/databases-api";
import { useSession } from "@/lib/session";

/**
 * Databases and database users (spec §11.4).
 *
 * Three things on this page are deliberate rather than incidental:
 *
 * 1. A generated password is shown **once**, in a dialog that cannot be
 *    dismissed by accident — no Escape, no backdrop click, no close cross.
 *    There is no endpoint that would hand it back; the only recovery is a
 *    reset, which invalidates the one the tenant may already be using.
 * 2. Dropping a database or a user is gated on retyping its name. Data has no
 *    re-render, so it gets a stronger gate than a vhost does.
 * 3. Adminer is presented as an SSH tunnel, not a link. It is bound to
 *    127.0.0.1 on purpose (the panel has no session-checking proxy for it
 *    yet), so a clickable URL would be a link that never works.
 */
export function DatabasesPage() {
  const { t } = useTranslation();
  const [creatingDb, setCreatingDb] = useState(false);
  const [creatingUser, setCreatingUser] = useState(false);
  const [secret, setSecret] = useState<DbUserSecret | null>(null);

  const list = useQuery({ queryKey: ["databases"], queryFn: databasesApi.list });

  const databases = list.data?.databases ?? [];
  const users = list.data?.users ?? [];

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-ink">{t("databases.title")}</h1>
          <p className="mt-1 text-sm text-ink-muted">{t("databases.subtitle")}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" onClick={() => setCreatingUser(true)}>
            <UserPlus className="h-4 w-4" aria-hidden />
            {t("databases.newUser")}
          </Button>
          <Button variant="primary" onClick={() => setCreatingDb(true)}>
            <Plus className="h-4 w-4" aria-hidden />
            {t("databases.newDatabase")}
          </Button>
        </div>
      </header>

      {list.error ? <ErrorNote error={list.error} /> : null}

      {list.isPending ? (
        <div className="flex justify-center py-24 text-ink-muted">
          <Spinner className="h-6 w-6" />
        </div>
      ) : (
        <>
          <DatabaseList
            databases={databases}
            users={users}
            onCreate={() => setCreatingDb(true)}
          />
          <UserList users={users} onCreate={() => setCreatingUser(true)} onSecret={setSecret} />
        </>
      )}

      <AdminerCard />

      <CreateDatabaseDialog
        open={creatingDb}
        onClose={() => setCreatingDb(false)}
        users={users}
        knownSubscriptions={subscriptionIds(databases, users)}
      />
      <CreateUserDialog
        open={creatingUser}
        onClose={() => setCreatingUser(false)}
        knownSubscriptions={subscriptionIds(databases, users)}
        onCreated={setSecret}
      />
      <PasswordOnceDialog secret={secret} onAcknowledge={() => setSecret(null)} />
    </div>
  );
}

/** Every subscription id already visible, so the optional field can offer them. */
function subscriptionIds(databases: DatabaseRow[], users: DbUserRow[]): number[] {
  const ids = new Set<number>();
  for (const row of databases) ids.add(row.subscription_id);
  for (const row of users) ids.add(row.subscription_id);
  return [...ids].sort((a, b) => a - b);
}

function ErrorNote({ error }: { error: unknown }) {
  return (
    <p role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
      {error instanceof ApiError ? error.message : String(error)}
    </p>
  );
}

function EngineBadge({ engine }: { engine: DbEngine }) {
  const { t } = useTranslation();
  // Two engines, two colours: an operator scanning a mixed list should not have
  // to read the word to know which one a row belongs to.
  return (
    <Badge tone={engine === "mysql" ? "warning" : "accent"}>{t(`databases.engine.${engine}`)}</Badge>
  );
}

function SubscriptionBadge({ id }: { id: number }) {
  const { t } = useTranslation();
  return (
    <Badge tone="neutral">
      <span>{t("databases.subscription")}</span>
      {/* The number stays LTR even on a Farsi page. */}
      <span dir="ltr">{id}</span>
    </Badge>
  );
}

// ---------------------------------------------------------------------------
// Databases
// ---------------------------------------------------------------------------

function DatabaseList({
  databases,
  users,
  onCreate,
}: {
  databases: DatabaseRow[];
  users: DbUserRow[];
  onCreate: () => void;
}) {
  const { t } = useTranslation();

  return (
    <Card>
      <CardHeader
        title={t("databases.databasesTitle")}
        description={t("databases.databasesHint")}
      />
      <CardBody className="pt-0">
        {databases.length === 0 ? (
          <div className="py-10 text-center">
            <Database className="mx-auto mb-3 h-8 w-8 text-ink-subtle" aria-hidden />
            <p className="text-sm font-medium text-ink">{t("databases.noDatabases")}</p>
            <p className="mx-auto mt-1 max-w-sm text-sm text-ink-muted">
              {t("databases.noDatabasesHint")}
            </p>
            <Button variant="primary" className="mt-4" onClick={onCreate}>
              <Plus className="h-4 w-4" aria-hidden />
              {t("databases.newDatabase")}
            </Button>
          </div>
        ) : (
          <ul className="divide-y divide-border">
            {databases.map((row) => (
              <li key={row.id} className="flex flex-wrap items-center gap-x-3 gap-y-2 py-3">
                <EngineBadge engine={row.engine} />
                <span dir="ltr" className="min-w-0 flex-1 truncate font-mono text-sm text-ink">
                  {row.name}
                </span>
                <SubscriptionBadge id={row.subscription_id} />
                <GrantButton database={row} users={users} />
                <DropDatabaseButton database={row} />
              </li>
            ))}
          </ul>
        )}
      </CardBody>
    </Card>
  );
}

function GrantButton({ database, users }: { database: DatabaseRow; users: DbUserRow[] }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [username, setUsername] = useState("");
  const [error, setError] = useState<string | null>(null);

  // Only users the agent would accept: same engine, same subscription. Offering
  // anything else would either fail on submit or, worse, list another tenant's
  // usernames in a picker (spec §6.1).
  const candidates = grantableUsers(database, users);

  const grant = useMutation({
    mutationFn: () => databasesApi.grant(database.name, username),
    onSuccess: () => {
      setOpen(false);
      setUsername("");
      void queryClient.invalidateQueries({ queryKey: ["databases"] });
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  return (
    <>
      <Button variant="ghost" size="sm" onClick={() => setOpen(true)}>
        <Link2 className="h-3.5 w-3.5" aria-hidden />
        {t("databases.grant")}
      </Button>

      <Dialog
        open={open}
        onClose={() => setOpen(false)}
        title={t("databases.grantTitle", { name: database.name })}
        description={t("databases.grantHint")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setOpen(false)}>
              {t("common.cancel")}
            </Button>
            <Button
              variant="primary"
              disabled={username === "" || grant.isPending}
              onClick={() => {
                setError(null);
                grant.mutate();
              }}
            >
              {grant.isPending ? <Spinner /> : null}
              {t("databases.grant")}
            </Button>
          </>
        }
      >
        {candidates.length === 0 ? (
          <p className="text-sm text-ink-muted">{t("databases.grantNoUsers")}</p>
        ) : (
          <Field label={t("databases.user")} htmlFor="grant-user">
            <Select
              id="grant-user"
              dir="ltr"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
            >
              <option value="">{t("databases.choose")}</option>
              {candidates.map((user) => (
                <option key={user.id} value={user.username}>
                  {user.username}
                </option>
              ))}
            </Select>
          </Field>
        )}
        {error ? <ErrorNote error={error} /> : null}
      </Dialog>
    </>
  );
}

function DropDatabaseButton({ database }: { database: DatabaseRow }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [typed, setTyped] = useState("");
  const [error, setError] = useState<string | null>(null);

  const armed = confirmsName(typed, database.name);

  const drop = useMutation({
    // The typed value goes over the wire, not the row's — the agent compares it
    // against the stored name, so sending what we read back would turn its
    // check into a no-op.
    mutationFn: () => databasesApi.drop(database.id, typed.trim()),
    onSuccess: () => {
      setOpen(false);
      setTyped("");
      void queryClient.invalidateQueries({ queryKey: ["databases"] });
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  return (
    <>
      <Button variant="ghost" size="sm" onClick={() => setOpen(true)}>
        <Trash2 className="h-3.5 w-3.5" aria-hidden />
        {t("databases.drop")}
      </Button>

      <Dialog
        open={open}
        onClose={() => setOpen(false)}
        title={t("databases.dropTitle", { name: database.name })}
        description={t("databases.dropHint")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setOpen(false)}>
              {t("common.cancel")}
            </Button>
            <Button
              variant="danger"
              disabled={!armed || drop.isPending}
              onClick={() => {
                setError(null);
                drop.mutate();
              }}
            >
              {drop.isPending ? <Spinner /> : null}
              {t("databases.dropConfirm")}
            </Button>
          </>
        }
      >
        <p className="mb-3 rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
          {t("databases.dropWarning")}
        </p>
        <Field
          label={t("databases.typeName")}
          htmlFor={`drop-db-${database.id}`}
          error={typed.length > 0 && !armed ? t("databases.typeNameMismatch") : undefined}
        >
          <Input
            id={`drop-db-${database.id}`}
            dir="ltr"
            autoComplete="off"
            autoFocus
            placeholder={database.name}
            value={typed}
            onChange={(event) => setTyped(event.target.value)}
          />
        </Field>
        {error ? <ErrorNote error={error} /> : null}
      </Dialog>
    </>
  );
}

// ---------------------------------------------------------------------------
// Database users
// ---------------------------------------------------------------------------

function UserList({
  users,
  onCreate,
  onSecret,
}: {
  users: DbUserRow[];
  onCreate: () => void;
  onSecret: (secret: DbUserSecret) => void;
}) {
  const { t } = useTranslation();

  return (
    <Card>
      <CardHeader title={t("databases.usersTitle")} description={t("databases.usersHint")} />
      <CardBody className="pt-0">
        {users.length === 0 ? (
          <div className="py-10 text-center">
            <KeyRound className="mx-auto mb-3 h-8 w-8 text-ink-subtle" aria-hidden />
            <p className="text-sm font-medium text-ink">{t("databases.noUsers")}</p>
            <p className="mx-auto mt-1 max-w-sm text-sm text-ink-muted">
              {t("databases.noUsersHint")}
            </p>
            <Button variant="outline" className="mt-4" onClick={onCreate}>
              <UserPlus className="h-4 w-4" aria-hidden />
              {t("databases.newUser")}
            </Button>
          </div>
        ) : (
          <ul className="divide-y divide-border">
            {users.map((user) => (
              <li key={user.id} className="flex flex-wrap items-center gap-x-3 gap-y-2 py-3">
                <EngineBadge engine={user.engine} />
                <span dir="ltr" className="min-w-0 flex-1 truncate font-mono text-sm text-ink">
                  {user.username}
                </span>
                <SubscriptionBadge id={user.subscription_id} />
                <ResetPasswordButton user={user} onSecret={onSecret} />
                <DropUserButton user={user} />
              </li>
            ))}
          </ul>
        )}
      </CardBody>
    </Card>
  );
}

function ResetPasswordButton({
  user,
  onSecret,
}: {
  user: DbUserRow;
  onSecret: (secret: DbUserSecret) => void;
}) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reset = useMutation({
    mutationFn: () => databasesApi.resetPassword(user.username),
    onSuccess: (secret) => {
      setOpen(false);
      onSecret(secret);
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  return (
    <>
      <Button variant="ghost" size="sm" onClick={() => setOpen(true)}>
        <RotateCw className="h-3.5 w-3.5" aria-hidden />
        {t("databases.resetPassword")}
      </Button>

      <Dialog
        open={open}
        onClose={() => setOpen(false)}
        title={t("databases.resetTitle", { name: user.username })}
        description={t("databases.resetHint")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setOpen(false)}>
              {t("common.cancel")}
            </Button>
            <Button
              variant="danger"
              disabled={reset.isPending}
              onClick={() => {
                setError(null);
                reset.mutate();
              }}
            >
              {reset.isPending ? <Spinner /> : null}
              {t("databases.resetConfirm")}
            </Button>
          </>
        }
      >
        {/* The old password stops working the moment this succeeds; anything
            still connecting with it breaks until it is updated. */}
        <p className="text-sm text-ink-muted">{t("databases.resetBreaks")}</p>
        {error ? <ErrorNote error={error} /> : null}
      </Dialog>
    </>
  );
}

function DropUserButton({ user }: { user: DbUserRow }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [typed, setTyped] = useState("");
  const [error, setError] = useState<string | null>(null);

  const armed = confirmsName(typed, user.username);

  const drop = useMutation({
    mutationFn: () => databasesApi.dropUser(user.username),
    onSuccess: () => {
      setOpen(false);
      setTyped("");
      void queryClient.invalidateQueries({ queryKey: ["databases"] });
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  return (
    <>
      <Button variant="ghost" size="sm" onClick={() => setOpen(true)}>
        <Trash2 className="h-3.5 w-3.5" aria-hidden />
        {t("databases.dropUser")}
      </Button>

      <Dialog
        open={open}
        onClose={() => setOpen(false)}
        title={t("databases.dropUserTitle", { name: user.username })}
        description={t("databases.dropUserHint")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setOpen(false)}>
              {t("common.cancel")}
            </Button>
            <Button
              variant="danger"
              disabled={!armed || drop.isPending}
              onClick={() => {
                setError(null);
                drop.mutate();
              }}
            >
              {drop.isPending ? <Spinner /> : null}
              {t("databases.dropUserConfirm")}
            </Button>
          </>
        }
      >
        {/* The user's databases survive; what dies is every application that
            was connecting as this account. Say which, so the operator can
            decide before rather than discover after. */}
        <p className="mb-3 rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
          {t("databases.dropUserWarning")}
        </p>
        <Field
          label={t("databases.typeUsername")}
          htmlFor={`drop-user-${user.id}`}
          error={typed.length > 0 && !armed ? t("databases.typeUsernameMismatch") : undefined}
        >
          <Input
            id={`drop-user-${user.id}`}
            dir="ltr"
            autoComplete="off"
            autoFocus
            placeholder={user.username}
            value={typed}
            onChange={(event) => setTyped(event.target.value)}
          />
        </Field>
        {error ? <ErrorNote error={error} /> : null}
      </Dialog>
    </>
  );
}

// ---------------------------------------------------------------------------
// The one sighting of a password
// ---------------------------------------------------------------------------

/**
 * The password dialog, deliberately *not* built on `Dialog`.
 *
 * `Dialog` closes on Escape and on a backdrop click, which is right for every
 * other modal in the panel and wrong for this one: the panel keeps no copy of
 * what is on screen, so a stray Escape costs the operator the credential and
 * forces a reset that breaks whatever is already using the account. The only
 * way out is the acknowledgement button.
 */
function PasswordOnceDialog({
  secret,
  onAcknowledge,
}: {
  secret: DbUserSecret | null;
  onAcknowledge: () => void;
}) {
  const { t } = useTranslation();
  const [copied, setCopied] = useState(false);
  const [copyFailed, setCopyFailed] = useState(false);

  // A fresh secret is a fresh dialog: never carry "copied" across two of them,
  // or the second one looks saved when it is not.
  useEffect(() => {
    setCopied(false);
    setCopyFailed(false);
  }, [secret]);

  if (!secret) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 p-4 pt-[8vh] backdrop-blur-[1px]"
      role="alertdialog"
      aria-modal="true"
      aria-label={t("databases.secretTitle")}
    >
      <div className="w-full max-w-lg rounded-card border border-warning/40 bg-surface shadow-2xl">
        <header className="flex items-start gap-3 border-b border-border px-5 py-4">
          <TriangleAlert className="mt-0.5 h-5 w-5 shrink-0 text-warning" aria-hidden />
          <div>
            <h2 className="text-sm font-semibold text-ink">{t("databases.secretTitle")}</h2>
            <p className="mt-0.5 text-sm text-ink-muted">
              {t("databases.secretFor", { name: secret.username })}
            </p>
          </div>
        </header>

        <div className="space-y-3 px-5 py-4">
          <p className="rounded-lg bg-warning-soft px-3 py-2 text-sm font-medium text-warning">
            {t("databases.secretOnlyTime")}
          </p>

          <div className="flex items-stretch gap-2">
            {/* Selectable text, not a masked field: if the clipboard is
                unavailable (no secure context, a browser that refuses the
                permission) the operator must still be able to select it. */}
            <code
              dir="ltr"
              className="min-w-0 flex-1 overflow-x-auto rounded-lg border border-border-strong bg-canvas px-3 py-2 font-mono text-sm break-all text-ink select-all"
            >
              {secret.password}
            </code>
            <Button
              variant={copied ? "secondary" : "primary"}
              aria-label={t("databases.copyPassword")}
              onClick={() => {
                void (async () => {
                  const ok = await copyToClipboard(secret.password);
                  setCopied(ok);
                  setCopyFailed(!ok);
                })();
              }}
            >
              {copied ? (
                <Check className="h-4 w-4" aria-hidden />
              ) : (
                <Copy className="h-4 w-4" aria-hidden />
              )}
              {copied ? t("databases.copied") : t("databases.copy")}
            </Button>
          </div>

          {copyFailed ? (
            <p role="alert" className="text-xs text-danger">
              {t("databases.copyFailed")}
            </p>
          ) : null}

          <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs text-ink-muted">
            <dt>{t("databases.user")}</dt>
            <dd dir="ltr" className="font-mono text-ink">
              {secret.username}
            </dd>
            <dt>{t("databases.engineLabel")}</dt>
            <dd className="text-ink">{t(`databases.engine.${secret.engine}`)}</dd>
            <dt>{t("databases.host")}</dt>
            <dd dir="ltr" className="font-mono text-ink">
              localhost
            </dd>
          </dl>

          <p className="text-xs text-ink-subtle">{t("databases.secretRecovery")}</p>
        </div>

        <footer className="flex justify-end border-t border-border px-5 py-3.5">
          <Button variant="primary" onClick={onAcknowledge} autoFocus>
            {t("databases.secretAcknowledge")}
          </Button>
        </footer>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Creation dialogs
// ---------------------------------------------------------------------------

/** The optional subscription field, shared by both creation dialogs. */
function SubscriptionField({
  id,
  value,
  onChange,
  known,
}: {
  id: string;
  value: string;
  onChange: (next: string) => void;
  known: number[];
}) {
  const { t } = useTranslation();
  const invalid = value.trim() !== "" && !/^\d+$/.test(value.trim());

  return (
    <>
      <Field
        label={t("databases.subscriptionOptional")}
        htmlFor={id}
        error={invalid ? t("databases.subscriptionInvalid") : undefined}
      >
        <Input
          id={id}
          dir="ltr"
          inputMode="numeric"
          // A datalist rather than a select: the panel has no endpoint that
          // lists subscriptions, so these are only the ids already on screen —
          // a suggestion, not the set of valid answers.
          list={`${id}-known`}
          aria-invalid={invalid}
          aria-describedby={`${id}-hint`}
          value={value}
          onChange={(event) => onChange(event.target.value)}
        />
      </Field>
      <datalist id={`${id}-known`}>
        {known.map((subscriptionId) => (
          <option key={subscriptionId} value={String(subscriptionId)} />
        ))}
      </datalist>
      <p id={`${id}-hint`} className="-mt-1 mb-3 text-xs text-ink-muted">
        {t("databases.subscriptionHint")}
      </p>
    </>
  );
}

function CreateDatabaseDialog({
  open,
  onClose,
  users,
  knownSubscriptions,
}: {
  open: boolean;
  onClose: () => void;
  users: DbUserRow[];
  knownSubscriptions: number[];
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [engine, setEngine] = useState<DbEngine>("mysql");
  const [subscription, setSubscription] = useState("");
  const [owner, setOwner] = useState("");
  const [error, setError] = useState<string | null>(null);

  const problem = name === "" ? null : dbNameProblem(name);
  const subscriptionId = subscription.trim() === "" ? undefined : Number(subscription.trim());

  // Owning a database means holding privileges on it, so the candidate list is
  // narrowed the same way a grant is: same engine, and — when a subscription
  // has been named — that subscription.
  const owners = users.filter(
    (user) =>
      user.engine === engine &&
      (subscriptionId === undefined || user.subscription_id === subscriptionId),
  );

  const close = () => {
    setName("");
    setOwner("");
    setSubscription("");
    setError(null);
    onClose();
  };

  const create = useMutation({
    mutationFn: () =>
      databasesApi.create({
        name: name.trim(),
        engine,
        ...(subscriptionId === undefined ? {} : { subscription_id: subscriptionId }),
        ...(owner === "" ? {} : { owner }),
      }),
    onSuccess: () => {
      close();
      void queryClient.invalidateQueries({ queryKey: ["databases"] });
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  const ready = name.trim() !== "" && dbNameProblem(name) === null;

  return (
    <Dialog
      open={open}
      onClose={close}
      title={t("databases.newDatabase")}
      description={t("databases.newDatabaseHint")}
      footer={
        <>
          <Button variant="ghost" onClick={close}>
            {t("common.cancel")}
          </Button>
          <Button
            variant="primary"
            disabled={!ready || create.isPending}
            onClick={() => {
              setError(null);
              create.mutate();
            }}
          >
            {create.isPending ? <Spinner /> : null}
            {t("databases.create")}
          </Button>
        </>
      }
    >
      <Field
        label={t("databases.name")}
        htmlFor="db-name"
        error={problem ? t(`databases.nameProblem.${problem}`) : undefined}
      >
        <Input
          id="db-name"
          dir="ltr"
          autoFocus
          placeholder="shop_main"
          aria-invalid={Boolean(problem)}
          aria-describedby="db-name-hint"
          value={name}
          onChange={(event) => setName(event.target.value)}
        />
      </Field>
      <p id="db-name-hint" className="-mt-1 mb-3 text-xs text-ink-muted">
        {t("databases.nameHint")}
      </p>

      <Field label={t("databases.engineLabel")} htmlFor="db-engine">
        <Select
          id="db-engine"
          value={engine}
          onChange={(event) => {
            setEngine(event.target.value as DbEngine);
            // The owner list is engine-specific; keeping a stale pick would
            // send a pairing the agent refuses.
            setOwner("");
          }}
        >
          {DB_ENGINES.map((value) => (
            <option key={value} value={value}>
              {t(`databases.engine.${value}`)}
            </option>
          ))}
        </Select>
      </Field>
      <div className="h-3" />

      <SubscriptionField
        id="db-subscription"
        value={subscription}
        onChange={(next) => {
          setSubscription(next);
          setOwner("");
        }}
        known={knownSubscriptions}
      />

      <Field label={t("databases.ownerOptional")} htmlFor="db-owner">
        <Select
          id="db-owner"
          dir="ltr"
          value={owner}
          onChange={(event) => setOwner(event.target.value)}
          aria-describedby="db-owner-hint"
        >
          <option value="">{t("databases.noOwner")}</option>
          {owners.map((user) => (
            <option key={user.id} value={user.username}>
              {user.username}
            </option>
          ))}
        </Select>
      </Field>
      <p id="db-owner-hint" className="-mt-1 text-xs text-ink-muted">
        {t("databases.ownerHint")}
      </p>

      {error ? (
        <p role="alert" className="mt-3 rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
          {error}
        </p>
      ) : null}
    </Dialog>
  );
}

function CreateUserDialog({
  open,
  onClose,
  knownSubscriptions,
  onCreated,
}: {
  open: boolean;
  onClose: () => void;
  knownSubscriptions: number[];
  onCreated: (secret: DbUserSecret) => void;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [username, setUsername] = useState("");
  const [engine, setEngine] = useState<DbEngine>("mysql");
  const [subscription, setSubscription] = useState("");
  const [error, setError] = useState<string | null>(null);

  const problem = username === "" ? null : dbNameProblem(username);
  const subscriptionId = subscription.trim() === "" ? undefined : Number(subscription.trim());

  const close = () => {
    setUsername("");
    setSubscription("");
    setError(null);
    onClose();
  };

  const create = useMutation({
    mutationFn: () =>
      databasesApi.createUser({
        username: username.trim(),
        engine,
        ...(subscriptionId === undefined ? {} : { subscription_id: subscriptionId }),
      }),
    onSuccess: (secret) => {
      close();
      void queryClient.invalidateQueries({ queryKey: ["databases"] });
      // Hand the password straight to the once-only dialog. It never touches
      // the query cache, where a devtools panel or a stale render could bring
      // it back after the operator dismissed it.
      onCreated(secret);
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  const ready = username.trim() !== "" && dbNameProblem(username) === null;

  return (
    <Dialog
      open={open}
      onClose={close}
      title={t("databases.newUser")}
      description={t("databases.newUserHint")}
      footer={
        <>
          <Button variant="ghost" onClick={close}>
            {t("common.cancel")}
          </Button>
          <Button
            variant="primary"
            disabled={!ready || create.isPending}
            onClick={() => {
              setError(null);
              create.mutate();
            }}
          >
            {create.isPending ? <Spinner /> : null}
            {t("databases.create")}
          </Button>
        </>
      }
    >
      <Field
        label={t("databases.username")}
        htmlFor="db-username"
        error={problem ? t(`databases.nameProblem.${problem}`) : undefined}
      >
        <Input
          id="db-username"
          dir="ltr"
          autoFocus
          placeholder="shop_app"
          aria-invalid={Boolean(problem)}
          value={username}
          onChange={(event) => setUsername(event.target.value)}
        />
      </Field>

      <Field label={t("databases.engineLabel")} htmlFor="db-user-engine">
        <Select
          id="db-user-engine"
          value={engine}
          onChange={(event) => setEngine(event.target.value as DbEngine)}
        >
          {DB_ENGINES.map((value) => (
            <option key={value} value={value}>
              {t(`databases.engine.${value}`)}
            </option>
          ))}
        </Select>
      </Field>
      <div className="h-3" />

      <SubscriptionField
        id="db-user-subscription"
        value={subscription}
        onChange={setSubscription}
        known={knownSubscriptions}
      />

      {/* Warn before, not after: the operator needs to be somewhere they can
          paste a password when they press the button. */}
      <p className="rounded-lg bg-warning-soft px-3 py-2 text-sm text-warning">
        {t("databases.passwordWarning")}
      </p>

      {error ? (
        <p role="alert" className="mt-3 rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
          {error}
        </p>
      ) : null}
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Adminer
// ---------------------------------------------------------------------------

/**
 * Adminer's card.
 *
 * `db.adminer.*` is `ServerManage`, so a reseller holding only `DbManage` gets
 * 403 on the status read. That is not an error worth shouting about on a page
 * that otherwise works, so the card simply does not render for them.
 */
function AdminerCard() {
  const { t } = useTranslation();
  const { user } = useSession();
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const allowed = user?.permissions.includes("server_manage") ?? false;

  const status = useQuery({
    queryKey: ["adminer"],
    queryFn: databasesApi.adminer,
    enabled: allowed,
    retry: false,
  });

  const toggle = useMutation({
    mutationFn: (enable: boolean) => databasesApi.setAdminer(enable),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["adminer"] }),
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  if (!allowed) return null;

  const enabled = status.data?.enabled ?? false;
  // `url` is loopback. The tunnel command is what actually gets a browser to
  // it, so that — not the URL — is the thing with a copy button.
  const port = status.data?.url?.match(/:(\d+)/)?.[1] ?? "8806";
  const tunnel = `ssh -N -L ${port}:127.0.0.1:${port} root@your-server`;

  return (
    <Card>
      <CardHeader
        title={t("databases.adminerTitle")}
        description={t("databases.adminerSubtitle")}
        action={
          status.isPending ? (
            <Spinner />
          ) : (
            <Button
              variant={enabled ? "outline" : "primary"}
              size="sm"
              disabled={toggle.isPending}
              onClick={() => {
                setError(null);
                toggle.mutate(!enabled);
              }}
            >
              {toggle.isPending ? <Spinner /> : null}
              {enabled ? t("databases.adminerDisable") : t("databases.adminerEnable")}
            </Button>
          )
        }
      />
      <CardBody className="space-y-3 pt-0">
        {status.error ? (
          <ErrorNote error={status.error} />
        ) : (
          <>
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone={enabled ? "success" : "neutral"} dot>
                {enabled ? t("databases.adminerOn") : t("databases.adminerOff")}
              </Badge>
              {status.data?.php_version ? (
                <Badge tone="neutral">
                  <span>PHP</span>
                  <span dir="ltr">{status.data.php_version}</span>
                </Badge>
              ) : null}
              {status.data ? (
                <Badge tone="neutral">
                  <span>Adminer</span>
                  <span dir="ltr">{status.data.adminer_version}</span>
                </Badge>
              ) : null}
            </div>

            {/* Not a link. Adminer binds 127.0.0.1 because nginx cannot check a
                Unihelm session cookie, so publishing a database login form on a
                real interface is not on the table until the panel proxies it
                itself. An <a href> here would be a promise the panel breaks. */}
            <div className="rounded-lg border border-border bg-canvas p-3">
              <p className="flex items-start gap-2 text-sm text-ink-muted">
                <Terminal className="mt-0.5 h-4 w-4 shrink-0 text-ink-subtle" aria-hidden />
                <span>{t("databases.adminerLoopback")}</span>
              </p>

              {enabled ? (
                <>
                  <p className="mt-3 mb-1 text-xs font-medium text-ink">
                    {t("databases.adminerTunnelStep")}
                  </p>
                  <div className="flex items-stretch gap-2">
                    <code
                      dir="ltr"
                      className="min-w-0 flex-1 overflow-x-auto rounded-md border border-border-strong bg-surface px-2.5 py-2 font-mono text-xs whitespace-pre text-ink select-all"
                    >
                      {tunnel}
                    </code>
                    <Button
                      variant="ghost"
                      size="icon"
                      aria-label={t("databases.copyCommand")}
                      onClick={() => {
                        void (async () => setCopied(await copyToClipboard(tunnel)))();
                      }}
                    >
                      {copied ? (
                        <Check className="h-4 w-4" aria-hidden />
                      ) : (
                        <Copy className="h-4 w-4" aria-hidden />
                      )}
                    </Button>
                  </div>
                  <p className="mt-2 text-xs text-ink-muted">
                    {t("databases.adminerThenOpen")}{" "}
                    <span dir="ltr" className="font-mono text-ink">
                      {status.data?.url ?? `http://127.0.0.1:${port}/`}
                    </span>
                  </p>
                </>
              ) : null}
            </div>

            {status.data?.pin_provenance ? (
              <p className="text-xs text-ink-subtle">
                {t("databases.adminerPin", { provenance: status.data.pin_provenance })}
              </p>
            ) : null}

            {error ? <ErrorNote error={error} /> : null}
          </>
        )}
      </CardBody>
    </Card>
  );
}
