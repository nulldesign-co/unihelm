import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Eye, EyeOff, KeyRound, Pencil, Plus, Trash2, UserCheck, UserX } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input } from "@/components/ui/input";
import { Menu, MenuItem, MenuSeparator } from "@/components/ui/menu";
import { PageHeader } from "@/components/ui/page-header";
import { Select } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { ApiError } from "@/lib/api";
import { staggerStyle } from "@/lib/motion";
import { useSession } from "@/lib/session";
import {
  confirmationMatches,
  newPasswordProblem,
  owned,
  passwordProblem,
  refusalFor,
  usersApi,
  type ManageAction,
  type PanelRole,
  type PanelUser,
  type Viewer,
} from "@/lib/users-api";

/**
 * Your password, and everyone who can sign in to this panel (spec §6.1).
 *
 * Both halves live on one page because they answer the same question — "who
 * gets into this panel" — and because until now neither had a screen at all:
 * the admin's password could only be changed from a root shell, and a second
 * administrator could only be made by an installer command that refuses once
 * any account exists.
 *
 * Three decisions shape it.
 *
 * **The password card is for everybody; the table is not.** Changing your own
 * password needs no permission — it is your account — so the card renders for
 * a customer exactly as it does for an admin. The account list is behind
 * `user_manage`, and its absence is silent rather than a "you may not" panel:
 * a customer has one account and it is theirs.
 *
 * **Refusals are shown before the click, and again after it.** `refusalFor`
 * repeats what `unihelm_ops::users` enforces, so the last administrator's
 * Delete is already greyed out with the reason under it — the pattern the
 * plans page uses for a plan that still has subscriptions. The server is still
 * the boundary: it refuses the same things over the same socket for the CLI,
 * and whatever it says is what this page shows if the two ever disagree.
 *
 * **Deleting says what goes and what stays.** The dialog names the account,
 * asks for its username back, and lists what is removed with it and what
 * survives — the audit trail keeps every entry under their name, which is the
 * part an operator is most likely to be wrong about.
 */
export function UsersPage() {
  const { t } = useTranslation();
  const { user } = useSession();
  const canManage = user?.permissions.includes("user_manage") ?? false;

  return (
    <div className="space-y-6">
      <PageHeader title={t("users.title")} description={t("users.subtitle")} />
      <PasswordCard />
      {canManage ? <AccountsCard viewerId={user?.id ?? 0} /> : null}
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
// Your own password
// ---------------------------------------------------------------------------

function PasswordCard() {
  const { t } = useTranslation();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [repeat, setRepeat] = useState("");
  const [reveal, setReveal] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<number | null>(null);

  const change = useMutation({
    mutationFn: () => usersApi.changePassword(current, next),
    onSuccess: (result) => {
      // Cleared rather than left on screen: the fields hold the credential
      // that was just replaced, and the browser would happily keep offering it.
      setCurrent("");
      setNext("");
      setRepeat("");
      setError(null);
      setProblem(null);
      setDone(result.sessions_ended);
    },
    onError: (e) => {
      setDone(null);
      setError(e instanceof ApiError ? e.message : String(e));
    },
  });

  return (
    <Card>
      <CardHeader title={t("users.password.title")} description={t("users.password.hint")} />
      <CardBody>
        <form
          className="max-w-md space-y-1"
          onSubmit={(event) => {
            event.preventDefault();
            if (passwordProblem(current) === "required") {
              setProblem(t("users.password.problem.currentRequired"));
              return;
            }
            const found = newPasswordProblem(current, next, repeat);
            if (found) {
              setProblem(t(`users.password.problem.${found}`));
              return;
            }
            setProblem(null);
            change.mutate();
          }}
        >
          <Field label={t("users.password.current")} htmlFor="current-password">
            <Input
              id="current-password"
              type="password"
              autoComplete="current-password"
              value={current}
              onChange={(e) => {
                setCurrent(e.target.value);
                setProblem(null);
              }}
            />
          </Field>
          <Field
            label={t("users.password.new")}
            htmlFor="new-password"
            error={problem ?? undefined}
          >
            <Input
              id="new-password"
              type={reveal ? "text" : "password"}
              autoComplete="new-password"
              aria-invalid={problem ? true : undefined}
              value={next}
              onChange={(e) => {
                setNext(e.target.value);
                setProblem(null);
              }}
            />
          </Field>
          <Field label={t("users.password.repeat")} htmlFor="repeat-password">
            <Input
              id="repeat-password"
              type={reveal ? "text" : "password"}
              autoComplete="new-password"
              value={repeat}
              onChange={(e) => {
                setRepeat(e.target.value);
                setProblem(null);
              }}
            />
          </Field>

          <div className="flex flex-wrap items-center gap-3">
            <Button type="submit" variant="primary" loading={change.isPending}>
              <KeyRound className="h-4 w-4" aria-hidden />
              {t("users.password.submit")}
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setReveal((on) => !on)}
              aria-pressed={reveal}
            >
              {reveal ? (
                <EyeOff className="h-4 w-4" aria-hidden />
              ) : (
                <Eye className="h-4 w-4" aria-hidden />
              )}
              {reveal ? t("login.hidePassword") : t("login.showPassword")}
            </Button>
          </div>

          <p className="mt-2 text-xs text-ink-muted">{t("users.password.policy")}</p>

          {error ? (
            <Callout tone="danger" className="mt-3">
              {error}
            </Callout>
          ) : null}

          {/* The count is the part worth reading: it says whether anybody else
              was signed in on this account, which is usually the reason the
              password is being changed at all. */}
          {done !== null ? (
            <Callout tone="success" className="mt-3">
              {done > 0
                ? t("users.password.changedWith", { count: done })
                : t("users.password.changed")}
            </Callout>
          ) : null}
        </form>
      </CardBody>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// The accounts
// ---------------------------------------------------------------------------

function AccountsCard({ viewerId }: { viewerId: number }) {
  const { t } = useTranslation();
  const [creating, setCreating] = useState(false);
  const users = useQuery({ queryKey: ["users"], queryFn: usersApi.list });
  const viewer: Viewer = { id: viewerId, adminCount: users.data?.admin_count ?? null };

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-end justify-between gap-x-4 gap-y-2">
        <div className="min-w-0">
          <h2 className="text-base font-semibold text-ink">{t("users.accounts.title")}</h2>
          <p className="mt-0.5 text-sm text-ink-muted">{t("users.accounts.hint")}</p>
        </div>
        <Button variant="primary" onClick={() => setCreating(true)}>
          <Plus className="h-4 w-4" aria-hidden />
          {t("users.new")}
        </Button>
      </div>

      {users.error ? <ErrorNote error={users.error} /> : null}

      {users.isPending ? (
        <UsersTableSkeleton />
      ) : (
        <Table>
          <UsersHead />
          <tbody>
            {(users.data?.users ?? []).map((row, index) => (
              <UserRow key={row.id} user={row} viewer={viewer} index={index} />
            ))}
          </tbody>
        </Table>
      )}

      <CreateDialog open={creating} onClose={() => setCreating(false)} />
    </div>
  );
}

/** Shared by the table and its skeleton, so the ghost has the real columns. */
function UsersHead() {
  const { t } = useTranslation();
  return (
    <thead>
      <tr>
        <Th>{t("users.username")}</Th>
        <Th>{t("users.role")}</Th>
        <Th>{t("users.status")}</Th>
        <Th>{t("users.lastLogin")}</Th>
        <Th>{t("users.holdings")}</Th>
        <Th>
          <span className="sr-only">{t("files.actions")}</span>
        </Th>
      </tr>
    </thead>
  );
}

function UsersTableSkeleton({ rows = 2 }: { rows?: number }) {
  return (
    <div role="status" aria-live="polite">
      <Table>
        <UsersHead />
        <tbody>
          {Array.from({ length: rows }, (_, i) => (
            <tr key={i} className="animate-rise-in stagger" style={staggerStyle(i)}>
              <Td>
                <Skeleton className="h-4 w-32" />
                <Skeleton className="mt-1.5 h-3 w-44" />
              </Td>
              <Td>
                <Skeleton className="h-5 w-24 rounded-full" />
              </Td>
              <Td>
                <Skeleton className="h-5 w-16 rounded-full" />
              </Td>
              <Td>
                <Skeleton className="h-4 w-28" />
              </Td>
              <Td>
                <Skeleton className="h-4 w-20" />
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

const STATUS_TONE = {
  active: "success",
  suspended: "warning",
  locked: "danger",
} as const;

function UserRow({
  user,
  viewer,
  index,
}: {
  user: PanelUser;
  viewer: Viewer;
  index: number;
}) {
  const { t, i18n } = useTranslation();
  const [editingRole, setEditingRole] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const holdings = owned(user);

  return (
    <Tr className="animate-rise-in stagger" style={staggerStyle(index)}>
      <Td>
        <div className="flex flex-wrap items-center gap-2">
          <span className="truncate text-sm font-medium text-ink">{user.username}</span>
          {user.id === viewer.id ? <Badge tone="accent">{t("users.you")}</Badge> : null}
        </div>
        <p className="mt-0.5 truncate text-xs text-ink-muted">{user.email}</p>
      </Td>
      <Td>
        <span className="text-sm">{t(`common.role.${user.role}`)}</span>
      </Td>
      <Td>
        <Badge tone={STATUS_TONE[user.status]} dot>
          {t(`users.state.${user.status}`)}
        </Badge>
      </Td>
      <Td className="text-sm whitespace-nowrap text-ink-muted">
        {user.last_login_at
          ? new Intl.DateTimeFormat(i18n.language, {
              dateStyle: "short",
              timeStyle: "short",
            }).format(new Date(user.last_login_at))
          : t("users.never")}
      </Td>
      <Td className="text-sm text-ink-muted">
        {holdings.length === 0
          ? t("common.none")
          : holdings
              .map((held) => t(`users.owns.${held.kind}`, { count: held.count }))
              .join(", ")}
      </Td>
      <Td className="text-end">
        <Menu label={t("files.actions")}>
          <RowAction
            action="role"
            user={user}
            viewer={viewer}
            icon={<Pencil aria-hidden />}
            label={t("users.actions.changeRole")}
            onClick={() => setEditingRole(true)}
          />
          <StatusAction user={user} viewer={viewer} />
          <MenuSeparator />
          <RowAction
            action="delete"
            user={user}
            viewer={viewer}
            danger
            icon={<Trash2 aria-hidden />}
            label={t("users.actions.delete")}
            onClick={() => setDeleting(true)}
          />
        </Menu>

        <RoleDialog open={editingRole} onClose={() => setEditingRole(false)} user={user} />
        <DeleteDialog open={deleting} onClose={() => setDeleting(false)} user={user} />
      </Td>
    </Tr>
  );
}

/**
 * One menu item, disabled with the reason underneath when the server would
 * refuse it.
 *
 * The reason is visible text rather than a `title`: a tooltip is invisible on a
 * touch screen, and a title on an item that already has a label muddies its
 * accessible name. Wrapped in a `role="group"` because `role="menu"` only
 * admits items, separators and groups, and the note belongs to its item.
 */
function RowAction({
  action,
  user,
  viewer,
  icon,
  label,
  danger,
  onClick,
}: {
  action: ManageAction;
  user: PanelUser;
  viewer: Viewer;
  icon: React.ReactNode;
  label: string;
  danger?: boolean;
  onClick: () => void;
}) {
  const { t } = useTranslation();
  const refusal = refusalFor(action, user, viewer);
  const noteId = `user-${user.id}-${action}-blocked`;

  return (
    <div role="group">
      <MenuItem
        danger={danger}
        icon={icon}
        disabled={refusal !== null}
        aria-describedby={refusal ? noteId : undefined}
        onClick={onClick}
      >
        {label}
      </MenuItem>
      {refusal ? (
        <p id={noteId} className="px-2.5 pb-1 text-start text-xs text-ink-subtle">
          {t(`users.blocked.${refusal}`)}
        </p>
      ) : null}
    </div>
  );
}

/**
 * Suspend, or let back in.
 *
 * Reinstating is never refused, so it is a plain item — the refusal mirror only
 * applies in the direction that takes somebody's access away.
 */
function StatusAction({ user, viewer }: { user: PanelUser; viewer: Viewer }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const suspending = user.status === "active";

  return (
    <>
      {suspending ? (
        <RowAction
          action="suspend"
          user={user}
          viewer={viewer}
          icon={<UserX aria-hidden />}
          label={t("users.actions.suspend")}
          onClick={() => setOpen(true)}
        />
      ) : (
        <MenuItem icon={<UserCheck aria-hidden />} onClick={() => setOpen(true)}>
          {t("users.actions.restore")}
        </MenuItem>
      )}
      <StatusDialog
        open={open}
        onClose={() => setOpen(false)}
        user={user}
        suspending={suspending}
      />
    </>
  );
}

// ---------------------------------------------------------------------------
// Dialogs
// ---------------------------------------------------------------------------

const ROLES: PanelRole[] = ["admin", "reseller", "customer"];

function CreateDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [fullName, setFullName] = useState("");
  const [role, setRole] = useState<PanelRole>("customer");
  const [password, setPassword] = useState("");
  const [problem, setProblem] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: () =>
      usersApi.create({
        username: username.trim(),
        email: email.trim(),
        role,
        password,
        full_name: fullName.trim() === "" ? null : fullName.trim(),
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["users"] });
      setUsername("");
      setEmail("");
      setFullName("");
      setPassword("");
      setError(null);
      onClose();
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={t("users.create.title")}
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button
            variant="primary"
            loading={create.isPending}
            onClick={() => {
              const found = passwordProblem(password);
              if (found) {
                setProblem(t(`users.password.problem.${found}`));
                return;
              }
              setProblem(null);
              create.mutate();
            }}
          >
            <Plus className="h-4 w-4" aria-hidden />
            {t("users.create.submit")}
          </Button>
        </>
      }
    >
      <div className="space-y-1">
        <Field label={t("users.username")} htmlFor="new-username">
          <Input
            id="new-username"
            autoComplete="off"
            spellCheck={false}
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </Field>
        <Field label={t("users.email")} htmlFor="new-email">
          <Input
            id="new-email"
            type="email"
            autoComplete="off"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </Field>
        <Field label={t("users.fullName")} htmlFor="new-full-name">
          <Input
            id="new-full-name"
            autoComplete="off"
            value={fullName}
            onChange={(e) => setFullName(e.target.value)}
          />
        </Field>
        <Field label={t("users.role")} htmlFor="new-role">
          <Select
            id="new-role"
            value={role}
            onChange={(e) => setRole(e.target.value as PanelRole)}
          >
            {ROLES.map((value) => (
              <option key={value} value={value}>
                {t(`common.role.${value}`)}
              </option>
            ))}
          </Select>
        </Field>
        <Field
          label={t("users.create.password")}
          htmlFor="new-user-password"
          error={problem ?? undefined}
        >
          <Input
            id="new-user-password"
            type="text"
            autoComplete="off"
            spellCheck={false}
            aria-invalid={problem ? true : undefined}
            value={password}
            onChange={(e) => {
              setPassword(e.target.value);
              setProblem(null);
            }}
          />
        </Field>
        {/* Shown, not masked: the operator has to be able to copy it to the
            person it belongs to, and the panel will not show it again. */}
        <p className="-mt-1 text-xs text-ink-muted">{t("users.create.passwordHint")}</p>

        {error ? (
          <Callout tone="danger" className="mt-3">
            {error}
          </Callout>
        ) : null}
      </div>
    </Dialog>
  );
}

function RoleDialog({
  open,
  onClose,
  user,
}: {
  open: boolean;
  onClose: () => void;
  user: PanelUser;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [role, setRole] = useState<PanelRole>(user.role);
  const [error, setError] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: () => usersApi.setRole(user.id, role),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["users"] });
      setError(null);
      onClose();
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={t("users.roleDialog.title", { name: user.username })}
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button
            variant="primary"
            loading={save.isPending}
            disabled={role === user.role}
            onClick={() => save.mutate()}
          >
            {t("users.roleDialog.submit")}
          </Button>
        </>
      }
    >
      <Field label={t("users.role")} htmlFor={`role-${user.id}`}>
        <Select
          id={`role-${user.id}`}
          value={role}
          onChange={(e) => setRole(e.target.value as PanelRole)}
        >
          {ROLES.map((value) => (
            <option key={value} value={value}>
              {t(`common.role.${value}`)}
            </option>
          ))}
        </Select>
      </Field>
      <p className="text-sm text-ink-muted">{t("users.roleDialog.hint")}</p>
      {error ? (
        <Callout tone="danger" className="mt-3">
          {error}
        </Callout>
      ) : null}
    </Dialog>
  );
}

function StatusDialog({
  open,
  onClose,
  user,
  suspending,
}: {
  open: boolean;
  onClose: () => void;
  user: PanelUser;
  suspending: boolean;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: () => usersApi.setStatus(user.id, suspending ? "suspended" : "active"),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["users"] });
      setError(null);
      onClose();
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  const prefix = suspending ? "users.suspendDialog" : "users.restoreDialog";

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={t(`${prefix}.title`, { name: user.username })}
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button
            variant={suspending ? "danger" : "primary"}
            loading={save.isPending}
            onClick={() => save.mutate()}
          >
            {suspending ? (
              <UserX className="h-4 w-4" aria-hidden />
            ) : (
              <UserCheck className="h-4 w-4" aria-hidden />
            )}
            {t(`${prefix}.submit`)}
          </Button>
        </>
      }
    >
      <p className="text-sm text-ink-muted">{t(`${prefix}.body`)}</p>
      {error ? (
        <Callout tone="danger" className="mt-3">
          {error}
        </Callout>
      ) : null}
    </Dialog>
  );
}

/**
 * The one thing on this page that cannot be undone by clicking the other way.
 *
 * It names the account, asks for the username back — the same confirmation
 * `user.delete` requires, so a mismatch is refused by the agent as well — and
 * says what goes and what stays before the button is reachable.
 */
function DeleteDialog({
  open,
  onClose,
  user,
}: {
  open: boolean;
  onClose: () => void;
  user: PanelUser;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [typed, setTyped] = useState("");
  const [error, setError] = useState<string | null>(null);

  const remove = useMutation({
    mutationFn: () => usersApi.remove(user.id, typed.trim()),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["users"] });
      setTyped("");
      setError(null);
      onClose();
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  const matches = confirmationMatches(typed, user.username);

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={t("users.deleteDialog.title", { name: user.username })}
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button
            variant="danger"
            loading={remove.isPending}
            disabled={!matches}
            onClick={() => remove.mutate()}
          >
            <Trash2 className="h-4 w-4" aria-hidden />
            {t("users.deleteDialog.submit")}
          </Button>
        </>
      }
    >
      <p className="text-sm text-ink-muted">{t("users.deleteDialog.body")}</p>
      <p className="mt-2 text-sm text-ink-muted">{t("users.deleteDialog.goes")}</p>
      <div className="mt-4">
        <Field
          label={t("users.deleteDialog.confirmLabel", { name: user.username })}
          htmlFor={`confirm-${user.id}`}
        >
          <Input
            id={`confirm-${user.id}`}
            autoComplete="off"
            spellCheck={false}
            value={typed}
            onChange={(e) => setTyped(e.target.value)}
          />
        </Field>
      </div>
      {error ? <Callout tone="danger">{error}</Callout> : null}
    </Dialog>
  );
}
