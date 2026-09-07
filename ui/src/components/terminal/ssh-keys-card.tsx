import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { KeyRound, ShieldAlert, Trash2 } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { Field, Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { ApiError } from "@/lib/api";
import { staggerStyle } from "@/lib/motion";
import { useSession } from "@/lib/session";
import {
  keysRequest,
  sshKeyAccount,
  subscriptionLabel,
  terminalApi,
  type KeyAccount,
  type SshKey,
} from "@/lib/terminal-api";

/**
 * The per-account `authorized_keys` manager (spec §11.16).
 *
 * Keys are installed per Linux account, so the first thing this card has to
 * establish is *whose*. It used to skip that: every call went out with no
 * account, which an administrator's scope has no answer for, and so the card
 * was a refusal quoting `subscription_id` — a field it did not offer — for the
 * one role most likely to open it. The account is chosen here now, and nothing
 * is requested until it is known.
 *
 * The server's own root account is not among the choices, and the card says so
 * rather than offering a control that fails. These operations reach a tenant's
 * `~/.ssh/authorized_keys` by running *as* that tenant, and the runner they use
 * refuses uid 0 outright — `/root/.ssh/authorized_keys` is a file the panel
 * cannot address at all, not one it merely does not list.
 */
export function SshKeysCard() {
  const { t } = useTranslation();
  const { user } = useSession();
  const queryClient = useQueryClient();
  const isAdmin = user?.role === "admin";

  const [picked, setPicked] = useState<number | null>(null);
  const [draft, setDraft] = useState("");
  const [error, setError] = useState<string | null>(null);

  // The same key the terminal's own chooser uses, so opening this page fetches
  // the list once however many components want it.
  const subscriptions = useQuery({
    queryKey: ["subscriptions"],
    queryFn: () => terminalApi.subscriptions(),
    retry: false,
  });

  const account = sshKeyAccount({
    isAdmin,
    loading: subscriptions.isPending,
    // The server's own sentence where there is one: whatever stopped the list
    // arriving is what the operator has to act on.
    error:
      subscriptions.error instanceof ApiError
        ? subscriptions.error.message
        : subscriptions.error
          ? t("sshKeys.accountsFailed")
          : null,
    subscriptions: subscriptions.data?.subscriptions ?? [],
    picked,
  });
  const request = keysRequest(account);

  const keys = useQuery({
    // Whose keys is part of what is cached: without the id in the key, picking
    // a second account would show the first one's list until a refetch landed.
    queryKey: ["ssh-keys", request.subscriptionId ?? "own"],
    queryFn: () => terminalApi.sshKeys(request.subscriptionId),
    enabled: request.enabled,
    retry: false,
  });

  const add = useMutation({
    mutationFn: (key: string) => terminalApi.addSshKey(key, request.subscriptionId),
    onSuccess: () => {
      setDraft("");
      setError(null);
      void queryClient.invalidateQueries({ queryKey: ["ssh-keys"] });
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : t("sshKeys.addFailed")),
  });

  const remove = useMutation({
    mutationFn: (fingerprint: string) =>
      terminalApi.removeSshKey(fingerprint, request.subscriptionId),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["ssh-keys"] }),
  });

  // Three different "no list for you" answers, and they mean different things:
  //
  // * 403 — the plan has no `can_ssh`. A statement about the plan, not an
  //   error to shout about.
  // * 400 — the account named was not one the agent would accept. The server's
  //   own wording says why.
  // * anything else — show what the server said rather than an empty list,
  //   because an empty list here reads as "this account has no keys" and that
  //   would be a lie.
  const problem = keys.error instanceof ApiError ? keys.error : null;
  const problemText =
    problem === null
      ? null
      : problem.slug === "permission_denied" || problem.slug === "plan_feature_disabled"
        ? t("sshKeys.notOnPlan")
        : problem.message;

  // What goes under the chooser, in the order the questions have to be
  // answered: is there an account at all, is one chosen, did the list come
  // back, and only then the keys themselves. The states that have already said
  // their piece in the chooser add nothing here.
  const chooserSaidItAll = account.kind === "none" || account.kind === "failed";
  const nothingChosenYet = account.kind === "list" && account.chosen === null;

  const body = chooserSaidItAll ? null : nothingChosenYet ? (
    <EmptyState
      icon={<KeyRound />}
      title={t("sshKeys.chooseAccountFirst")}
      hint={t("sshKeys.chooseAccountHint")}
    />
  ) : problemText !== null ? (
    <EmptyState icon={<ShieldAlert />} title={problemText} />
  ) : account.kind === "loading" || keys.isPending ? (
    <KeysSkeleton />
  ) : (
    <>
      {keys.data?.has_unmanaged_keys ? (
        <Callout tone="warning">{t("sshKeys.unmanaged")}</Callout>
      ) : null}

      {(keys.data?.keys.length ?? 0) === 0 ? (
        <EmptyState icon={<KeyRound />} title={t("sshKeys.empty")} hint={t("sshKeys.emptyHint")} />
      ) : (
        <ul className="divide-y divide-border">
          {(keys.data?.keys ?? []).map((key, index) => (
            <KeyRow
              key={key.fingerprint}
              entry={key}
              index={index}
              onRemove={() => remove.mutate(key.fingerprint)}
              busy={remove.isPending}
              removing={remove.isPending && remove.variables === key.fingerprint}
            />
          ))}
        </ul>
      )}

      <form
        className="space-y-2"
        onSubmit={(event) => {
          event.preventDefault();
          if (draft.trim()) add.mutate(draft.trim());
        }}
      >
        <Field label={t("sshKeys.add")} htmlFor="ssh-key" error={error ?? undefined}>
          <Input
            id="ssh-key"
            className="font-mono text-xs"
            placeholder={t("sshKeys.placeholder")}
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
            aria-invalid={error !== null}
          />
        </Field>
        <Button type="submit" variant="secondary" loading={add.isPending} disabled={!draft.trim()}>
          {t("sshKeys.add")}
        </Button>
        <p className="text-xs text-ink-subtle">{t("sshKeys.hint")}</p>
      </form>
    </>
  );

  return (
    <Card>
      <CardHeader title={t("sshKeys.title")} />
      <CardBody className="space-y-4">
        <AccountChooser
          account={account}
          onPick={(id) => {
            setPicked(id);
            // The message belonged to the account that was on screen when it
            // was written; carrying it across would attach one account's
            // refusal to another's list.
            setError(null);
          }}
        />

        {/* Said where the choices are, because "whose keys" is exactly the
            question this answers: root is not on that list, and this is the
            operator's one chance to learn that before they go looking. */}
        {isAdmin ? <p className="text-xs text-ink-subtle">{t("sshKeys.rootUnmanaged")}</p> : null}

        {body}
      </CardBody>
    </Card>
  );
}

/** Two ghost rows and an input, in the shape the list will take. */
function KeysSkeleton() {
  return (
    <div className="space-y-3" role="status" aria-live="polite">
      {[0, 1].map((i) => (
        <div
          key={i}
          className="flex animate-rise-in items-center gap-3 py-1 stagger"
          style={staggerStyle(i)}
        >
          <div className="min-w-0 flex-1 space-y-1.5">
            <Skeleton className="h-3 w-3/5" />
            <Skeleton className="h-3 w-2/5" />
          </div>
          <Skeleton className="h-5 w-20 rounded-full" />
        </div>
      ))}
      <Skeleton className="h-9 w-full rounded-lg" />
    </div>
  );
}

/**
 * Whose keys the card is showing, and how it knows.
 *
 * The states that say nothing render nothing: with one account there is a
 * sentence rather than a list of one, and with a caller the agent can resolve
 * for itself there is no question to ask.
 */
function AccountChooser({
  account,
  onPick,
}: {
  account: KeyAccount;
  onPick: (id: number | null) => void;
}) {
  const { t } = useTranslation();

  if (account.kind === "loading") {
    return (
      <div role="status" aria-live="polite" className="space-y-1.5">
        <Skeleton className="h-4 w-24" />
        <Skeleton className="h-9 w-full rounded-lg" />
      </div>
    );
  }

  if (account.kind === "failed") {
    return <Callout tone="danger">{account.message}</Callout>;
  }

  if (account.kind === "none") {
    // Not an empty picker with a refusal waiting behind it: there is no Linux
    // account here to hold a key yet, and the place accounts are made is one
    // click away.
    return (
      <Callout
        tone="info"
        title={t("sshKeys.noAccounts")}
        action={
          <Link to="/sites" className="font-medium text-accent transition-colors hover:underline">
            {t("sshKeys.noAccountsLink")}
          </Link>
        }
      >
        {t("sshKeys.noAccountsHint")}
      </Callout>
    );
  }

  // Nothing to ask: the agent resolves this caller's own account, and the list
  // that would have named it is not available.
  if (account.kind === "own") return null;

  const sole = account.options.length === 1 ? account.options[0] : undefined;
  if (sole !== undefined) {
    // Chosen, and said out loud. Making somebody pick from a list of one is a
    // click that carries no decision — but installing a key on an account the
    // card never named would be worse.
    return (
      <p className="text-sm text-ink-muted">
        {t("sshKeys.accountOnly", { account: subscriptionLabel(sole) })}
      </p>
    );
  }

  return (
    <Field label={t("sshKeys.whichAccount")} htmlFor="ssh-keys-account">
      <Select
        id="ssh-keys-account"
        // Off the resolved account rather than the raw pick: an id whose row
        // has gone would otherwise leave a value selected that is not in the
        // list, and the card would name an account it is not showing.
        value={account.chosen === null ? "" : String(account.chosen.id)}
        onChange={(event) => onPick(event.target.value === "" ? null : Number(event.target.value))}
      >
        {/* No pre-selected first row: whose login a key is added to is not a
            thing to decide for an operator by list order. */}
        <option value="">{t("sshKeys.chooseAccount")}</option>
        {account.options.map((option) => (
          <option key={option.id} value={option.id}>
            {option.status === "active"
              ? subscriptionLabel(option)
              : t("terminal.subscriptionSuspended", { account: subscriptionLabel(option) })}
          </option>
        ))}
      </Select>
    </Field>
  );
}

function KeyRow({
  entry,
  index,
  onRemove,
  busy,
  removing,
}: {
  entry: SshKey;
  /** Position in the list, for the staggered entrance. */
  index: number;
  onRemove: () => void;
  /** Any removal is in flight — every row's button is refused meanwhile. */
  busy: boolean;
  /** *This* row is the one being removed, so only it spins. */
  removing: boolean;
}) {
  const { t } = useTranslation();
  return (
    <li
      // The negative margin lets the hover tint reach past the text without
      // pulling the dividers in with it.
      className="-mx-2 flex animate-rise-in flex-wrap items-center gap-x-3 gap-y-1 rounded-lg px-2 py-2 transition-colors duration-150 stagger hover:bg-surface-muted/60"
      style={staggerStyle(index)}
    >
      <span className="min-w-0 flex-1">
        <span className="block truncate font-mono text-xs text-ink">{entry.fingerprint}</span>
        <span className="block truncate text-xs text-ink-muted">
          {entry.comment ?? t("sshKeys.noComment")}
        </span>
      </span>
      <Badge tone="neutral" className="tnum">
        {entry.bits ? `${entry.algorithm} · ${entry.bits}` : entry.algorithm}
      </Badge>
      <Button
        variant="ghost"
        size="icon-sm"
        onClick={onRemove}
        loading={removing}
        disabled={busy}
        aria-label={t("sshKeys.remove")}
      >
        <Trash2 className="h-4 w-4" />
      </Button>
    </li>
  );
}
