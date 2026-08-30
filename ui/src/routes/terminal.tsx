import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Plug, PowerOff, ShieldAlert, TerminalSquare, Trash2 } from "lucide-react";
import { Suspense, lazy, useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import type { XtermHandle } from "@/components/terminal/xterm-view";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody } from "@/components/ui/card";
import { Field, Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";
import { ApiError } from "@/lib/api";
import { useSession } from "@/lib/session";
import {
  decodeBytes,
  encodeText,
  terminalApi,
  websocketUrl,
  type ServerMessage,
  type SshKey,
  type TerminalTargetKind,
} from "@/lib/terminal-api";

// The 350 KB initial-bundle budget (spec §3) is why this is a `lazy` import:
// xterm.js and its stylesheet load as their own chunk the first time somebody
// opens a terminal, never on the route itself.
const XtermView = lazy(() => import("@/components/terminal/xterm-view"));

/**
 * The web terminal (spec §11.16).
 *
 * The panel's most dangerous screen, and the UI says so out loud before a root
 * shell opens — an operator who has forgotten which server this tab is pointing
 * at is exactly who the warning is for.
 *
 * The session id is kept in `sessionStorage`, which is what makes reconnecting
 * work: the shell lives in `unihelm-agentd`, so a reload, a dropped Wi-Fi
 * connection or a panel restart all leave it running, and the page reattaches
 * to the same one instead of starting a second.
 */
type Phase =
  | { kind: "idle" }
  | { kind: "connecting" }
  | { kind: "open"; account: string }
  | { kind: "closed"; reason: string | null }
  | { kind: "denied"; reason: string };

const SESSION_KEY = "unihelm.terminal.session";

function rememberedSession(): string | null {
  try {
    return window.sessionStorage.getItem(SESSION_KEY);
  } catch {
    // Private mode, or storage disabled. A terminal that cannot remember its
    // session still works; it just cannot reattach.
    return null;
  }
}

function rememberSession(id: string | null) {
  try {
    if (id === null) window.sessionStorage.removeItem(SESSION_KEY);
    else window.sessionStorage.setItem(SESSION_KEY, id);
  } catch {
    /* see above */
  }
}

export function TerminalPage() {
  const { t } = useTranslation();
  const { user } = useSession();
  const isAdmin = user?.role === "admin";

  const [phase, setPhase] = useState<Phase>({ kind: "idle" });
  const [target, setTarget] = useState<TerminalTargetKind>(isAdmin ? "root" : "tenant");
  const [confirmedRoot, setConfirmedRoot] = useState(false);

  const socket = useRef<WebSocket | null>(null);
  const term = useRef<XtermHandle>(null);
  const sessionId = useRef<string | null>(rememberedSession());
  // Rendered only once a connection has been asked for, so the xterm chunk is
  // not fetched by merely visiting the page.
  const [mounted, setMounted] = useState(false);

  const send = useCallback((message: unknown) => {
    if (socket.current?.readyState === WebSocket.OPEN) {
      socket.current.send(JSON.stringify(message));
    }
  }, []);

  const connect = useCallback(
    async (options: { reattach: boolean }) => {
      setPhase({ kind: "connecting" });
      setMounted(true);
      const size = term.current?.size() ?? { cols: 80, rows: 24 };
      try {
        const opened = await terminalApi.openSession(
          options.reattach && sessionId.current
            ? { session_id: sessionId.current }
            : { target, cols: size.cols, rows: size.rows },
        );
        sessionId.current = opened.session_id;
        rememberSession(opened.session_id);

        const ws = new WebSocket(websocketUrl(opened.websocket_url));
        socket.current = ws;

        ws.onmessage = (event) => {
          const message = JSON.parse(event.data as string) as ServerMessage;
          if (message.type === "output") {
            term.current?.write(decodeBytes(message.data));
            return;
          }
          switch (message.status) {
            case "open": {
              setPhase({ kind: "open", account: message.user ?? "" });
              // The shell was started with whatever size we could measure
              // before xterm existed. Now that it does, tell the PTY the truth
              // — otherwise the first `vim` lays itself out for 80x24.
              const size = term.current?.size();
              if (size) ws.send(JSON.stringify({ type: "resize", ...size }));
              term.current?.focus();
              break;
            }
            case "denied":
              setPhase({ kind: "denied", reason: message.detail ?? t("terminal.deniedGeneric") });
              rememberSession(null);
              sessionId.current = null;
              break;
            case "closed":
              setPhase({ kind: "closed", reason: message.detail });
              rememberSession(null);
              sessionId.current = null;
              break;
            case "lagged":
              term.current?.notice(t("terminal.lagged"));
              break;
          }
        };

        // A socket that ends is not a shell that ended: the agent still holds
        // the PTY, so this is a reconnect prompt rather than a closure.
        ws.onclose = () => {
          socket.current = null;
          setPhase((current) =>
            current.kind === "open" ? { kind: "closed", reason: null } : current,
          );
        };
        ws.onerror = () => {
          setPhase({ kind: "closed", reason: t("terminal.socketError") });
        };
      } catch (error) {
        const reason =
          error instanceof ApiError ? error.message : t("terminal.deniedGeneric");
        setPhase({ kind: "denied", reason });
      }
    },
    [target, t],
  );

  // Leaving the page drops the socket and nothing else — the shell keeps
  // running and the id in sessionStorage is how we find it again.
  useEffect(() => () => socket.current?.close(), []);

  const onData = useCallback((data: string) => send({ type: "input", data: encodeText(data) }), [send]);
  const onResize = useCallback(
    (cols: number, rows: number) => send({ type: "resize", cols, rows }),
    [send],
  );

  const endSession = useCallback(() => {
    send({ type: "close" });
    socket.current?.close();
    rememberSession(null);
    sessionId.current = null;
    setPhase({ kind: "closed", reason: t("terminal.endedByYou") });
  }, [send, t]);

  const rootBlocked = target === "root" && !confirmedRoot;

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-ink">{t("terminal.title")}</h1>
          <p className="mt-1 max-w-2xl text-sm text-ink-muted">{t("terminal.subtitle")}</p>
        </div>
        <div className="flex items-center gap-2">
          {phase.kind === "open" ? (
            <>
              <Badge tone={phase.account === "root" ? "danger" : "success"} dot>
                {t("terminal.connectedAs", { account: phase.account })}
              </Badge>
              <Button variant="ghost" onClick={endSession}>
                <PowerOff className="h-4 w-4" />
                {t("terminal.end")}
              </Button>
            </>
          ) : null}
        </div>
      </header>

      {phase.kind === "idle" || phase.kind === "closed" || phase.kind === "denied" ? (
        <StartPanel
          isAdmin={isAdmin}
          target={target}
          onTarget={(next) => {
            setTarget(next);
            setConfirmedRoot(false);
          }}
          confirmedRoot={confirmedRoot}
          onConfirmRoot={setConfirmedRoot}
          blocked={rootBlocked}
          phase={phase}
          canReattach={sessionId.current !== null}
          onConnect={connect}
        />
      ) : null}

      {mounted ? (
        <Card>
          <CardBody className="p-0">
            <div className="h-[28rem] overflow-hidden rounded-xl">
              <Suspense
                fallback={
                  <div className="flex h-full items-center justify-center text-ink-muted">
                    <Spinner className="h-6 w-6" />
                  </div>
                }
              >
                <XtermView
                  handleRef={term}
                  onData={onData}
                  onResize={onResize}
                  dark={document.documentElement.classList.contains("dark")}
                />
              </Suspense>
            </div>
          </CardBody>
        </Card>
      ) : null}

      <SshKeysCard />
    </div>
  );
}

function StartPanel({
  isAdmin,
  target,
  onTarget,
  confirmedRoot,
  onConfirmRoot,
  blocked,
  phase,
  canReattach,
  onConnect,
}: {
  isAdmin: boolean;
  target: TerminalTargetKind;
  onTarget: (next: TerminalTargetKind) => void;
  confirmedRoot: boolean;
  onConfirmRoot: (value: boolean) => void;
  blocked: boolean;
  phase: Phase;
  canReattach: boolean;
  onConnect: (options: { reattach: boolean }) => void;
}) {
  const { t } = useTranslation();

  return (
    <Card>
      <CardBody className="space-y-4">
        {phase.kind === "denied" ? (
          <p className="flex items-start gap-2 rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
            <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
            <span>{phase.reason}</span>
          </p>
        ) : null}
        {phase.kind === "closed" ? (
          <p className="rounded-lg bg-surface-muted px-3 py-2 text-sm text-ink-muted">
            {phase.reason ?? t("terminal.disconnected")}
          </p>
        ) : null}

        {isAdmin ? (
          <fieldset className="space-y-2">
            <legend className="text-sm font-medium text-ink">{t("terminal.runAs")}</legend>
            <div className="flex flex-wrap gap-2">
              {(["root", "tenant"] as const).map((option) => (
                <Button
                  key={option}
                  variant={target === option ? "primary" : "secondary"}
                  onClick={() => onTarget(option)}
                  aria-pressed={target === option}
                >
                  {t(`terminal.target.${option}`)}
                </Button>
              ))}
            </div>
          </fieldset>
        ) : (
          <p className="text-sm text-ink-muted">{t("terminal.tenantOnly")}</p>
        )}

        {target === "root" ? (
          <label className="flex items-start gap-2.5 rounded-lg border border-danger/40 bg-danger-soft px-3 py-2.5 text-sm text-ink">
            <input
              type="checkbox"
              className="mt-0.5 h-4 w-4 accent-[var(--color-danger)]"
              checked={confirmedRoot}
              onChange={(event) => onConfirmRoot(event.target.checked)}
            />
            <span>{t("terminal.rootWarning")}</span>
          </label>
        ) : null}

        <div className="flex flex-wrap gap-2">
          <Button
            variant="primary"
            disabled={blocked || phase.kind === "connecting"}
            onClick={() => onConnect({ reattach: false })}
          >
            <TerminalSquare className="h-4 w-4" />
            {t("terminal.start")}
          </Button>
          {canReattach ? (
            <Button variant="secondary" onClick={() => onConnect({ reattach: true })}>
              <Plug className="h-4 w-4" />
              {t("terminal.reattach")}
            </Button>
          ) : null}
        </div>
        <p className="text-xs text-ink-subtle">{t("terminal.idleNote")}</p>
      </CardBody>
    </Card>
  );
}

/** The per-account `authorized_keys` manager (spec §11.16). */
function SshKeysCard() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [draft, setDraft] = useState("");
  const [error, setError] = useState<string | null>(null);

  const keys = useQuery({
    queryKey: ["ssh-keys"],
    queryFn: () => terminalApi.sshKeys(),
    retry: false,
  });

  const add = useMutation({
    mutationFn: (key: string) => terminalApi.addSshKey(key),
    onSuccess: () => {
      setDraft("");
      setError(null);
      void queryClient.invalidateQueries({ queryKey: ["ssh-keys"] });
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : t("sshKeys.addFailed")),
  });

  const remove = useMutation({
    mutationFn: (fingerprint: string) => terminalApi.removeSshKey(fingerprint),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["ssh-keys"] }),
  });

  // Three different "no list for you" answers, and they mean different things:
  //
  // * 403 — the plan has no `can_ssh`. A statement about the plan, not an
  //   error to shout about.
  // * 400 — an administrator asked for "my keys" when their scope is the whole
  //   server, so there is no "my". The server's own wording says so.
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

  return (
    <Card>
      <CardBody className="space-y-4">
        <div className="flex items-center gap-2">
          <KeyRound className="h-4 w-4 text-ink-muted" aria-hidden />
          <h2 className="text-sm font-semibold text-ink">{t("sshKeys.title")}</h2>
        </div>

        {problemText !== null ? (
          <p className="text-sm text-ink-muted">{problemText}</p>
        ) : keys.isPending ? (
          <div className="flex justify-center py-6 text-ink-muted">
            <Spinner className="h-5 w-5" />
          </div>
        ) : (
          <>
            {keys.data?.has_unmanaged_keys ? (
              <p className="rounded-lg bg-warning-soft px-3 py-2 text-xs text-warning">
                {t("sshKeys.unmanaged")}
              </p>
            ) : null}

            {(keys.data?.keys.length ?? 0) === 0 ? (
              <p className="text-sm text-ink-muted">{t("sshKeys.empty")}</p>
            ) : (
              <ul className="divide-y divide-border">
                {keys.data!.keys.map((key) => (
                  <KeyRow
                    key={key.fingerprint}
                    entry={key}
                    onRemove={() => remove.mutate(key.fingerprint)}
                    busy={remove.isPending}
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
                  // A key is machine text: LTR even when the panel is mirrored.
                  dir="ltr"
                  className="font-mono text-xs"
                  placeholder={t("sshKeys.placeholder")}
                  value={draft}
                  onChange={(event) => setDraft(event.target.value)}
                  aria-invalid={error !== null}
                />
              </Field>
              <Button type="submit" variant="secondary" disabled={add.isPending || !draft.trim()}>
                {add.isPending ? t("sshKeys.adding") : t("sshKeys.add")}
              </Button>
              <p className="text-xs text-ink-subtle">{t("sshKeys.hint")}</p>
            </form>
          </>
        )}
      </CardBody>
    </Card>
  );
}

function KeyRow({
  entry,
  onRemove,
  busy,
}: {
  entry: SshKey;
  onRemove: () => void;
  busy: boolean;
}) {
  const { t } = useTranslation();
  return (
    <li className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2.5">
      <span className="min-w-0 flex-1">
        <span dir="ltr" className="block truncate font-mono text-xs text-ink">
          {entry.fingerprint}
        </span>
        <span className="block truncate text-xs text-ink-muted">
          {entry.comment ?? t("sshKeys.noComment")}
        </span>
      </span>
      <Badge tone="neutral">
        {entry.bits ? `${entry.algorithm} · ${entry.bits}` : entry.algorithm}
      </Badge>
      <Button
        variant="ghost"
        size="icon"
        onClick={onRemove}
        disabled={busy}
        aria-label={t("sshKeys.remove")}
      >
        <Trash2 className="h-4 w-4" />
      </Button>
    </li>
  );
}
