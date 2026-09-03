/**
 * The API client.
 *
 * The UI is just another client of the public REST API (spec §13), so this file
 * is thin on purpose: attach the CSRF token, parse the error taxonomy, and get
 * out of the way.
 */

export interface ApiErrorBody {
  code: string;
  slug: string;
  message: string;
  field?: string;
  request_id?: string;
}

/** An error carrying the panel's stable `UNI-xxxx` code, so callers can branch. */
export class ApiError extends Error {
  readonly code: string;
  readonly slug: string;
  readonly field?: string;
  readonly status: number;
  readonly requestId?: string;

  constructor(status: number, body: ApiErrorBody) {
    super(body.message);
    this.name = "ApiError";
    this.status = status;
    this.code = body.code;
    this.slug = body.slug;
    this.field = body.field;
    this.requestId = body.request_id;
  }

  /** True when the session is gone and the UI should return to the login screen. */
  get isUnauthenticated(): boolean {
    return this.slug === "session_invalid" || this.slug === "session_expired";
  }
}

let csrfToken: string | null = null;

export function setCsrfToken(token: string | null) {
  csrfToken = token;
}

export function getCsrfToken(): string | null {
  return csrfToken;
}

// What to do when the server stops recognising this session.
//
// Sessions expire, and the panel can be restarted out from under an open tab.
// Without this every request simply threw a 401 that each screen rendered as its
// own error, leaving the operator on a dashboard where nothing loads and no
// screen ever says the word "login" — the tab looked broken rather than logged
// out. SessionProvider registers a handler that clears the user, which sends the
// router back to the login route.
let onUnauthorized: (() => void) | null = null;

export function setUnauthorizedHandler(handler: (() => void) | null) {
  onUnauthorized = handler;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  const method = (init.method ?? "GET").toUpperCase();

  if (init.body !== undefined) headers.set("content-type", "application/json");
  if (!["GET", "HEAD", "OPTIONS"].includes(method) && csrfToken) {
    headers.set("x-unihelm-csrf", csrfToken);
  }

  const response = await fetch(path, {
    ...init,
    headers,
    // The session is an HttpOnly cookie; JavaScript never sees it.
    credentials: "same-origin",
  });

  if (!response.ok) {
    let body: ApiErrorBody;
    try {
      body = (await response.json()) as ApiErrorBody;
    } catch {
      body = {
        code: `HTTP-${response.status}`,
        slug: "unexpected_response",
        message: response.statusText || "Request failed",
      };
    }
    // The login request answers 401 for a wrong password; that is a failed
    // attempt, not an expired session, and must not bounce the form.
    if (response.status === 401 && !path.endsWith("/auth/login")) {
      onUnauthorized?.();
    }
    throw new ApiError(response.status, body);
  }

  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "POST", body: body === undefined ? undefined : JSON.stringify(body) }),
  patch: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "PATCH", body: body === undefined ? undefined : JSON.stringify(body) }),
  put: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "PUT", body: body === undefined ? undefined : JSON.stringify(body) }),
  del: <T>(path: string) => request<T>(path, { method: "DELETE" }),
};

// ---------------------------------------------------------------------------
// Response shapes
// ---------------------------------------------------------------------------

export interface User {
  id: number;
  username: string;
  email: string;
  role: "admin" | "reseller" | "customer";
  full_name: string | null;
  locale: string;
  permissions: string[];
  is_impersonated: boolean;
}

export interface SessionResponse {
  user: User;
  csrf_token: string;
}

export interface DiskUsage {
  mount: string;
  filesystem: string;
  total_bytes: number;
  used_bytes: number;
  available_bytes: number;
}

export interface Metrics {
  at: string;
  uptime_seconds: number;
  load: { one: number; five: number; fifteen: number };
  cpu: { cores: number; usage_pct: number };
  memory: {
    total_bytes: number;
    used_bytes: number;
    available_bytes: number;
    swap_total_bytes: number;
    swap_used_bytes: number;
  };
  disks: DiskUsage[];
  network: { rx_bytes: number; tx_bytes: number; rx_bytes_per_sec: number; tx_bytes_per_sec: number };
  panel: {
    web_rss_bytes: number | null;
    agent_rss_bytes: number | null;
    total_rss_bytes: number | null;
  };
}

export interface SystemInfo {
  agent_version: string;
  distro: string;
  family: string;
  arch: string;
  package_backend: string;
  firewall_backend: string;
  security_module: string;
}

export interface Overview {
  agent_online: boolean;
  panel_version: string;
  panel_uptime_seconds: number;
  metrics?: Metrics;
  system?: SystemInfo;
  agent_error?: string;
}

export type UnitState =
  | "active"
  | "inactive"
  | "failed"
  | "activating"
  | "deactivating"
  | "not_found"
  | "unknown";

export interface ServiceStatus {
  display_name: string;
  unit: string;
  state: UnitState;
  sub_state: string;
  enabled: string | null;
  main_pid: number | null;
  memory_bytes: number | null;
  since: string | null;
}

export interface ServicesResponse {
  services: ServiceStatus[];
  agent_error?: string;
}

export type TaskStatus = "queued" | "running" | "ok" | "failed" | "cancelled";

export interface Task {
  id: string;
  op: string;
  status: TaskStatus;
  progress: number;
  error_code: string | null;
  error_detail: string | null;
  cancellable: boolean;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface TaskListResponse {
  tasks: Task[];
  active: number;
  /** Op names present in this account's history — the filter's own options. */
  ops: string[];
}

/**
 * What the task history page is asking for (spec §11.17).
 *
 * Every field is optional and they combine with AND, which is how a row of
 * filter controls reads. Empty strings are dropped rather than sent, so
 * clearing a control means "no filter" and not "match the empty string".
 */
export interface TaskQuery {
  op?: string;
  status?: TaskStatus | "";
  /** RFC 3339, inclusive. */
  since?: string;
  until?: string;
  limit?: number;
  offset?: number;
}

export function taskQueryString(query: TaskQuery = {}): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === "") continue;
    params.set(key, String(value));
  }
  const encoded = params.toString();
  return encoded ? `?${encoded}` : "";
}

export interface TaskLogLine {
  seq: number;
  at: string;
  line: string;
}

// --- stack ------------------------------------------------------------------

export type ComponentState =
  | "absent"
  | "installing"
  | "installed"
  | "failed"
  | "removing";

export interface StackComponentView {
  slug: string;
  display_name: string;
  status: ComponentState;
  installed_version: string | null;
  last_error: string | null;
  unit_state: string;
  unit_active: boolean;
}

export interface StackResponse {
  components: StackComponentView[];
  unverified_pins: string[];
}

// --- sites ------------------------------------------------------------------

export type SiteKind = "php" | "static" | "proxy" | "redirect";
export type SiteState = "provisioning" | "active" | "suspended" | "failed";

export interface SiteView {
  id: number;
  /**
   * Which subscription owns the site. The server has always sent it (the row
   * is flattened into the view); the plans page is the first screen that needs
   * it, because there is no endpoint that lists subscriptions on their own.
   */
  subscription_id: number;
  domain: string;
  site_type: SiteKind;
  php_version: string | null;
  root_dir: string;
  status: SiteState;
  force_https: boolean;
  http3: boolean;
  maintenance_mode: boolean;
  client_max_body_size: string;
  custom_nginx_snippet: string | null;
  php_ini_overrides: string | null;
  rate_limit_enabled: boolean;
  aliases: string[];
  linux_user: string;
  has_certificate: boolean;
  certificate_expires_in_days?: number;
}

export interface SitesResponse {
  sites: SiteView[];
}

export interface DriftResponse {
  path: string;
  state: string;
  diff: { line: number; kind: "same" | "added" | "removed"; text: string }[];
}

/** A long-running operation's receipt. */
export interface TaskAccepted {
  task_id: string;
  task_url: string;
}

export interface CreateSiteRequest {
  domain: string;
  site_type: SiteKind;
  php_version?: string;
  with_www?: boolean;
  proxy_port?: number;
  redirect_target?: string;
}

export interface UpdateSiteRequest {
  php_version?: string;
  force_https?: boolean;
  http3?: boolean;
  maintenance_mode?: boolean;
  client_max_body_size?: string;
  custom_nginx_snippet?: string | null;
  php_ini_overrides?: string | null;
  rate_limit_enabled?: boolean;
}

// --- node apps ---------------------------------------------------------------

export type NodeEnv = "production" | "development" | "test";

/**
 * One row of `GET /api/apps`.
 *
 * The stored row and systemd's view of the unit arrive flattened together: the
 * row says what the panel intended, `state` says what is actually running, and
 * an app that crash-looped overnight is exactly where the two differ.
 */
export interface AppView {
  id: number;
  subscription_id: number;
  site_id: number | null;
  name: string;
  entry: string;
  port: number;
  node_env: NodeEnv;
  enabled: boolean;
  created_at: string;
  updated_at: string;
  unit: string;
  state: UnitState;
  memory_bytes?: number;
}

export interface AppsResponse {
  apps: AppView[];
}

export interface AppEnvVar {
  key: string;
  value: string;
}

export interface CreateAppRequest {
  name: string;
  entry: string;
  env?: AppEnvVar[];
  node_env?: NodeEnv;
  memory_mb?: number;
  proxy_domain?: string;
}

export interface AppLogsResponse {
  unit: string;
  lines: string[];
}

/** What the logs modal asks for. The agent clamps anything above 2000. */
export const DEFAULT_LOG_LINES = 200;

// --- cron -------------------------------------------------------------------

/**
 * One row of `GET /api/cron`.
 *
 * `last_error` is the field the page is built around: a job whose crontab could
 * not be installed still has a row, still reads `enabled`, and is *not running*.
 * Nothing else in the response says so.
 */
export interface CronJob {
  id: number;
  subscription_id: number;
  schedule: string;
  command: string;
  enabled: boolean;
  last_error: string | null;
}

// --- firewall + Sentinel (spec §11.9) ---------------------------------------

/**
 * Which backend owns the ruleset. `none` is not a failure — it is a host with
 * no firewall installed, and the page has to say so out loud rather than draw
 * an empty rule table that reads as "nothing is open".
 */
export type FirewallBackend = "firewalld" | "ufw" | "nftables" | "none";

/**
 * Where the panel's record and the live ruleset disagree.
 *
 * `missing_from_backend` — the panel promised this hole and the firewall has
 * never heard of it (somebody flushed the ruleset).
 * `unrecorded` — the firewall enforces a Unihelm-marked rule the panel has no
 * row for (a restored database, or an older build).
 */
export type RuleDrift = "missing_from_backend" | "unrecorded";

export interface FirewallRule {
  port: number;
  proto: "tcp" | "udp";
  /** `null` means "from anywhere". */
  source: string | null;
  comment: string;
  in_panel: boolean;
  in_backend: boolean;
  drift: RuleDrift | null;
}

export interface FirewallResponse {
  backend: FirewallBackend;
  /** A backend that is installed but stopped enforces nothing. */
  active: boolean;
  rules: FirewallRule[];
  /**
   * The address this request arrived from, as the web layer saw it.
   *
   * A browser cannot see past its own NAT, so this is the only way the ban form
   * can refuse "my own address" before the round trip. Optional on purpose: if
   * the server does not report it, the agent still refuses the ban and the form
   * simply cannot explain it in advance.
   */
  your_ip?: string | null;
}

export interface PortRuleRequest {
  port: number;
  proto: "tcp" | "udp";
  /** A literal address or CIDR, never a hostname. */
  source?: string;
  comment?: string;
}

/**
 * What an open/close answers with: the rule as the backend accepted it, plus
 * which backend did the work — not a `FirewallRule`, because drift is a
 * property of the merged view and not of a write that just succeeded.
 */
export interface PortRuleResult {
  port: number;
  proto: string;
  source: string | null;
  comment: string;
  backend: FirewallBackend;
}

export interface BanRecord {
  id: number;
  ip: string;
  reason: string;
  banned_at: string;
  /** `null` is a permanent ban — only ever an operator's deliberate choice. */
  expires_at: string | null;
  lifted_at: string | null;
  /** The backend is holding this address right now. */
  in_backend: boolean;
}

export interface BansResponse {
  backend: FirewallBackend;
  bans: BanRecord[];
  /** Addresses the firewall drops that the panel has no open record for. */
  unrecorded: string[];
}

export interface BanRequest {
  ip: string;
  /** Absent = the configured default; `0` = permanent. */
  minutes?: number;
  reason?: string;
}

export interface BanResult {
  ip: string;
  expires_at: string | null;
  backend: FirewallBackend;
}

export interface UnbanResult {
  ip: string;
  /**
   * How many open records this closed. Zero means the panel never banned the
   * address — reported rather than papered over, because "unbanned!" for an
   * address still blocked by an operator's own rule is a lie.
   */
  lifted: number;
  backend: FirewallBackend;
}

export interface SentinelSettings {
  enabled: boolean;
  ssh_threshold: number;
  window_minutes: number;
  ban_minutes: number;
  allowlist: string[];
}

// --- alerting (spec §11.11) --------------------------------------------------

export type AlertKind = "disk_pct" | "mem_pct" | "load" | "service_down" | "cert_expiry_days";

export interface AlertRule {
  id: number;
  kind: AlertKind;
  /** `null` = every subject of this kind. */
  target: string | null;
  threshold: number;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface CronListResponse {
  jobs: CronJob[];
  max_jobs_per_subscription: number;
}

export interface CronSetRequest {
  schedule: string;
  command: string;
  /** Create only: an update takes the job's existing subscription. */
  subscription_id?: number;
  enabled?: boolean;
}

export interface CronSetResponse {
  job: CronJob;
  /** How many jobs the crontab that was just installed actually schedules. */
  scheduled: number;
  linux_user: string;
}

// --- backups ----------------------------------------------------------------

export type BackupRepoKind = "local" | "s3";
export type BackupScopeKind = "panel" | "subscription";
export type BackupRunStatus = "running" | "ok" | "failed";

/**
 * A repository as the API returns it.
 *
 * Note what is missing: there is no password field and no credentials field,
 * because `unihelm_db::BackupRepo` has none. The password exists in exactly one
 * response, `RepoInitResponse`, and exactly once.
 */
export interface BackupRepo {
  id: number;
  kind: BackupRepoKind;
  label: string;
  path_or_url: string;
  has_credentials: boolean;
}

/**
 * One span during which a rule's condition held.
 *
 * An event is a span, not a notification: `raised_at` with a null `resolved_at`
 * is happening now, and the pair together is what makes "the disk was full for
 * forty minutes last night" readable.
 */
export interface AlertEvent {
  id: number;
  rule_id: number;
  subject: string;
  message: string;
  value: number | null;
  raised_at: string;
  resolved_at: string | null;
  notified: number;
}

export interface AlertRulesResponse {
  rules: AlertRule[];
  open: AlertEvent[];
  kinds: AlertKind[];
}

export interface AlertEventsResponse {
  events: AlertEvent[];
}

export interface AlertRuleRequest {
  kind: AlertKind;
  target?: string | null;
  threshold?: number;
  enabled: boolean;
}

export type ChannelKind = "webhook" | "telegram";

/**
 * A notifier channel, without its configuration — ever.
 *
 * The server skips the sealed blob when it serializes, so there is no field
 * here to render. That is why the form shows "configured" instead of an empty
 * secret box: an empty box would read as data the panel had lost.
 */
export interface NotifyChannel {
  id: number;
  kind: ChannelKind;
  label: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface RepoInitRequest {
  kind: BackupRepoKind;
  label: string;
  path_or_url: string;
  s3?: { access_key_id: string; secret_access_key: string; region?: string };
}

/** The one response in the panel that carries a secret. See `backups.tsx`. */
export interface RepoInitResponse {
  repo_id: number;
  label: string;
  kind: BackupRepoKind;
  repository: string;
  password: string;
  password_notice: string;
}

export interface BackupSchedule {
  id: number;
  repo_id: number;
  scope: BackupScopeKind;
  subscription_id: number | null;
  cron: string;
  keep_daily: number;
  keep_weekly: number;
  keep_monthly: number;
  enabled: boolean;
}

export interface BackupScheduleRequest {
  repo_id: number;
  scope: BackupScopeKind;
  subscription_id?: number;
  cron: string;
  keep_daily?: number;
  keep_weekly?: number;
  keep_monthly?: number;
  enabled?: boolean;
}

export interface BackupRun {
  id: number;
  schedule_id: number | null;
  repo_id: number;
  scope: BackupScopeKind;
  subscription_id: number | null;
  started_at: string;
  finished_at: string | null;
  status: BackupRunStatus;
  snapshot_id: string | null;
  bytes: number | null;
  error: string | null;
}

export interface BackupSnapshot {
  id: string;
  short_id: string;
  time: string;
  hostname: string;
  paths: string[];
  tags: string[];
}

// --- dns --------------------------------------------------------------------

export interface DnsNameRecords {
  name: string;
  a: string[];
  aaaa: string[];
  /** Why there is nothing, when there is nothing: NXDOMAIN ≠ a timeout. */
  error: string | null;
}

export interface DnsCheckResponse {
  domain: string;
  /** The apex and its `www.` form, in that order. */
  records: DnsNameRecords[];
  server_addresses: string[];
  matches_server: boolean;
  /** Resolves into Cloudflare's anycast space: not matching is then correct. */
  proxied_hint: boolean;
  advice: string;
}

export interface DnsProviderResponse {
  id: number;
  kind: string;
  label: string;
  token_status: string;
  /** Every zone the token administers — the credential's blast radius. */
  zones: string[];
}

export interface ChannelsResponse {
  channels: NotifyChannel[];
}

export interface ChannelRequest {
  /** Absent = create. */
  id?: number;
  kind?: ChannelKind;
  label?: string;
  /** Omitted on an edit = keep the stored credential. */
  config?: Record<string, string>;
  enabled?: boolean;
}

/** A failed test answers 200 with `delivered: false` — it is an answer, not an error. */
export interface ChannelTestResult {
  delivered: boolean;
  detail: string | null;
}

export const endpoints = {
  login: (username: string, password: string) =>
    api.post<SessionResponse>("/api/auth/login", { username, password }),
  logout: () => api.post<{ ok: boolean }>("/api/auth/logout"),
  me: () => api.get<SessionResponse>("/api/auth/me"),
  overview: () => api.get<Overview>("/api/server/overview"),
  services: () => api.get<ServicesResponse>("/api/server/services"),
  tasks: (query: TaskQuery = {}) =>
    api.get<TaskListResponse>(`/api/tasks${taskQueryString(query)}`),
  taskLogs: (id: string, afterSeq = 0) =>
    api.get<{ lines: TaskLogLine[] }>(`/api/tasks/${id}/logs?after_seq=${afterSeq}`),
  cancelTask: (id: string) =>
    api.post<{ task_id: string; requested: boolean }>(`/api/tasks/${id}/cancel`),
  // A retry starts a *new* task, so the failed one keeps its logs and its
  // reason — the history is the point of this page.
  retryTask: (id: string) => api.post<TaskAccepted>(`/api/tasks/${id}/retry`),

  stack: () => api.get<StackResponse>("/api/stack"),
  installComponent: (component: { component: "nginx" } | { component: "php"; version: string }) =>
    api.post<TaskAccepted>("/api/stack/install", component),
  removeComponent: (component: { component: "nginx" } | { component: "php"; version: string }) =>
    api.post<TaskAccepted>("/api/stack/remove", component),

  sites: () => api.get<SitesResponse>("/api/sites"),
  createSite: (body: CreateSiteRequest) => api.post<TaskAccepted>("/api/sites", body),
  updateSite: (id: number, body: UpdateSiteRequest) =>
    api.patch<TaskAccepted>(`/api/sites/${id}`, body),
  deleteSite: (id: number, purgeFiles: boolean) =>
    api.del<TaskAccepted>(`/api/sites/${id}?purge_files=${purgeFiles}`),
  siteDrift: (id: number) => api.get<DriftResponse>(`/api/sites/${id}/drift`),
  issueCertificate: (id: number, staging: boolean) =>
    api.post<TaskAccepted>(`/api/sites/${id}/certificate`, { staging }),

  apps: () => api.get<AppsResponse>("/api/apps"),
  createApp: (body: CreateAppRequest) => api.post<TaskAccepted>("/api/apps", body),
  deleteApp: (id: number) => api.del<TaskAccepted>(`/api/apps/${id}`),
  restartApp: (id: number) => api.post<TaskAccepted>(`/api/apps/${id}/restart`),
  appLogs: (id: number, lines = DEFAULT_LOG_LINES) =>
    api.get<AppLogsResponse>(`/api/apps/${id}/logs?lines=${lines}`),

  cron: () => api.get<CronListResponse>("/api/cron"),
  createCronJob: (body: CronSetRequest) => api.post<CronSetResponse>("/api/cron", body),
  // PUT, not POST: the id comes from the path so a body that echoed a different
  // one cannot move the edit onto another job (see routes/cron.rs).
  updateCronJob: (id: number, body: CronSetRequest) =>
    api.put<CronSetResponse>(`/api/cron/${id}`, body),
  deleteCronJob: (id: number) =>
    api.del<{ id: number; subscription_id: number; scheduled: number }>(`/api/cron/${id}`),

  backupRepos: () => api.get<{ repos: BackupRepo[] }>("/api/backups/repos"),
  createBackupRepo: (body: RepoInitRequest) =>
    api.post<RepoInitResponse>("/api/backups/repos", body),
  deleteBackupRepo: (id: number) => api.del<{ id: number }>(`/api/backups/repos/${id}`),
  backupSnapshots: (repoId: number, subscriptionId?: number) =>
    api.get<{ repo_id: number; label: string; snapshots: BackupSnapshot[] }>(
      `/api/backups/repos/${repoId}/snapshots${
        subscriptionId === undefined ? "" : `?subscription_id=${subscriptionId}`
      }`,
    ),
  backupSchedules: () => api.get<{ schedules: BackupSchedule[] }>("/api/backups/schedules"),
  createBackupSchedule: (body: BackupScheduleRequest) =>
    api.post<{ schedule: BackupSchedule }>("/api/backups/schedules", body),
  deleteBackupSchedule: (id: number) => api.del<{ id: number }>(`/api/backups/schedules/${id}`),
  backupRuns: (limit = 50) => api.get<{ runs: BackupRun[] }>(`/api/backups/runs?limit=${limit}`),
  runBackup: (body: { repo_id: number; scope: BackupScopeKind; subscription_id?: number }) =>
    api.post<TaskAccepted>("/api/backups/runs", body),
  restoreBackup: (body: { repo_id: number; snapshot_id: string }) =>
    api.post<TaskAccepted>("/api/backups/restores", body),

  dnsCheck: (domain: string) =>
    api.get<DnsCheckResponse>(`/api/dns/check?domain=${encodeURIComponent(domain)}`),
  // An upsert keyed on (kind, label): re-sending a label rotates that credential
  // in place rather than leaving a revoked row behind to be tried first.
  setDnsProvider: (body: { kind: string; label: string; token: string }) =>
    api.put<DnsProviderResponse>("/api/dns/provider", body),
  issueWildcardCertificate: (siteId: number, staging: boolean) =>
    api.post<TaskAccepted>(`/api/sites/${siteId}/certificate-wildcard`, { staging }),
  // Firewall + Sentinel. Every one of these is an immediate operation, so they
  // answer 200 with data rather than a task receipt.
  firewall: () => api.get<FirewallResponse>("/api/firewall"),
  openPort: (body: PortRuleRequest) => api.post<PortRuleResult>("/api/firewall/ports", body),
  // A close carries the rule's whole identity rather than an id: `(port, proto,
  // source)` *is* the identity of a hole, and the panel may be asked to close
  // one it never recorded.
  closePort: (body: PortRuleRequest) => api.post<PortRuleResult>("/api/firewall/ports/close", body),
  bans: () => api.get<BansResponse>("/api/firewall/bans"),
  // No `client_ip` in the body: the web layer fills that in from the live
  // connection, precisely so a client cannot spoof its way past the self-ban
  // guard by claiming to be somewhere else.
  ban: (body: BanRequest) => api.post<BanResult>("/api/firewall/bans", body),
  unban: (ip: string) => api.del<UnbanResult>(`/api/firewall/bans/${encodeURIComponent(ip)}`),
  sentinel: () => api.get<SentinelSettings>("/api/firewall/sentinel"),
  // The whole settings object every time: the agent deserializes
  // `SentinelSettings` with no per-field defaults, so a partial body is a
  // rejected request rather than a merge.
  setSentinel: (body: SentinelSettings) => api.put<SentinelSettings>("/api/firewall/sentinel", body),

  alertEvents: (limit = 200) => api.get<AlertEventsResponse>(`/api/alerts?limit=${limit}`),
  openAlerts: () => api.get<AlertEventsResponse>("/api/alerts?open_only=true"),
  alertRules: () => api.get<AlertRulesResponse>("/api/alerts/rules"),
  setAlertRule: (body: AlertRuleRequest) => api.post<{ rule: AlertRule }>("/api/alerts/rules", body),
  channels: () => api.get<ChannelsResponse>("/api/alerts/channels"),
  setChannel: (body: ChannelRequest) =>
    api.post<{ channel: NotifyChannel }>("/api/alerts/channels", body),
  deleteChannel: (id: number) => api.del<{ deleted: boolean }>(`/api/alerts/channels/${id}`),
  testChannel: (id: number) => api.post<ChannelTestResult>(`/api/alerts/channels/${id}/test`),

  mailRelay: () => api.get<MailRelayResponse>("/api/mail/relay"),
  // PUT because there is exactly one relay and this is an upsert of it.
  // `password` is write-only: leave the field out to keep the stored one, send
  // an empty string to clear it. A `null` would be neither.
  setMailRelay: (body: MailRelayRequest) => api.put<TaskAccepted>("/api/mail/relay", body),
  // A rejected message answers 200 with `delivered: false` — it is an answer,
  // not an error, and the stage is what makes it actionable.
  testMailRelay: (to?: string) =>
    api.post<MailTestReport>("/api/mail/relay/test", to ? { to } : {}),
  // A dry run unless `apply` is true: the operation reports what it would put
  // in the zone and writes nothing. `apply` is always sent explicitly rather
  // than left to the server's default, so a caller cannot write by omission.
  publishMailDns: (apply: boolean) =>
    api.post<MailDnsPublishReport>("/api/mail/dns/publish", { apply }),

  // The authenticated half. `GET /api/branding` is public and is fetched by the
  // login page before there is a session; see lib/branding.ts.
  brandingSettings: (resellerId?: number) =>
    api.get<BrandingSettings>(
      `/api/branding/settings${resellerId === undefined ? "" : `?reseller_id=${resellerId}`}`,
    ),
  setBranding: (body: BrandingRequest) =>
    api.put<BrandingSetResult>("/api/branding/settings", body),
};

// --- mail -------------------------------------------------------------------

/** How the connection to the relay is protected. */
export type TlsMode = "none" | "starttls" | "implicit";

/**
 * One record the operator should publish.
 *
 * `managed` is always false and the UI says so out loud: Unihelm surfaces
 * SPF/DKIM/DMARC as guidance and does not publish or verify them (spec §11.18).
 * `value` is null for DKIM, because only the relay provider knows the selector
 * and the public key.
 */
export interface MailDnsRecord {
  name: string;
  record_type: string;
  value: string | null;
  managed: boolean;
  purpose: string;
}

export interface MailRelayResponse {
  configured: boolean;
  host: string | null;
  port: number | null;
  tls_mode: TlsMode | null;
  username: string | null;
  /** Whether a password is stored — never which one. */
  has_password: boolean;
  from_address: string | null;
  from_name: string | null;
  enabled: boolean;
  /** False means sites cannot send however well the relay is configured. */
  agent_installed: boolean;
  agent: string;
  credential_note: string;
  dns: { records: MailDnsRecord[]; advice: string };
}

export interface MailRelayRequest {
  host: string;
  port: number;
  tls_mode: TlsMode;
  username?: string;
  /** Omit to keep the stored password; empty string clears it. */
  password?: string;
  from_address: string;
  from_name?: string;
  enabled?: boolean;
}

export type MailStage =
  | "connect"
  | "tls"
  | "greeting"
  | "ehlo"
  | "starttls"
  | "auth"
  | "mail_from"
  | "rcpt_to"
  | "data"
  | "body"
  | "quit";

/**
 * What publishing did, or would do, to one advisory record.
 *
 * `would-create` is what a dry run answers and is the only outcome that means
 * nothing happened yet. `exists` is deliberately not an error: the operation
 * never overwrites, because merging two SPF policies is not something to guess
 * at, and a record the operator wrote by hand was meant.
 */
export type MailPublishOutcome = "would-create" | "created" | "exists" | "skipped" | "failed";

export interface MailPublishedRecord {
  name: string;
  record_type: string;
  value: string | null;
  outcome: MailPublishOutcome;
  /** Why it was skipped, or what the provider said when it failed. */
  detail: string | null;
}

/** The result of `mail.dns.publish`. Immediate, so this is the whole answer. */
export interface MailDnsPublishReport {
  /** False for a dry run — the default, and what an unconfirmed click gets. */
  applied: boolean;
  results: MailPublishedRecord[];
  advice: string;
}

/** The SMTP conversation's outcome. A failure is data, not an error. */
export interface MailTestReport {
  delivered: boolean;
  stage: MailStage;
  detail: string;
  code: number | null;
  transcript: string[];
  encrypted: boolean;
}

// --- branding ---------------------------------------------------------------

export type BrandingAssetKind = "logo" | "favicon" | "login_background";

export interface BrandingAssetInfo {
  kind: BrandingAssetKind;
  /** The reseller whose upload it is, or 0 for the panel default. */
  owner_id: number;
  content_type: string;
  sha256: string;
  size_bytes: number;
}

export interface ResolvedBranding {
  reseller_id: number;
  panel_name: string | null;
  support_url: string | null;
  primary_color: string | null;
  assets: BrandingAssetInfo[];
}

/** The stored row. Every null means "inherits from the panel default". */
export interface BrandingRow {
  reseller_id: number;
  panel_name: string | null;
  support_url: string | null;
  primary_color: string | null;
  login_host: string | null;
  updated_at: string;
}

export interface BrandingSettings {
  reseller_id: number;
  own: BrandingRow | null;
  resolved: ResolvedBranding;
  limits: { kind: BrandingAssetKind; max_bytes: number }[];
  accepted_formats: string[];
  svg_note: string;
}

/**
 * Three states, spelled out.
 *
 * "leave the logo alone" and "go back to the panel's logo" are different
 * intentions, and expressing the difference as a missing key versus a null is
 * how one of them gets sent by accident.
 */
export type BrandingAssetChange =
  | { action: "keep" }
  | { action: "clear" }
  | { action: "set"; content_b64: string };

export interface BrandingRequest {
  reseller_id?: number;
  panel_name?: string;
  support_url?: string;
  primary_color?: string;
  login_host?: string;
  /** Fields to reset to "inherit". */
  clear?: ("panel_name" | "support_url" | "primary_color" | "login_host")[];
  logo?: BrandingAssetChange;
  favicon?: BrandingAssetChange;
  login_background?: BrandingAssetChange;
}

export interface BrandingSetResult {
  reseller_id: number;
  resolved: ResolvedBranding;
  assets: {
    kind: BrandingAssetKind;
    action: "kept" | "cleared" | "replaced";
    content_type: string | null;
    size_bytes: number | null;
  }[];
}

/** PHP versions the panel knows about, newest first. */
export const PHP_VERSIONS = ["8.5", "8.4", "8.3", "8.2", "8.1", "8.0", "7.4"] as const;

/** Versions upstream no longer patches — shown with a warning. */
export const EOL_PHP_VERSIONS = new Set(["8.2", "8.1", "8.0", "7.4"]);
