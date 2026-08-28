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

/** An error carrying the panel's stable `FER-xxxx` code, so callers can branch. */
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

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  const method = (init.method ?? "GET").toUpperCase();

  if (init.body !== undefined) headers.set("content-type", "application/json");
  if (!["GET", "HEAD", "OPTIONS"].includes(method) && csrfToken) {
    headers.set("x-ferrum-csrf", csrfToken);
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
 * because `ferrum_db::BackupRepo` has none. The password exists in exactly one
 * response, `RepoInitResponse`, and exactly once.
 */
export interface BackupRepo {
  id: number;
  kind: BackupRepoKind;
  label: string;
  path_or_url: string;
  has_credentials: boolean;
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

export const endpoints = {
  login: (username: string, password: string) =>
    api.post<SessionResponse>("/api/auth/login", { username, password }),
  logout: () => api.post<{ ok: boolean }>("/api/auth/logout"),
  me: () => api.get<SessionResponse>("/api/auth/me"),
  overview: () => api.get<Overview>("/api/server/overview"),
  services: () => api.get<ServicesResponse>("/api/server/services"),
  tasks: () => api.get<TaskListResponse>("/api/tasks"),
  taskLogs: (id: string, afterSeq = 0) =>
    api.get<{ lines: TaskLogLine[] }>(`/api/tasks/${id}/logs?after_seq=${afterSeq}`),

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
};

/** PHP versions the panel knows about, newest first. */
export const PHP_VERSIONS = ["8.5", "8.4", "8.3", "8.2", "8.1", "8.0", "7.4"] as const;

/** Versions upstream no longer patches — shown with a warning. */
export const EOL_PHP_VERSIONS = new Set(["8.2", "8.1", "8.0", "7.4"]);
