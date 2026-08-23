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
};
