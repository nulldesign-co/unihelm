export const en = {
  common: {
    appName: "Ferrum",
    loading: "Loading…",
    retry: "Try again",
    dismiss: "Dismiss",
    close: "Close",
    cancel: "Cancel",
    signOut: "Sign out",
    search: "Search",
    none: "—",
    unknown: "Unknown",
  },
  login: {
    title: "Sign in",
    subtitle: "Manage your server.",
    username: "Username",
    password: "Password",
    submit: "Sign in",
    submitting: "Signing in…",
    usernameRequired: "Enter your username",
    passwordRequired: "Enter your password",
    genericError: "Could not sign in. Check the details and try again.",
    rateLimited: "Too many attempts. Wait a few minutes before trying again.",
  },
  nav: {
    dashboard: "Dashboard",
    tasks: "Tasks",
    commandPalette: "Command palette",
    theme: "Theme",
    language: "Language",
    themeLight: "Light",
    themeDark: "Dark",
    themeSystem: "System",
  },
  dashboard: {
    title: "Dashboard",
    subtitle: "Live status of this server.",
    cpu: "CPU",
    memory: "Memory",
    disk: "Disk",
    load: "Load average",
    uptime: "Uptime",
    cores: "{{count}} core",
    cores_other: "{{count}} cores",
    ofTotal: "of {{total}}",
    services: "Services",
    system: "System",
    panelFootprint: "Panel footprint",
    panelFootprintHint: "Web and agent combined, against the {{budget}} budget.",
    withinBudget: "Within budget",
    overBudget: "Over budget",
    agentOffline: "The agent is not responding",
    agentOfflineHint:
      "Privileged actions are unavailable. Your sites keep serving — nginx and PHP do not depend on the panel.",
    noServices: "No managed services are installed yet.",
    installHint: "Install a stack component to see it here.",
  },
  service: {
    active: "Running",
    inactive: "Stopped",
    failed: "Failed",
    activating: "Starting",
    deactivating: "Stopping",
    not_found: "Not installed",
    unknown: "Unknown",
    enabled: "Starts at boot",
    disabled: "Manual start",
  },
  tasks: {
    title: "Tasks",
    empty: "Nothing has run yet.",
    emptyHint: "Long-running actions appear here with their live output.",
    active: "{{count}} running",
    status: {
      queued: "Queued",
      running: "Running",
      ok: "Done",
      failed: "Failed",
      cancelled: "Cancelled",
    },
    logs: "Output",
    noLogs: "No output yet.",
    reconnected: "Reconnected — some live output was skipped. Reopen the task to see the full log.",
  },
  error: {
    title: "Something went wrong",
    requestId: "Reference: {{id}}",
  },
} as const;

/**
 * The shape every locale must fill, with the English strings widened to `string`.
 *
 * `as const` above is what makes `t("tasks.status.ok")` autocomplete; this mapped
 * type is what lets another language supply different words for the same keys.
 * A missing or misspelled key is then a compile error, not a stray English
 * sentence in the middle of a Farsi page.
 */
export type Translations = Widen<typeof en>;

type Widen<T> = {
  [K in keyof T]: T[K] extends string ? string : Widen<T[K]>;
};
