import {
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
} from "@tanstack/react-router";

import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { AppShell } from "@/components/app-shell";
import { useSession } from "@/lib/session";
import { AlertsPage } from "@/routes/alerts";
import { AppsPage } from "@/routes/apps";
import { BackupsPage } from "@/routes/backups";
import { BrandingPage } from "@/routes/branding";
import { CronPage } from "@/routes/cron";
import { DashboardPage } from "@/routes/dashboard";
import { DatabasesPage } from "@/routes/databases";
import { DnsPage } from "@/routes/dns";
import { FilesPage, validateFilesSearch } from "@/routes/files";
import { FirewallPage } from "@/routes/firewall";
import { LoginPage } from "@/routes/login";
import { MailPage } from "@/routes/mail";
import { PlansPage } from "@/routes/plans";
import { SiteDetailPage } from "@/routes/site-detail";
import { SitesPage } from "@/routes/sites";
import { StackPage } from "@/routes/stack";
import { TasksPage } from "@/routes/tasks";
import { TerminalPage } from "@/routes/terminal";

/**
 * One gate for the whole app.
 *
 * The server is the authority on whether a session is valid — this only decides
 * which screen to render while we wait for it to say so.
 */
function RootLayout() {
  const { user, ready } = useSession();

  if (!ready) return <BootScreen />;

  if (!user) return <LoginPage />;

  return (
    <AppShell>
      <Outlet />
    </AppShell>
  );
}

/**
 * The first frame of every load, while the server decides whether the cookie is
 * still a session.
 *
 * It waits before showing anything. A restored session usually resolves in well
 * under a tenth of a second, and a spinner that appears and vanishes inside
 * that window is a flash of nothing — worse than the blank canvas it replaced.
 * Past the delay the mark breathes, which says "starting" rather than
 * "waiting".
 */
function BootScreen() {
  const { t } = useTranslation();
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const timer = setTimeout(() => setVisible(true), 160);
    return () => clearTimeout(timer);
  }, []);

  return (
    <div className="app-aurora relative grid min-h-dvh place-items-center bg-canvas">
      {visible ? (
        <span className="relative grid h-12 w-12 animate-fade-in place-items-center" aria-hidden>
          <span className="absolute inset-0 animate-ping-slow rounded-2xl bg-accent/40" />
          <span className="relative grid h-12 w-12 place-items-center rounded-2xl bg-accent text-lg font-bold text-on-accent shadow-glow">
            U
          </span>
        </span>
      ) : null}
      {/* The status lives for a screen reader whether or not the mark is drawn. */}
      <span role="status" aria-live="polite" className="sr-only">
        {t("common.loading")}
      </span>
    </div>
  );
}

const rootRoute = createRootRoute({ component: RootLayout });

const dashboardRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  component: DashboardPage,
});

const sitesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/sites",
  component: SitesPage,
});

const siteDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/sites/$siteId",
  component: SiteDetailPage,
});

const appsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/apps",
  component: AppsPage,
});

const databasesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/databases",
  component: DatabasesPage,
});

const plansRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/plans",
  component: PlansPage,
});

const cronRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/cron",
  component: CronPage,
});

const backupsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/backups",
  component: BackupsPage,
});

const dnsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/dns",
  component: DnsPage,
});

const mailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/mail",
  component: MailPage,
});

const brandingRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/branding",
  component: BrandingPage,
});

const stackRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/stack",
  component: StackPage,
});

const filesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/files",
  component: FilesPage,
  // The current directory rides in `?path=…` so reloads and shared links land
  // in the same folder (spec §11.7).
  validateSearch: validateFilesSearch,
});

const firewallRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/firewall",
  component: FirewallPage,
});

const tasksRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/tasks",
  component: TasksPage,
});

const terminalRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/terminal",
  component: TerminalPage,
});

const alertsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/alerts",
  component: AlertsPage,
});

const routeTree = rootRoute.addChildren([
  dashboardRoute,
  sitesRoute,
  siteDetailRoute,
  appsRoute,
  databasesRoute,
  plansRoute,
  cronRoute,
  backupsRoute,
  dnsRoute,
  stackRoute,
  filesRoute,
  firewallRoute,
  alertsRoute,
  mailRoute,
  brandingRoute,
  tasksRoute,
  terminalRoute,
]);

export const router = createRouter({ routeTree, defaultPreload: "intent" });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
