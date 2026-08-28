import {
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
} from "@tanstack/react-router";

import { AppShell } from "@/components/app-shell";
import { Spinner } from "@/components/ui/spinner";
import { useSession } from "@/lib/session";
import { AppsPage } from "@/routes/apps";
import { BackupsPage } from "@/routes/backups";
import { CronPage } from "@/routes/cron";
import { DashboardPage } from "@/routes/dashboard";
import { DatabasesPage } from "@/routes/databases";
import { DnsPage } from "@/routes/dns";
import { FilesPage, validateFilesSearch } from "@/routes/files";
import { LoginPage } from "@/routes/login";
import { PlansPage } from "@/routes/plans";
import { SiteDetailPage } from "@/routes/site-detail";
import { SitesPage } from "@/routes/sites";
import { StackPage } from "@/routes/stack";

/**
 * One gate for the whole app.
 *
 * The server is the authority on whether a session is valid — this only decides
 * which screen to render while we wait for it to say so.
 */
function RootLayout() {
  const { user, ready } = useSession();

  if (!ready) {
    return (
      <div className="flex min-h-dvh items-center justify-center bg-canvas text-ink-muted">
        <Spinner className="h-6 w-6" />
      </div>
    );
  }

  if (!user) return <LoginPage />;

  return (
    <AppShell>
      <Outlet />
    </AppShell>
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
]);

export const router = createRouter({ routeTree, defaultPreload: "intent" });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
