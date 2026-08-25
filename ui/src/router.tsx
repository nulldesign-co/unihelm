import {
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
} from "@tanstack/react-router";

import { AppShell } from "@/components/app-shell";
import { Spinner } from "@/components/ui/spinner";
import { useSession } from "@/lib/session";
import { DashboardPage } from "@/routes/dashboard";
import { FilesPage, validateFilesSearch } from "@/routes/files";
import { LoginPage } from "@/routes/login";
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
  stackRoute,
  filesRoute,
]);

export const router = createRouter({ routeTree, defaultPreload: "intent" });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
