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
import { LoginPage } from "@/routes/login";
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

const stackRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/stack",
  component: StackPage,
});

const routeTree = rootRoute.addChildren([dashboardRoute, sitesRoute, stackRoute]);

export const router = createRouter({ routeTree, defaultPreload: "intent" });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
