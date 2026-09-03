import { Link, useNavigate, useRouterState } from "@tanstack/react-router";
import {
  Archive,
  BellRing,
  Boxes,
  Clock,
  Compass,
  Container,
  Database,
  FolderOpen,
  Gauge,
  Globe,
  Layers,
  ListChecks,
  LogOut,
  Mail,
  Menu as MenuIcon,
  Monitor,
  Moon,
  Network,
  Palette,
  Search,
  Settings,
  ShieldCheck,
  Sun,
  TerminalSquare,
  Wallet,
  X,
  type LucideIcon,
} from "lucide-react";
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { CommandPalette, type Command } from "@/components/command-palette";
import { TaskDrawer } from "@/components/task-drawer";
import { Button } from "@/components/ui/button";
import { assetUrl, useApplyBranding, useBranding, type PublicBranding } from "@/lib/branding";
import { useFocusTrap } from "@/lib/focus";
import { useSession } from "@/lib/session";
import { useTheme } from "@/lib/theme";
import { cn } from "@/lib/utils";

interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
}

interface NavGroup {
  label: string | null;
  items: NavItem[];
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const { t } = useTranslation();
  const { user, signOut } = useSession();
  const { theme, setTheme } = useTheme();
  const [tasksOpen, setTasksOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const navigate = useNavigate();
  const drawerRef = useRef<HTMLDivElement>(null);
  useFocusTrap(sidebarOpen, drawerRef);
  // Branding is data, so the accent colour, the tab title and the favicon
  // follow a save with no reload (spec §11.19).
  const branding = useBranding();
  useApplyBranding(branding);

  // Navigating is what the mobile drawer is for; arriving closes it.
  useEffect(() => {
    setSidebarOpen(false);
  }, [pathname]);

  // Escape closes the drawer, like every other layer in the panel.
  useEffect(() => {
    if (!sidebarOpen) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setSidebarOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [sidebarOpen]);

  // Sixteen destinations don't belong in one flat strip. Grouped by what the
  // operator is doing, not by when the feature shipped.
  const groups = useMemo<NavGroup[]>(
    () => [
      { label: null, items: [{ to: "/", label: t("nav.dashboard"), icon: Gauge }] },
      {
        label: t("nav.groupHosting"),
        items: [
          { to: "/sites", label: t("nav.sites"), icon: Globe },
          { to: "/discover", label: t("nav.discover"), icon: Compass },
          { to: "/apps", label: t("nav.apps"), icon: Boxes },
          { to: "/databases", label: t("nav.databases"), icon: Database },
          { to: "/files", label: t("nav.files"), icon: FolderOpen },
          { to: "/mail", label: t("nav.mail"), icon: Mail },
          { to: "/dns", label: t("nav.dns"), icon: Network },
        ],
      },
      {
        label: t("nav.groupOperations"),
        items: [
          { to: "/cron", label: t("nav.cron"), icon: Clock },
          { to: "/backups", label: t("nav.backups"), icon: Archive },
          { to: "/tasks", label: t("nav.tasks"), icon: ListChecks },
          { to: "/terminal", label: t("nav.terminal"), icon: TerminalSquare },
          { to: "/stack", label: t("nav.stack"), icon: Layers },
          { to: "/runtimes", label: t("nav.runtimes"), icon: Boxes },
          { to: "/docker", label: t("nav.docker"), icon: Container },
        ],
      },
      {
        label: t("nav.groupSecurity"),
        items: [
          { to: "/firewall", label: t("nav.firewall"), icon: ShieldCheck },
          { to: "/alerts", label: t("nav.alerts"), icon: BellRing },
        ],
      },
      {
        label: t("nav.groupAdmin"),
        items: [
          { to: "/plans", label: t("nav.plans"), icon: Wallet },
          { to: "/branding", label: t("nav.branding"), icon: Palette },
          { to: "/settings", label: t("nav.settings"), icon: Settings },
        ],
      },
    ],
    [t],
  );

  const commands = useMemo<Command[]>(
    () => [
      { id: "tasks", label: t("tasks.title"), hint: "T", run: () => setTasksOpen(true) },
      ...groups.flatMap((group) =>
        group.items.map((item) => ({
          id: `go-${item.to}`,
          label: item.label,
          icon: item.icon,
          run: () => void navigate({ to: item.to }),
        })),
      ),
      { id: "theme-light", label: `${t("nav.theme")}: ${t("nav.themeLight")}`, icon: Sun, run: () => setTheme("light") },
      { id: "theme-dark", label: `${t("nav.theme")}: ${t("nav.themeDark")}`, icon: Moon, run: () => setTheme("dark") },
      { id: "theme-system", label: `${t("nav.theme")}: ${t("nav.themeSystem")}`, icon: Monitor, run: () => setTheme("system") },
      { id: "sign-out", label: t("common.signOut"), icon: LogOut, run: () => void signOut() },
    ],
    [t, groups, setTheme, signOut, navigate],
  );

  const sidebar = (
    <SidebarContent
      branding={branding}
      groups={groups}
      pathname={pathname}
      username={user?.username}
      role={user?.role}
      onSearch={() => {
        setSidebarOpen(false);
        setPaletteOpen(true);
      }}
      onTasks={() => {
        setSidebarOpen(false);
        setTasksOpen(true);
      }}
      theme={theme}
      setTheme={setTheme}
      onSignOut={() => void signOut()}
    />
  );

  return (
    <div className="app-aurora relative min-h-dvh bg-canvas">
      {/* Keyboard users should not have to tab through sixteen nav links to
          reach the page they just navigated to. */}
      <a
        href="#main"
        className="sr-only z-50 focus:not-sr-only focus:fixed focus:start-4 focus:top-4 focus:rounded-lg focus:bg-surface focus:px-4 focus:py-2 focus:text-sm focus:font-medium focus:text-ink focus:shadow-pop"
      >
        {t("common.skipToContent")}
      </a>

      {/* Mobile top bar: the drawer trigger and the two things worth a thumb's
          reach. Desktop needs none of it — the sidebar is always there. */}
      <header className="sticky top-0 z-30 flex h-14 items-center gap-1 border-b border-border bg-surface/80 px-3 backdrop-blur-xl lg:hidden">
        <Button
          variant="ghost"
          size="icon"
          onClick={() => setSidebarOpen(true)}
          aria-label={t("nav.menu")}
          aria-expanded={sidebarOpen}
        >
          <MenuIcon className="h-5 w-5" />
        </Button>
        <Brand branding={branding} className="ms-1" />
        <div className="ms-auto flex items-center gap-1">
          <Button variant="ghost" size="icon" onClick={() => setPaletteOpen(true)} aria-label={t("common.search")}>
            <Search className="h-4 w-4" />
          </Button>
          <Button variant="ghost" size="icon" onClick={() => setTasksOpen(true)} aria-label={t("tasks.title")}>
            <ListChecks className="h-4 w-4" />
          </Button>
        </div>
      </header>

      {/* Desktop sidebar: fixed to the start edge, flipped for free by logical
          properties when the document is RTL. */}
      <aside className="fixed inset-y-0 start-0 z-30 hidden w-64 lg:block">{sidebar}</aside>

      {/* Mobile drawer: mounted only while open, so the entrance animation is
          the mount and closing is instant. */}
      {sidebarOpen ? (
        <div className="fixed inset-0 z-40 lg:hidden" role="dialog" aria-modal="true" aria-label={t("nav.menu")}>
          <div className="absolute inset-0 animate-fade-in bg-black/40 backdrop-blur-[2px]" onClick={() => setSidebarOpen(false)} />
          <div
            ref={drawerRef}
            tabIndex={-1}
            className="absolute inset-y-0 start-0 w-72 max-w-[85vw] animate-slide-in-start shadow-pop outline-none"
          >
            {sidebar}
            <Button
              variant="ghost"
              size="icon-sm"
              onClick={() => setSidebarOpen(false)}
              aria-label={t("common.close")}
              className="absolute top-3 -end-11 bg-black/30 text-white hover:bg-black/50 hover:text-white"
            >
              <X className="h-4 w-4" />
            </Button>
          </div>
        </div>
      ) : null}

      <div className="relative lg:ps-64">
        <main id="main" className="mx-auto w-full max-w-screen-xl px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
          {/* Keyed on the path so arriving somewhere new is a short rise rather
              than a hard swap: the eye gets told "this is a different page"
              without waiting for anything. */}
          <div key={pathname} className="animate-page-in">
            {children}
          </div>
        </main>
      </div>

      <TaskDrawer open={tasksOpen} onClose={() => setTasksOpen(false)} />
      <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} commands={commands} />
    </div>
  );
}

function Brand({ branding, className }: { branding: PublicBranding; className?: string }) {
  const { t } = useTranslation();
  const logo = assetUrl(branding, "logo");
  return (
    <Link
      to="/"
      className={cn(
        "group flex min-w-0 items-center gap-2.5 font-semibold tracking-tight text-ink",
        className,
      )}
    >
      {/* The reseller's mark and name where the product's used to be
          (spec §11.19). Both fall back per field, so a reseller with only a
          logo keeps the product name and vice versa. */}
      {logo ? (
        <img src={logo} alt="" aria-hidden className="h-6 max-w-24 shrink-0 object-contain" />
      ) : (
        <span
          className="grid h-7 w-7 shrink-0 place-items-center rounded-lg bg-accent text-[11px] font-bold text-on-accent shadow-glow transition-transform duration-200 ease-out-back group-hover:scale-105 motion-reduce:group-hover:scale-100"
          aria-hidden
        >
          U
        </span>
      )}
      <span className="truncate">{branding.panel_name ?? t("common.appName")}</span>
    </Link>
  );
}

function SidebarContent({
  branding,
  groups,
  pathname,
  username,
  role,
  onSearch,
  onTasks,
  theme,
  setTheme,
  onSignOut,
}: {
  branding: PublicBranding;
  groups: NavGroup[];
  pathname: string;
  username?: string;
  role?: "admin" | "reseller" | "customer";
  onSearch: () => void;
  onTasks: () => void;
  theme: "light" | "dark" | "system";
  setTheme: (theme: "light" | "dark" | "system") => void;
  onSignOut: () => void;
}) {
  const { t } = useTranslation();
  const navRef = useRef<HTMLElement>(null);
  const [pill, setPill] = useState<{ top: number; height: number } | null>(null);
  // The first measurement must not animate: an indicator that flies in from the
  // top of the sidebar on every page load is a magic trick, not a cue. This is
  // state, not a ref, precisely so a render commits *with* the transition
  // enabled and the old position still in place — otherwise the class and the
  // new transform would land in the same frame and the browser would have
  // nothing to interpolate from.
  const [settled, setSettled] = useState(false);

  const isActive = (to: string) => (to === "/" ? pathname === "/" : pathname === to || pathname.startsWith(`${to}/`));

  /**
   * The single highlight that slides between destinations.
   *
   * One element moved with a transform, rather than a background painted on
   * whichever link is current: the movement is what tells the eye where it went
   * and where it came from, and it costs one compositor-only property.
   */
  useLayoutEffect(() => {
    const nav = navRef.current;
    if (!nav) return;

    const measure = () => {
      const active = nav.querySelector<HTMLElement>('[aria-current="page"]');
      // `offsetParent === null` means this copy of the sidebar is the one
      // `display: none` is hiding — the desktop aside below the `lg` breakpoint,
      // or the drawer above it. Measuring it yields zeros and would park the
      // highlight at the top of the list until the next navigation.
      if (!active || nav.offsetParent === null) {
        setPill(null);
        setSettled(false);
        return;
      }
      setPill({ top: active.offsetTop, height: active.offsetHeight });
    };

    measure();

    // A resize can change which copy is visible, and wrapping a long label can
    // change an item's height, so the highlight follows the layout rather than
    // only the route.
    const observer = new ResizeObserver(measure);
    observer.observe(nav);
    return () => observer.disconnect();
  }, [pathname, groups]);

  // Once positioned and painted, later moves are allowed to animate.
  useEffect(() => {
    if (!pill || settled) return;
    const frame = requestAnimationFrame(() => setSettled(true));
    return () => cancelAnimationFrame(frame);
  }, [pill, settled]);

  return (
    <div className="flex h-full flex-col border-e border-border bg-surface/85 backdrop-blur-xl">
      <div className="flex h-14 shrink-0 items-center px-4">
        <Brand branding={branding} />
      </div>

      <div className="px-3 pb-2">
        <button
          onClick={onSearch}
          aria-keyshortcuts="Meta+K Control+K"
          className="group flex h-9 w-full items-center gap-2 rounded-lg border border-border bg-canvas px-2.5 text-sm text-ink-subtle transition-[border-color,color,box-shadow] duration-150 hover:border-border-strong hover:text-ink-muted hover:shadow-card"
        >
          <Search className="h-3.5 w-3.5 transition-transform duration-200 group-hover:scale-110 motion-reduce:group-hover:scale-100" aria-hidden />
          <span className="min-w-0 flex-1 truncate text-start">{t("common.search")}</span>
          <kbd className="rounded border border-border bg-surface px-1 font-mono text-[10px] text-ink-subtle">
            ⌘K
          </kbd>
        </button>
      </div>

      <nav
        ref={navRef}
        className="relative min-h-0 flex-1 space-y-4 overflow-y-auto px-3 pt-1 pb-3"
        aria-label={t("nav.menu")}
      >
        {pill ? (
          <span
            aria-hidden
            className={cn(
              "pointer-events-none absolute inset-x-3 z-0 rounded-lg bg-accent-soft",
              settled && "transition-transform duration-300 ease-out-quint motion-reduce:transition-none",
            )}
            style={{ height: pill.height, transform: `translateY(${pill.top}px)` }}
          />
        ) : null}

        {groups.map((group, index) => (
          <div key={group.label ?? index}>
            {group.label ? (
              <p className="px-2 pb-1 text-[11px] font-medium tracking-wider text-ink-subtle uppercase">
                {group.label}
              </p>
            ) : null}
            <ul className="space-y-0.5">
              {group.items.map((item) => {
                const active = isActive(item.to);
                return (
                  <li key={item.to}>
                    <Link
                      to={item.to}
                      aria-current={active ? "page" : undefined}
                      className={cn(
                        "group relative z-10 flex items-center gap-2.5 rounded-lg px-2 py-1.5 text-sm transition-colors duration-150",
                        active
                          ? "font-medium text-accent"
                          : "text-ink-muted hover:bg-surface-muted hover:text-ink",
                      )}
                    >
                      <item.icon
                        className={cn(
                          "h-4 w-4 shrink-0 transition-transform duration-200 ease-out-back motion-reduce:transition-none",
                          active
                            ? "scale-110 motion-reduce:scale-100"
                            : "text-ink-subtle group-hover:scale-110 group-hover:text-ink-muted motion-reduce:group-hover:scale-100",
                        )}
                        aria-hidden
                      />
                      <span className="truncate">{item.label}</span>
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </nav>

      {/* Who you are and the three things you do without leaving the page, on
          one line. Spread across their own row the icons read as a scattered
          toolbar; anchored to the end of the identity they read as its
          controls. */}
      <div className="shrink-0 border-t border-border p-3">
        <div className="flex items-center gap-1 rounded-lg bg-surface-muted/60 p-1.5">
          {username ? (
            <>
              <span
                className="grid h-7 w-7 shrink-0 place-items-center rounded-full bg-accent-soft text-xs font-semibold text-accent uppercase"
                aria-hidden
              >
                {username.slice(0, 1)}
              </span>
              <span className="me-auto min-w-0 ps-0.5">
                <span dir="ltr" className="block truncate text-start text-sm font-medium text-ink">
                  {username}
                </span>
                {role ? (
                  <span className="block truncate text-xs text-ink-muted">
                    {t(`common.role.${role}`)}
                  </span>
                ) : null}
              </span>
            </>
          ) : (
            <span className="me-auto" />
          )}

          <Button
            variant="ghost"
            size="icon-sm"
            onClick={onTasks}
            aria-label={t("tasks.title")}
            title={t("tasks.title")}
          >
            <ListChecks className="h-4 w-4" />
          </Button>
          <ThemeToggle theme={theme} setTheme={setTheme} />
          <Button
            variant="ghost"
            size="icon-sm"
            onClick={onSignOut}
            aria-label={t("common.signOut")}
            title={t("common.signOut")}
          >
            <LogOut className="h-4 w-4" />
          </Button>
        </div>
      </div>
    </div>
  );
}

function ThemeToggle({
  theme,
  setTheme,
}: {
  theme: "light" | "dark" | "system";
  setTheme: (theme: "light" | "dark" | "system") => void;
}) {
  const { t } = useTranslation();
  const next = theme === "light" ? "dark" : theme === "dark" ? "system" : "light";
  const Icon = theme === "light" ? Sun : theme === "dark" ? Moon : Monitor;
  const label =
    theme === "light" ? t("nav.themeLight") : theme === "dark" ? t("nav.themeDark") : t("nav.themeSystem");

  return (
    <Button
      variant="ghost"
      size="icon-sm"
      onClick={() => setTheme(next)}
      aria-label={`${t("nav.theme")}: ${label}`}
      title={`${t("nav.theme")}: ${label}`}
    >
      {/* Keyed so React swaps the element and the entrance replays: the icon
          turns over rather than being quietly substituted. */}
      <Icon key={theme} className="h-4 w-4 animate-pop-in" />
    </Button>
  );
}
