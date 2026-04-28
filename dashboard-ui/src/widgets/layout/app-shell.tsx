import { Link, NavLink, Outlet } from "react-router-dom";
import { LayoutDashboard, Users, Shield, KeyRound, Activity, ScrollText, Moon, Sun, Settings } from "lucide-react";

import { Button } from "@/shared/ui/button";
import { useThemeStore } from "@/features/theme/theme-store";
import { useAuth } from "@/features/auth/use-auth";
import { useAuthStore } from "@/features/auth/auth-store";

const baseNav = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/users", label: "Users", icon: Users },
  { to: "/clients", label: "Clients", icon: KeyRound },
  { to: "/roles", label: "Roles", icon: Shield },
  { to: "/sessions", label: "Sessions", icon: Activity },
  { to: "/audit", label: "Audit Logs", icon: ScrollText },
];

const settingsNavItem = { to: "/settings", label: "Settings", icon: Settings };

export function AppShell() {
  const accessLevel = useAuthStore((s) => s.accessLevel);
  const theme = useThemeStore((s) => s.theme);
  const toggleTheme = useThemeStore((s) => s.toggleTheme);
  const { logout } = useAuth();

  const nav =
    accessLevel === "client_settings" ? [settingsNavItem] : [...baseNav, settingsNavItem];

  return (
    <div className="min-h-screen bg-slate-50/70 text-slate-900 dark:bg-slate-950/60 dark:text-slate-100">
      <div className="grid min-h-screen grid-cols-1 lg:grid-cols-[260px_1fr]">
        <aside className="border-r border-slate-200/90 bg-white/90 p-4 backdrop-blur-sm dark:border-slate-800/80 dark:bg-slate-900/80">
          <Link to="/" className="mb-6 flex items-center gap-3 rounded-md p-1 transition hover:bg-slate-100 dark:hover:bg-slate-800/70">
            <img
              src="/icons.png"
              alt="Auth Service logo"
              className="brand-logo h-10 w-10 rounded-full object-cover"
            />
            <span className="text-lg font-semibold">Auth Admin</span>
          </Link>
          <nav className="space-y-1">
            {nav.map((item) => (
              <NavLink key={item.to} to={item.to} className={({ isActive }) => `flex items-center gap-2 rounded-md px-3 py-2 text-sm transition ${isActive ? "bg-slate-200 dark:bg-slate-800" : "hover:bg-slate-100 dark:hover:bg-slate-800/70"}`}>
                <item.icon size={16} />
                {item.label}
              </NavLink>
            ))}
          </nav>
        </aside>

        <main>
          <header className="flex items-center justify-between border-b border-slate-200/90 bg-white/85 px-6 py-3 backdrop-blur-sm dark:border-slate-800/80 dark:bg-slate-900/75">
            <h1 className="text-base font-semibold">Admin Dashboard</h1>
            <div className="flex items-center gap-2">
              <Button variant="outline" onClick={toggleTheme}>{theme === "dark" ? <Sun size={16} /> : <Moon size={16} />}</Button>
              <Button variant="outline" onClick={() => void logout()}>Logout</Button>
            </div>
          </header>
          <div className="p-6">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
