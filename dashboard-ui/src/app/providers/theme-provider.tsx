import { useEffect, type PropsWithChildren } from "react";

import { useThemeStore } from "@/features/theme/theme-store";

export function ThemeProvider({ children }: PropsWithChildren) {
  const theme = useThemeStore((s) => s.theme);

  useEffect(() => {
    const root = document.documentElement;
    root.classList.toggle("dark", theme === "dark");
  }, [theme]);

  return children;
}
