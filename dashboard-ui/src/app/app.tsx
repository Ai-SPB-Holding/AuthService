import { useEffect } from "react";
import { RouterProvider } from "react-router-dom";

import { AppQueryProvider } from "@/app/providers/query-provider";
import { ThemeProvider } from "@/app/providers/theme-provider";
import { useAuthStore } from "@/features/auth/auth-store";
import { router } from "@/app/routes/router";

function AuthBootstrap() {
  const bootstrap = useAuthStore((s) => s.bootstrap);
  useEffect(() => {
    void bootstrap();
  }, [bootstrap]);
  return null;
}

export function App() {
  return (
    <AppQueryProvider>
      <ThemeProvider>
        <AuthBootstrap />
        <RouterProvider router={router} />
      </ThemeProvider>
    </AppQueryProvider>
  );
}
