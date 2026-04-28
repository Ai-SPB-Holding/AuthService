import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router-dom";

import { useAuthStore } from "@/features/auth/auth-store";
import { ProtectedRoute } from "@/app/routes/protected-route";

function resetAuth() {
  useAuthStore.setState({
    accessToken: null,
    refreshToken: null,
    audience: null,
    roles: [],
    isAuthenticated: false,
    isLoading: false,
    isBootstrapping: false,
    sessionLoaded: true,
    accessLevel: "admin",
    isDeploymentGlobalAdmin: false,
  });
}

describe("ProtectedRoute", () => {
  beforeEach(() => {
    resetAuth();
  });
  afterEach(() => {
    resetAuth();
  });

  it("shows loading when bootstrapping", () => {
    useAuthStore.setState({
      isBootstrapping: true,
      isAuthenticated: true,
      sessionLoaded: true,
      accessLevel: "admin",
      isDeploymentGlobalAdmin: false,
    });
    const router = createMemoryRouter(
      [
        {
          path: "/",
          element: <ProtectedRoute />,
          children: [{ index: true, element: <p>Inside</p> }],
        },
      ],
      { initialEntries: ["/"] },
    );
    render(<RouterProvider router={router} />);
    expect(screen.getByText(/Loading session/)).toBeInTheDocument();
  });

  it("shows loading when authenticated but admin session not loaded yet", () => {
    useAuthStore.setState({
      isBootstrapping: false,
      isAuthenticated: true,
      sessionLoaded: false,
      accessLevel: null,
      isDeploymentGlobalAdmin: false,
    });
    const router = createMemoryRouter(
      [
        {
          path: "/",
          element: <ProtectedRoute />,
          children: [{ index: true, element: <p>Inside</p> }],
        },
      ],
      { initialEntries: ["/"] },
    );
    render(<RouterProvider router={router} />);
    expect(screen.getByText(/Loading session/)).toBeInTheDocument();
  });

  it("redirects to login when not authenticated and not bootstrapping", async () => {
    useAuthStore.setState({
      isBootstrapping: false,
      isAuthenticated: false,
      sessionLoaded: true,
      accessLevel: null,
      isDeploymentGlobalAdmin: false,
    });
    const router = createMemoryRouter(
      [
        { path: "/login", element: <p>Login</p> },
        {
          path: "/",
          element: <ProtectedRoute />,
          children: [{ index: true, element: <p>Inside</p> }],
        },
      ],
      { initialEntries: ["/"] },
    );
    render(<RouterProvider router={router} />);
    await waitFor(() => {
      expect(screen.getByText("Login")).toBeInTheDocument();
    });
  });
});
