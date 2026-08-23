import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import "./index.css";
import "./i18n";

import { ApiError } from "@/lib/api";
import { SessionProvider } from "@/lib/session";
import { ThemeProvider } from "@/lib/theme";
import { router } from "@/router";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 2_000,
      // Retrying an authorisation failure just burns time before the login
      // screen appears; retrying a network blip is worth one attempt.
      retry: (failureCount, error) => {
        if (error instanceof ApiError && (error.isUnauthenticated || error.status < 500)) return false;
        return failureCount < 2;
      },
      refetchOnWindowFocus: true,
    },
  },
});

const container = document.getElementById("root");
if (!container) throw new Error("#root is missing from index.html");

createRoot(container).render(
  <StrictMode>
    <ThemeProvider>
      <QueryClientProvider client={queryClient}>
        <SessionProvider>
          <RouterProvider router={router} />
        </SessionProvider>
      </QueryClientProvider>
    </ThemeProvider>
  </StrictMode>,
);
