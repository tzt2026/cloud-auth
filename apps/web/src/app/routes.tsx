import type { RouteObject } from "react-router-dom";
import { AccountLayout } from "@/app/account-layout";
import { PublicLayout } from "@/app/root-layout";
import { HomePage } from "@/pages/home-page";
import { DevicesPage } from "@/pages/account/devices-page";
import { DcControlPage } from "@/pages/account/dc-control-page";
import { CloudAgentPage } from "@/pages/account/cloud-agent-page";
import { OverviewPage } from "@/pages/account/overview-page";
import { SecurityPage } from "@/pages/account/security-page";
import { ServicesPage } from "@/pages/account/services-page";
import { LoginPage } from "@/pages/login-page";
import { NotFoundPage } from "@/pages/not-found-page";
import { RouteErrorPage } from "@/pages/route-error-page";

/**
 * Two shells, one route tree:
 * - public: `/`, `/login`, unknown URLs (PublicLayout → PortalShell)
 * - console: `/account` and its four sections (AccountLayout → rail + session block)
 * Unknown `/account/*` URLs stay inside the console shell so a signed-in user
 * keeps the rail and the session block while reading the 404.
 */
export const routes: RouteObject[] = [
  {
    element: <PublicLayout />,
    errorElement: <RouteErrorPage />,
    children: [
      {
        index: true,
        element: <HomePage />,
      },
      {
        path: "login",
        element: <LoginPage />,
      },
      {
        path: "*",
        element: <NotFoundPage />,
      },
    ],
  },
  {
    path: "account",
    element: <AccountLayout />,
    errorElement: <RouteErrorPage />,
    children: [
      {
        index: true,
        element: <OverviewPage />,
      },
      {
        path: "devices",
        element: <DevicesPage />,
      },
      {
        path: "security",
        element: <SecurityPage />,
      },
      {
        path: "services",
        element: <ServicesPage />,
      },
      {
        path: "services/dc",
        element: <DcControlPage />,
      },
      {
        path: "services/cloud-agent",
        element: <CloudAgentPage />,
      },
      {
        path: "*",
        element: <NotFoundPage />,
      },
    ],
  },
];
