import { Clerk } from "@clerk/clerk-js";
import { ClerkProvider } from "@clerk/react";
import { ui } from "@clerk/ui";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./App";
import "./styles/fonts.css";
import "./styles/tokens.css";
import "./styles/base.css";
import "./styles/console.css";

// The build-time Vite value is the deployment contract. The DOM lookup keeps the protected
// application in credential-free verification builds and permits a same-origin HTML injector
// to supply the same public identifier without exposing any secret material.
const publishableKey =
  import.meta.env.VITE_CLERK_PUBLISHABLE_KEY ||
  document.documentElement.dataset.clerkPublishableKey;
const root = createRoot(document.getElementById("root")!);

if (!publishableKey) {
  root.render(
    <main className="security-shell">
      <div className="security-card">
        <div className="brand-mark" aria-hidden="true">H</div>
        <p className="eyebrow">HEADSHOT ACCESS BOUNDARY</p>
        <h1>Authentication not configured</h1>
        <p>The public Clerk identifier is absent. Protected access remains closed.</p>
      </div>
    </main>,
  );
} else {
  root.render(
    <StrictMode>
      <ClerkProvider
        publishableKey={publishableKey}
        Clerk={Clerk}
        ui={ui}
        telemetry={false}
        allowedRedirectOrigins={[window.location.origin]}
        allowedRedirectProtocols={[window.location.protocol.replace(":", "")]}
        signInUrl="/sign-in"
        taskUrls={{
          "choose-organization": "/session-tasks/choose-organization",
          "setup-mfa": "/session-tasks/setup-mfa",
          "reset-password": "/session-tasks/reset-password",
        }}
      >
        <App />
      </ClerkProvider>
    </StrictMode>,
  );
}
