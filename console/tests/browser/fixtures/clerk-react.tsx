import type { ReactNode } from "react";

const getToken = async () => "browser-fixture-session";

export function ClerkProvider({ children }: { children: ReactNode }) {
  return <>{children}</>;
}

export const useClerk = () => ({ status: "ready" as const });

export const useAuth = () => ({
  isLoaded: true as const,
  isSignedIn: true as const,
  actor: null,
  orgId: "org_browser_fixture",
  getToken,
});

export function UserButton() {
  return <span aria-label="Account menu">Account</span>;
}

export function SignIn() {
  return <div>Sign in</div>;
}

export function TaskChooseOrganization() {
  return <div>Choose organization</div>;
}

export function TaskSetupMFA() {
  return <div>Set up MFA</div>;
}

export function TaskResetPassword() {
  return <div>Reset password</div>;
}
