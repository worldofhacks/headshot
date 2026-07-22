import type { ReactNode } from "react";

export function AdversarialText({ children }: { children: ReactNode }) {
  return <pre className="adversarial-text">{children}</pre>;
}
