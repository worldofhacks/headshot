import { useState, type ReactNode } from "react";

import { AdversarialText } from "./AdversarialText";

export interface PromptMessageView {
  role: "system" | "user" | "assistant" | "tool";
  content: string;
}

export interface PromptRedactionView {
  path: string;
  reason: string;
  replacement: string;
}

function CopyableHash({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  const [copyState, setCopyState] = useState<"idle" | "copied" | "unavailable">("idle");

  const copyHash = async () => {
    if (!navigator.clipboard?.writeText) {
      setCopyState("unavailable");
      return;
    }
    try {
      await navigator.clipboard.writeText(value);
      setCopyState("copied");
    } catch {
      setCopyState("unavailable");
    }
  };

  const actionLabel = copyState === "copied"
    ? `${label} copied`
    : copyState === "unavailable"
      ? `${label} copy unavailable`
      : `Copy ${label}`;

  return (
    <dd className="prompt-hash-value mono">
      <code aria-label={`${label}: ${value}`} title={value}>{value}</code>
      <button
        type="button"
        className="prompt-hash-copy"
        onClick={() => void copyHash()}
        aria-label={actionLabel}
        aria-live="polite"
        title={`Copy ${label}`}
      >
        {copyState === "copied"
          ? "Copied"
          : copyState === "unavailable"
            ? "Unavailable"
            : "Copy"}
      </button>
    </dd>
  );
}

export function ExpandableEvidence({
  title,
  meta,
  children,
  defaultOpen = false,
  onToggle,
}: {
  title: string;
  meta?: string;
  children: ReactNode;
  defaultOpen?: boolean;
  onToggle?: (open: boolean) => void;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <details
      className="event-record"
      open={open}
      onToggle={(event) => {
        const next = event.currentTarget.open;
        setOpen(next);
        onToggle?.(next);
      }}
    >
      <summary>
        <span>
          <strong>{title}</strong>
          {meta && <small className="mono">{meta}</small>}
        </span>
      </summary>
      <div className="event-detail">{children}</div>
    </details>
  );
}

export function PromptTranscript({
  promptVersion,
  promptSha256,
  transcriptSha256,
  systemPrompt,
  messages,
  redactions,
}: {
  promptVersion: string;
  promptSha256: string;
  transcriptSha256: string;
  systemPrompt: string;
  messages: PromptMessageView[];
  redactions: PromptRedactionView[];
}) {
  return (
    <div className="evidence-stack">
      <dl className="detail-grid prompt-identity-grid">
        <div>
          <dt>Prompt version</dt>
          <dd className="mono">{promptVersion}</dd>
        </div>
        <div>
          <dt>System prompt SHA-256</dt>
          <CopyableHash label="System prompt SHA-256" value={promptSha256} />
        </div>
        <div>
          <dt>Transcript SHA-256</dt>
          <CopyableHash label="Transcript SHA-256" value={transcriptSha256} />
        </div>
      </dl>
      <div className="event-stack">
        <ExpandableEvidence title="Exact system prompt" meta="immutable snapshot">
          <AdversarialText>{systemPrompt}</AdversarialText>
        </ExpandableEvidence>
        <ExpandableEvidence
          title="Ordered provider messages"
          meta={`${messages.length} exact message${messages.length === 1 ? "" : "s"}`}
        >
          <div className="event-stack">
            {messages.map((message, index) => (
              <ExpandableEvidence
                key={`${index}-${message.role}`}
                title={`${index + 1}. ${message.role}`}
              >
                <AdversarialText>{message.content}</AdversarialText>
              </ExpandableEvidence>
            ))}
          </div>
        </ExpandableEvidence>
        {redactions.length > 0 && (
          <ExpandableEvidence
            title="Bounded redaction metadata"
            meta={`${redactions.length} entr${redactions.length === 1 ? "y" : "ies"}`}
          >
            <dl className="detail-grid">
              {redactions.map((redaction, index) => (
                <div key={`${index}-${redaction.path}`}>
                  <dt className="mono">{redaction.path}</dt>
                  <dd>
                    {redaction.reason} · <span className="mono">{redaction.replacement}</span>
                  </dd>
                </div>
              ))}
            </dl>
          </ExpandableEvidence>
        )}
      </div>
    </div>
  );
}
