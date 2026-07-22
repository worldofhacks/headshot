import type { ReactNode } from "react";

import {
  displayValue,
  isJsonRecord,
  type JsonRecord,
  type ResourceResult,
} from "../api/contracts";

export function StateNotice({
  state,
  reason,
  detail,
}: {
  state: string;
  reason?: string;
  detail?: string;
}) {
  return (
    <div className={`state-notice state-${state}`} role={state === "error" ? "alert" : "status"}>
      <span className="state-kicker mono">{state.toUpperCase()}</span>
      <span>{detail || reason || "No further detail was returned by the server."}</span>
    </div>
  );
}

export function ResourceView<T>({
  result,
  emptyLabel,
  children,
}: {
  result: ResourceResult<T>;
  emptyLabel: string;
  children: (data: T) => ReactNode;
}) {
  if (result.state === "loading") {
    return <StateNotice state="loading" detail="Waiting for an authenticated server response." />;
  }
  if (result.state === "empty") {
    return <StateNotice state="empty" detail={emptyLabel} />;
  }
  if (result.state === "unavailable" || result.state === "error") {
    return (
      <StateNotice
        state={result.state}
        reason={result.reason_code}
        detail={result.detail}
      />
    );
  }
  if (result.data === null) {
    return <StateNotice state="error" reason="missing_response_data" />;
  }
  return (
    <>
      {(result.state === "stale" || result.state === "degraded") && (
        <StateNotice
          state={result.state}
          reason={result.reason_code}
          detail={result.detail}
        />
      )}
      {children(result.data)}
    </>
  );
}

export interface Column {
  key: string;
  label: string;
  mono?: boolean;
}

export function RecordTable<T extends JsonRecord>({
  data,
  columns,
  identityKeys,
  onSelect,
}: {
  data: T[];
  columns: Column[];
  identityKeys: string[];
  onSelect?: (record: T) => void;
}) {
  const rows = data;
  if (rows.length === 0) {
    return <StateNotice state="empty" detail="The server returned no records for this view." />;
  }
  const keyFor = (row: JsonRecord, index: number) =>
    identityKeys.map((key) => displayValue(row[key])).join(":") || `row-${index}`;
  return (
    <div className="table-scroll" tabIndex={0} aria-label="Authoritative records">
      <table className="record-table">
        <thead>
          <tr>{columns.map((column) => <th key={column.key}>{column.label}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr
              key={keyFor(row, index)}
              className={onSelect ? "selectable" : undefined}
              onClick={onSelect ? () => onSelect(row) : undefined}
            >
              {columns.map((column) => (
                <td key={column.key} className={column.mono ? "mono" : undefined}>
                  {displayValue(row[column.key])}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function RecordDetails({ data, preferredKeys }: { data: unknown; preferredKeys: string[] }) {
  const record = isJsonRecord(data)
    ? data
    : Array.isArray(data) && data.length === 1 && isJsonRecord(data[0])
      ? data[0]
      : null;
  if (!record) return <StateNotice state="empty" detail="No record detail was returned." />;
  const keys = preferredKeys.filter((key) => key in record);
  return (
    <dl className="detail-grid">
      {keys.map((key) => (
        <div key={key}>
          <dt>{key.replaceAll("_", " ")}</dt>
          <dd className="mono">{displayValue(record[key])}</dd>
        </div>
      ))}
    </dl>
  );
}
