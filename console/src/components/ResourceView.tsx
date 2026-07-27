import {
  useRef,
  useState,
  type KeyboardEvent,
  type ReactNode,
} from "react";

import {
  displayValue,
  isJsonRecord,
  type JsonRecord,
  type ResourceResult,
} from "../api/contracts";
import { time } from "./Analytics";

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
  timestamp?: boolean;
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
  const [focusedRowIndex, setFocusedRowIndex] = useState(0);
  const rowRefs = useRef<Array<HTMLTableRowElement | null>>([]);
  if (rows.length === 0) {
    return <StateNotice state="empty" detail="The server returned no records for this view." />;
  }
  const keyFor = (row: JsonRecord, index: number) =>
    identityKeys.map((key) => displayValue(row[key])).join(":") || `row-${index}`;
  const rovingRowIndex = Math.min(focusedRowIndex, rows.length - 1);
  const moveRowFocus = (index: number) => {
    const boundedIndex = Math.max(0, Math.min(index, rows.length - 1));
    setFocusedRowIndex(boundedIndex);
    rowRefs.current[boundedIndex]?.focus();
  };
  const handleRowKeyDown = (
    event: KeyboardEvent<HTMLTableRowElement>,
    row: T,
    index: number,
  ) => {
    if (!onSelect) return;
    if (event.key === "Enter" || event.key === " " || event.key === "Spacebar") {
      event.preventDefault();
      onSelect(row);
      return;
    }
    let nextIndex: number | null = null;
    if (event.key === "ArrowDown") nextIndex = Math.min(index + 1, rows.length - 1);
    if (event.key === "ArrowUp") nextIndex = Math.max(index - 1, 0);
    if (event.key === "Home") nextIndex = 0;
    if (event.key === "End") nextIndex = rows.length - 1;
    if (nextIndex === null) return;
    event.preventDefault();
    moveRowFocus(nextIndex);
  };
  return (
    <div
      className="table-scroll"
      tabIndex={onSelect ? undefined : 0}
      aria-label="Authoritative records"
    >
      <table className="record-table">
        <thead>
          <tr>{columns.map((column) => <th key={column.key}>{column.label}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr
              key={keyFor(row, index)}
              ref={(node) => {
                rowRefs.current[index] = node;
              }}
              className={onSelect ? "selectable" : undefined}
              tabIndex={onSelect ? (index === rovingRowIndex ? 0 : -1) : undefined}
              onClick={onSelect ? () => onSelect(row) : undefined}
              onFocus={onSelect ? () => setFocusedRowIndex(index) : undefined}
              onKeyDown={onSelect
                ? (event) => handleRowKeyDown(event, row, index)
                : undefined}
            >
              {columns.map((column) => (
                <td key={column.key} className={column.mono ? "mono" : undefined}>
                  {column.timestamp && typeof row[column.key] === "string"
                    ? time(row[column.key] as string)
                    : displayValue(row[column.key])}
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
  const detailValue = (key: string): string => {
    const value = record[key];
    return key.endsWith("_at") && typeof value === "string"
      ? time(value)
      : displayValue(value);
  };
  return (
    <dl className="detail-grid">
      {keys.map((key) => (
        <div key={key}>
          <dt>{key.replaceAll("_", " ")}</dt>
          <dd className="mono">{detailValue(key)}</dd>
        </div>
      ))}
    </dl>
  );
}
