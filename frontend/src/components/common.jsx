// Small shared presentational components used across the analysis views.

import { useState } from 'react';

export function BoolBadge({ value, on = 'yes', off = 'no' }) {
  return <span className={`badge ${value ? 'on' : 'off'}`}>{value ? on : off}</span>;
}

export function DifficultyBadge({ level }) {
  return <span className={`badge ${level}`}>{level}</span>;
}

export function ErrorBanner({ error }) {
  if (!error) return null;
  return <div className="error-banner" role="alert">⚠ {String(error)}</div>;
}

export function Loading({ label = 'Loading…' }) {
  return (
    <div className="state-panel" role="status" aria-live="polite">
      <span className="spinner" aria-hidden="true" />
      <span>{label}</span>
    </div>
  );
}

export function Empty({ label, detail, action }) {
  return (
    <div className="state-panel empty-state">
      <span className="state-icon" aria-hidden="true">◇</span>
      <strong>{label}</strong>
      {detail && <span>{detail}</span>}
      {action}
    </div>
  );
}

export function ProvenanceBadge({ kind = 'heuristic' }) {
  const labels = {
    verified: 'Verified',
    heuristic: 'Heuristic',
    inferred: 'Inferred',
    dynamic: 'Dynamic observation',
    user: 'User annotation',
  };
  return <span className={`provenance provenance-${kind}`}>{labels[kind] || kind}</span>;
}

export function StatusDot({ status = 'idle', label }) {
  return (
    <span className={`status-dot status-${status}`}>
      <span aria-hidden="true" />
      {label || status}
    </span>
  );
}

// A generic, sticky-header data table. `columns` = [{ key, header, render?, mono? }].
export function DataTable({ columns, rows, emptyLabel = 'No data.' }) {
  const [scrollTop, setScrollTop] = useState(0);
  if (!rows || rows.length === 0) return <Empty label={emptyLabel} />;
  const rowHeight = 31;
  const virtualized = rows.length > 250;
  const start = virtualized ? Math.max(0, Math.floor(scrollTop / rowHeight) - 10) : 0;
  const end = virtualized ? Math.min(rows.length, start + 70) : rows.length;
  const visibleRows = rows.slice(start, end);
  return (
    <div
      className="table-scroll"
      role="region"
      aria-label="Analysis data"
      data-virtualized={virtualized || undefined}
      tabIndex={0}
      onScroll={(event) => setScrollTop(event.currentTarget.scrollTop)}
    >
      <table className="data" aria-rowcount={rows.length + 1}>
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.key}>{c.header}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {virtualized && start > 0 && <tr className="virtual-spacer" aria-hidden="true"><td colSpan={columns.length} style={{ height: start * rowHeight }} /></tr>}
          {visibleRows.map((row, i) => (
            <tr key={start + i}>
              {columns.map((c) => (
                <td key={c.key} className={c.mono ? 'mono' : undefined}>
                  {c.render ? c.render(row) : row[c.key]}
                </td>
              ))}
            </tr>
          ))}
          {virtualized && end < rows.length && <tr className="virtual-spacer" aria-hidden="true"><td colSpan={columns.length} style={{ height: (rows.length - end) * rowHeight }} /></tr>}
        </tbody>
      </table>
    </div>
  );
}
