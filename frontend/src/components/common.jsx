// Small shared presentational components used across the analysis views.

export function BoolBadge({ value, on = 'yes', off = 'no' }) {
  return <span className={`badge ${value ? 'on' : 'off'}`}>{value ? on : off}</span>;
}

export function DifficultyBadge({ level }) {
  return <span className={`badge ${level}`}>{level}</span>;
}

export function ErrorBanner({ error }) {
  if (!error) return null;
  return <div className="error-banner">⚠ {String(error)}</div>;
}

export function Loading({ label = 'Loading…' }) {
  return <div className="center-empty">{label}</div>;
}

export function Empty({ label }) {
  return <div className="center-empty">{label}</div>;
}

// A generic, sticky-header data table. `columns` = [{ key, header, render?, mono? }].
export function DataTable({ columns, rows, emptyLabel = 'No data.' }) {
  if (!rows || rows.length === 0) return <Empty label={emptyLabel} />;
  return (
    <div className="table-scroll">
      <table className="data">
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.key}>{c.header}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i}>
              {columns.map((c) => (
                <td key={c.key} className={c.mono ? 'mono' : undefined}>
                  {c.render ? c.render(row) : row[c.key]}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
