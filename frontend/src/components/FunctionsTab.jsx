import { useEffect, useMemo, useState } from 'react';
import { api, hex } from '../api.js';
import { DataTable, ErrorBanner, Loading, ProvenanceBadge } from './common.jsx';

const COLUMNS = [
  { key: 'address', header: 'Address', mono: true, render: (r) => <span className="address-cell">{hex(r.address)}</span> },
  {
    key: 'name',
    header: 'Function',
    render: (r) => (
      <>
        <strong className="mono">{r.user_name || r.demangled_name || r.name}</strong>
        {r.user_name && <small className="original-name">original: {r.name}</small>}
      </>
    ),
  },
  { key: 'size', header: 'Size', mono: true },
  { key: 'call_count', header: 'Calls', mono: true },
  { key: 'basic_block_count', header: 'Blocks', mono: true },
  { key: 'cyclomatic_complexity', header: 'Complexity', mono: true },
  {
    key: 'confidence',
    header: 'Confidence',
    render: (r) => (
      <>
        <ProvenanceBadge kind={r.provenance} />{' '}
        <span className="confidence">{Math.round(r.confidence * 100)}%</span>
      </>
    ),
  },
];

export function FunctionsTab({ sha, selectedAddress, onSelect }) {
  const [data, setData] = useState(null);
  const [query, setQuery] = useState('');
  const [error, setError] = useState(null);

  useEffect(() => {
    let active = true;
    setData(null);
    api.functions(sha)
      .then((result) => active && (setData(result), setError(null)))
      .catch((failure) => active && setError(failure.message));
    return () => { active = false; };
  }, [sha]);

  const rows = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle || !data) return data?.items || [];
    return data.items.filter((item) => {
      const name = item.user_name || item.demangled_name || item.name;
      return name.toLowerCase().includes(needle) || hex(item.address).includes(needle);
    });
  }, [data, query]);

  if (error) return <ErrorBanner error={error} />;
  if (!data) return <Loading label="Recovering bounded function inventory…" />;

  return (
    <div className="function-explorer">
      <div className="toolbar">
        <input
          className="text function-search"
          type="search"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Filter name or address…"
          aria-label="Filter functions"
        />
        <span className="muted">{rows.length} of {data.total} functions</span>
        {data.items.some((item) => item.truncated) && <span className="badge medium">bounded result</span>}
      </div>
      <div className="function-table">
        <DataTable
          columns={COLUMNS}
          rows={rows}
          ariaLabel="Recovered functions"
          emptyLabel="No functions match the filter."
          rowKey={(item) => item.address}
          selectedKey={selectedAddress}
          onRowClick={(item) => onSelect(item.address)}
          rowHeight={34}
        />
      </div>
    </div>
  );
}
