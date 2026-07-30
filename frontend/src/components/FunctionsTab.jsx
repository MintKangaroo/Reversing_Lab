import { useEffect, useMemo, useState } from 'react';
import { api, hex } from '../api.js';
import { ErrorBanner, Loading, ProvenanceBadge } from './common.jsx';

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
      <div className="table-scroll function-table" role="region" aria-label="Recovered functions" tabIndex={0}>
        <table className="data">
          <thead>
            <tr>
              <th>Address</th><th>Function</th><th>Size</th><th>Calls</th>
              <th>Blocks</th><th>Complexity</th><th>Confidence</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((item) => (
              <tr
                key={item.address}
                className={selectedAddress === item.address ? 'selected-row' : ''}
                onClick={() => onSelect(item.address)}
                onKeyDown={(event) => (event.key === 'Enter' || event.key === ' ') && onSelect(item.address)}
                tabIndex={0}
              >
                <td className="mono address-cell">{hex(item.address)}</td>
                <td>
                  <strong className="mono">{item.user_name || item.demangled_name || item.name}</strong>
                  {item.user_name && <small className="original-name">original: {item.name}</small>}
                </td>
                <td className="mono">{item.size}</td>
                <td className="mono">{item.call_count}</td>
                <td className="mono">{item.basic_block_count}</td>
                <td className="mono">{item.cyclomatic_complexity}</td>
                <td><ProvenanceBadge kind={item.provenance} /> <span className="confidence">{Math.round(item.confidence * 100)}%</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
