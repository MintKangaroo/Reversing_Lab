import { useEffect, useState } from 'react';
import { api, hex } from '../api.js';
import { DataTable, ErrorBanner, Loading } from './common.jsx';

export function StringsTab({ sha }) {
  const [minLength, setMinLength] = useState(4);
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    setLoading(true);
    api
      .strings(sha, minLength)
      .then((d) => active && (setData(d), setError(null)))
      .catch((e) => active && setError(e.message))
      .finally(() => active && setLoading(false));
    return () => {
      active = false;
    };
  }, [sha, minLength]);

  return (
    <div>
      <div className="toolbar">
        <label className="muted">Min length</label>
        <input
          className="text"
          type="number"
          min="1"
          max="64"
          value={minLength}
          style={{ width: 70 }}
          onChange={(e) => setMinLength(Math.max(1, Number(e.target.value) || 1))}
        />
        {data && <span className="muted">{data.count} strings</span>}
      </div>
      <ErrorBanner error={error} />
      {loading ? (
        <Loading />
      ) : (
        <DataTable
          rows={data?.strings}
          emptyLabel="No strings found."
          columns={[
            { key: 'offset', header: 'Offset', mono: true, render: (r) => hex(r.offset) },
            { key: 'encoding', header: 'Encoding' },
            { key: 'length', header: 'Len', mono: true },
            { key: 'value', header: 'Value', mono: true },
          ]}
        />
      )}
    </div>
  );
}
