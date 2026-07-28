import { useEffect, useState } from 'react';
import { api } from '../api.js';
import { ErrorBanner, Loading } from './common.jsx';

const PAGE = 512;

export function HexTab({ sha }) {
  const [offset, setOffset] = useState(0);
  const [page, setPage] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    setLoading(true);
    api
      .hex(sha, offset, PAGE)
      .then((d) => active && (setPage(d), setError(null)))
      .catch((e) => active && setError(e.message))
      .finally(() => active && setLoading(false));
    return () => {
      active = false;
    };
  }, [sha, offset]);

  const total = page?.total_size ?? 0;
  const canPrev = offset > 0;
  const canNext = offset + PAGE < total;

  return (
    <div>
      <div className="toolbar">
        <button className="btn secondary" disabled={!canPrev} onClick={() => setOffset(Math.max(0, offset - PAGE))}>
          ← Prev
        </button>
        <button className="btn secondary" disabled={!canNext} onClick={() => setOffset(offset + PAGE)}>
          Next →
        </button>
        <span className="muted">
          bytes {offset.toLocaleString()}–{Math.min(offset + PAGE, total).toLocaleString()} of {total.toLocaleString()}
        </span>
      </div>
      <ErrorBanner error={error} />
      {loading ? (
        <Loading />
      ) : (
        <div className="card hex">
          {page.rows.map((row) => (
            <div key={row.offset}>
              <span className="off">{row.offset.toString(16).padStart(8, '0')}</span>
              {'  '}
              {row.hex_bytes.join(' ').padEnd(16 * 3 - 1, ' ')}
              {'  '}
              <span className="ascii">{row.ascii}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
