import { useEffect, useState } from 'react';
import { api } from '../api.js';
import { ErrorBanner, Loading } from './common.jsx';

export function PackingTab({ sha }) {
  const [report, setReport] = useState(null);
  const [entropy, setEntropy] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    setLoading(true);
    Promise.all([api.packing(sha), api.entropy(sha)])
      .then(([p, e]) => active && (setReport(p), setEntropy(e), setError(null)))
      .catch((e) => active && setError(e.message))
      .finally(() => active && setLoading(false));
    return () => {
      active = false;
    };
  }, [sha]);

  if (loading) return <Loading />;
  if (error) return <ErrorBanner error={error} />;

  const maxWindow = Math.max(...entropy.windows.map((w) => w.entropy), 8);

  return (
    <div>
      <div className="card">
        <div className="grid">
          <div className="kv">
            <span className="k">Verdict</span>
            <span className="v">
              <span className={`badge ${report.likely_packed ? 'off' : 'on'}`}>
                {report.likely_packed ? 'Likely packed' : 'Not packed'}
              </span>
            </span>
          </div>
          <div className="kv"><span className="k">Score</span><span className="v">{report.score}</span></div>
          <div className="kv"><span className="k">Detected packer</span><span className="v">{report.detected_packer || '—'}</span></div>
          <div className="kv"><span className="k">Overall entropy</span><span className="v">{report.overall_entropy.toFixed(3)} / 8.0</span></div>
        </div>
      </div>

      <div className="card">
        <div className="section-title">Indicators</div>
        {report.indicators.length === 0 ? (
          <div className="muted">No packing indicators triggered.</div>
        ) : (
          report.indicators.map((ind) => (
            <div key={ind.name} className="row" style={{ marginBottom: 10 }}>
              <span className="badge neutral" style={{ marginRight: 8 }}>+{ind.weight}</span>
              <strong className="mono">{ind.name}</strong>
              <div className="desc" style={{ marginTop: 2 }}>{ind.detail}</div>
            </div>
          ))
        )}
      </div>

      <div className="card">
        <div className="section-title">Entropy profile (per window)</div>
        <div style={{ display: 'flex', alignItems: 'flex-end', gap: 2, height: 120 }}>
          {entropy.windows.map((w) => (
            <div
              key={w.offset}
              title={`offset 0x${w.offset.toString(16)} · ${w.entropy.toFixed(2)} bits/byte`}
              style={{
                flex: 1,
                minWidth: 2,
                height: `${(w.entropy / maxWindow) * 100}%`,
                background: w.entropy >= 7.2 ? 'var(--red)' : 'var(--accent-dim)',
                borderRadius: '2px 2px 0 0',
              }}
            />
          ))}
        </div>
        <div className="muted" style={{ marginTop: 6, fontSize: 12 }}>
          Bars ≥ 7.2 bits/byte (red) indicate compressed/encrypted content.
        </div>
      </div>
    </div>
  );
}
