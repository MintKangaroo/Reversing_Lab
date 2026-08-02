import { useEffect, useState } from 'react';
import { api } from '../api.js';
import { ErrorBanner, Loading } from './common.jsx';

export function PackingTab({ sha }) {
  const [report, setReport] = useState(null);
  const [entropy, setEntropy] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const [upx, setUpx] = useState(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [unpacking, setUnpacking] = useState(false);
  const [unpacked, setUnpacked] = useState(null);

  useEffect(() => {
    let active = true;
    setLoading(true);
    Promise.all([api.packing(sha), api.entropy(sha), api.toolingDetail('upx')])
      .then(([p, e, tool]) => active && (setReport(p), setEntropy(e), setUpx(tool), setError(null)))
      .catch((e) => active && setError(e.message))
      .finally(() => active && setLoading(false));
    return () => {
      active = false;
    };
  }, [sha]);

  if (loading) return <Loading />;
  if (error) return <ErrorBanner error={error} />;

  const maxWindow = Math.max(...entropy.windows.map((w) => w.entropy), 8);

  async function unpack() {
    setUnpacking(true);
    setError(null);
    try {
      setUnpacked(await api.unpack(sha));
    } catch (failure) {
      setError(failure.message);
    } finally {
      setUnpacking(false);
    }
  }

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
          <div className="kv"><span className="k">Confidence</span><span className="v">{Math.round(report.confidence * 100)}%</span></div>
          <div className="kv"><span className="k">Detected packer</span><span className="v">{report.detected_packer || '—'}</span></div>
          <div className="kv"><span className="k">Overall entropy</span><span className="v">{report.overall_entropy.toFixed(3)} / 8.0</span></div>
        </div>
      </div>

      {report.detected_packers.length > 0 && (
        <div className="card">
          <div className="section-title">Detected packer candidates</div>
          {report.detected_packers.map((packer) => (
            <div className="packer-candidate" key={packer.name}>
              <strong>{packer.name}</strong>
              <span>{Math.round(packer.confidence * 100)}% confidence</span>
              <small>{packer.evidence.map((item) => item.message).join(' ')}</small>
            </div>
          ))}
        </div>
      )}

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
        {report.recommended_next_steps.length > 0 && (
          <div className="next-steps">
            <strong>Recommended next steps</strong>
            <ol>{report.recommended_next_steps.map((step) => <li key={step}>{step}</li>)}</ol>
          </div>
        )}
      </div>

      <div className="card explicit-action">
        <div>
          <div className="section-title">Explicit UPX unpack action</div>
          <p>Creates a separate content-addressed artifact. The original sample is never overwritten or executed.</p>
          <label className="acknowledgement">
            <input type="checkbox" checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)} />
            I understand this invokes a local, trusted UPX executable on the stored sample.
          </label>
          <span className={`badge ${upx?.available ? 'on' : 'off'}`}>{upx?.available ? 'UPX available' : 'UPX unavailable'}</span>
        </div>
        <button className="btn" disabled={!upx?.available || !acknowledged || unpacking} onClick={unpack}>
          {unpacking ? 'Unpacking…' : 'Create unpacked artifact'}
        </button>
      </div>
      {unpacked && (
        <div className="card unpack-result">
          <div className="section-title">Derived artifact created</div>
          <div className="grid">
            <div className="kv"><span className="k">Original hash</span><span className="v">{unpacked.original_sha256}</span></div>
            <div className="kv"><span className="k">Derived hash</span><span className="v">{unpacked.unpacked_sha256}</span></div>
            <div className="kv"><span className="k">Size change</span><span className="v">{unpacked.original_size} → {unpacked.unpacked_size}</span></div>
          </div>
        </div>
      )}

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
