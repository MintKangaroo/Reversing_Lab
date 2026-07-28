import { useEffect, useState } from 'react';
import { api } from '../api.js';
import { BoolBadge, ErrorBanner, Loading } from './common.jsx';

const LABELS = { radare2: 'radare2', ghidra: 'Ghidra', binary_ninja: 'Binary Ninja' };

export function IntegrationsTab({ sha }) {
  const [items, setItems] = useState(null);
  const [error, setError] = useState(null);
  const [running, setRunning] = useState(null);
  const [result, setResult] = useState(null);

  useEffect(() => {
    api.listIntegrations().then(setItems).catch((e) => setError(e.message));
  }, []);

  async function run(name) {
    setRunning(name);
    setResult(null);
    setError(null);
    try {
      setResult(await api.runIntegration(sha, name));
    } catch (e) {
      setError(`${LABELS[name] || name}: ${e.message}`);
    } finally {
      setRunning(null);
    }
  }

  if (!items) return <Loading />;

  return (
    <div>
      <ErrorBanner error={error} />
      <div className="grid">
        {items.map((tool) => (
          <div className="card" key={tool.name}>
            <div className="row" style={{ justifyContent: 'space-between', display: 'flex' }}>
              <strong>{LABELS[tool.name] || tool.name}</strong>
              <BoolBadge value={tool.available} on="available" off="not installed" />
            </div>
            <div className="muted" style={{ fontSize: 12, margin: '8px 0' }}>
              {tool.version ? `Version: ${tool.version}` : tool.detail}
            </div>
            <button
              className="btn"
              disabled={!tool.available || running === tool.name}
              onClick={() => run(tool.name)}
            >
              {running === tool.name ? 'Running…' : 'Analyze'}
            </button>
          </div>
        ))}
      </div>

      {result && (
        <div className="card" style={{ marginTop: 16 }}>
          <div className="section-title">{LABELS[result.name] || result.name} result</div>
          <p>{result.summary}</p>
          {result.functions.length > 0 && (
            <div className="mono" style={{ fontSize: 12 }}>
              {result.functions.slice(0, 100).map((fn) => (
                <div key={fn}>{fn}</div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
