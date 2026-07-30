import { useEffect, useState } from 'react';
import { api } from '../api.js';
import { ErrorBanner, Loading, StatusDot } from './common.jsx';

function readableBytes(value) {
  if (value >= 1024 ** 3) return `${(value / 1024 ** 3).toFixed(1)} GiB`;
  if (value >= 1024 ** 2) return `${(value / 1024 ** 2).toFixed(1)} MiB`;
  return `${value.toLocaleString()} B`;
}

export function SettingsWorkspace() {
  const [tools, setTools] = useState(null);
  const [configuration, setConfiguration] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    Promise.all([api.tooling(), api.toolingConfiguration()])
      .then(([toolItems, config]) => {
        setTools(toolItems);
        setConfiguration(config);
      })
      .catch((failure) => setError(failure.message));
  }, []);

  if (!tools || !configuration) return <div className="page-scroll"><ErrorBanner error={error} />{!error && <Loading label="Inspecting configured tooling and limits…" />}</div>;
  const limits = configuration.limits;
  const sandbox = configuration.sandbox_policy;
  return (
    <div className="page-scroll settings-workspace">
      <div className="page-title">
        <div><span className="eyebrow">CAPABILITY INVENTORY</span><h1>Tooling & settings</h1><p>Availability is detected at runtime. Optional tools degrade independently.</p></div>
      </div>
      <ErrorBanner error={error} />
      <h2 className="workspace-heading">External tools</h2>
      <div className="tooling-grid">
        {tools.map((tool) => (
          <article key={`${tool.category}-${tool.name}`} className="tooling-card">
            <div><span className="eyebrow">{tool.category}</span><h3>{tool.name}</h3></div>
            <StatusDot status={tool.available ? 'ready' : 'disabled'} label={tool.available ? 'available' : 'unavailable'} />
            <p>{tool.detail}</p>
            <ul>{tool.capabilities.map((item) => <li key={item}>{item}</li>)}</ul>
          </article>
        ))}
      </div>
      <div className="settings-columns">
        <section className="settings-card">
          <h2>Analysis limits</h2>
          {Object.entries(limits).map(([name, value]) => (
            <div className="inspector-kv" key={name}><span>{name.replaceAll('_', ' ')}</span><b>{name.endsWith('_bytes') ? readableBytes(value) : value}</b></div>
          ))}
        </section>
        <section className="settings-card">
          <h2>Sandbox policy</h2>
          {Object.entries(sandbox).map(([name, value]) => (
            <div className="inspector-kv" key={name}><span>{name.replaceAll('_', ' ')}</span><b>{String(value)}</b></div>
          ))}
          <div className="security-callout">Docker alone is not presented as a strong malware boundary. Real samples require a separately managed VM-backed worker.</div>
        </section>
      </div>
    </div>
  );
}
