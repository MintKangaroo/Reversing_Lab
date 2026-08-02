import { useEffect, useMemo, useState } from 'react';
import { api, hex } from '../api.js';
import { ErrorBanner, Loading, ProvenanceBadge } from './common.jsx';

export function PseudoCodeTab({ sha, address, onAddressSelect }) {
  const [provider, setProvider] = useState('auto');
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setResult(null);
    api.decompile(sha, address, provider)
      .then((data) => active && (setResult(data), setError(null)))
      .catch((failure) => active && setError(failure.message))
      .finally(() => active && setLoading(false));
    return () => { active = false; };
  }, [sha, address, provider]);

  const sourceByLine = useMemo(
    () => new Map((result?.source_map || []).map((item) => [item.line, item])),
    [result],
  );

  if (loading) return <Loading label="Generating estimated C-like representation…" />;
  if (error) return <ErrorBanner error={error} />;

  return (
    <div className="pseudo-code-view">
      <div className="decompiler-notice">
        <strong>Estimated C-like code</strong>
        <span>This is not the original source. Types, names, and control structures may be incorrect.</span>
      </div>
      <div className="toolbar">
        <label className="muted" htmlFor="decompiler-provider">Provider</label>
        <select id="decompiler-provider" className="text" value={provider} onChange={(event) => setProvider(event.target.value)}>
          <option value="auto">Auto (graceful fallback)</option>
          <option value="ghidra">Ghidra headless</option>
          <option value="pseudo_c">Built-in pseudo-C</option>
        </select>
        <span className="provider-chip">{result.provider}</span>
        <span className="muted">{Math.round(result.confidence * 100)}% overall confidence · {result.elapsed_ms} ms</span>
        <ProvenanceBadge kind={result.provenance} />
      </div>
      {result.warnings.length > 0 && (
        <div className="decompiler-warnings">
          {result.warnings.map((warning) => <div key={warning}>△ {warning}</div>)}
        </div>
      )}
      <div className="code-editor" role="region" aria-label="Estimated C-like code" tabIndex={0}>
        {result.code.split('\n').map((line, index) => {
          const lineNumber = index + 1;
          const mapping = sourceByLine.get(lineNumber);
          return (
            <button
              key={lineNumber}
              className={`code-line ${mapping ? 'mapped' : ''}`}
              disabled={!mapping}
              onClick={() => mapping && onAddressSelect(mapping.address_start)}
              title={mapping ? `${hex(mapping.address_start)} · ${Math.round(mapping.confidence * 100)}% confidence` : ''}
            >
              <span className="line-number">{lineNumber}</span>
              <span className="source-address">{mapping ? hex(mapping.address_start) : ''}</span>
              <code>{line || ' '}</code>
            </button>
          );
        })}
      </div>
      <div className="source-map-status">
        {result.source_map.length} mapped lines · click a mapped line to synchronize the selected address
      </div>
    </div>
  );
}
