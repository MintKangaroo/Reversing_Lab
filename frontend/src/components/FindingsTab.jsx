import { useEffect, useMemo, useState } from 'react';
import { api, hex } from '../api.js';
import { Empty, ErrorBanner, Loading, ProvenanceBadge } from './common.jsx';

const OPERATIONS = [
  ['base64_decode', 'Base64 decode'],
  ['hex_decode', 'Hex → bytes'],
  ['hex_encode', 'Text → hex'],
  ['url_decode', 'URL decode'],
  ['url_encode', 'URL encode'],
  ['xor_single', 'Single-byte XOR'],
  ['xor_repeating', 'Repeating-key XOR'],
  ['add', 'ADD bytes'],
  ['sub', 'SUB bytes'],
  ['rol', 'ROL bytes'],
  ['ror', 'ROR bytes'],
  ['utf16_decode', 'UTF-16 decode'],
  ['escaped_bytes', 'Escaped \\xNN bytes'],
  ['stack_string', 'Stack immediates'],
  ['rot', 'ROT / Caesar'],
  ['integer_endian', 'Integer → endian bytes'],
  ['signed_convert', 'Signed / unsigned'],
  ['bitwise', 'Bitwise bytes'],
  ['hash', 'Hash'],
  ['checksum', 'Checksum'],
];

export function DecoderPlayground() {
  const [operation, setOperation] = useState('base64_decode');
  const [input, setInput] = useState('');
  const [key, setKey] = useState('5a');
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function run() {
    setBusy(true);
    setError(null);
    setResult(null);
    const parameters = {};
    if (operation.startsWith('xor_')) Object.assign(parameters, { input_format: 'hex', key, key_format: 'hex' });
    if (['add', 'sub'].includes(operation)) Object.assign(parameters, { input_format: 'hex', amount: Number(key) || 0 });
    if (['rol', 'ror'].includes(operation)) Object.assign(parameters, { input_format: 'hex', count: Number(key) || 1 });
    if (operation === 'rot') Object.assign(parameters, { shift: Number(key) || 13 });
    if (operation === 'bitwise') Object.assign(parameters, { input_format: 'hex', operator: 'xor', operand: Number(key) || 0 });
    try {
      setResult(await api.transform(operation, input, parameters));
    } catch (failure) {
      setError(failure.message);
    } finally {
      setBusy(false);
    }
  }

  const keyed = operation.startsWith('xor_') || ['add', 'sub', 'rol', 'ror', 'rot', 'bitwise'].includes(operation);
  return (
    <section className="decoder-playground">
      <div className="finding-heading">
        <div><span className="eyebrow">DATA ONLY</span><h2>Deobfuscation assistant</h2></div>
        <ProvenanceBadge kind="user" />
      </div>
      <p className="muted">Transforms copied data only. Input is processed in the request and is not persisted.</p>
      <div className="decoder-controls">
        <select className="text" value={operation} onChange={(event) => setOperation(event.target.value)}>
          {OPERATIONS.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
        </select>
        {keyed && <input className="text decoder-key" value={key} onChange={(event) => setKey(event.target.value)} aria-label="Transform key or amount" placeholder="key / amount" />}
        <button className="btn" disabled={busy || !input} onClick={run}>{busy ? 'Transforming…' : 'Transform'}</button>
      </div>
      <div className="decoder-columns">
        <label><span>Input</span><textarea value={input} onChange={(event) => setInput(event.target.value)} placeholder="Paste encoded text or hex bytes…" /></label>
        <label><span>Output</span><textarea readOnly value={result?.text || ''} placeholder="Decoded text appears here" /></label>
      </div>
      <ErrorBanner error={error} />
      {result && (
        <div className="decoder-result">
          <div><b>Bytes</b><code>{result.bytes_hex || '—'}</code></div>
          {result.warnings.map((warning) => <div className="inline-warning" key={warning}>△ {warning}</div>)}
          <details><summary>Reviewable Python snippet</summary><pre>{result.python_snippet}</pre></details>
        </div>
      )}
    </section>
  );
}

export function FindingsTab({ sha, onAddressSelect }) {
  const [findings, setFindings] = useState(null);
  const [severity, setSeverity] = useState('all');
  const [error, setError] = useState(null);

  useEffect(() => {
    let active = true;
    api.obfuscation(sha)
      .then((data) => active && (setFindings(data), setError(null)))
      .catch((failure) => active && setError(failure.message));
    return () => { active = false; };
  }, [sha]);

  const visible = useMemo(
    () => (findings || []).filter((item) => severity === 'all' || item.severity === severity),
    [findings, severity],
  );

  if (error) return <ErrorBanner error={error} />;
  if (!findings) return <Loading label="Evaluating bounded obfuscation heuristics…" />;

  return (
    <div className="findings-layout">
      <div className="toolbar">
        <label className="muted" htmlFor="severity-filter">Severity</label>
        <select id="severity-filter" className="text" value={severity} onChange={(event) => setSeverity(event.target.value)}>
          {['all', 'critical', 'high', 'medium', 'low', 'info'].map((item) => <option key={item}>{item}</option>)}
        </select>
        <span className="muted">{visible.length} evidence-backed findings</span>
      </div>
      {visible.length === 0 ? (
        <Empty label="No matching obfuscation findings" detail="A clean heuristic result does not prove the sample is unobfuscated." />
      ) : (
        <div className="finding-list">
          {visible.map((finding) => (
            <article key={finding.id} className={`finding-card severity-${finding.severity}`}>
              <div className="finding-heading">
                <div><span className={`severity-label ${finding.severity}`}>{finding.severity}</span><h2>{finding.title}</h2></div>
                <span className="confidence">{Math.round(finding.confidence * 100)}% confidence</span>
              </div>
              <p>{finding.summary}</p>
              <div className="finding-meta">
                <code>{finding.technique}</code>
                {finding.related_function != null && (
                  <button className="link-button" onClick={() => onAddressSelect(finding.related_function)}>
                    function {hex(finding.related_function)}
                  </button>
                )}
                {finding.mitre_id && <span>{finding.mitre_id}</span>}
              </div>
              <details>
                <summary>Evidence ({finding.evidence.length})</summary>
                <ul className="evidence-list">
                  {finding.evidence.map((item, index) => (
                    <li key={`${item.source}-${index}`}>
                      <ProvenanceBadge kind={item.provenance} />
                      <span>{item.message}</span>
                      {item.address != null && <button className="link-button mono" onClick={() => onAddressSelect(item.address)}>{hex(item.address)}</button>}
                    </li>
                  ))}
                </ul>
              </details>
              <div className="caveat"><b>False-positive caveat</b>{finding.false_positive_notes.join(' ')}</div>
              <div className="investigation"><b>Suggested investigation</b>{finding.recommendations.join(' ')}</div>
            </article>
          ))}
        </div>
      )}
      <DecoderPlayground />
    </div>
  );
}
