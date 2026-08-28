import { useEffect, useState } from 'react';
import { api, hex } from '../api.js';
import { Empty, ErrorBanner, Loading, StatusDot } from './common.jsx';

const TERMINAL_STATES = ['completed', 'failed', 'cancelled'];

function regionLabel(region) {
  return `${region.start_hex || hex(region.start)}–${region.end_hex || hex(region.end)}`;
}

export function MemoryRegionInspector({ dump, regions, volatility }) {
  const [selectedRegion, setSelectedRegion] = useState(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [architecture, setArchitecture] = useState('x86_64');
  const [job, setJob] = useState(null);
  const [artifacts, setArtifacts] = useState([]);
  const [selectedArtifact, setSelectedArtifact] = useState(null);
  const [hexPage, setHexPage] = useState(null);
  const [disassembly, setDisassembly] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    let active = true;
    api.memoryRegionArtifacts(dump.id)
      .then((page) => active && setArtifacts(page.items))
      .catch((failure) => active && setError(failure.message));
    return () => { active = false; };
  }, [dump.id]);

  async function loadArtifact(artifact, offset = 0) {
    setBusy(true);
    setError(null);
    try {
      const [nextHexPage, nextDisassembly] = await Promise.all([
        api.memoryRegionHex(dump.id, artifact.id, offset, 256),
        api.memoryRegionDisassembly(dump.id, artifact.id, offset, 200),
      ]);
      setSelectedArtifact(artifact);
      setHexPage(nextHexPage);
      setDisassembly(nextDisassembly);
    } catch (failure) {
      setError(failure.message);
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    if (!job || TERMINAL_STATES.includes(job.state)) return undefined;
    const timer = window.setInterval(async () => {
      try {
        const next = await api.job(job.id);
        setJob(next);
        if (next.state === 'completed') {
          const page = await api.memoryRegionArtifacts(dump.id);
          setArtifacts(page.items);
          const artifact = page.items.find((item) => item.id === next.result_ref);
          if (artifact) await loadArtifact(artifact, 0);
        }
      } catch (failure) {
        setError(failure.message);
      }
    }, 450);
    return () => window.clearInterval(timer);
  }, [job, dump.id]);

  function reviewRegion(region) {
    setSelectedRegion(region);
    setAcknowledged(false);
    setJob(null);
    setError(null);
  }

  async function inspect() {
    setError(null);
    setSelectedArtifact(null);
    setHexPage(null);
    setDisassembly(null);
    try {
      setJob(await api.inspectMemoryRegion(dump.id, selectedRegion, architecture));
    } catch (failure) {
      setError(failure.message);
    }
  }

  async function downloadArtifact() {
    setError(null);
    try {
      await api.downloadMemoryRegionArtifact(dump.id, selectedArtifact);
    } catch (failure) {
      setError(failure.message);
    }
  }

  const providerReady = Boolean(volatility?.available);
  const canInspect = providerReady
    && selectedRegion?.pid != null
    && selectedRegion?.source_provider === 'volatility3'
    && acknowledged
    && (!job || TERMINAL_STATES.includes(job.state));
  const pageOffset = hexPage?.offset || 0;
  const nextOffset = pageOffset + (hexPage?.length || 0);

  return (
    <div className="memory-region-view">
      <div className="memory-region-list">
        {regions.length ? (
          <div className="memory-table-scroll">
            <table className="data">
              <thead><tr><th>PID</th><th>Range</th><th>Protection</th><th>Private</th><th>Mapped file</th><th>Assessment</th><th>Action</th></tr></thead>
              <tbody>{regions.map((item) => (
                <tr className={item.suspicious ? 'suspicious-row' : ''} key={`${item.pid ?? 'unknown'}-${item.start_hex || item.start}`}>
                  <td className="mono">{item.pid ?? '—'}</td>
                  <td className="mono">{regionLabel(item)}</td>
                  <td>{item.protection}</td>
                  <td>{item.private_memory == null ? 'unavailable' : item.private_memory ? 'yes' : 'no'}</td>
                  <td>{item.mapped_file || '—'}</td>
                  <td>{item.reason || 'No signal'}</td>
                  <td><button className="table-action" type="button" onClick={() => reviewRegion(item)}>Review</button></td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        ) : <Empty label="Memory map unavailable" />}
      </div>

      <section className="region-inspector-panel" aria-label="Memory region inspector">
        <div className="region-inspector-heading">
          <div><span className="eyebrow">EXPLICIT EXTRACTION</span><h3>Region inspector</h3></div>
          <StatusDot status={providerReady ? 'ready' : 'disabled'} label={providerReady ? 'provider ready' : 'disabled'} />
        </div>
        <ErrorBanner error={error} />
        {!selectedRegion ? (
          <Empty label="Select a VAD to inspect" detail="Reviewing metadata does not extract bytes. Choose a row to prepare an explicit bounded request." />
        ) : (
          <div className="region-request">
            <div className="region-selection">
              <span>PID {selectedRegion.pid ?? 'unavailable'}</span>
              <strong className="mono">{regionLabel(selectedRegion)}</strong>
              <small>{selectedRegion.protection} · {selectedRegion.source_provider}</small>
            </div>
            <label>Decode architecture
              <select aria-label="Memory region architecture" value={architecture} onChange={(event) => setArchitecture(event.target.value)}>
                <option value="x86_64">x86-64</option>
                <option value="x86">x86</option>
              </select>
            </label>
            <label className="region-acknowledgement">
              <input type="checkbox" checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)} />
              <span>I understand this creates a separate bounded artifact from the selected VAD.</span>
            </label>
            <button className="btn" type="button" disabled={!canInspect} onClick={inspect}>Extract & inspect</button>
            {!providerReady && <p>Install and configure Volatility 3 to enable extraction. Metadata remains available.</p>}
            {selectedRegion.source_provider !== 'volatility3' && <p>Only VADs verified by the Volatility provider can be extracted.</p>}
          </div>
        )}

        {job && (
          <div className="region-job" role="status">
            <div><strong>{job.message}</strong><span>{job.progress}% · {job.state}</span></div>
            <div className="progressbar"><span style={{ width: `${job.progress}%` }} /></div>
            {job.error && <ErrorBanner error={job.error} />}
          </div>
        )}

        {artifacts.length > 0 && (
          <div className="region-artifact-list">
            <div><h4>Extracted artifacts</h4><span>{artifacts.length}</span></div>
            {artifacts.map((artifact) => (
              <button className={selectedArtifact?.id === artifact.id ? 'active' : ''} type="button" key={artifact.id} onClick={() => loadArtifact(artifact, 0)}>
                <span className="mono">PID {artifact.pid} · {artifact.start_hex}</span>
                <small>{artifact.size.toLocaleString()} B · {artifact.content_sha256.slice(0, 12)}…</small>
              </button>
            ))}
          </div>
        )}

        {busy && <Loading label="Loading bounded region view…" />}
        {selectedArtifact && hexPage && disassembly && !busy && (
          <div className="region-artifact-view">
            <div className="region-artifact-toolbar">
              <div><strong>Region artifact ready</strong><span>{selectedArtifact.architecture} · SHA-256 {selectedArtifact.content_sha256.slice(0, 16)}…</span></div>
              <button className="btn secondary" type="button" onClick={downloadArtifact}>Download bytes</button>
            </div>
            <div className="region-code-grid">
              <section>
                <div className="region-pane-heading"><h4>Hex</h4><span>{hexPage.base_address_hex} + {hexPage.offset}</span></div>
                <div className="region-hex" role="region" aria-label="Extracted region hex">
                  {hexPage.rows.map((row) => <div className="region-hex-row" key={row.offset}><span>{row.address_hex}</span><code>{row.hex_bytes.join(' ')}</code><em>{row.ascii}</em></div>)}
                </div>
                <div className="region-page-controls">
                  <button className="btn secondary" type="button" disabled={pageOffset === 0} onClick={() => loadArtifact(selectedArtifact, Math.max(0, pageOffset - 256))}>Previous</button>
                  <span>{pageOffset.toLocaleString()}–{Math.min(nextOffset, hexPage.total_size).toLocaleString()} / {hexPage.total_size.toLocaleString()} B</span>
                  <button className="btn secondary" type="button" disabled={nextOffset >= hexPage.total_size} onClick={() => loadArtifact(selectedArtifact, nextOffset)}>Next</button>
                </div>
              </section>
              <section>
                <div className="region-pane-heading"><h4>Disassembly</h4><span>Estimated decode · {disassembly.architecture}</span></div>
                <div className="region-disassembly" role="region" aria-label="Extracted region disassembly">
                  {disassembly.instructions.length ? disassembly.instructions.map((instruction) => (
                    <div key={instruction.address_hex}><span>{instruction.address_hex}</span><code>{instruction.bytes_hex}</code><b>{instruction.mnemonic}</b><em>{instruction.op_str}</em></div>
                  )) : <span className="region-no-code">No instructions decoded at this offset.</span>}
                </div>
              </section>
            </div>
            <p className="region-caveat">Disassembly is an architecture-dependent interpretation of extracted bytes, not proof that the region executed.</p>
          </div>
        )}
      </section>
    </div>
  );
}
