import { useEffect, useRef, useState } from 'react';
import { api, hex } from '../api.js';
import { Empty, ErrorBanner, Loading, StatusDot } from './common.jsx';

export function MemoryWorkspace() {
  const inputRef = useRef(null);
  const [dump, setDump] = useState(null);
  const [volatility, setVolatility] = useState(null);
  const [useVolatility, setUseVolatility] = useState(true);
  const [job, setJob] = useState(null);
  const [summary, setSummary] = useState(null);
  const [processes, setProcesses] = useState([]);
  const [regions, setRegions] = useState([]);
  const [findings, setFindings] = useState([]);
  const [tab, setTab] = useState('overview');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    api.toolingDetail('volatility3')
      .then(setVolatility)
      .catch((failure) => setError(failure.message));
  }, []);

  useEffect(() => {
    if (!job || ['completed', 'failed', 'cancelled'].includes(job.state)) return undefined;
    const timer = window.setInterval(async () => {
      try {
        const next = await api.job(job.id);
        setJob(next);
        if (next.state === 'completed') {
          const [overview, processPage, regionPage, resultFindings] = await Promise.all([
            api.memorySummary(dump.id),
            api.memoryProcesses(dump.id),
            api.memoryRegions(dump.id),
            api.memoryFindings(dump.id),
          ]);
          setSummary(overview);
          setProcesses(processPage.items);
          setRegions(regionPage.items);
          setFindings(resultFindings);
        }
      } catch (failure) {
        setError(failure.message);
      }
    }, 450);
    return () => window.clearInterval(timer);
  }, [job, dump]);

  async function upload(file) {
    setBusy(true);
    setError(null);
    setSummary(null);
    setJob(null);
    try {
      setDump(await api.uploadMemoryDump(file));
    } catch (failure) {
      setError(failure.message);
    } finally {
      setBusy(false);
    }
  }

  async function analyze() {
    setError(null);
    try {
      setJob(await api.startMemoryAnalysis(dump.id, useVolatility));
    } catch (failure) {
      setError(failure.message);
    }
  }

  async function cancel() {
    try {
      setJob(await api.cancelJob(job.id));
    } catch (failure) {
      setError(failure.message);
    }
  }

  return (
    <div className="page-scroll memory-workspace">
      <input ref={inputRef} type="file" hidden onChange={(event) => event.target.files?.[0] && upload(event.target.files[0])} />
      <div className="page-title">
        <div>
          <span className="eyebrow">OFFLINE DUMP TRIAGE</span>
          <h1>Memory analysis</h1>
          <p>Inspect a dump as hostile data. Volatility runs only server-selected plugins; no sample process is executed.</p>
        </div>
        <button className="btn" disabled={busy} onClick={() => inputRef.current?.click()}>{busy ? 'Uploading…' : '＋ Upload dump'}</button>
      </div>
      <ErrorBanner error={error} />
      {!dump ? (
        <Empty label="No memory dump selected" detail="Windows dumps, Linux core files, process images, and raw memory regions are accepted within the configured size bound." action={<button className="btn secondary" onClick={() => inputRef.current?.click()}>Choose dump</button>} />
      ) : (
        <>
          <div className="memory-header">
            <div><span>Dump</span><strong>{dump.filename}</strong></div>
            <div><span>Format</span><strong>{dump.dump_format}</strong></div>
            <div><span>Size</span><strong>{dump.size.toLocaleString()} B</strong></div>
            <div><span>SHA-256</span><strong className="mono">{dump.sha256.slice(0, 16)}…</strong></div>
          </div>
          <section className="memory-run-card">
            <div>
              <h2>Analysis provider</h2>
              <StatusDot status={volatility?.available ? 'ready' : 'disabled'} label={volatility?.available ? 'Volatility 3 available' : 'Volatility 3 unavailable'} />
              <label>
                <input type="checkbox" checked={useVolatility} disabled={!volatility?.available} onChange={(event) => setUseVolatility(event.target.checked)} />
                Use allowlisted Volatility plugins when compatible
              </label>
              {!volatility?.available && <p>Basic metadata, strings, URLs, IPs, domains, and possible secret material remain available.</p>}
            </div>
            {!job ? <button className="btn" onClick={analyze}>Start analysis</button> : !['completed', 'failed', 'cancelled'].includes(job.state) ? <button className="btn secondary" onClick={cancel}>Cancel job</button> : <span className={`badge ${job.state === 'completed' ? 'on' : 'off'}`}>{job.state}</span>}
          </section>
          {job && (
            <section className="job-progress">
              <div><strong>{job.message}</strong><span>{job.progress}% · {job.state}</span></div>
              <div className="progressbar"><span style={{ width: `${job.progress}%` }} /></div>
              {job.error && <ErrorBanner error={job.error} />}
            </section>
          )}
          {job && !summary && !['failed', 'cancelled'].includes(job.state) && <Loading label="Memory analysis job is running…" />}
          {summary && (
            <div className="memory-results">
              <div className="result-tabs">
                {['overview', 'processes', 'regions', 'findings'].map((item) => <button key={item} className={tab === item ? 'active' : ''} onClick={() => setTab(item)}>{item} {item === 'processes' ? `(${processes.length})` : item === 'regions' ? `(${regions.length})` : item === 'findings' ? `(${findings.length})` : ''}</button>)}
              </div>
              {tab === 'overview' && (
                <div className="memory-overview">
                  <div className="metric-grid">
                    <div className="metric-card"><span>Provider</span><strong>{summary.provider}</strong><small>{summary.metadata.os_guess || 'OS unknown'}</small></div>
                    <div className="metric-card tone-violet"><span>Strings</span><strong>{summary.string_count}</strong><small>Bounded extraction</small></div>
                    <div className="metric-card tone-green"><span>IOCs</span><strong>{summary.urls.length + summary.ip_addresses.length + summary.domains.length}</strong><small>URLs · IPs · domains</small></div>
                    <div className="metric-card tone-red"><span>Findings</span><strong>{summary.finding_count}</strong><small>Review required</small></div>
                  </div>
                  <div className="memory-iocs"><h3>Network artifacts</h3>{[...summary.urls, ...summary.ip_addresses, ...summary.domains].map((item) => <code key={item}>{item}</code>)}</div>
                  <div className="unavailable-list"><h3>Unavailable from this provider</h3>{summary.unavailable.map((item) => <span key={item}>{item}</span>)}</div>
                </div>
              )}
              {tab === 'processes' && (processes.length ? <table className="data"><thead><tr><th>PID</th><th>PPID</th><th>Name</th><th>Threads</th><th>Provider</th></tr></thead><tbody>{processes.map((item) => <tr key={item.pid}><td className="mono">{item.pid}</td><td className="mono">{item.ppid ?? '—'}</td><td>{item.name}</td><td>{item.thread_count ?? 'unavailable'}</td><td>{item.source_provider}</td></tr>)}</tbody></table> : <Empty label="Process list unavailable" />)}
              {tab === 'regions' && (regions.length ? <table className="data"><thead><tr><th>Range</th><th>Protection</th><th>Mapped file</th><th>Assessment</th></tr></thead><tbody>{regions.map((item) => <tr key={item.start}><td className="mono">{hex(item.start)}–{hex(item.end)}</td><td>{item.protection}</td><td>{item.mapped_file || '—'}</td><td>{item.reason || 'No signal'}</td></tr>)}</tbody></table> : <Empty label="Memory map unavailable" />)}
              {tab === 'findings' && (findings.length ? findings.map((item) => <article className={`finding-card severity-${item.severity}`} key={item.id}><div className="finding-heading"><h2>{item.title}</h2><span>{Math.round(item.confidence * 100)}%</span></div><p>{item.summary}</p><div className="caveat"><b>False-positive caveat</b>{item.false_positive_note}</div></article>) : <Empty label="No memory findings" />)}
            </div>
          )}
        </>
      )}
    </div>
  );
}
