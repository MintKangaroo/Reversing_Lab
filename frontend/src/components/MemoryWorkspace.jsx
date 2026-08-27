import { useEffect, useRef, useState } from 'react';
import { api, hex } from '../api.js';
import { Empty, ErrorBanner, Loading, StatusDot } from './common.jsx';
import { MemoryRegionInspector } from './MemoryRegionInspector.jsx';

function endpoint(address, port) {
  if (!address) return '—';
  const host = address.includes(':') && !address.startsWith('[') ? `[${address}]` : address;
  return port == null ? host : `${host}:${port}`;
}

export function MemoryWorkspace() {
  const inputRef = useRef(null);
  const [dump, setDump] = useState(null);
  const [volatility, setVolatility] = useState(null);
  const [useVolatility, setUseVolatility] = useState(true);
  const [job, setJob] = useState(null);
  const [summary, setSummary] = useState(null);
  const [processes, setProcesses] = useState([]);
  const [modules, setModules] = useState([]);
  const [handles, setHandles] = useState([]);
  const [handleTotal, setHandleTotal] = useState(0);
  const [handleFilters, setHandleFilters] = useState({ pid: '', object_type: '', keyword: '' });
  const [handleBusy, setHandleBusy] = useState(false);
  const [threads, setThreads] = useState([]);
  const [threadTotal, setThreadTotal] = useState(0);
  const [threadFilters, setThreadFilters] = useState({ pid: '', tid: '', keyword: '' });
  const [threadBusy, setThreadBusy] = useState(false);
  const [regions, setRegions] = useState([]);
  const [network, setNetwork] = useState([]);
  const [networkTotal, setNetworkTotal] = useState(0);
  const [networkFilters, setNetworkFilters] = useState({ pid: '', protocol: '', state: '', keyword: '' });
  const [networkBusy, setNetworkBusy] = useState(false);
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
          const [overview, processPage, modulePage, handlePage, threadPage, regionPage, networkPage, resultFindings] = await Promise.all([
            api.memorySummary(dump.id),
            api.memoryProcesses(dump.id),
            api.memoryModules(dump.id),
            api.memoryHandles(dump.id),
            api.memoryThreads(dump.id),
            api.memoryRegions(dump.id),
            api.memoryNetwork(dump.id),
            api.memoryFindings(dump.id),
          ]);
          setSummary(overview);
          setProcesses(processPage.items);
          setModules(modulePage.items);
          setHandles(handlePage.items);
          setHandleTotal(handlePage.total);
          setThreads(threadPage.items);
          setThreadTotal(threadPage.total);
          setRegions(regionPage.items);
          setNetwork(networkPage.items);
          setNetworkTotal(networkPage.total);
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
    setProcesses([]);
    setModules([]);
    setHandles([]);
    setHandleTotal(0);
    setHandleFilters({ pid: '', object_type: '', keyword: '' });
    setThreads([]);
    setThreadTotal(0);
    setThreadFilters({ pid: '', tid: '', keyword: '' });
    setRegions([]);
    setNetwork([]);
    setNetworkTotal(0);
    setNetworkFilters({ pid: '', protocol: '', state: '', keyword: '' });
    setFindings([]);
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

  async function applyNetworkFilters(event) {
    event.preventDefault();
    setNetworkBusy(true);
    setError(null);
    try {
      const params = Object.fromEntries(
        Object.entries(networkFilters).filter(([, value]) => value !== ''),
      );
      const page = await api.memoryNetwork(dump.id, params);
      setNetwork(page.items);
      setNetworkTotal(page.total);
    } catch (failure) {
      setError(failure.message);
    } finally {
      setNetworkBusy(false);
    }
  }

  async function applyHandleFilters(event) {
    event.preventDefault();
    setHandleBusy(true);
    setError(null);
    try {
      const params = Object.fromEntries(
        Object.entries(handleFilters).filter(([, value]) => value !== ''),
      );
      const page = await api.memoryHandles(dump.id, params);
      setHandles(page.items);
      setHandleTotal(page.total);
    } catch (failure) {
      setError(failure.message);
    } finally {
      setHandleBusy(false);
    }
  }

  async function applyThreadFilters(event) {
    event.preventDefault();
    setThreadBusy(true);
    setError(null);
    try {
      const params = Object.fromEntries(
        Object.entries(threadFilters).filter(([, value]) => value !== ''),
      );
      const page = await api.memoryThreads(dump.id, params);
      setThreads(page.items);
      setThreadTotal(page.total);
    } catch (failure) {
      setError(failure.message);
    } finally {
      setThreadBusy(false);
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
                {['overview', 'processes', 'threads', 'modules', 'handles', 'regions', 'network', 'findings'].map((item) => <button key={item} className={tab === item ? 'active' : ''} onClick={() => setTab(item)}>{item} {item === 'processes' ? `(${summary.process_count})` : item === 'threads' ? `(${summary.thread_count})` : item === 'modules' ? `(${summary.module_count})` : item === 'handles' ? `(${summary.handle_count})` : item === 'regions' ? `(${summary.region_count})` : item === 'network' ? `(${summary.network_count})` : item === 'findings' ? `(${summary.finding_count})` : ''}</button>)}
              </div>
              {tab === 'overview' && (
                <div className="memory-overview">
                  <div className="metric-grid">
                    <div className="metric-card"><span>Provider</span><strong>{summary.provider}</strong><small>{summary.process_count} processes · {summary.thread_count} threads · {summary.module_count} modules · {summary.handle_count} handles · {summary.region_count} regions · {summary.network_count} sockets</small></div>
                    <div className="metric-card tone-violet"><span>Strings</span><strong>{summary.string_count}</strong><small>Bounded extraction</small></div>
                    <div className="metric-card tone-green"><span>IOCs</span><strong>{summary.urls.length + summary.ip_addresses.length + summary.domains.length}</strong><small>URLs · IPs · domains</small></div>
                    <div className="metric-card tone-red"><span>Findings</span><strong>{summary.finding_count}</strong><small>Review required</small></div>
                  </div>
                  <div className="memory-iocs"><h3>Network artifacts</h3>{[...summary.urls, ...summary.ip_addresses, ...summary.domains].map((item) => <code key={item}>{item}</code>)}</div>
                  {summary.warnings.length > 0 && <div className="memory-warnings"><h3>Provider warnings</h3>{summary.warnings.map((item) => <span key={item}>{item}</span>)}</div>}
                  <div className="unavailable-list"><h3>Unavailable from this provider</h3>{summary.unavailable.map((item) => <span key={item}>{item}</span>)}</div>
                </div>
              )}
              {tab === 'processes' && (processes.length ? <div className="memory-table-scroll"><table className="data"><thead><tr><th>PID</th><th>PPID</th><th>Process tree</th><th>Command line</th><th>Threads</th><th>Modules</th><th>Provider</th></tr></thead><tbody>{processes.map((item) => <tr key={item.pid}><td className="mono">{item.pid}</td><td className="mono">{item.ppid ?? '—'}</td><td><span className="process-tree-name" style={{ paddingLeft: `${Math.min(item.tree_depth ?? 0, 12) * 14}px` }}>{item.tree_depth > 0 ? '↳ ' : ''}{item.name}</span>{item.orphaned && <span className="memory-orphan">orphan</span>}</td><td className="mono">{item.command_line || 'unavailable'}</td><td>{item.thread_count ?? 'unavailable'}</td><td>{item.module_count ?? 'unavailable'}</td><td>{item.source_provider}</td></tr>)}</tbody></table></div> : <Empty label="Process list unavailable" />)}
              {tab === 'threads' && <div className="memory-threads-view"><form className="memory-filter-bar" onSubmit={applyThreadFilters}><label>PID<input aria-label="Filter threads by PID" type="number" min="0" value={threadFilters.pid} onChange={(event) => setThreadFilters({ ...threadFilters, pid: event.target.value })} /></label><label>TID<input aria-label="Filter threads by TID" type="number" min="0" value={threadFilters.tid} onChange={(event) => setThreadFilters({ ...threadFilters, tid: event.target.value })} /></label><label>Keyword<input aria-label="Filter threads by keyword" placeholder="path, timestamp, hex address" value={threadFilters.keyword} onChange={(event) => setThreadFilters({ ...threadFilters, keyword: event.target.value })} /></label><button className="btn secondary" disabled={threadBusy}>{threadBusy ? 'Filtering…' : 'Apply filters'}</button><span>{threadTotal.toLocaleString()} matching records</span></form>{threads.length ? <div className="memory-table-scroll"><table className="data"><thead><tr><th>PID / TID</th><th>Process</th><th>ETHREAD</th><th>Kernel start</th><th>Win32 start</th><th>Lifetime</th><th>Provider</th></tr></thead><tbody>{threads.map((item, index) => <tr key={item.object_offset_hex || `${item.pid}-${item.tid}-${index}`}><td className="mono">{item.pid} / {item.tid}</td><td>{item.process_name || 'unknown'}</td><td className="mono">{item.object_offset_hex || '—'}</td><td><span className="mono">{item.start_address_hex || '—'}</span><small className="mono">{item.start_path || 'unresolved'}</small></td><td><span className="mono">{item.win32_start_address_hex || '—'}</span><small className="mono">{item.win32_start_path || 'unresolved'}</small></td><td><span>{item.create_time || 'unknown'}</span><small>{item.exit_time ? `Exited ${item.exit_time}` : 'No exit time observed'}</small></td><td>{item.source_provider}</td></tr>)}</tbody></table></div> : <Empty label="No thread records match this filter" />}</div>}
              {tab === 'modules' && (modules.length ? <div className="memory-table-scroll"><table className="data"><thead><tr><th>PID</th><th>Base</th><th>Size</th><th>Name</th><th>Path</th><th>Provider</th></tr></thead><tbody>{modules.map((item) => <tr key={`${item.pid}-${item.base_address_hex || item.base_address}`}><td className="mono">{item.pid}</td><td className="mono">{item.base_address_hex || hex(item.base_address)}</td><td>{item.size.toLocaleString()} B</td><td>{item.name}</td><td className="mono">{item.path || '—'}</td><td>{item.source_provider}</td></tr>)}</tbody></table></div> : <Empty label="Loaded modules unavailable" />)}
              {tab === 'handles' && <div className="memory-handles-view"><form className="memory-filter-bar" onSubmit={applyHandleFilters}><label>PID<input aria-label="Filter handles by PID" type="number" min="0" value={handleFilters.pid} onChange={(event) => setHandleFilters({ ...handleFilters, pid: event.target.value })} /></label><label>Object type<input aria-label="Filter handles by object type" placeholder="File" value={handleFilters.object_type} onChange={(event) => setHandleFilters({ ...handleFilters, object_type: event.target.value })} /></label><label>Keyword<input aria-label="Filter handles by keyword" placeholder="name, process, hex value" value={handleFilters.keyword} onChange={(event) => setHandleFilters({ ...handleFilters, keyword: event.target.value })} /></label><button className="btn secondary" disabled={handleBusy}>{handleBusy ? 'Filtering…' : 'Apply filters'}</button><span>{handleTotal.toLocaleString()} matching records</span></form>{handles.length ? <div className="memory-table-scroll"><table className="data"><thead><tr><th>PID / Process</th><th>Type</th><th>Handle</th><th>Object offset</th><th>Access</th><th>Name</th><th>Provider</th></tr></thead><tbody>{handles.map((item, index) => <tr key={item.object_offset_hex || `${item.pid}-${item.handle_value_hex}-${index}`}><td><span className="mono">{item.pid}</span> · {item.process_name || 'unknown'}</td><td>{item.object_type}</td><td className="mono">{item.handle_value_hex || '—'}</td><td className="mono">{item.object_offset_hex || '—'}</td><td className="mono">{item.granted_access_hex || '—'}</td><td className="mono">{item.name || 'unnamed'}</td><td>{item.source_provider}</td></tr>)}</tbody></table></div> : <Empty label="No handle records match this filter" />}</div>}
              {tab === 'regions' && <MemoryRegionInspector dump={dump} regions={regions} volatility={volatility} />}
              {tab === 'network' && <div className="memory-network-view"><form className="memory-filter-bar" onSubmit={applyNetworkFilters}><label>PID<input aria-label="Filter network by PID" type="number" min="0" value={networkFilters.pid} onChange={(event) => setNetworkFilters({ ...networkFilters, pid: event.target.value })} /></label><label>Protocol<input aria-label="Filter network by protocol" placeholder="TCPV4" value={networkFilters.protocol} onChange={(event) => setNetworkFilters({ ...networkFilters, protocol: event.target.value })} /></label><label>State<input aria-label="Filter network by state" placeholder="ESTABLISHED" value={networkFilters.state} onChange={(event) => setNetworkFilters({ ...networkFilters, state: event.target.value })} /></label><label>Keyword<input aria-label="Filter network by keyword" placeholder="IP, port, process" value={networkFilters.keyword} onChange={(event) => setNetworkFilters({ ...networkFilters, keyword: event.target.value })} /></label><button className="btn secondary" disabled={networkBusy}>{networkBusy ? 'Filtering…' : 'Apply filters'}</button><span>{networkTotal.toLocaleString()} matching records</span></form>{network.length ? <div className="memory-table-scroll"><table className="data"><thead><tr><th>PID / Process</th><th>Protocol</th><th>Local</th><th>Remote</th><th>State</th><th>Created</th></tr></thead><tbody>{network.map((item, index) => <tr key={item.offset_hex || `${item.pid}-${item.protocol}-${index}`}><td><span className="mono">{item.pid ?? '—'}</span> · {item.process_name || 'unattributed'}</td><td>{item.protocol}</td><td className="mono">{endpoint(item.local_address, item.local_port)}</td><td className="mono">{endpoint(item.remote_address, item.remote_port)}</td><td>{item.state || 'unavailable'}</td><td>{item.created_at || '—'}</td></tr>)}</tbody></table></div> : <Empty label="No network records match this filter" />}</div>}
              {tab === 'findings' && (findings.length ? findings.map((item) => <article className={`finding-card severity-${item.severity}`} key={item.id}><div className="finding-heading"><div><h2>{item.title}</h2><span className={`severity-label ${item.severity}`}>{item.severity}</span></div><span>{Math.round(item.confidence * 100)}%</span></div><p>{item.summary}</p>{item.evidence.length > 0 && <details><summary>Evidence ({item.evidence.length})</summary><ul className="evidence-list">{item.evidence.map((evidence) => <li key={evidence}>◆ {evidence}</li>)}</ul></details>}<div className="caveat"><b>False-positive caveat</b>{item.false_positive_note}</div></article>) : <Empty label="No memory findings" />)}
            </div>
          )}
        </>
      )}
    </div>
  );
}
