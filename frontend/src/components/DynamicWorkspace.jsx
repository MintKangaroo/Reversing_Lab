import { useEffect, useState } from 'react';
import { api } from '../api.js';
import { Empty, ErrorBanner, StatusDot } from './common.jsx';

const GUARDS = [
  ['provider_configured', 'Sandbox provider configured'],
  ['isolated_worker_available', 'Isolated worker available'],
  ['resource_limits_configured', 'CPU, memory, and process limits configured'],
  ['timeout_configured', 'Execution timeout configured'],
  ['network_policy_configured', 'Network policy configured'],
  ['writable_workspace_configured', 'Private writable workspace configured'],
  ['sample_path_validated', 'Content-addressed sample path validated'],
  ['user_acknowledged', 'Analyst acknowledgement completed'],
];

export function DynamicWorkspace({ sample }) {
  const [acknowledged, setAcknowledged] = useState(false);
  const [readiness, setReadiness] = useState(null);
  const [run, setRun] = useState(null);
  const [events, setEvents] = useState(null);
  const [filter, setFilter] = useState('');
  const [error, setError] = useState(null);

  useEffect(() => {
    let active = true;
    setReadiness(null);
    api.dynamicReadiness(sample?.sha256, acknowledged)
      .then((result) => active && (setReadiness(result), setError(null)))
      .catch((failure) => active && setError(failure.message));
    return () => { active = false; };
  }, [sample, acknowledged]);

  useEffect(() => {
    if (!run || ['completed', 'failed', 'cancelled'].includes(run.job.state)) return undefined;
    const timer = window.setInterval(async () => {
      try {
        const next = await api.dynamicRun(run.id);
        setRun(next);
        if (next.job.state === 'completed') {
          setEvents(await api.dynamicEvents(run.id, { limit: 500 }));
        }
      } catch (failure) {
        setError(failure.message);
      }
    }, 500);
    return () => window.clearInterval(timer);
  }, [run]);

  async function start() {
    setError(null);
    setEvents(null);
    try {
      setRun(await api.startDynamicAnalysis(sample.sha256));
    } catch (failure) {
      setError(failure.message);
    }
  }

  async function cancel() {
    try {
      setRun(await api.cancelDynamicRun(run.id));
    } catch (failure) {
      setError(failure.message);
    }
  }

  async function exportReport(format) {
    setError(null);
    try {
      await api.downloadDynamicReport(run.id, format);
    } catch (failure) {
      setError(failure.message);
    }
  }

  const shown = (events?.items || []).filter((item) => {
    if (!filter) return true;
    return JSON.stringify(item).toLowerCase().includes(filter.toLowerCase());
  });

  return (
    <div className="page-scroll dynamic-workspace">
      <div className="page-title">
        <div>
          <span className="eyebrow">OPT-IN · ISOLATED PROVIDER ONLY</span>
          <h1>Dynamic analysis</h1>
          <p>The API never executes uploaded binaries. A separately managed VM sandbox is recommended for real malware; Docker alone is not described as a strong isolation boundary.</p>
        </div>
        <StatusDot status={readiness?.ready ? 'ready' : 'disabled'} label={readiness?.ready ? 'Ready' : 'Execution locked'} />
      </div>
      <ErrorBanner error={error} />
      {!sample ? (
        <Empty label="Select a sample first" detail="Choose a content-addressed sample in the explorer before evaluating sandbox readiness." />
      ) : (
        <>
          <div className="sandbox-banner">
            <div><span className="eyebrow">SELECTED SAMPLE</span><strong>{sample.filename}</strong><code>{sample.sha256}</code></div>
            <span className="badge neutral">{sample.binary_format} · {sample.size.toLocaleString()} B</span>
          </div>
          {readiness && (
            <>
              <section className="guardrail-card">
                <div className="guardrail-heading">
                  <div><h2>Sandbox guardrails</h2><p>{readiness.warning}</p></div>
                  <span className={`badge ${readiness.ready ? 'on' : 'off'}`}>{readiness.provider}</span>
                </div>
                <div className="guardrail-grid">
                  {GUARDS.map(([key, label]) => (
                    <div key={key} className={readiness[key] ? 'passed' : 'blocked'}>
                      <span aria-hidden="true">{readiness[key] ? '✓' : '×'}</span>{label}
                    </div>
                  ))}
                </div>
                {readiness.reasons.length > 0 && <ul className="readiness-reasons">{readiness.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>}
              </section>
              <section className="sandbox-policy">
                <div>
                  <h2>Mandatory default policy</h2>
                  <div className="policy-chips">
                    <span>network blocked</span><span>read-only base</span><span>temporary overlay</span>
                    <span>no host mounts</span><span>no Docker socket</span><span>not privileged</span>
                    <span>no host PID/network</span><span>destroy after run</span>
                  </div>
                  <label className="acknowledgement">
                    <input type="checkbox" checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)} />
                    I am authorized to analyze this sample and understand the configured isolation limits.
                  </label>
                </div>
                {!run ? <button className="btn" disabled={!readiness.ready} onClick={start}>Run in isolated provider</button> : !['completed', 'failed', 'cancelled'].includes(run.job.state) ? <button className="btn secondary" onClick={cancel}>Cancel run</button> : <span className={`badge ${run.job.state === 'completed' ? 'on' : 'off'}`}>{run.job.state}</span>}
              </section>
            </>
          )}
          {run && (
            <section className="job-progress">
              <div><strong>{run.job.message}</strong><span>{run.job.progress}% · {run.provider}</span></div>
              <div className="progressbar"><span style={{ width: `${run.job.progress}%` }} /></div>
              {run.job.error && <ErrorBanner error={run.job.error} />}
            </section>
          )}
          {events && (
            <section className="timeline-panel">
              <div className="timeline-toolbar">
                <div><span className="eyebrow">PROVIDER EVENTS</span><h2>Dynamic timeline</h2></div>
                <div className="timeline-toolbar-actions">
                  <input className="text" type="search" value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Filter process, API, file, registry, network…" />
                  <div className="report-actions">
                    {['json', 'markdown', 'html'].map((format) => (
                      <button className="btn secondary" type="button" key={format} onClick={() => exportReport(format)}>
                        Export {format.toUpperCase()}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
              {events.warnings.map((warning) => <div className="decompiler-notice" key={warning}><strong>Provider note</strong><span>{warning}</span></div>)}
              <div className="timeline-list">
                {shown.map((item, index) => (
                  <article key={`${item.timestamp}-${index}`}>
                    <time>{item.timestamp}</time>
                    <span className={`event-category category-${item.category}`}>{item.category}</span>
                    <div><strong>{item.operation}</strong><p>{item.target || '—'} · {item.result}</p><small>{item.arguments_summary}</small></div>
                    <span className={`severity-label ${item.severity}`}>{item.severity}</span>
                  </article>
                ))}
              </div>
              {events.unavailable_events.length > 0 && <div className="unavailable-list"><h3>Unavailable from provider</h3>{events.unavailable_events.map((item) => <span key={item}>{item}</span>)}</div>}
            </section>
          )}
        </>
      )}
    </div>
  );
}
