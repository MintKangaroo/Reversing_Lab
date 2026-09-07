import { useEffect, useState } from 'react';
import { api } from '../api.js';
import { Empty, ErrorBanner, Loading, ProvenanceBadge } from './common.jsx';

export function ReportsWorkspace({ sample }) {
  const [preview, setPreview] = useState(null);
  const [runs, setRuns] = useState([]);
  const [error, setError] = useState(null);

  async function exportReport(format) {
    try {
      setError(null);
      await api.downloadReport(sample.sha256, format);
    } catch (failure) {
      setError(failure.message);
    }
  }

  async function exportRunReport(runId, format) {
    try {
      setError(null);
      await api.downloadDynamicReport(runId, format);
    } catch (failure) {
      setError(failure.message);
    }
  }

  useEffect(() => {
    if (!sample) {
      setPreview(null);
      setRuns([]);
      setError(null);
      return;
    }
    let active = true;
    setPreview(null);
    setRuns([]);
    api.report(sample.sha256)
      .then((result) => active && setPreview(result))
      .catch((failure) => active && setError(failure.message));
    api.dynamicRuns(sample.sha256)
      .then((result) => active && setRuns(result))
      .catch(() => active && setRuns([]));
    return () => { active = false; };
  }, [sample]);

  return (
    <div className="page-scroll reports-workspace">
      <div className="page-title">
        <div><span className="eyebrow">EVIDENCE-LINKED EXPORT</span><h1>Analysis reports</h1><p>Export the same bounded analysis model as JSON, Markdown, or standalone HTML.</p></div>
      </div>
      <ErrorBanner error={error} />
      {!sample ? <Empty label="Select a sample to generate a report" detail="Reports never execute the sample and identify unavailable dynamic or memory evidence." /> : !preview ? (
        <Loading label="Building report preview…" />
      ) : (
        <>
          <section className="report-hero">
            <div><ProvenanceBadge kind="verified" /><h2>{sample.filename}</h2><code>{sample.sha256}</code></div>
            <div className="report-actions">
              {['json', 'markdown', 'html'].map((format) => (
                <button className="btn secondary" type="button" key={format} onClick={() => exportReport(format)}>
                  Export {format.toUpperCase()}
                </button>
              ))}
            </div>
          </section>
          <div className="metric-grid report-metrics">
            <div><span>Functions</span><strong>{preview.executive_summary.function_count}</strong></div>
            <div><span>Findings</span><strong>{preview.executive_summary.finding_count}</strong></div>
            <div><span>Packing</span><strong>{preview.packer_analysis.likely_packed ? 'Likely' : 'Not indicated'}</strong></div>
            <div><span>Embedded strings</span><strong>{preview.strings_and_iocs.total_strings}</strong></div>
          </div>
          <div className="report-sections">
            {[
              ['Sample & hashes', `${preview.sample_metadata.format} · ${preview.sample_metadata.architecture} · ${preview.hashes.sha256.slice(0, 16)}…`],
              ['Static call flow', `${preview.static_call_flow.program_flow.stages.length} evidence-linked stages`],
              ['Dynamic timeline', preview.dynamic_timeline.message],
              ['Memory findings', preview.memory_findings.message],
              ['Decompiler limits', 'Pseudo-C is an estimate, not recovered original source.'],
              ['Analyst overlays', `${preview.analyst_notes.annotations.length} annotations · ${preview.analyst_notes.bookmarks.length} bookmarks`],
            ].map(([title, detail]) => <article key={title}><h3>{title}</h3><p>{detail}</p></article>)}
          </div>
          <section className="report-runs">
            <div className="page-title compact"><h2>Behavioral reports</h2><p>Dynamic runs recorded for this sample. Export each completed run's bounded behavioral report.</p></div>
            {runs.length === 0 ? (
              <Empty label="No dynamic runs for this sample" detail="Start an isolated run from the Dynamic workspace; completed runs appear here for export." />
            ) : (
              <ul className="run-report-list">
                {runs.map((run) => {
                  const completed = run.job.state === 'completed' && run.result_available;
                  return (
                    <li key={run.id}>
                      <div className="run-report-meta">
                        <code>{run.id.slice(0, 12)}</code>
                        <span>{run.provider}</span>
                        <span className={`badge ${completed ? 'on' : 'off'}`}>{run.job.state}</span>
                        <span className="run-report-time">{new Date(run.created_at).toLocaleString()}</span>
                      </div>
                      <div className="report-actions">
                        {['json', 'markdown', 'html'].map((format) => (
                          <button className="btn secondary" type="button" key={format} disabled={!completed} onClick={() => exportRunReport(run.id, format)}>
                            Export {format.toUpperCase()}
                          </button>
                        ))}
                      </div>
                    </li>
                  );
                })}
              </ul>
            )}
          </section>
        </>
      )}
    </div>
  );
}
