import { useEffect, useState } from 'react';
import { api, hex } from '../api.js';
import { ErrorBanner, Loading, ProvenanceBadge } from './common.jsx';

export function ProgramFlowTab({ sha, onAddressSelect }) {
  const [summary, setSummary] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    let active = true;
    setSummary(null);
    api.flowSummary(sha)
      .then((result) => active && (setSummary(result), setError(null)))
      .catch((failure) => active && setError(failure.message));
    return () => { active = false; };
  }, [sha]);

  if (error) return <ErrorBanner error={error} />;
  if (!summary) return <Loading label="Building evidence-linked flow summary…" />;

  return (
    <div className="program-flow">
      <div className="flow-intro">
        <div><span className="eyebrow">HEURISTIC NARRATIVE</span><h2>Program flow summary</h2></div>
        <ProvenanceBadge kind="inferred" />
      </div>
      <div className="flow-chain">
        {summary.stages.map((stage, index) => (
          <article className="flow-stage" key={stage.id}>
            <span className="flow-index">{String(index + 1).padStart(2, '0')}</span>
            <div>
              <div className="flow-stage-title">
                <h3>{stage.title}</h3>
                <span>{Math.round(stage.confidence * 100)}%</span>
              </div>
              <p>{stage.summary}</p>
              {stage.function_addresses.length > 0 && (
                <div className="flow-functions">
                  {stage.function_addresses.map((address) => (
                    <button key={address} onClick={() => onAddressSelect(address)}>{hex(address)}</button>
                  ))}
                </div>
              )}
              <details>
                <summary>{stage.evidence.length} evidence item(s)</summary>
                {stage.evidence.map((item, itemIndex) => (
                  <div className="flow-evidence" key={`${item.source}-${itemIndex}`}>
                    <ProvenanceBadge kind={item.provenance} />
                    <span>{item.message}</span>
                    {item.address != null && <button onClick={() => onAddressSelect(item.address)}>{hex(item.address)}</button>}
                  </div>
                ))}
              </details>
            </div>
          </article>
        ))}
      </div>
      <div className="flow-grid">
        <section>
          <span className="eyebrow">BRANCHES</span><h3>Major decision points</h3>
          {summary.major_branches.length ? summary.major_branches.map((item, index) => (
            <button key={index} onClick={() => item.address != null && onAddressSelect(item.address)}>{item.message}</button>
          )) : <p>No high-confidence branch summary recovered.</p>}
        </section>
        <section>
          <span className="eyebrow">FAILURE PATHS</span><h3>Failure indicators</h3>
          {summary.failure_paths.length ? summary.failure_paths.map((item, index) => <p key={index}>{item.message}</p>) : <p>No explicit failure strings recovered.</p>}
        </section>
        <section>
          <span className="eyebrow">ANTI-ANALYSIS</span><h3>Suspicious control signals</h3>
          {summary.anti_analysis.length ? summary.anti_analysis.map((item, index) => <p key={index}>{item.message}</p>) : <p>No anti-analysis evidence linked.</p>}
        </section>
      </div>
      <div className="limitations">
        <strong>Limitations</strong>
        <ul>{summary.limitations.map((item) => <li key={item}>{item}</li>)}</ul>
      </div>
    </div>
  );
}
