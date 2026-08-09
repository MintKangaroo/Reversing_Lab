import { useCallback, useEffect, useState } from 'react';
import { api } from '../api.js';
import { DataTable, ErrorBanner, Loading, StatusDot } from './common.jsx';

function readableBytes(value) {
  if (value >= 1024 ** 3) return `${(value / 1024 ** 3).toFixed(1)} GiB`;
  if (value >= 1024 ** 2) return `${(value / 1024 ** 2).toFixed(1)} MiB`;
  return `${value.toLocaleString()} B`;
}

function readableLabel(value) {
  return value.replaceAll('_', ' ');
}

function readableDate(value) {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : date.toLocaleString();
}

const AUDIT_COLUMNS = [
  { key: 'created_at', header: 'Time', render: (row) => readableDate(row.created_at) },
  { key: 'principal_id', header: 'Principal', mono: true },
  { key: 'action', header: 'Action', mono: true },
  {
    key: 'outcome',
    header: 'Outcome',
    render: (row) => <span className={`audit-outcome outcome-${row.outcome}`}>{row.outcome}</span>,
  },
  { key: 'status_code', header: 'Status', mono: true },
  {
    key: 'request_id',
    header: 'Request ID',
    mono: true,
    render: (row) => <span title={row.request_id}>{row.request_id.slice(0, 12)}</span>,
  },
];

export function SettingsWorkspace({ principal = null }) {
  const [tools, setTools] = useState(null);
  const [configuration, setConfiguration] = useState(null);
  const [error, setError] = useState(null);
  const [auditPage, setAuditPage] = useState(null);
  const [retention, setRetention] = useState(null);
  const [securityError, setSecurityError] = useState(null);
  const [securityLoading, setSecurityLoading] = useState(true);
  const [includeBinaryAccess, setIncludeBinaryAccess] = useState(false);
  const [confirmation, setConfirmation] = useState('');
  const [purging, setPurging] = useState(false);
  const [purgeResult, setPurgeResult] = useState(null);

  useEffect(() => {
    Promise.all([api.tooling(), api.toolingConfiguration()])
      .then(([toolItems, config]) => {
        setTools(toolItems);
        setConfiguration(config);
      })
      .catch((failure) => setError(failure.message));
  }, []);

  const loadSecurityData = useCallback(async () => {
    setSecurityLoading(true);
    setSecurityError(null);
    try {
      const [events, preview] = await Promise.all([
        api.auditEvents({ limit: 12 }),
        api.retentionPreview(includeBinaryAccess),
      ]);
      setAuditPage(events);
      setRetention(preview);
    } catch (failure) {
      setSecurityError(failure.message);
    } finally {
      setSecurityLoading(false);
    }
  }, [includeBinaryAccess]);

  useEffect(() => {
    loadSecurityData();
  }, [loadSecurityData]);

  async function purgeOwnedData() {
    setPurging(true);
    setSecurityError(null);
    setPurgeResult(null);
    try {
      const result = await api.purgeRetention(confirmation, includeBinaryAccess);
      setPurgeResult(result);
      setConfirmation('');
      await loadSecurityData();
    } catch (failure) {
      setSecurityError(failure.message);
    } finally {
      setPurging(false);
    }
  }

  if (!tools || !configuration) return <div className="page-scroll"><ErrorBanner error={error} />{!error && <Loading label="Inspecting configured tooling and limits…" />}</div>;
  const limits = configuration.limits;
  const sandbox = configuration.sandbox_policy;
  const isViewer = principal?.role === 'viewer';
  const confirmationMatches = confirmation === retention?.required_confirmation;
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
          <h2>Authentication</h2>
          {Object.entries(configuration.authentication).map(([name, value]) => (
            <div className="inspector-kv" key={name}><span>{name.replaceAll('_', ' ')}</span><b>{String(value)}</b></div>
          ))}
          <div className="security-callout">Projects, samples, annotations, jobs, memory dumps, dynamic runs, and CTF workspaces are principal-scoped. Administrators can inspect shared operational state, but retention purge always targets only the current principal.</div>
        </section>
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
      <h2 className="workspace-heading settings-section-heading">Security operations</h2>
      <ErrorBanner error={securityError} />
      {securityLoading && !retention ? <Loading label="Loading audit and retention state…" /> : (
        <div className="security-settings-grid">
          <section className="settings-card audit-card">
            <div className="settings-card-heading">
              <div><span className="eyebrow">APPEND-ONLY METADATA</span><h2>Recent audit events</h2></div>
              <span className="record-count">{auditPage?.total ?? 0} total</span>
            </div>
            <p className="settings-help">Mutation metadata is recorded without request bodies, authorization headers, or decoder input.</p>
            <DataTable columns={AUDIT_COLUMNS} rows={auditPage?.items || []} emptyLabel="No mutation events recorded." />
          </section>
          <section className="settings-card retention-card">
            <div className="settings-card-heading">
              <div><span className="eyebrow">DRY-RUN FIRST</span><h2>Owned data retention</h2></div>
              <StatusDot status={retention?.active_jobs ? 'warning' : 'ready'} label={retention?.active_jobs ? `${retention.active_jobs} active job(s)` : 'ready'} />
            </div>
            <p className="settings-help">Preview and remove mutable records owned by <code>{retention?.principal_id}</code>. Audit events are always retained.</p>
            <div className="retention-counts">
              {Object.entries(retention?.counts || {}).map(([name, value]) => (
                <div className="inspector-kv" key={name}><span>{readableLabel(name)}</span><b>{value.toLocaleString()}</b></div>
              ))}
            </div>
            <label className="retention-option">
              <input
                type="checkbox"
                checked={includeBinaryAccess}
                onChange={(event) => {
                  setIncludeBinaryAccess(event.target.checked);
                  setConfirmation('');
                  setPurgeResult(null);
                }}
              />
              <span><strong>Also remove sample access grants</strong><small>Content-addressed binaries are reclaimed only when no owner or analysis record still references them.</small></span>
            </label>
            {includeBinaryAccess && retention && (
              <div className="reclaim-preview">
                <span>Orphanable binaries <b>{retention.orphanable_binary_count}</b></span>
                <span>Estimated reclaimable <b>{readableBytes(retention.estimated_reclaimable_binary_bytes)}</b></span>
              </div>
            )}
            <label className="retention-confirmation">
              Type <code>{retention?.required_confirmation}</code> to confirm
              <input
                className="text"
                type="text"
                autoComplete="off"
                spellCheck="false"
                value={confirmation}
                onChange={(event) => setConfirmation(event.target.value)}
                disabled={isViewer || purging || securityLoading || Boolean(securityError) || Boolean(retention?.active_jobs)}
              />
            </label>
            {isViewer && <div className="security-callout">Viewer accounts cannot run data retention mutations.</div>}
            {retention?.active_jobs > 0 && <div className="security-callout">Cancel or wait for owned analysis jobs before purging data.</div>}
            {purgeResult && (
              <div className="purge-result" role="status">
                Removed {purgeResult.files_removed} file(s) and reclaimed {readableBytes(purgeResult.bytes_reclaimed)}. Audit events were retained.
              </div>
            )}
            <button
              className="btn danger-button"
              type="button"
              disabled={!confirmationMatches || purging || securityLoading || Boolean(securityError) || isViewer || Boolean(retention?.active_jobs)}
              onClick={purgeOwnedData}
            >
              {purging ? 'Purging owned data…' : 'Purge owned data'}
            </button>
          </section>
        </div>
      )}
    </div>
  );
}
