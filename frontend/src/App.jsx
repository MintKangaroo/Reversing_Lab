import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { api, hex } from './api.js';
import { ErrorBanner, Empty, Loading, ProvenanceBadge, StatusDot } from './components/common.jsx';
import { Exports, Imports, Overview, Sections, Symbols } from './components/BinaryTabs.jsx';
import { StringsTab } from './components/StringsTab.jsx';
import { HexTab } from './components/HexTab.jsx';
import { DisasmTab } from './components/DisasmTab.jsx';
import { CfgTab } from './components/CfgTab.jsx';
import { PackingTab } from './components/PackingTab.jsx';
import { IntegrationsTab } from './components/Integrations.jsx';
import { WorkbenchShell } from './components/WorkbenchShell.jsx';
import { FunctionsTab } from './components/FunctionsTab.jsx';
import { CallGraphTab } from './components/CallGraphTab.jsx';
import { PseudoCodeTab } from './components/PseudoCodeTab.jsx';
import { FindingsTab } from './components/FindingsTab.jsx';
import { ProgramFlowTab } from './components/ProgramFlowTab.jsx';
import { MemoryWorkspace } from './components/MemoryWorkspace.jsx';
import { DynamicWorkspace } from './components/DynamicWorkspace.jsx';
import { CtfWorkspace } from './components/CtfWorkspace.jsx';
import { ReportsWorkspace } from './components/ReportsWorkspace.jsx';
import { SettingsWorkspace } from './components/SettingsWorkspace.jsx';

const NAVIGATION = [
  { id: 'home', label: 'Home', icon: '⌂', shortcut: '1' },
  { id: 'projects', label: 'Projects & samples', icon: '▦', shortcut: '2' },
  { id: 'analyze', label: 'Analysis workbench', icon: '⌘', shortcut: '3' },
  { id: 'memory', label: 'Memory analysis', icon: '◉', shortcut: '4' },
  { id: 'dynamic', label: 'Dynamic analysis', icon: '▷', shortcut: '5' },
  { id: 'ctf', label: 'CTF workspace', icon: '◇', shortcut: '6' },
  { id: 'reports', label: 'Reports', icon: '≡', shortcut: '7' },
  { id: 'settings', label: 'Tooling & settings', icon: '⚙', shortcut: '8' },
];

const ANALYSIS_TABS = [
  { id: 'overview', label: 'Overview' },
  { id: 'functions', label: 'Functions' },
  { id: 'disasm', label: 'Disassembly' },
  { id: 'decompile', label: 'Pseudo-C' },
  { id: 'cfg', label: 'CFG' },
  { id: 'callgraph', label: 'Call Graph' },
  { id: 'flow', label: 'Program Flow' },
  { id: 'strings', label: 'Strings & IOC' },
  { id: 'hex', label: 'Hex' },
  { id: 'sections', label: 'Sections' },
  { id: 'symbols', label: 'Symbols' },
  { id: 'imports', label: 'Imports' },
  { id: 'exports', label: 'Exports' },
  { id: 'packing', label: 'Packing' },
  { id: 'obfuscation', label: 'Obfuscation' },
  { id: 'integrations', label: 'Tooling' },
];

function routeFromHash() {
  const value = window.location.hash.replace(/^#\/?/, '').split('/')[0];
  return NAVIGATION.some((item) => item.id === value) ? value : 'home';
}

function useHashRoute() {
  const [route, setRoute] = useState(routeFromHash);

  useEffect(() => {
    const update = () => setRoute(routeFromHash());
    window.addEventListener('hashchange', update);
    return () => window.removeEventListener('hashchange', update);
  }, []);

  const navigate = useCallback((next) => {
    if (routeFromHash() === next) {
      setRoute(next);
    } else {
      window.location.hash = `/${next}`;
    }
  }, []);

  return [route, navigate];
}

function ProductMark() {
  return (
    <svg className="product-mark" width="25" height="25" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <rect x="1.5" y="1.5" width="21" height="21" rx="4" stroke="currentColor" strokeWidth="1.5" />
      <path d="M8.5 7.5 5 12l3.5 4.5M15.5 7.5 19 12l-3.5 4.5M13.4 6.8l-2.8 10.4" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function Header({ route, selectedRecord, info, version, searchRef, filter, onFilter }) {
  const title = NAVIGATION.find((item) => item.id === route)?.label || 'Reversing Lab';
  return (
    <>
      <div className="brand">
        <ProductMark />
        <span>Reversing Lab</span>
      </div>
      <div className="header-context">
        <span className="context-separator">/</span>
        <strong>{selectedRecord?.filename || title}</strong>
        {info && (
          <>
            <span className="context-chip">{info.binary_format}</span>
            <span className="context-chip">{info.architecture} · {info.bits}</span>
            <span className="hash-chip" title={info.sha256}>{info.sha256.slice(0, 12)}</span>
          </>
        )}
      </div>
      <label className="command-search">
        <span aria-hidden="true">⌕</span>
        <input
          ref={searchRef}
          type="search"
          value={filter}
          onChange={(event) => onFilter(event.target.value)}
          placeholder="Search samples"
          aria-label="Search samples"
        />
        <kbd>/</kbd>
      </label>
      <StatusDot status="ready" label={version ? `API ${version}` : 'API connecting'} />
    </>
  );
}

function ActivityNavigation({ route, navigate }) {
  return (
    <>
      <div className="activity-items">
        {NAVIGATION.slice(0, 7).map((item) => (
          <button
            key={item.id}
            className={`activity-button ${route === item.id ? 'active' : ''}`}
            onClick={() => navigate(item.id)}
            title={`${item.label} (Ctrl+${item.shortcut})`}
            aria-label={item.label}
            aria-current={route === item.id ? 'page' : undefined}
          >
            <span aria-hidden="true">{item.icon}</span>
          </button>
        ))}
      </div>
      <button
        className={`activity-button activity-settings ${route === 'settings' ? 'active' : ''}`}
        onClick={() => navigate('settings')}
        title="Tooling & settings (Ctrl+8)"
        aria-label="Tooling & settings"
      >
        <span aria-hidden="true">⚙</span>
      </button>
    </>
  );
}

function SampleExplorer({ binaries, selected, onSelect, onUpload, uploading, filter, onFilter }) {
  const inputRef = useRef(null);
  const [drag, setDrag] = useState(false);
  const visible = useMemo(
    () => binaries.filter((binary) => binary.filename.toLowerCase().includes(filter.toLowerCase())),
    [binaries, filter],
  );

  const handleFiles = (files) => files?.[0] && onUpload(files[0]);
  return (
    <div className="panel-content">
      <div className="panel-heading">
        <span>Explorer</span>
        <button className="icon-button" onClick={() => inputRef.current?.click()} title="Upload sample" aria-label="Upload sample">＋</button>
      </div>
      <div className="explorer-section">
        <button className="tree-heading" aria-expanded="true">
          <span aria-hidden="true">⌄</span> LOCAL WORKSPACE
        </button>
        <div
          className={`compact-upload ${drag ? 'drag' : ''}`}
          role="button"
          tabIndex={0}
          onClick={() => inputRef.current?.click()}
          onKeyDown={(event) => (event.key === 'Enter' || event.key === ' ') && inputRef.current?.click()}
          onDragOver={(event) => {
            event.preventDefault();
            setDrag(true);
          }}
          onDragLeave={() => setDrag(false)}
          onDrop={(event) => {
            event.preventDefault();
            setDrag(false);
            handleFiles(event.dataTransfer.files);
          }}
        >
          <strong>{uploading ? 'Uploading…' : 'Drop or open a binary'}</strong>
          <span>ELF · PE · Mach-O · max policy enforced</span>
          <input ref={inputRef} type="file" hidden onChange={(event) => handleFiles(event.target.files)} />
        </div>
      </div>
      <div className="explorer-section samples-tree">
        <button className="tree-heading" aria-expanded="true">
          <span aria-hidden="true">⌄</span> SAMPLES <em>{visible.length}</em>
        </button>
        {visible.length === 0 ? (
          <div className="tree-empty">{filter ? 'No matching samples' : 'No samples uploaded'}</div>
        ) : visible.map((binary) => (
          <button
            key={binary.sha256}
            className={`sample-row ${selected === binary.sha256 ? 'active' : ''}`}
            onClick={() => onSelect(binary.sha256)}
          >
            <span className={`file-kind kind-${binary.binary_format.toLowerCase().replace('-', '')}`}>
              {binary.binary_format.slice(0, 2)}
            </span>
            <span className="sample-copy">
              <strong>{binary.filename}</strong>
              <small>{binary.sha256.slice(0, 10)} · {binary.size.toLocaleString()} B</small>
            </span>
          </button>
        ))}
      </div>
      <div className="explorer-section">
        <button className="tree-heading" aria-expanded="false">
          <span aria-hidden="true">›</span> MEMORY DUMPS <em>0</em>
        </button>
        <button className="tree-heading" aria-expanded="false">
          <span aria-hidden="true">›</span> CTF WORKSPACES <em>0</em>
        </button>
      </div>
      <input
        className="explorer-filter"
        type="search"
        value={filter}
        onChange={(event) => onFilter(event.target.value)}
        placeholder="Filter explorer…"
        aria-label="Filter explorer"
      />
    </div>
  );
}

function MetricCard({ label, value, detail, tone = 'blue' }) {
  return (
    <div className={`metric-card tone-${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{detail}</small>
    </div>
  );
}

function HomeDashboard({ binaries, onOpen, onUpload }) {
  const formats = new Set(binaries.map((item) => item.binary_format)).size;
  return (
    <div className="page-scroll">
      <div className="page-title">
        <div>
          <span className="eyebrow">ANALYSIS OPERATIONS</span>
          <h1>Reversing workbench</h1>
          <p>Static analysis first, with memory and isolated dynamic workflows kept behind explicit safety gates.</p>
        </div>
        <button className="btn" onClick={onUpload}>＋ Upload sample</button>
      </div>
      <div className="metric-grid">
        <MetricCard label="Stored samples" value={binaries.length} detail="Content-addressed" />
        <MetricCard label="Formats observed" value={formats} detail="ELF · PE · Mach-O" tone="violet" />
        <MetricCard label="Active jobs" value="0" detail="Queue is idle" tone="green" />
        <MetricCard label="Critical findings" value="0" detail="No analysis selected" tone="red" />
      </div>
      <section className="dashboard-section">
        <div className="section-heading">
          <div><span className="eyebrow">RECENT</span><h2>Samples</h2></div>
          <span>{binaries.length} total</span>
        </div>
        {binaries.length === 0 ? (
          <Empty
            label="No samples in this workspace"
            detail="Upload an authorized ELF, PE, or Mach-O sample to begin static analysis."
            action={<button className="btn secondary" onClick={onUpload}>Choose a file</button>}
          />
        ) : (
          <div className="recent-list">
            {binaries.slice(0, 8).map((binary) => (
              <button key={binary.sha256} onClick={() => onOpen(binary.sha256)}>
                <span className="recent-format">{binary.binary_format}</span>
                <span><strong>{binary.filename}</strong><small>{binary.sha256}</small></span>
                <span>{binary.size.toLocaleString()} B</span>
                <span aria-hidden="true">→</span>
              </button>
            ))}
          </div>
        )}
      </section>
      <div className="dashboard-columns">
        <section className="dashboard-section">
          <div className="section-heading"><div><span className="eyebrow">POLICY</span><h2>Safety posture</h2></div></div>
          <div className="policy-list">
            <StatusDot status="ready" label="Static analysis available" />
            <StatusDot status="disabled" label="Dynamic execution requires isolated provider" />
            <StatusDot status="idle" label="Memory tooling capability checked on demand" />
          </div>
        </section>
        <section className="dashboard-section">
          <div className="section-heading"><div><span className="eyebrow">SHORTCUTS</span><h2>Keyboard</h2></div></div>
          <dl className="shortcut-list">
            <div><dt><kbd>Ctrl</kbd> <kbd>1–8</kbd></dt><dd>Switch workspace</dd></div>
            <div><dt><kbd>/</kbd></dt><dd>Search samples</dd></div>
            <div><dt><kbd>Tab</kbd></dt><dd>Move across controls</dd></div>
          </dl>
        </section>
      </div>
    </div>
  );
}

function ProjectSamples({ binaries, onOpen, onUpload }) {
  return (
    <div className="page-scroll">
      <div className="page-title">
        <div><span className="eyebrow">LOCAL WORKSPACE</span><h1>Projects & samples</h1><p>Samples are stored by SHA-256; display names never become filesystem paths.</p></div>
        <button className="btn" onClick={onUpload}>＋ Add sample</button>
      </div>
      {binaries.length ? (
        <div className="table-scroll">
          <table className="data">
            <thead><tr><th>Name</th><th>Format</th><th>Size</th><th>SHA-256</th><th /></tr></thead>
            <tbody>
              {binaries.map((item) => (
                <tr key={item.sha256}>
                  <td>{item.filename}</td><td>{item.binary_format}</td>
                  <td className="mono">{item.size.toLocaleString()}</td>
                  <td className="mono">{item.sha256}</td>
                  <td><button className="link-button" onClick={() => onOpen(item.sha256)}>Open →</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : <Empty label="No samples" detail="Create a project sample by uploading an authorized binary." />}
    </div>
  );
}

function PendingAnalysis({ title }) {
  return (
    <Empty
      label={`${title} is being connected`}
      detail="The workbench surface is ready. Its evidence-backed analysis endpoint is added in the next implementation phase."
    />
  );
}

function AnalysisView({ sha, info, error, functionAddress, onFunctionSelect }) {
  const [tab, setTab] = useState('overview');

  useEffect(() => setTab('overview'), [sha]);

  if (error) return <div className="workspace-padding"><ErrorBanner error={error} /></div>;
  if (!info) return <Loading label="Parsing binary metadata…" />;

  return (
    <div className="analysis-surface">
      <div className="editor-tabs" role="tablist" aria-label="Analysis views">
        {ANALYSIS_TABS.map((item) => (
          <button
            key={item.id}
            role="tab"
            aria-selected={tab === item.id}
            className={tab === item.id ? 'active' : ''}
            onClick={() => setTab(item.id)}
          >
            {item.label}{item.pending && <span className="pending-dot" title="Analysis provider pending" />}
          </button>
        ))}
      </div>
      <div className="editor-toolbar">
        <span className="breadcrumb"><b>{info.binary_format}</b> › <span className="mono">{hex(info.entry_point)}</span></span>
        <span className="toolbar-spacer" />
        <ProvenanceBadge kind="verified" />
        <button className="icon-button" title="More view actions" aria-label="More view actions">•••</button>
      </div>
      <div className="analysis-content" role="tabpanel">
        {tab === 'overview' && <Overview info={info} />}
        {tab === 'functions' && (
          <FunctionsTab sha={sha} selectedAddress={functionAddress} onSelect={onFunctionSelect} />
        )}
        {tab === 'sections' && <Sections info={info} />}
        {tab === 'symbols' && <Symbols info={info} />}
        {tab === 'imports' && <Imports info={info} />}
        {tab === 'exports' && <Exports info={info} />}
        {tab === 'strings' && <StringsTab sha={sha} />}
        {tab === 'hex' && <HexTab sha={sha} />}
        {tab === 'disasm' && (
          <DisasmTab sha={sha} address={functionAddress} onAddressSelect={onFunctionSelect} />
        )}
        {tab === 'decompile' && (
          <PseudoCodeTab
            sha={sha}
            address={functionAddress ?? info.entry_point}
            onAddressSelect={onFunctionSelect}
          />
        )}
        {tab === 'cfg' && <CfgTab sha={sha} />}
        {tab === 'callgraph' && (
          <CallGraphTab sha={sha} selectedAddress={functionAddress} onSelect={onFunctionSelect} />
        )}
        {tab === 'flow' && <ProgramFlowTab sha={sha} onAddressSelect={onFunctionSelect} />}
        {tab === 'packing' && <PackingTab sha={sha} />}
        {tab === 'obfuscation' && <FindingsTab sha={sha} onAddressSelect={onFunctionSelect} />}
        {tab === 'integrations' && <IntegrationsTab sha={sha} />}
        {ANALYSIS_TABS.find((item) => item.id === tab)?.pending && (
          <PendingAnalysis title={ANALYSIS_TABS.find((item) => item.id === tab).label} />
        )}
      </div>
    </div>
  );
}

function CapabilityPage({ kind }) {
  const content = {
    memory: ['Memory analysis', 'Upload and inspect dump metadata, processes, modules, and suspicious regions.', 'Volatility provider not checked'],
    dynamic: ['Dynamic analysis', 'Execution remains disabled until every isolation guardrail is configured.', 'Sandbox provider not configured'],
    reports: ['Analysis reports', 'Export evidence, findings, notes, and limitations as JSON, Markdown, or HTML.', 'Select a sample first'],
    settings: ['Tooling & settings', 'Inspect optional tool availability and the configured resource limits.', 'Capability inventory loading in Phase 10'],
  }[kind];
  return (
    <div className="page-scroll">
      <div className="page-title"><div><span className="eyebrow">WORKSPACE</span><h1>{content[0]}</h1><p>{content[1]}</p></div></div>
      <div className="disabled-capability">
        <span className="capability-icon" aria-hidden="true">⏸</span>
        <div><h2>{content[2]}</h2><p>This control is intentionally unavailable; the backend will expose structured readiness reasons instead of attempting an unsafe fallback.</p></div>
        <button className="btn" disabled>Run analysis</button>
      </div>
    </div>
  );
}

function Inspector({ info, selectedRecord, route, sha, functionDetail, onFunctionUpdated }) {
  const [name, setName] = useState('');
  const [comment, setComment] = useState('');
  const [saveError, setSaveError] = useState(null);
  const [saving, setSaving] = useState(false);
  const [bookmarked, setBookmarked] = useState(false);

  useEffect(() => {
    setName(functionDetail?.user_name || '');
    setComment(functionDetail?.user_comment || '');
    setSaveError(null);
    setBookmarked(false);
  }, [functionDetail]);

  async function saveOverlay() {
    if (!functionDetail) return;
    setSaving(true);
    setSaveError(null);
    try {
      if (name.trim()) await api.saveAnnotation(sha, functionDetail.address, 'function_name', name.trim());
      if (comment.trim()) await api.saveAnnotation(sha, functionDetail.address, 'comment', comment.trim());
      onFunctionUpdated();
    } catch (failure) {
      setSaveError(failure.message);
    } finally {
      setSaving(false);
    }
  }

  async function bookmark() {
    if (!functionDetail) return;
    try {
      await api.saveBookmark(sha, functionDetail.address, name || functionDetail.name, comment);
      setBookmarked(true);
    } catch (failure) {
      setSaveError(failure.message);
    }
  }

  return (
    <div className="panel-content">
      <div className="panel-heading"><span>Inspector</span><button className="icon-button" aria-label="Inspector actions">•••</button></div>
      {info ? (
        <>
          {functionDetail && (
            <section className="inspector-section function-inspector">
              <div className="inspector-label">SELECTED FUNCTION</div>
              <h3 className="mono">{functionDetail.user_name || functionDetail.name}</h3>
              <div className="inspector-kv"><span>Address</span><b className="mono">{hex(functionDetail.address)}</b></div>
              <div className="inspector-kv"><span>Instructions</span><b>{functionDetail.instruction_count}</b></div>
              <div className="inspector-kv"><span>Complexity</span><b>{functionDetail.cyclomatic_complexity}</b></div>
              <div className="inspector-kv"><span>Callers / callees</span><b>{functionDetail.callers.length} / {functionDetail.callees.length}</b></div>
              <label className="inspector-field">
                <span>User-defined name</span>
                <input className="text" value={name} maxLength={160} onChange={(event) => setName(event.target.value)} placeholder={functionDetail.name} />
              </label>
              <label className="inspector-field">
                <span>Analyst comment</span>
                <textarea value={comment} maxLength={8192} onChange={(event) => setComment(event.target.value)} placeholder="Add evidence or investigation notes…" />
              </label>
              {saveError && <div className="inline-error">{saveError}</div>}
              <div className="inspector-actions">
                <button className="btn" disabled={saving || (!name.trim() && !comment.trim())} onClick={saveOverlay}>{saving ? 'Saving…' : 'Save overlay'}</button>
                <button className="btn secondary" onClick={bookmark}>{bookmarked ? 'Bookmarked ✓' : 'Bookmark'}</button>
              </div>
              <p className="inspector-help"><ProvenanceBadge kind="user" /> Overlays do not alter recovered analysis.</p>
            </section>
          )}
          <section className="inspector-section">
            <div className="inspector-label">SAMPLE</div>
            <h3>{selectedRecord?.filename}</h3>
            <div className="inspector-kv"><span>Format</span><b>{info.binary_format}</b></div>
            <div className="inspector-kv"><span>Architecture</span><b>{info.architecture} / {info.bits}</b></div>
            <div className="inspector-kv"><span>Entry</span><b className="mono">{hex(info.entry_point)}</b></div>
            <div className="inspector-kv"><span>Size</span><b>{info.file_size.toLocaleString()} B</b></div>
          </section>
          <section className="inspector-section">
            <div className="inspector-label">MITIGATIONS</div>
            <div className="mitigation-row"><span>PIE / ASLR</span><StatusDot status={info.is_pie ? 'ready' : 'warning'} label={info.is_pie ? 'enabled' : 'disabled'} /></div>
            <div className="mitigation-row"><span>NX / DEP</span><StatusDot status={info.has_nx ? 'ready' : 'warning'} label={info.has_nx ? 'enabled' : 'disabled'} /></div>
            <div className="mitigation-row"><span>RELRO</span><StatusDot status={info.has_relro ? 'ready' : 'idle'} label={info.has_relro ? 'present' : 'not observed'} /></div>
          </section>
          <section className="inspector-section">
            <div className="inspector-label">PROVENANCE</div>
            <ProvenanceBadge kind="verified" />
            <p className="inspector-help">Header and section facts were read directly from the uploaded binary.</p>
          </section>
          <section className="inspector-section">
            <div className="inspector-label">CROSS REFERENCES</div>
            <div className="panel-empty">Select an address or function to inspect references.</div>
          </section>
        </>
      ) : (
        <div className="panel-empty spacious">
          <span>◎</span>
          <strong>{route === 'home' ? 'Workspace overview' : 'Nothing selected'}</strong>
          <p>Select a sample or analysis object to inspect its evidence and cross references.</p>
        </div>
      )}
    </div>
  );
}

function BottomPanel({ error }) {
  const [tab, setTab] = useState('jobs');
  const [jobItems, setJobItems] = useState([]);
  const tabs = ['console', 'jobs', 'findings', 'explanations'];

  useEffect(() => {
    let active = true;
    const refreshJobs = () => api.jobs().then((items) => active && setJobItems(items)).catch(() => {});
    refreshJobs();
    const timer = window.setInterval(refreshJobs, 1800);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, []);

  const activeJobs = jobItems.filter((item) => ['queued', 'running'].includes(item.state)).length;
  return (
    <div className="bottom-content">
      <div className="bottom-tabs">
        {tabs.map((item) => (
          <button key={item} className={tab === item ? 'active' : ''} onClick={() => setTab(item)}>
            {item === 'explanations' ? 'AI EXPLANATION' : item.toUpperCase()}
            {item === 'jobs' && <span className="count-badge">{activeJobs}</span>}
          </button>
        ))}
        <span className="toolbar-spacer" />
        <span className="bottom-status"><span /> Static-only default</span>
      </div>
      <div className="bottom-body">
        {error ? <ErrorBanner error={error} /> : (
          <>
            {tab === 'console' && <div className="console-line"><span>[ready]</span> Reversing Lab workbench initialized.</div>}
            {tab === 'jobs' && (jobItems.length ? (
              <div className="bottom-job-list">
                {jobItems.slice(0, 20).map((item) => (
                  <div key={item.id}>
                    <span className={`job-state state-${item.state}`}>{item.state}</span>
                    <code>{item.kind}</code><span>{item.message}</span><b>{item.progress}%</b>
                  </div>
                ))}
              </div>
            ) : <div className="panel-empty inline">No analysis jobs have been created.</div>)}
            {tab === 'findings' && <div className="panel-empty inline">Select and analyze a sample to review findings.</div>}
            {tab === 'explanations' && <div className="panel-empty inline">Automated explanations will always link back to binary evidence.</div>}
          </>
        )}
      </div>
    </div>
  );
}

export default function App() {
  const [route, navigate] = useHashRoute();
  const [binaries, setBinaries] = useState([]);
  const [selected, setSelected] = useState(null);
  const [info, setInfo] = useState(null);
  const [infoError, setInfoError] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState(null);
  const [version, setVersion] = useState('');
  const [filter, setFilter] = useState('');
  const [functionAddress, setFunctionAddress] = useState(null);
  const [functionDetail, setFunctionDetail] = useState(null);
  const [functionRevision, setFunctionRevision] = useState(0);
  const uploadRef = useRef(null);
  const searchRef = useRef(null);

  const refresh = useCallback(async () => {
    setBinaries(await api.listBinaries());
  }, []);

  useEffect(() => {
    api.health().then((health) => setVersion(health.version)).catch(() => setError('Backend API is unavailable.'));
    refresh().catch((failure) => setError(failure.message));
  }, [refresh]);

  useEffect(() => {
    if (!selected) {
      setInfo(null);
      setInfoError(null);
      setFunctionAddress(null);
      return;
    }
    let active = true;
    setInfo(null);
    setInfoError(null);
    api.info(selected)
      .then((data) => active && setInfo(data))
      .catch((failure) => active && setInfoError(failure.message));
    return () => { active = false; };
  }, [selected]);

  useEffect(() => {
    if (!selected || functionAddress == null) {
      setFunctionDetail(null);
      return;
    }
    let active = true;
    api.functionDetail(selected, functionAddress)
      .then((result) => active && setFunctionDetail(result))
      .catch((failure) => active && setError(failure.message));
    return () => { active = false; };
  }, [selected, functionAddress, functionRevision]);

  useEffect(() => {
    const onKeyDown = (event) => {
      const tag = event.target?.tagName;
      if (event.key === '/' && !['INPUT', 'TEXTAREA'].includes(tag)) {
        event.preventDefault();
        searchRef.current?.focus();
      }
      if (event.ctrlKey && /^[1-8]$/.test(event.key)) {
        event.preventDefault();
        navigate(NAVIGATION[Number(event.key) - 1].id);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [navigate]);

  const upload = async (file) => {
    setUploading(true);
    setError(null);
    try {
      const record = await api.uploadBinary(file);
      await refresh();
      setSelected(record.sha256);
      navigate('analyze');
    } catch (failure) {
      setError(failure.message);
    } finally {
      setUploading(false);
      if (uploadRef.current) uploadRef.current.value = '';
    }
  };

  const openSample = (sha) => {
    if (sha !== selected) setFunctionAddress(null);
    setSelected(sha);
    navigate('analyze');
  };

  const selectedRecord = binaries.find((item) => item.sha256 === selected);

  let workspace;
  if (route === 'home') workspace = <HomeDashboard binaries={binaries} onOpen={openSample} onUpload={() => uploadRef.current?.click()} />;
  else if (route === 'projects') workspace = <ProjectSamples binaries={binaries} onOpen={openSample} onUpload={() => uploadRef.current?.click()} />;
  else if (route === 'analyze') {
    workspace = selected
      ? (
        <AnalysisView
          sha={selected}
          info={info}
          error={infoError}
          functionAddress={functionAddress}
          onFunctionSelect={setFunctionAddress}
        />
      )
      : <Empty label="No sample selected" detail="Choose a sample from the explorer or upload a new authorized binary." />;
  } else if (route === 'memory') workspace = <MemoryWorkspace />;
  else if (route === 'dynamic') workspace = <DynamicWorkspace sample={selectedRecord} />;
  else if (route === 'ctf') workspace = <CtfWorkspace sample={selectedRecord} />;
  else if (route === 'reports') workspace = <ReportsWorkspace sample={selectedRecord} />;
  else if (route === 'settings') workspace = <SettingsWorkspace />;
  else workspace = <CapabilityPage kind={route} />;

  return (
    <>
      <input ref={uploadRef} type="file" hidden onChange={(event) => event.target.files?.[0] && upload(event.target.files[0])} />
      <WorkbenchShell
        header={(
          <Header
            route={route}
            selectedRecord={selectedRecord}
            info={info}
            version={version}
            searchRef={searchRef}
            filter={filter}
            onFilter={setFilter}
          />
        )}
        navigation={<ActivityNavigation route={route} navigate={navigate} />}
        explorer={(
          <SampleExplorer
            binaries={binaries}
            selected={selected}
            onSelect={openSample}
            onUpload={upload}
            uploading={uploading}
            filter={filter}
            onFilter={setFilter}
          />
        )}
        workspace={workspace}
        inspector={(
          <Inspector
            info={info}
            selectedRecord={selectedRecord}
            route={route}
            sha={selected}
            functionDetail={functionDetail}
            onFunctionUpdated={() => setFunctionRevision((value) => value + 1)}
          />
        )}
        bottom={<BottomPanel error={error} />}
      />
    </>
  );
}
