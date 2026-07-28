import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from './api.js';
import { ErrorBanner, Loading } from './components/common.jsx';
import { Exports, Imports, Overview, Sections, Symbols } from './components/BinaryTabs.jsx';
import { StringsTab } from './components/StringsTab.jsx';
import { HexTab } from './components/HexTab.jsx';
import { DisasmTab } from './components/DisasmTab.jsx';
import { CfgTab } from './components/CfgTab.jsx';
import { PackingTab } from './components/PackingTab.jsx';
import { IntegrationsTab } from './components/Integrations.jsx';
import { Challenges } from './components/Challenges.jsx';

const TABS = [
  { id: 'overview', label: 'Overview' },
  { id: 'sections', label: 'Sections' },
  { id: 'symbols', label: 'Symbols' },
  { id: 'imports', label: 'Imports' },
  { id: 'exports', label: 'Exports' },
  { id: 'strings', label: 'Strings' },
  { id: 'hex', label: 'Hex' },
  { id: 'disasm', label: 'Disassembly' },
  { id: 'cfg', label: 'Control Flow' },
  { id: 'packing', label: 'Packing' },
  { id: 'integrations', label: 'Integrations' },
];

function Sidebar({ binaries, selected, onSelect, onUpload, uploading }) {
  const inputRef = useRef(null);
  const [drag, setDrag] = useState(false);

  const handleFiles = (files) => files?.[0] && onUpload(files[0]);

  return (
    <aside className="sidebar">
      <div className="section-title">Upload binary</div>
      <div
        className={`upload-drop ${drag ? 'drag' : ''}`}
        onClick={() => inputRef.current?.click()}
        onDragOver={(e) => {
          e.preventDefault();
          setDrag(true);
        }}
        onDragLeave={() => setDrag(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDrag(false);
          handleFiles(e.dataTransfer.files);
        }}
      >
        <div>{uploading ? 'Uploading…' : '↑ Drop a file or click'}</div>
        <div className="hint">ELF · PE · Mach-O</div>
        <input
          ref={inputRef}
          type="file"
          hidden
          onChange={(e) => handleFiles(e.target.files)}
        />
      </div>

      <div className="section-title">Samples ({binaries.length})</div>
      {binaries.length === 0 ? (
        <div className="muted" style={{ fontSize: 13 }}>No binaries yet.</div>
      ) : (
        binaries.map((b) => (
          <button
            key={b.sha256}
            className={`binary-item ${selected === b.sha256 ? 'active' : ''}`}
            onClick={() => onSelect(b.sha256)}
          >
            <div className="name">{b.filename}</div>
            <div className="meta">
              {b.binary_format} · {b.size.toLocaleString()} B · {b.sha256.slice(0, 10)}
            </div>
          </button>
        ))
      )}
    </aside>
  );
}

function AnalysisView({ sha }) {
  const [tab, setTab] = useState('overview');
  const [info, setInfo] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    setInfo(null);
    setError(null);
    setTab('overview');
    api.info(sha).then(setInfo).catch((e) => setError(e.message));
  }, [sha]);

  if (error) return <ErrorBanner error={error} />;
  if (!info) return <Loading label="Parsing binary…" />;

  return (
    <div>
      <div className="tabs">
        {TABS.map((t) => (
          <button key={t.id} className={`tab ${tab === t.id ? 'active' : ''}`} onClick={() => setTab(t.id)}>
            {t.label}
          </button>
        ))}
      </div>
      {tab === 'overview' && <Overview info={info} />}
      {tab === 'sections' && <Sections info={info} />}
      {tab === 'symbols' && <Symbols info={info} />}
      {tab === 'imports' && <Imports info={info} />}
      {tab === 'exports' && <Exports info={info} />}
      {tab === 'strings' && <StringsTab sha={sha} />}
      {tab === 'hex' && <HexTab sha={sha} />}
      {tab === 'disasm' && <DisasmTab sha={sha} />}
      {tab === 'cfg' && <CfgTab sha={sha} />}
      {tab === 'packing' && <PackingTab sha={sha} />}
      {tab === 'integrations' && <IntegrationsTab sha={sha} />}
    </div>
  );
}

export default function App() {
  const [mode, setMode] = useState('analyze'); // 'analyze' | 'challenges'
  const [binaries, setBinaries] = useState([]);
  const [selected, setSelected] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState(null);
  const [version, setVersion] = useState('');

  const refresh = useCallback(async () => {
    setBinaries(await api.listBinaries());
  }, []);

  useEffect(() => {
    api.health().then((h) => setVersion(h.version)).catch(() => {});
    refresh().catch((e) => setError(e.message));
  }, [refresh]);

  const upload = async (file) => {
    setUploading(true);
    setError(null);
    try {
      const record = await api.uploadBinary(file);
      await refresh();
      setSelected(record.sha256);
      setMode('analyze');
    } catch (e) {
      setError(e.message);
    } finally {
      setUploading(false);
    }
  };

  return (
    <div>
      <header className="app-header">
        <svg className="logo" width="26" height="26" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <rect x="1.5" y="1.5" width="21" height="21" rx="5" stroke="#58a6ff" strokeWidth="1.6" />
          <path d="M8.5 8L5.5 12L8.5 16" stroke="#3fb950" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
          <path d="M15.5 8L18.5 12L15.5 16" stroke="#3fb950" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
          <line x1="13.2" y1="7" x2="10.8" y2="17" stroke="#d29922" strokeWidth="1.8" strokeLinecap="round" />
        </svg>
        <h1>Reversing Lab</h1>
        <button className={`tab ${mode === 'analyze' ? 'active' : ''}`} onClick={() => setMode('analyze')}>
          Analyze
        </button>
        <button className={`tab ${mode === 'challenges' ? 'active' : ''}`} onClick={() => setMode('challenges')}>
          Challenges
        </button>
        <span className="spacer" />
        <span className="version">{version && `API v${version}`}</span>
      </header>

      <div className="layout">
        <Sidebar
          binaries={binaries}
          selected={selected}
          onSelect={(sha) => {
            setSelected(sha);
            setMode('analyze');
          }}
          onUpload={upload}
          uploading={uploading}
        />
        <main className="main">
          <ErrorBanner error={error} />
          {mode === 'challenges' ? (
            <Challenges />
          ) : selected ? (
            <AnalysisView sha={selected} />
          ) : (
            <div className="center-empty">
              <h2>Upload a binary to begin</h2>
              <p>Supported formats: ELF, PE, and Mach-O. Or try the Challenges tab.</p>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
