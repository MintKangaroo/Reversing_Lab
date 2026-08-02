import { useEffect, useState } from 'react';
import { api, hex } from '../api.js';
import { Challenges } from './Challenges.jsx';
import { DecoderPlayground } from './FindingsTab.jsx';
import { Empty, ErrorBanner, Loading } from './common.jsx';

export function CtfWorkspace({ sample }) {
  const [mode, setMode] = useState('workspace');
  const [items, setItems] = useState(null);
  const [selected, setSelected] = useState(null);
  const [title, setTitle] = useState('');
  const [note, setNote] = useState('');
  const [noteKind, setNoteKind] = useState('note');
  const [address, setAddress] = useState('');
  const [candidate, setCandidate] = useState('');
  const [hypothesis, setHypothesis] = useState('');
  const [step, setStep] = useState('');
  const [error, setError] = useState(null);

  async function refresh(selectId = selected?.id) {
    const workspaces = await api.ctfWorkspaces();
    setItems(workspaces);
    if (selectId) setSelected(workspaces.find((item) => item.id === selectId) || null);
  }

  useEffect(() => {
    refresh().catch((failure) => setError(failure.message));
  // Initial load only.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function create() {
    if (!title.trim()) return;
    try {
      const workspace = await api.createCtfWorkspace({
        title: title.trim(),
        description: '',
        category: 'reversing',
        difficulty: 'unknown',
        binary_sha256: sample?.sha256 || null,
      });
      setTitle('');
      await refresh(workspace.id);
    } catch (failure) {
      setError(failure.message);
    }
  }

  async function patch(payload) {
    try {
      const workspace = await api.updateCtfWorkspace(selected.id, payload);
      setSelected(workspace);
      setItems((current) => current.map((item) => item.id === workspace.id ? workspace : item));
    } catch (failure) {
      setError(failure.message);
    }
  }

  async function addNote() {
    if (!note.trim()) return;
    try {
      await api.addCtfNote(selected.id, {
        kind: noteKind,
        content: note.trim(),
        address: address.trim() ? Number.parseInt(address, 0) : null,
      });
      setNote('');
      setAddress('');
      await refresh(selected.id);
    } catch (failure) {
      setError(failure.message);
    }
  }

  function addList(field, value, clear) {
    if (!value.trim()) return;
    patch({ [field]: [...selected[field], value.trim()] }).then(clear);
  }

  async function exportWorkspace(format) {
    try {
      setError(null);
      await api.downloadCtfExport(selected.id, format);
    } catch (failure) {
      setError(failure.message);
    }
  }

  if (!items) return <Loading label="Loading CTF workspaces…" />;

  return (
    <div className="page-scroll ctf-workspace">
      <div className="page-title">
        <div><span className="eyebrow">AUTHORIZED CHALLENGE MODE</span><h1>CTF workspace</h1><p>Track evidence, hypotheses, addresses, candidates, and write-up steps alongside safe decoder tools.</p></div>
        <div className="view-switch"><button className={mode === 'workspace' ? 'active' : ''} onClick={() => setMode('workspace')}>Investigation</button><button className={mode === 'challenges' ? 'active' : ''} onClick={() => setMode('challenges')}>Practice challenges</button></div>
      </div>
      <ErrorBanner error={error} />
      {mode === 'challenges' ? <Challenges /> : (
        <div className="ctf-layout">
          <aside className="ctf-list">
            <div className="ctf-create"><input className="text" value={title} onChange={(event) => setTitle(event.target.value)} placeholder="New challenge title" /><button className="btn" disabled={!title.trim()} onClick={create}>Create</button></div>
            {items.map((item) => <button key={item.id} className={selected?.id === item.id ? 'active' : ''} onClick={() => setSelected(item)}><strong>{item.title}</strong><span>{item.category} · {item.difficulty}</span><small>{item.binary_sha256?.slice(0, 12) || 'no sample linked'}</small></button>)}
          </aside>
          <section className="ctf-main">
            {!selected ? <Empty label="Select or create a workspace" detail={sample ? `The new workspace can link ${sample.filename}.` : 'Select a sample first if you want it linked automatically.'} /> : (
              <>
                <div className="ctf-header">
                  <div><span className="eyebrow">{selected.category} · {selected.difficulty}</span><h2>{selected.title}</h2>{selected.binary_sha256 && <code>{selected.binary_sha256}</code>}</div>
                  <div><button className="btn secondary" type="button" onClick={() => exportWorkspace('markdown')}>Export Markdown</button><button className="btn secondary" type="button" onClick={() => exportWorkspace('json')}>JSON</button></div>
                </div>
                <div className="ctf-grid">
                  <section className="ctf-card checklist">
                    <h3>Analysis checklist</h3>
                    {Object.entries(selected.checklist).map(([item, complete]) => <label key={item}><input type="checkbox" checked={complete} onChange={() => patch({ checklist: { ...selected.checklist, [item]: !complete } })} />{item}</label>)}
                  </section>
                  <section className="ctf-card">
                    <h3>Notes & evidence</h3>
                    <div className="note-compose"><select className="text" value={noteKind} onChange={(event) => setNoteKind(event.target.value)}>{['note', 'hypothesis', 'address', 'string', 'bookmark', 'hint'].map((item) => <option key={item}>{item}</option>)}</select><input className="text" value={address} onChange={(event) => setAddress(event.target.value)} placeholder="0x address (optional)" /><textarea value={note} onChange={(event) => setNote(event.target.value)} placeholder="Evidence or analyst note…" /><button className="btn" onClick={addNote}>Add note</button></div>
                    <div className="ctf-notes">{selected.notes.map((item) => <article key={item.id}><span>{item.kind}</span>{item.address != null && <code>{hex(item.address)}</code>}<p>{item.content}</p></article>)}</div>
                  </section>
                  <section className="ctf-card compact-lists">
                    <h3>Hypotheses</h3>
                    <div><input className="text" value={hypothesis} onChange={(event) => setHypothesis(event.target.value)} /><button onClick={() => addList('hypotheses', hypothesis, () => setHypothesis(''))}>＋</button></div>
                    <ul>{selected.hypotheses.map((item) => <li key={item}>{item}</li>)}</ul>
                    <h3>Flag candidates</h3>
                    <div><input className="text" value={candidate} onChange={(event) => setCandidate(event.target.value)} /><button onClick={() => addList('flag_candidates', candidate, () => setCandidate(''))}>＋</button></div>
                    <ul>{selected.flag_candidates.map((item) => <li key={item}><code>{item}</code></li>)}</ul>
                    <h3>Write-up steps</h3>
                    <div><input className="text" value={step} onChange={(event) => setStep(event.target.value)} /><button onClick={() => addList('writeup_steps', step, () => setStep(''))}>＋</button></div>
                    <ol>{selected.writeup_steps.map((item) => <li key={item}>{item}</li>)}</ol>
                  </section>
                </div>
                <DecoderPlayground />
              </>
            )}
          </section>
        </div>
      )}
    </div>
  );
}
