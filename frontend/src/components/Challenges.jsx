import { useEffect, useState } from 'react';
import { api } from '../api.js';
import { DifficultyBadge, ErrorBanner, Loading } from './common.jsx';

function ChallengeCard({ challenge, solved, onSolved }) {
  const [answer, setAnswer] = useState('');
  const [status, setStatus] = useState(null); // { correct, message }
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    if (!answer.trim()) return;
    setBusy(true);
    try {
      const result = await api.submitChallenge(challenge.slug, answer.trim());
      setStatus(result);
      if (result.correct) onSolved(challenge.slug);
    } catch (err) {
      setStatus({ correct: false, message: err.message });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card challenge-card">
      <div className="row" style={{ justifyContent: 'space-between', display: 'flex' }}>
        <h3>{challenge.title}</h3>
        <DifficultyBadge level={challenge.difficulty} />
      </div>
      <div className="row">
        <span className="badge neutral">{challenge.category}</span>
        {solved && <span className="solved-tag">✓ Solved</span>}
      </div>
      <p className="desc">{challenge.description}</p>
      <details>
        <summary className="muted" style={{ cursor: 'pointer', fontSize: 12 }}>Show hint</summary>
        <div className="hint" style={{ marginTop: 6 }}>{challenge.hint}</div>
      </details>
      <div className="row">
        <a className="btn secondary" href={api.challengeArtifactUrl(challenge.slug)}>
          ↓ Download {challenge.artifact_filename} ({challenge.artifact_size} B)
        </a>
      </div>
      <form className="row" onSubmit={submit}>
        <input
          className="text"
          style={{ flex: 1 }}
          placeholder="RLAB{...}"
          value={answer}
          onChange={(e) => setAnswer(e.target.value)}
        />
        <button className="btn" disabled={busy} type="submit">
          {busy ? '…' : 'Submit'}
        </button>
      </form>
      {status && (
        <div className={`badge ${status.correct ? 'on' : 'off'}`} style={{ alignSelf: 'flex-start' }}>
          {status.message}
        </div>
      )}
    </div>
  );
}

export function Challenges() {
  const [challenges, setChallenges] = useState(null);
  const [error, setError] = useState(null);
  const [solved, setSolved] = useState(() => new Set());

  useEffect(() => {
    api.listChallenges().then(setChallenges).catch((e) => setError(e.message));
  }, []);

  const markSolved = (slug) => setSolved((prev) => new Set(prev).add(slug));

  if (error) return <ErrorBanner error={error} />;
  if (!challenges) return <Loading />;

  return (
    <div>
      <div className="toolbar">
        <h2 style={{ margin: 0 }}>Challenges</h2>
        <span className="muted">
          {solved.size} / {challenges.length} solved
        </span>
      </div>
      <div className="challenge-grid">
        {challenges.map((c) => (
          <ChallengeCard key={c.slug} challenge={c} solved={solved.has(c.slug)} onSolved={markSolved} />
        ))}
      </div>
    </div>
  );
}
