import { useState } from 'react';
import { api } from '../api.js';
import { ErrorBanner } from './common.jsx';

export function AuthGate({ onAuthenticated }) {
  const [token, setToken] = useState('');
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function authenticate(event) {
    event.preventDefault();
    if (!token) return;
    setBusy(true);
    setError(null);
    api.setApiKey(token);
    try {
      const principal = await api.authMe();
      setToken('');
      await onAuthenticated(principal);
    } catch (failure) {
      api.clearApiKey();
      setError(failure.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="auth-gate">
      <section className="auth-card">
        <span className="auth-mark" aria-hidden="true">⌘</span>
        <span className="eyebrow">PRIVATE ANALYSIS WORKSPACE</span>
        <h1>Authentication required</h1>
        <p>Enter an operator-issued API key. The raw key remains in this tab's memory only and is not written to browser storage.</p>
        <ErrorBanner error={error} />
        <form onSubmit={authenticate}>
          <label htmlFor="api-key">Bearer API key</label>
          <input id="api-key" className="text" type="password" autoComplete="off" value={token} onChange={(event) => setToken(event.target.value)} autoFocus />
          <button className="btn" type="submit" disabled={busy || !token}>{busy ? 'Verifying…' : 'Unlock workbench'}</button>
        </form>
        <small>Keys are configured as SHA-256 digests on the server. Contact the deployment administrator if access is denied.</small>
      </section>
    </main>
  );
}
