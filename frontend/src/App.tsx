import { useState } from 'react';
import './App.css';
import {
  sendSecureRequest,
  fetchAdminRequests,
  fetchAdminResponses,
  replayRequest
} from './api';

const defaultPayload = {
  action: 'INVESTMENT_SUMMARY',
  accountId: 'ACC123',
  month: 'JAN-2025'
};

export default function App() {
  const [kid, setKid] = useState('server-key-1');
  const [serverPublicKey, setServerPublicKey] = useState('');
  const [clientPrivateKey, setClientPrivateKey] = useState('');
  const [payloadText, setPayloadText] = useState(
    JSON.stringify(defaultPayload, null, 2)
  );
  const [response, setResponse] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isSending, setIsSending] = useState(false);
  const [adminRequests, setAdminRequests] = useState<any[]>([]);
  const [adminResponses, setAdminResponses] = useState<any[]>([]);
  const [adminError, setAdminError] = useState<string | null>(null);
  const [replayId, setReplayId] = useState('');
  const [replayTarget, setReplayTarget] = useState('');
  const [replayStatus, setReplayStatus] = useState<string | null>(null);

  const handleSend = async () => {
    setError(null);
    setResponse(null);

    let parsedPayload: unknown;
    try {
      parsedPayload = JSON.parse(payloadText);
    } catch {
      setError('Payload must be valid JSON.');
      return;
    }

    if (!serverPublicKey.trim() || !clientPrivateKey.trim()) {
      setError('Provide both the server public key and your client private key.');
      return;
    }

    setIsSending(true);

    try {
      const result = await sendSecureRequest(
        parsedPayload,
        {
          kid: kid.trim() || 'server-key-1',
          publicKey: serverPublicKey.trim()
        },
        clientPrivateKey.trim()
      );
      setResponse(JSON.stringify(result, null, 2));
    } catch (err) {
      const message =
        err instanceof Error
          ? err.message
          : 'Unable to send secure request. Check console for details.';
      setError(message);
      console.error(err);
    } finally {
      setIsSending(false);
    }
  };

  const loadRequests = async () => {
    setAdminError(null);
    try {
      const docs = await fetchAdminRequests();
      setAdminRequests(docs);
    } catch (err) {
      setAdminError(err instanceof Error ? err.message : 'Failed to load requests');
    }
  };

  const loadResponses = async () => {
    setAdminError(null);
    try {
      const docs = await fetchAdminResponses();
      setAdminResponses(docs);
    } catch (err) {
      setAdminError(err instanceof Error ? err.message : 'Failed to load responses');
    }
  };

  const handleReplay = async () => {
    setReplayStatus(null);
    setAdminError(null);
    if (!replayId.trim()) {
      setAdminError('Enter a request_id to replay.');
      return;
    }
    try {
      const result = await replayRequest(replayId.trim(), replayTarget.trim() || undefined);
      setReplayStatus(JSON.stringify(result, null, 2));
    } catch (err) {
      setAdminError(err instanceof Error ? err.message : 'Replay failed');
    }
  };

  return (
    <main className="app">
      <header>
        <p className="eyebrow">Asymmetric workflow</p>
        <h1>Secure request client</h1>
        <p className="lede">
          Encrypts with the server public key, signs with your client private key, and
          appends nonce + timestamp before calling the backend.
        </p>
      </header>

      <section className="panel">
        <div className="field">
          <label htmlFor="kid">Key ID (kid)</label>
          <input
            id="kid"
            value={kid}
            onChange={e => setKid(e.target.value)}
            placeholder="server-key-1"
          />
        </div>

        <div className="field">
          <label htmlFor="server-key">Server public key (PEM)</label>
          <textarea
            id="server-key"
            value={serverPublicKey}
            onChange={e => setServerPublicKey(e.target.value)}
            placeholder="-----BEGIN PUBLIC KEY-----"
            rows={6}
          />
        </div>

        <div className="field">
          <label htmlFor="client-key">Client private key (PEM, RSA-PSS)</label>
          <textarea
            id="client-key"
            value={clientPrivateKey}
            onChange={e => setClientPrivateKey(e.target.value)}
            placeholder="-----BEGIN PRIVATE KEY-----"
            rows={8}
          />
        </div>

        <div className="field">
          <label htmlFor="payload">Payload (JSON)</label>
          <textarea
            id="payload"
            value={payloadText}
            onChange={e => setPayloadText(e.target.value)}
            rows={8}
          />
        </div>

        <div className="actions">
          <button onClick={handleSend} disabled={isSending}>
            {isSending ? 'Sending...' : 'Send secure request'}
          </button>
          <p className="hint">
            Each request generates nonce + timestamp so backend replay checks pass.
          </p>
        </div>
      </section>

      <section className="panel">
        <div className="result-header">
          <h2>Backend response</h2>
          <span className="status-chip">
            {isSending ? 'Encrypting and sending...' : 'Ready'}
          </span>
        </div>

        {error && <div className="error-box">{error}</div>}
        {response && <pre className="code-block">{response}</pre>}
        {!error && !response && (
          <p className="muted">Submit a payload to see the backend response here.</p>
        )}
      </section>

      <section className="panel">
        <div className="result-header">
          <h2>Admin debug dashboard</h2>
          <span className="status-chip">Observability</span>
        </div>

        <div className="actions">
          <button onClick={loadRequests}>Load recent requests</button>
          <button onClick={loadResponses}>Load recent responses</button>
        </div>

        <div className="field">
          <label htmlFor="replay-id">Replay request_id</label>
          <input
            id="replay-id"
            value={replayId}
            onChange={e => setReplayId(e.target.value)}
            placeholder="request UUID"
          />
        </div>

        <div className="field">
          <label htmlFor="replay-target">Replay target URL (optional)</label>
          <input
            id="replay-target"
            value={replayTarget}
            onChange={e => setReplayTarget(e.target.value)}
            placeholder="http://localhost:3000/secure"
          />
        </div>

        <div className="actions">
          <button onClick={handleReplay}>Replay</button>
          {adminError && <div className="error-box">{adminError}</div>}
        </div>

        {replayStatus && (
          <div style={{width:"70%"}}>
            <p className="muted">Replay result</p>
            <pre className="code-block">{replayStatus}</pre>
          </div>
        )}

        {adminRequests.length > 0 && (
          <div>
            <p className="muted">Recent requests</p>
            <pre className="code-block">
              {JSON.stringify(adminRequests.slice(0, 5), null, 2)}
            </pre>
          </div>
        )}

        {adminResponses.length > 0 && (
          <div>
            <p className="muted">Recent responses</p>
            <pre className="code-block">
              {JSON.stringify(adminResponses.slice(0, 5), null, 2)}
            </pre>
          </div>
        )}
      </section>
    </main>
  );
}
