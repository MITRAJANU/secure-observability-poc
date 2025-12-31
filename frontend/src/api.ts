import { encryptHybridWithNonce, verifyResponseSignature } from './crypto';

export type ServerKey = {
  kid: string;
  publicKey: string;
};

export async function sendSecureRequest(
  payload: unknown,
  serverKey: ServerKey,
  clientPrivateKeyPem: string
) {
  const encrypted = await encryptHybridWithNonce(
    payload,
    serverKey.publicKey,
    clientPrivateKeyPem,
    serverKey.kid
  );

  const res = await fetch('http://localhost:3000/secure', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(encrypted)
  });

  let data: unknown = null;
  try {
    data = await res.json();
  } catch {
    // ignore parse failures so we can still surface the HTTP status
  }

  if (!res.ok) {
    const message =
      data &&
      typeof data === 'object' &&
      'error' in (data as Record<string, unknown>)
        ? `Server responded ${res.status}: ${
            (data as Record<string, unknown>).error
          }`
        : `Server responded with status ${res.status}`;
    throw new Error(message);
  }

  // Verify server response signature
  if (
    data &&
    typeof data === 'object' &&
    'signature' in (data as Record<string, unknown>)
  ) {
    try {
      const { signature, ...unsigned } = data as Record<string, unknown>;
      const valid = await verifyResponseSignature(
        unsigned,
        String(signature),
        serverKey.publicKey
      );
      if (!valid) {
        throw new Error('Invalid server response signature');
      }
      return data;
    } catch (err) {
      throw err instanceof Error
        ? err
        : new Error('Failed to verify server response signature');
    }
  }

  throw new Error('Missing server response signature');
}

export async function fetchAdminRequests() {
  const res = await fetch('http://localhost:3000/admin/requests');
  if (!res.ok) throw new Error(`Admin requests failed: ${res.status}`);
  return res.json();
}

export async function fetchAdminResponses() {
  const res = await fetch('http://localhost:3000/admin/responses');
  if (!res.ok) throw new Error(`Admin responses failed: ${res.status}`);
  return res.json();
}

export async function replayRequest(requestId: string, targetUrl?: string) {
  const res = await fetch(`http://localhost:3000/admin/replay/${requestId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(targetUrl ? { targetUrl } : {})
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(
      typeof data?.error === 'string'
        ? data.error
        : `Replay failed with ${res.status}`
    );
  }
  return data;
}
