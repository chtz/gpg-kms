import { APIGatewayProxyStructuredResultV2 } from 'aws-lambda';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  UpdateCommand,
} from '@aws-sdk/lib-dynamodb';
import { KMSClient, GetPublicKeyCommand, SignCommand } from '@aws-sdk/client-kms';
import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';
import { SSMClient, GetParameterCommand } from '@aws-sdk/client-ssm';
import { ulid } from 'ulid';
import crypto from 'crypto';

// ---------- Environment ----------
const {
  TABLE_NAME,
  KMS_KEY_ID,
  SNS_TOPIC_ARN,
  API_BASE_URL,
  APPROVAL_HMAC_PARAM_NAME,
} = process.env;

const REQUEST_TTL_SECONDS = parseInt(process.env.REQUEST_TTL_SECONDS || '3600', 10);
const APPROVAL_TTL_SECONDS = parseInt(process.env.APPROVAL_TTL_SECONDS || '1800', 10);

if (!TABLE_NAME || !KMS_KEY_ID || !SNS_TOPIC_ARN || !API_BASE_URL || !APPROVAL_HMAC_PARAM_NAME) {
  // We don't throw here to avoid Lambda init failure; checks occur at runtime paths as well.
  console.warn(
    JSON.stringify({
      level: 'warn',
      msg: 'Missing required environment variables',
      missing: {
        TABLE_NAME: !!TABLE_NAME,
        KMS_KEY_ID: !!KMS_KEY_ID,
        SNS_TOPIC_ARN: !!SNS_TOPIC_ARN,
        API_BASE_URL: !!API_BASE_URL,
        APPROVAL_HMAC_PARAM_NAME: !!APPROVAL_HMAC_PARAM_NAME,
      },
    })
  );
}

// ---------- AWS SDK Clients ----------
const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}), {
  marshallOptions: { removeUndefinedValues: true },
});
const kms = new KMSClient({});
const sns = new SNSClient({});
const ssm = new SSMClient({});

// ---------- Types ----------
type Status = 'WAITING' | 'SIGNING' | 'SIGNED' | 'FAILED' | 'REJECTED';

interface SignRequestItem {
  requestId: string;
  status: Status;
  artifactDigest: string; // sha256 hex
  artifact?: string;
  version?: string;
  environment?: string;
  metadata?: Record<string, unknown>;
  createdAt: number; // epoch seconds
  expiresAt: number; // epoch seconds (TTL)
  approvalExpiresAt: number; // epoch seconds
  approvedAt?: number;
  approverIp?: string;
  rejectedAt?: number;
  rejectionReason?: string;
  signedAt?: number;
  algorithm?: string;
  signature?: string; // base64 DER ECDSA
  error?: string;
}

// ---------- Utilities ----------
function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function isHttpEvent(event: any): boolean {
  return Boolean(event?.requestContext?.http?.method);
}

function jsonResponse(statusCode: number, body: unknown): APIGatewayProxyStructuredResultV2 {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
    },
    body: JSON.stringify(body),
  };
}

function htmlResponse(statusCode: number, html: string): APIGatewayProxyStructuredResultV2 {
  return {
    statusCode,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
    },
    body: html,
  };
}

function escapeHtml(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function chunk64(s: string): string {
  return s.replace(/(.{64})/g, '$1\n');
}

function toBase64Url(buf: Buffer): string {
  return buf
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function fromBase64Url(s: string): Buffer {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const pad = b64.length % 4 ? 4 - (b64.length % 4) : 0;
  return Buffer.from(b64 + '='.repeat(pad), 'base64');
}

function timingSafeEqual(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// ---------- HMAC Approval/Poll Tokens ----------
type Capability = 'approve' | 'poll';
interface TokenPayload {
  ver: 1;
  cap: Capability;
  rid: string; // requestId
  exp: number; // epoch seconds
}

let cachedHmacSecret: { value: Buffer; loadedAt: number } | null = null;
const SECRET_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

async function getApprovalSecret(): Promise<Buffer> {
  const now = Date.now();
  if (cachedHmacSecret && now - cachedHmacSecret.loadedAt < SECRET_CACHE_TTL_MS) {
    return cachedHmacSecret.value;
  }
  if (!APPROVAL_HMAC_PARAM_NAME) throw new Error('APPROVAL_HMAC_PARAM_NAME not set');
  const resp = await ssm.send(
    new GetParameterCommand({
      Name: APPROVAL_HMAC_PARAM_NAME,
      WithDecryption: true,
    })
  );
  const v = resp.Parameter?.Value;
  if (!v) throw new Error('Approval HMAC secret parameter missing value');
  const secret = Buffer.from(v, 'utf8');
  cachedHmacSecret = { value: secret, loadedAt: now };
  return secret;
}

async function signToken(payload: TokenPayload): Promise<string> {
  const secret = await getApprovalSecret();
  const body = Buffer.from(JSON.stringify(payload), 'utf8');
  const mac = crypto.createHmac('sha256', secret).update(body).digest();
  return `${toBase64Url(body)}.${toBase64Url(mac)}`;
}

async function verifyToken(token: string, expectedCap: Capability): Promise<TokenPayload> {
  const [bodyB64u, sigB64u] = token.split('.');
  if (!bodyB64u || !sigB64u) throw new Error('Malformed token');
  const body = fromBase64Url(bodyB64u);
  const sig = fromBase64Url(sigB64u);
  const secret = await getApprovalSecret();
  const mac = crypto.createHmac('sha256', secret).update(body).digest();
  if (!timingSafeEqual(mac, sig)) throw new Error('Invalid token signature');
  const payload = JSON.parse(body.toString('utf8')) as TokenPayload;
  if (payload.ver !== 1) throw new Error('Unsupported token version');
  if (payload.cap !== expectedCap) throw new Error('Wrong capability');
  if (typeof payload.exp !== 'number' || payload.exp < nowSeconds()) throw new Error('Token expired');
  if (!payload.rid) throw new Error('Missing rid');
  return payload;
}

// ---------- Core logic ----------
function isHexSha256(s: string): boolean {
  return /^[a-f0-9]{64}$/i.test(s);
}

function hexToBuffer(hex: string): Buffer {
  return Buffer.from(hex, 'hex');
}

async function createRequest(input: any) {
  if (!TABLE_NAME || !KMS_KEY_ID || !SNS_TOPIC_ARN || !API_BASE_URL) {
    throw new Error('Service not configured (env vars missing)');
  }
  const { digest, artifact, version, environment, metadata } = input || {};
  if (!digest || typeof digest !== 'string' || !isHexSha256(digest)) {
    return {
      ok: false,
      error: 'Invalid or missing digest: expected 64-char hex SHA-256',
      code: 'BAD_DIGEST',
    };
  }
  const requestId = ulid();
  const createdAt = nowSeconds();
  const expiresAt = createdAt + REQUEST_TTL_SECONDS;
  const approvalExpiresAt = createdAt + APPROVAL_TTL_SECONDS;

  const item: SignRequestItem = {
    requestId,
    status: 'WAITING',
    artifactDigest: digest.toLowerCase(),
    artifact,
    version,
    environment,
    metadata,
    createdAt,
    expiresAt,
    approvalExpiresAt,
  };

  await ddb.send(
    new PutCommand({
      TableName: TABLE_NAME,
      Item: item,
      ConditionExpression: 'attribute_not_exists(requestId)',
    })
  );

  const approvalToken = await signToken({
    ver: 1,
    cap: 'approve',
    rid: requestId,
    exp: approvalExpiresAt,
  });
  const pollToken = await signToken({
    ver: 1,
    cap: 'poll',
    rid: requestId,
    exp: expiresAt,
  });
  const approvalUrl = `${API_BASE_URL}/approve?token=${encodeURIComponent(approvalToken)}`;
  const pollUrl = `${API_BASE_URL}/requests/${encodeURIComponent(requestId)}?token=${encodeURIComponent(
    pollToken
  )}`;

  // Publish approval notification via SNS (do not log token/URL)
  const messageLines = [
    `Artifact signing approval requested`,
    artifact ? `Artifact: ${artifact}` : undefined,
    version ? `Version: ${version}` : undefined,
    environment ? `Environment: ${environment}` : undefined,
    `Request ID: ${requestId}`,
    `SHA-256: ${digest.toLowerCase()}`,
    `Approval link (expires ${new Date(approvalExpiresAt * 1000).toISOString()}):`,
    `${approvalUrl}`,
  ].filter(Boolean) as string[];
  await sns.send(
    new PublishCommand({
      TopicArn: SNS_TOPIC_ARN,
      Subject: 'Artifact signing approval requested',
      Message: messageLines.join('\n'),
    })
  );
  console.log(
    JSON.stringify({
      level: 'info',
      msg: 'Created signing request',
      requestId,
      createdAt,
      expiresAt,
      hasApproval: true,
    })
  );

  return {
    ok: true,
    requestId,
    status: 'WAITING' as Status,
    expiresAt,
    approvalExpiresAt,
    pollUrl,
    pollToken,
  };
}

async function getRequest(requestId: string): Promise<SignRequestItem | null> {
  if (!TABLE_NAME) throw new Error('TABLE_NAME not set');
  const out = await ddb.send(
    new GetCommand({
      TableName: TABLE_NAME,
      Key: { requestId },
      ConsistentRead: true,
    })
  );
  return (out.Item as SignRequestItem) ?? null;
}

function renderApprovalPage(opts: {
  ok: boolean;
  error?: string;
  token?: string;
  item?: SignRequestItem | null;
}): string {
  const { ok, error, token, item } = opts;
  const title = 'Artifact Signing Approval';
  const safeError = error ? escapeHtml(error) : '';
  const body = ok && item
    ? `
    <h1>${title}</h1>
    <p>Please review the artifact details below. Clicking Approve authorizes a KMS signature for this exact SHA-256 digest. GET does not approve.</p>
    <ul>
      <li><strong>Request ID:</strong> ${escapeHtml(item.requestId)}</li>
      ${item.artifact ? `<li><strong>Artifact:</strong> ${escapeHtml(item.artifact)}</li>` : ''}
      ${item.version ? `<li><strong>Version:</strong> ${escapeHtml(item.version)}</li>` : ''}
      ${item.environment ? `<li><strong>Environment:</strong> ${escapeHtml(item.environment)}</li>` : ''}
      <li><strong>SHA-256:</strong> <code>${escapeHtml(item.artifactDigest)}</code></li>
      <li><strong>Status:</strong> ${escapeHtml(item.status)}</li>
      <li><strong>Created:</strong> ${new Date(item.createdAt * 1000).toISOString()}</li>
      <li><strong>Expires:</strong> ${new Date(item.expiresAt * 1000).toISOString()}</li>
    </ul>
    ${
      item.status === 'WAITING'
        ? `
    <form method="POST" action="${escapeHtml((API_BASE_URL || '') + '/approve')}" style="display:inline-block;margin-right:1rem;">
      <input type="hidden" name="token" value="${escapeHtml(token || '')}"/>
      <input type="hidden" name="decision" value="approve"/>
      <button type="submit" style="padding:0.5rem 1rem;background:#0a7b2f;color:#fff;border:none;border-radius:4px;cursor:pointer;">Approve</button>
    </form>
    <form method="POST" action="${escapeHtml((API_BASE_URL || '') + '/approve')}" style="display:inline-block;">
      <input type="hidden" name="token" value="${escapeHtml(token || '')}"/>
      <input type="hidden" name="decision" value="reject"/>
      <button type="submit" style="padding:0.5rem 1rem;background:#b00020;color:#fff;border:none;border-radius:4px;cursor:pointer;">Reject</button>
    </form>
    `
        : `<p>No action available: status is ${escapeHtml(item.status)}.</p>`
    }
  `
    : `
    <h1>${title}</h1>
    <p style="color:#b00020;">${safeError || 'Unable to load approval page.'}</p>
  `;
  return `<!doctype html>
  <html lang="en">
    <head>
      <meta charset="utf-8"/>
      <meta name="viewport" content="width=device-width, initial-scale=1"/>
      <title>${title}</title>
      <style>
        body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; margin: 2rem; line-height: 1.5; }
        code { background: #f2f2f2; padding: 0.15rem 0.35rem; border-radius: 3px; }
      </style>
    </head>
    <body>
      ${body}
    </body>
  </html>`;
}

function parseFormUrlEncoded(body: string): Record<string, string> {
  return body
    .split('&')
    .map((kv) => kv.split('='))
    .reduce((acc, [k, v]) => {
      if (!k) return acc;
      acc[decodeURIComponent(k)] = decodeURIComponent(v || '');
      return acc;
    }, {} as Record<string, string>);
}

async function handleApproveGet(event: any) {
  try {
    const token = event.queryStringParameters?.token || '';
    if (!token) {
      return htmlResponse(400, renderApprovalPage({ ok: false, error: 'Missing token' }));
    }
    let payload: TokenPayload;
    try {
      payload = await verifyToken(token, 'approve');
    } catch (e: any) {
      return htmlResponse(400, renderApprovalPage({ ok: false, error: e.message || 'Invalid token' }));
    }
    const item = await getRequest(payload.rid);
    if (!item) {
      return htmlResponse(404, renderApprovalPage({ ok: false, error: 'Request not found' }));
    }
    if (item.expiresAt < nowSeconds()) {
      return htmlResponse(400, renderApprovalPage({ ok: false, error: 'Request expired' }));
    }
    return htmlResponse(200, renderApprovalPage({ ok: true, token, item }));
  } catch (err: any) {
    console.error(JSON.stringify({ level: 'error', msg: 'approve GET failed', error: err?.message }));
    return htmlResponse(500, renderApprovalPage({ ok: false, error: 'Internal error' }));
  }
}

async function handleApprovePost(event: any) {
  try {
    const isBase64 = !!event.isBase64Encoded;
    const raw = isBase64 ? Buffer.from(event.body || '', 'base64').toString('utf8') : event.body || '';
    let token = '';
    let decision = '';
    const contentType = event.headers?.['content-type'] || event.headers?.['Content-Type'] || '';
    if (contentType.includes('application/x-www-form-urlencoded')) {
      const form = parseFormUrlEncoded(raw);
      token = form['token'] || '';
      decision = (form['decision'] || '').toLowerCase();
    } else if (contentType.includes('application/json')) {
      const parsed = JSON.parse(raw || '{}');
      token = parsed.token || '';
      decision = (parsed.decision || '').toLowerCase();
    } else {
      // best effort parse as form
      const form = parseFormUrlEncoded(raw);
      token = form['token'] || '';
      decision = (form['decision'] || '').toLowerCase();
    }
    if (!token) {
      return htmlResponse(400, renderApprovalPage({ ok: false, error: 'Missing token' }));
    }
    let payload: TokenPayload;
    try {
      payload = await verifyToken(token, 'approve');
    } catch (e: any) {
      return htmlResponse(400, renderApprovalPage({ ok: false, error: e.message || 'Invalid token' }));
    }
    const item = await getRequest(payload.rid);
    if (!item) {
      return htmlResponse(404, renderApprovalPage({ ok: false, error: 'Request not found' }));
    }
    if (item.expiresAt < nowSeconds()) {
      return htmlResponse(400, renderApprovalPage({ ok: false, error: 'Request expired' }));
    }
    if (item.status !== 'WAITING') {
      return htmlResponse(400, renderApprovalPage({ ok: false, error: `Already handled: ${item.status}` }));
    }
    const sourceIp: string | undefined = event.requestContext?.http?.sourceIp;
    const now = nowSeconds();
    if (decision === 'reject') {
      // WAITING -> REJECTED (one-time)
      try {
        await ddb.send(
          new UpdateCommand({
            TableName: TABLE_NAME!,
            Key: { requestId: item.requestId },
            UpdateExpression:
              'SET #s = :rejected, rejectedAt = :now, rejectionReason = :rr, approverIp = :ip',
            ConditionExpression: '#s = :waiting AND :now <= expiresAt AND attribute_not_exists(approvedAt)',
            ExpressionAttributeNames: { '#s': 'status' },
            ExpressionAttributeValues: {
              ':rejected': 'REJECTED',
              ':waiting': 'WAITING',
              ':now': now,
              ':rr': 'Rejected by approver',
              ':ip': sourceIp || 'unknown',
            },
          })
        );
      } catch (e: any) {
        return htmlResponse(
          409,
          renderApprovalPage({ ok: false, error: 'Request is no longer waiting or already handled' })
        );
      }
      return htmlResponse(
        200,
        `<!doctype html><html><body><h1>Request Rejected</h1><p>Request ${escapeHtml(
          item.requestId
        )} rejected.</p></body></html>`
      );
    }
    if (decision !== 'approve') {
      return htmlResponse(400, renderApprovalPage({ ok: false, error: 'Invalid decision' }));
    }
    // WAITING -> SIGNING (claim)
    try {
      await ddb.send(
        new UpdateCommand({
          TableName: TABLE_NAME!,
          Key: { requestId: item.requestId },
          UpdateExpression:
            'SET #s = :signing, approvedAt = :now, approverIp = :ip',
          ConditionExpression: '#s = :waiting AND :now <= expiresAt AND attribute_not_exists(approvedAt)',
          ExpressionAttributeNames: { '#s': 'status' },
          ExpressionAttributeValues: {
            ':signing': 'SIGNING',
            ':waiting': 'WAITING',
            ':now': now,
            ':ip': sourceIp || 'unknown',
          },
        })
      );
    } catch (e: any) {
      return htmlResponse(
        409,
        renderApprovalPage({ ok: false, error: 'Request is no longer waiting or already handled' })
      );
    }
    // Perform KMS Sign over DIGEST (hex -> bytes)
    let signatureB64 = '';
    let finalStatus: Status = 'SIGNED';
    let error: string | undefined;
    try {
      const digestBytes = hexToBuffer(item.artifactDigest);
      const signOut = await kms.send(
        new SignCommand({
          KeyId: KMS_KEY_ID!,
          Message: digestBytes,
          MessageType: 'DIGEST',
          SigningAlgorithm: 'ECDSA_SHA_256',
        })
      );
      const sig = signOut.Signature;
      if (!sig) throw new Error('KMS returned no signature');
      signatureB64 = Buffer.from(sig).toString('base64');
      finalStatus = 'SIGNED';
    } catch (e: any) {
      finalStatus = 'FAILED';
      error = e?.message || 'KMS signing failed';
    }
    // Persist outcome SIGNED or FAILED
    try {
      await ddb.send(
        new UpdateCommand({
          TableName: TABLE_NAME!,
          Key: { requestId: item.requestId },
          UpdateExpression:
            finalStatus === 'SIGNED'
              ? 'SET #s = :signed, signature = :sig, #algo = :algo, signedAt = :now2 REMOVE #err'
              : 'SET #s = :failed, #err = :err, signedAt = :now2',
          ConditionExpression: '#s = :signing',
          ExpressionAttributeNames:
            finalStatus === 'SIGNED'
              ? { '#s': 'status', '#algo': 'algorithm', '#err': 'error' }
              : { '#s': 'status', '#err': 'error' },
          ExpressionAttributeValues:
            finalStatus === 'SIGNED'
              ? {
                  ':signed': 'SIGNED',
                  ':signing': 'SIGNING',
                  ':sig': signatureB64,
                  ':algo': 'ECDSA_SHA_256',
                  ':now2': nowSeconds(),
                }
              : {
                  ':failed': 'FAILED',
                  ':signing': 'SIGNING',
                  ':err': error || 'Unknown error',
                  ':now2': nowSeconds(),
                },
        })
      );
    } catch (persistErr: any) {
      console.error(
        JSON.stringify({
          level: 'error',
          msg: 'Persisting sign outcome failed',
          requestId: item.requestId,
          error: persistErr?.message,
        })
      );
      return htmlResponse(
        500,
        `<!doctype html><html><body><h1>Failed to Save Signature</h1>
        <p>Request ${escapeHtml(item.requestId)} was signed but the result was not stored: ${escapeHtml(
          persistErr?.message || 'DynamoDB update failed'
        )}</p></body></html>`
      );
    }
    if (finalStatus === 'SIGNED') {
      return htmlResponse(
        200,
        `<!doctype html><html><body><h1>Signature Created</h1>
        <p>Request ${escapeHtml(item.requestId)} signed successfully.</p>
        <p>Signature (base64 DER):</p>
        <pre style="white-space:pre-wrap;word-break:break-all;">${escapeHtml(signatureB64)}</pre>
        </body></html>`
      );
    } else {
      return htmlResponse(
        500,
        `<!doctype html><html><body><h1>Signing Failed</h1>
        <p>Request ${escapeHtml(item.requestId)} failed: ${escapeHtml(error || '')}</p>
        </body></html>`
      );
    }
  } catch (err: any) {
    console.error(JSON.stringify({ level: 'error', msg: 'approve POST failed', error: err?.message }));
    return htmlResponse(500, renderApprovalPage({ ok: false, error: 'Internal error' }));
  }
}

async function handleGetRequestStatus(event: any) {
  try {
    const rid: string | undefined = event.pathParameters?.id || event.pathParameters?.requestId;
    if (!rid) return jsonResponse(400, { ok: false, error: 'Missing request id' });
    // Token via query or Authorization: Bearer <token>
    const token =
      event.queryStringParameters?.token ||
      (event.headers?.authorization || event.headers?.Authorization || '')
        .toString()
        .replace(/^Bearer\s+/i, '')
        .trim();
    if (!token) return jsonResponse(401, { ok: false, error: 'Missing token' });
    let payload: TokenPayload;
    try {
      payload = await verifyToken(token, 'poll');
    } catch (e: any) {
      return jsonResponse(401, { ok: false, error: e.message || 'Invalid token' });
    }
    if (payload.rid !== rid) return jsonResponse(403, { ok: false, error: 'Token not for this request' });
    const item = await getRequest(rid);
    if (!item) return jsonResponse(404, { ok: false, error: 'Not found' });
    const response: any = {
      ok: true,
      requestId: item.requestId,
      status: item.status,
      artifactDigest: item.artifactDigest,
      artifact: item.artifact,
      version: item.version,
      environment: item.environment,
      createdAt: item.createdAt,
      expiresAt: item.expiresAt,
    };
    if (item.status === 'SIGNED' && item.signature) {
      response.signature = item.signature;
      response.signingAlgorithm = item.algorithm || 'ECDSA_SHA_256';
      response.publicKeyUrl = `${API_BASE_URL}/public-key`;
    }
    if (item.status === 'FAILED' && item.error) {
      response.error = item.error;
    }
    if (item.status === 'REJECTED') {
      response.rejectionReason = item.rejectionReason || 'Rejected';
    }
    return jsonResponse(200, response);
  } catch (err: any) {
    console.error(JSON.stringify({ level: 'error', msg: 'status get failed', error: err?.message }));
    return jsonResponse(500, { ok: false, error: 'Internal error' });
  }
}

let cachedPublicKeyPem: string | null = null;
let cachedKeyMeta: { keySpec?: string; signingAlgorithms?: string[]; keyUsage?: string } | null = null;

async function handleGetPublicKey() {
  try {
    if (cachedPublicKeyPem && cachedKeyMeta) {
      return jsonResponse(200, {
        ok: true,
        keyId: KMS_KEY_ID,
        publicKeyPem: cachedPublicKeyPem,
        keySpec: cachedKeyMeta.keySpec,
        signingAlgorithms: cachedKeyMeta.signingAlgorithms,
        keyUsage: cachedKeyMeta.keyUsage,
      });
    }
    const out = await kms.send(
      new GetPublicKeyCommand({
        KeyId: KMS_KEY_ID!,
      })
    );
    const publicKeyDer = out.PublicKey;
    if (!publicKeyDer) throw new Error('No public key');
    const b64 = Buffer.from(publicKeyDer).toString('base64');
    const pem = `-----BEGIN PUBLIC KEY-----\n${chunk64(b64)}\n-----END PUBLIC KEY-----\n`;
    cachedPublicKeyPem = pem;
    cachedKeyMeta = {
      keySpec: out.KeySpec,
      signingAlgorithms: out.SigningAlgorithms as string[] | undefined,
      keyUsage: out.KeyUsage,
    };
    return jsonResponse(200, {
      ok: true,
      keyId: KMS_KEY_ID,
      publicKeyPem: pem,
      keySpec: out.KeySpec,
      signingAlgorithms: out.SigningAlgorithms,
      keyUsage: out.KeyUsage,
    });
  } catch (err: any) {
    console.error(JSON.stringify({ level: 'error', msg: 'public-key failed', error: err?.message }));
    return jsonResponse(500, { ok: false, error: 'Internal error' });
  }
}

function httpPath(event: any): string {
  const stage: string | undefined = event.requestContext?.stage;
  let path: string = event.requestContext?.http?.path || event.rawPath || '/';
  if (stage && stage !== '$default') {
    const prefix = `/${stage}`;
    if (path === prefix) path = '/';
    else if (path.startsWith(`${prefix}/`)) path = path.slice(prefix.length);
  }
  return path;
}

// ---------- HTTP Router ----------
async function handleHttp(event: any): Promise<APIGatewayProxyStructuredResultV2> {
  const method = event.requestContext.http.method;
  const path = httpPath(event);
  const routeKey: string = event.routeKey || `${method} ${path}`;

  if (routeKey === 'GET /approve' || (method === 'GET' && path === '/approve')) {
    return handleApproveGet(event);
  }
  if (routeKey === 'POST /approve' || (method === 'POST' && path === '/approve')) {
    return handleApprovePost(event);
  }
  if (routeKey === 'GET /requests/{id}' || (method === 'GET' && /^\/requests\/[^/]+$/.test(path))) {
    const m = path.match(/^\/requests\/([^/]+)$/);
    if (m && !event.pathParameters?.id) {
      event.pathParameters = { ...(event.pathParameters || {}), id: decodeURIComponent(m[1]) };
    }
    return handleGetRequestStatus(event);
  }
  if (routeKey === 'GET /public-key' || (method === 'GET' && path === '/public-key')) {
    return handleGetPublicKey();
  }
  return jsonResponse(404, { ok: false, error: 'Not found' });
}

// ---------- Lambda Invoke (create) ----------
async function handleInvoke(event: any) {
  const action = event?.action;
  if (action !== 'create') {
    return { ok: false, error: 'Unsupported action', supported: ['create'] };
  }
  const result = await createRequest(event);
  return result;
}

// ---------- Handler ----------
export const handler = async (event: any): Promise<any> => {
  try {
    if (isHttpEvent(event)) {
      return await handleHttp(event);
    }
    return await handleInvoke(event);
  } catch (err: any) {
    console.error(JSON.stringify({ level: 'error', msg: 'Unhandled error', error: err?.message }));
    if (isHttpEvent(event)) {
      return jsonResponse(500, { ok: false, error: 'Internal error' });
    }
    return { ok: false, error: 'Internal error' };
  }
};

