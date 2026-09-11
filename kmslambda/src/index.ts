import { APIGatewayProxyStructuredResultV2, Context } from 'aws-lambda';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  UpdateCommand,
} from '@aws-sdk/lib-dynamodb';
import { KMSClient, DescribeKeyCommand, GetPublicKeyCommand, SignCommand } from '@aws-sdk/client-kms';
import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';
import { SSMClient, GetParameterCommand } from '@aws-sdk/client-ssm';
import { ulid } from 'ulid';
import crypto from 'crypto';
import { exportCertifiedPublicKey, fingerprintOf, OpenPgpPublicKey } from './openpgp';
import {
  ApprovalIdentity,
  formatFingerprint,
  isoSeconds,
  renderApprovalPage,
} from './approvalPage';

// ---------- Environment ----------
const {
  TABLE_NAME,
  KMS_KEY_ID,
  SNS_TOPIC_ARN,
  API_BASE_URL,
  APPROVAL_HMAC_PARAM_NAME,
  OPENPGP_USER_NAME,
  OPENPGP_USER_EMAIL,
} = process.env;

const REQUEST_TTL_SECONDS = parseInt(process.env.REQUEST_TTL_SECONDS || '3600', 10);
const APPROVAL_TTL_SECONDS = parseInt(process.env.APPROVAL_TTL_SECONDS || '1800', 10);

if (
  !TABLE_NAME ||
  !KMS_KEY_ID ||
  !SNS_TOPIC_ARN ||
  !API_BASE_URL ||
  !APPROVAL_HMAC_PARAM_NAME ||
  !OPENPGP_USER_NAME ||
  !OPENPGP_USER_EMAIL
) {
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
        OPENPGP_USER_NAME: !!OPENPGP_USER_NAME,
        OPENPGP_USER_EMAIL: !!OPENPGP_USER_EMAIL,
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
  artifactDigest: string; // OpenPGP SHA-256 digest KMS signs (hex)
  hashedAt: number; // unix seconds in the hashed signature creation-time subpacket
  artifact?: string;
  version?: string;
  environment?: string;
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

const SECURITY_HEADERS = {
  'Cache-Control': 'no-store',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'",
};

function jsonResponse(statusCode: number, body: unknown): APIGatewayProxyStructuredResultV2 {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      ...SECURITY_HEADERS,
    },
    body: JSON.stringify(body),
  };
}

function htmlResponse(statusCode: number, html: string): APIGatewayProxyStructuredResultV2 {
  return {
    statusCode,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      ...SECURITY_HEADERS,
    },
    body: html,
  };
}

function redirectToApprove(token: string): APIGatewayProxyStructuredResultV2 {
  return {
    statusCode: 303,
    headers: {
      Location: `${API_BASE_URL}/approve?token=${encodeURIComponent(token)}`,
      ...SECURITY_HEADERS,
    },
  };
}

function openPgpUserId(): string {
  const name = (OPENPGP_USER_NAME || '').trim();
  const email = (OPENPGP_USER_EMAIL || '').trim();
  if (!name || !email) return '';
  return `${name} <${email}>`;
}

async function approvalIdentity(): Promise<ApprovalIdentity> {
  const userId = openPgpUserId();
  try {
    return { userId, fingerprint: formatFingerprint(await signingFingerprint()) };
  } catch {
    return { userId };
  }
}

function approvePage(opts: {
  token?: string;
  item?: SignRequestItem | null;
  error?: string;
  identity: ApprovalIdentity;
}): string {
  return renderApprovalPage({
    token: opts.token,
    item: opts.item,
    error: opts.error,
    identity: opts.identity,
    approveAction: `${API_BASE_URL || ''}/approve`,
  });
}

function snsSubject(artifact?: string, version?: string): string {
  const leaf = artifact ? artifact.split('/').filter(Boolean).pop() || artifact : '';
  const parts = ['Sign', leaf, version].filter((p) => !!p);
  let subject = parts.join(' ') || 'Sign request';
  if (subject.length > 100) subject = subject.slice(0, 100);
  return subject;
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

async function verifyToken(
  token: string,
  expectedCap: Capability,
  opts?: { allowExpired?: boolean }
): Promise<TokenPayload> {
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
  if (typeof payload.exp !== 'number') throw new Error('Token expired');
  if (payload.exp < nowSeconds() && !opts?.allowExpired) throw new Error('Token expired');
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

const ARTIFACT_RE = /^[A-Za-z0-9._@/+:-]{1,256}$/;
const SHORT_RE = /^[A-Za-z0-9._@/+:-]{1,64}$/;

function optionalAscii(value: unknown, re: RegExp, field: string): { ok: true; value?: string } | { ok: false; error: string; code: string } {
  if (value == null || value === '') {
    return { ok: true };
  }
  if (typeof value !== 'string' || !re.test(value)) {
    return {
      ok: false,
      error: `Invalid ${field}: expected ASCII matching ${re}`,
      code: 'BAD_FIELD',
    };
  }
  return { ok: true, value };
}

function asUnixSeconds(value: unknown): number | null {
  if (typeof value === 'number' && Number.isInteger(value)) return value;
  if (typeof value === 'string' && /^-?\d+$/.test(value)) return parseInt(value, 10);
  return null;
}

async function createRequest(input: any) {
  if (!TABLE_NAME || !KMS_KEY_ID || !SNS_TOPIC_ARN || !API_BASE_URL) {
    throw new Error('Service not configured (env vars missing)');
  }
  const { digest, hashedAt: hashedAtRaw, artifact, version, environment } = input || {};
  if (!digest || typeof digest !== 'string' || !isHexSha256(digest)) {
    return {
      ok: false,
      error: 'Invalid or missing digest: expected 64-char hex SHA-256',
      code: 'BAD_DIGEST',
    };
  }
  const hashedAt = asUnixSeconds(hashedAtRaw);
  if (hashedAt == null || hashedAt < 946684800 || hashedAt > nowSeconds() + 86400) {
    return {
      ok: false,
      error: 'Invalid or missing hashedAt: expected unix seconds of the OpenPGP hashed creation time',
      code: 'BAD_HASHED_AT',
    };
  }
  const artifactR = optionalAscii(artifact, ARTIFACT_RE, 'artifact');
  if (!artifactR.ok) return artifactR;
  const versionR = optionalAscii(version, SHORT_RE, 'version');
  if (!versionR.ok) return versionR;
  const environmentR = optionalAscii(environment, SHORT_RE, 'environment');
  if (!environmentR.ok) return environmentR;

  const requestId = ulid();
  const createdAt = nowSeconds();
  const expiresAt = createdAt + REQUEST_TTL_SECONDS;
  const approvalExpiresAt = createdAt + APPROVAL_TTL_SECONDS;
  const digestHex = digest.toLowerCase();

  const item: SignRequestItem = {
    requestId,
    status: 'WAITING',
    artifactDigest: digestHex,
    hashedAt,
    artifact: artifactR.value,
    version: versionR.value,
    environment: environmentR.value,
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

  const signer = openPgpUserId();
  let fingerprintLine: string | undefined;
  try {
    fingerprintLine = `Fingerprint: ${formatFingerprint(await signingFingerprint())}`;
  } catch {
    fingerprintLine = undefined;
  }
  const expiresIso = isoSeconds(approvalExpiresAt);
  const messageLines = [
    `Request ID: ${requestId}`,
    item.artifact ? `Artifact: ${item.artifact}` : undefined,
    item.version ? `Version: ${item.version}` : undefined,
    item.environment ? `Environment: ${item.environment}` : undefined,
    signer ? `Signer: ${signer}` : undefined,
    fingerprintLine,
    ``,
    `Digest KMS will sign (must match the sign command):`,
    digestHex,
    `hashedAt: ${isoSeconds(hashedAt)} (${hashedAt})`,
    `This is not sha256sum of the file.`,
    ``,
    `Opening the link does not sign.`,
    `Approval link (expires ${expiresIso}):`,
    approvalUrl,
  ].filter((line) => line !== undefined) as string[];
  await sns.send(
    new PublishCommand({
      TopicArn: SNS_TOPIC_ARN,
      Subject: snsSubject(item.artifact, item.version),
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
  const identity = await approvalIdentity();
  try {
    const token = event.queryStringParameters?.token || '';
    if (!token) {
      return htmlResponse(400, approvePage({ error: 'Missing token', identity }));
    }
    let payload: TokenPayload;
    try {
      payload = await verifyToken(token, 'approve', { allowExpired: true });
    } catch (e: any) {
      return htmlResponse(400, approvePage({ error: e.message || 'Invalid token', identity }));
    }
    const item = await getRequest(payload.rid);
    if (!item) {
      return htmlResponse(404, approvePage({ error: 'Request not found', identity }));
    }
    return htmlResponse(200, approvePage({ token, item, identity }));
  } catch (err: any) {
    console.error(JSON.stringify({ level: 'error', msg: 'approve GET failed', error: err?.message }));
    return htmlResponse(500, approvePage({ error: 'Internal error', identity }));
  }
}

async function handleApprovePost(event: any) {
  const identity = await approvalIdentity();
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
      return htmlResponse(400, approvePage({ error: 'Missing token', identity }));
    }
    let payload: TokenPayload;
    try {
      payload = await verifyToken(token, 'approve');
    } catch (e: any) {
      if (e.message === 'Token expired') {
        return redirectToApprove(token);
      }
      return htmlResponse(400, approvePage({ error: e.message || 'Invalid token', identity }));
    }
    const item = await getRequest(payload.rid);
    if (!item) {
      return htmlResponse(404, approvePage({ error: 'Request not found', identity }));
    }
    if (item.status !== 'WAITING' || nowSeconds() > item.approvalExpiresAt) {
      return redirectToApprove(token);
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
        return redirectToApprove(token);
      }
      return redirectToApprove(token);
    }
    if (decision !== 'approve') {
      return htmlResponse(400, approvePage({ error: 'Invalid decision', identity }));
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
      return redirectToApprove(token);
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
        approvePage({
          identity,
          error: `Request ${item.requestId} was signed but the result was not stored.`,
        })
      );
    }
    return redirectToApprove(token);
  } catch (err: any) {
    console.error(JSON.stringify({ level: 'error', msg: 'approve POST failed', error: err?.message }));
    return htmlResponse(500, approvePage({ error: 'Internal error', identity }));
  }
}

async function handleGetRequestStatus(event: any) {
  try {
    const rid: string | undefined = event.pathParameters?.id || event.pathParameters?.requestId;
    if (!rid) return jsonResponse(400, { ok: false, error: 'Missing request id' });
    const token = event.queryStringParameters?.token || '';
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
      hashedAt: item.hashedAt,
      artifact: item.artifact,
      version: item.version,
      environment: item.environment,
      createdAt: item.createdAt,
      expiresAt: item.expiresAt,
    };
    if (item.status === 'SIGNED' && item.signature) {
      response.signature = item.signature;
      response.signingAlgorithm = item.algorithm || 'ECDSA_SHA_256';
      response.fingerprint = await signingFingerprint();
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

interface PublicKeyInfo {
  pem: string;
  creationDate: Date;
  description?: string;
  fingerprint: string;
}

let cachedPublicKey: PublicKeyInfo | null = null;

async function loadPublicKey(): Promise<PublicKeyInfo> {
  if (cachedPublicKey) return cachedPublicKey;
  if (!KMS_KEY_ID) throw new Error('KMS_KEY_ID not set');
  const [pub, des] = await Promise.all([
    kms.send(new GetPublicKeyCommand({ KeyId: KMS_KEY_ID })),
    kms.send(new DescribeKeyCommand({ KeyId: KMS_KEY_ID })),
  ]);
  const publicKeyDer = pub.PublicKey;
  if (!publicKeyDer) throw new Error('No public key');
  const created = des.KeyMetadata?.CreationDate;
  if (!created) throw new Error('KMS key has no creation date');
  const b64 = Buffer.from(publicKeyDer).toString('base64');
  const pem = `-----BEGIN PUBLIC KEY-----\n${chunk64(b64)}\n-----END PUBLIC KEY-----\n`;
  cachedPublicKey = {
    pem,
    creationDate: created,
    description: des.KeyMetadata?.Description,
    fingerprint: fingerprintOf(pem, created),
  };
  return cachedPublicKey;
}

async function signingFingerprint(): Promise<string> {
  return (await loadPublicKey()).fingerprint;
}

const openPgpCache = new Map<string, OpenPgpPublicKey>();

async function exportOpenPgp(): Promise<OpenPgpPublicKey> {
  const userName = (OPENPGP_USER_NAME || '').trim();
  const userEmail = (OPENPGP_USER_EMAIL || '').trim();
  if (!userName || !userEmail) {
    throw new Error('OpenPGP user id is not configured');
  }
  const info = await loadPublicKey();
  let userId = `${userName} <${userEmail}>`;
  if (info.description && info.description.trim()) {
    userId += ` (${info.description.trim()})`;
  }
  const cached = openPgpCache.get(userId);
  if (cached) return cached;
  const exported = await exportCertifiedPublicKey({
    publicKeyPem: info.pem,
    createdAt: info.creationDate,
    userId,
    signDigest: async (digest) => {
      const signOut = await kms.send(
        new SignCommand({
          KeyId: KMS_KEY_ID!,
          Message: digest,
          MessageType: 'DIGEST',
          SigningAlgorithm: 'ECDSA_SHA_256',
        })
      );
      if (!signOut.Signature) throw new Error('KMS returned no signature');
      return Buffer.from(signOut.Signature);
    },
  });
  openPgpCache.set(userId, exported);
  return exported;
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
  return jsonResponse(404, { ok: false, error: 'Not found' });
}

// ---------- Lambda Invoke (create / export) ----------
const EXPORT_ALIAS = 'export';

function invokedViaExportAlias(context: Context): boolean {
  const arn = context.invokedFunctionArn || '';
  const name = context.functionName || '';
  const marker = `:function:${name}:`;
  const i = arn.lastIndexOf(marker);
  if (i < 0) return false;
  return arn.slice(i + marker.length) === EXPORT_ALIAS;
}

async function handleInvoke(event: any, context: Context) {
  const action = event?.action;
  if (action === 'export') {
    if (!invokedViaExportAlias(context)) {
      return { ok: false, error: 'export requires the export alias' };
    }
    try {
      const exported = await exportOpenPgp();
      return { ok: true, ...exported };
    } catch (e: any) {
      return { ok: false, error: e?.message || 'export failed' };
    }
  }
  if (action !== 'create') {
    return { ok: false, error: 'Unsupported action', supported: ['create', 'export'] };
  }
  return createRequest(event);
}

// ---------- Handler ----------
export const handler = async (event: any, context: Context): Promise<any> => {
  try {
    if (isHttpEvent(event)) {
      return await handleHttp(event);
    }
    return await handleInvoke(event, context);
  } catch (err: any) {
    console.error(JSON.stringify({ level: 'error', msg: 'Unhandled error', error: err?.message }));
    if (isHttpEvent(event)) {
      return jsonResponse(500, { ok: false, error: 'Internal error' });
    }
    return { ok: false, error: 'Internal error' };
  }
};

