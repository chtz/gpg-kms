export type ApprovalStatus = 'WAITING' | 'SIGNING' | 'SIGNED' | 'FAILED' | 'REJECTED';

export interface ApprovalView {
  requestId: string;
  status: ApprovalStatus;
  artifactDigest: string;
  hashedAt: number;
  artifact?: string;
  version?: string;
  environment?: string;
  createdAt: number;
  approvalExpiresAt: number;
}

export interface ApprovalIdentity {
  userId: string;
  fingerprint?: string;
}

export interface ApprovalPageOpts {
  token?: string;
  item?: ApprovalView | null;
  error?: string;
  identity: ApprovalIdentity;
  approveAction: string;
  now?: number;
}

type DisplayState = 'WAITING' | 'SIGNING' | 'SIGNED' | 'FAILED' | 'REJECTED' | 'expired';

const STATE_TITLE: Record<DisplayState, string> = {
  WAITING: 'Approve signature',
  SIGNING: 'Signing',
  SIGNED: 'Signed',
  FAILED: 'Signing failed',
  REJECTED: 'Rejected',
  expired: 'Link expired',
};

const STATE_BANNER: Record<DisplayState, string> = {
  WAITING: 'Review this request',
  SIGNING: 'Signing',
  SIGNED: 'Signed',
  FAILED: 'Signing failed',
  REJECTED: 'Rejected',
  expired: 'Link expired',
};

const STATE_NEXT: Record<DisplayState, string> = {
  WAITING: '',
  SIGNING: 'Signing now…',
  SIGNED: 'The waiting sign command will write the signature and continue.',
  FAILED: 'Retry the sign command.',
  REJECTED: 'The waiting sign command will fail. No signature was created.',
  expired: 'Run the sign command again.',
};

export function isoSeconds(epoch: number): string {
  return new Date(epoch * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

export function groupHex(hex: string, groupSize: number, groupsPerLine?: number): string {
  const clean = hex.replace(/[^0-9a-f]/gi, '').toLowerCase();
  const groups = clean.match(new RegExp(`.{1,${groupSize}}`, 'g')) || [clean];
  if (!groupsPerLine) return groups.join(' ');
  const lines: string[] = [];
  for (let i = 0; i < groups.length; i += groupsPerLine) {
    lines.push(groups.slice(i, i + groupsPerLine).join(' '));
  }
  return lines.join('\n');
}

export function formatFingerprint(hex: string): string {
  const clean = hex.replace(/[^0-9a-f]/gi, '').toUpperCase();
  const parts = clean.match(/.{1,4}/g) || [clean];
  if (parts.length === 10) {
    return `${parts.slice(0, 5).join(' ')}\n${parts.slice(5).join(' ')}`;
  }
  return parts.join(' ');
}

export function escapeHtml(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function displayState(item: ApprovalView, now: number): DisplayState {
  if (item.status === 'WAITING' && now > item.approvalExpiresAt) return 'expired';
  return item.status;
}

function breakable(value: string): string {
  return escapeHtml(value).replace(/([/.])/g, '$1<wbr>');
}

function dlRow(label: string, value: string, opts?: { mono?: boolean; breakable?: boolean }): string {
  const body = opts?.breakable ? breakable(value) : escapeHtml(value);
  return `<div class="row"><dt>${escapeHtml(label)}</dt><dd${opts?.mono ? ' class="mono"' : ''}>${body}</dd></div>`;
}

export function renderApprovalPage(opts: ApprovalPageOpts): string {
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  const item = opts.item;
  const state = item ? displayState(item, now) : undefined;
  const title = state ? STATE_TITLE[state] : 'Approve signature';
  const canAct = Boolean(opts.token && item && state === 'WAITING');
  const expiresLabel = item ? isoSeconds(item.approvalExpiresAt) : '';

  const identity = `
    <header class="brand">
      <p class="wordmark">gpg-kms</p>
      <h1>${escapeHtml(title)}</h1>
      ${
        opts.identity.userId
          ? `<p class="uid">${escapeHtml(opts.identity.userId)}</p>`
          : ''
      }
      ${
        opts.identity.fingerprint
          ? `<pre class="fpr mono">${escapeHtml(opts.identity.fingerprint)}</pre>`
          : ''
      }
    </header>`;

  let main: string;
  if (item && state) {
    const next = STATE_NEXT[state];
    main = `
    ${identity}
    <p class="chip chip-${state}">${escapeHtml(STATE_BANNER[state])}</p>
    ${state === 'WAITING' ? '<p class="lede">Nothing is signed until you click Approve.</p>' : ''}
    <section class="digest" aria-label="OpenPGP digest">
      <h2>OpenPGP SHA-256 digest</h2>
      <pre class="mono digest-hex">${escapeHtml(groupHex(item.artifactDigest, 8, 4))}</pre>
      <p class="hashed"><span class="lbl">hashedAt</span> ${escapeHtml(isoSeconds(item.hashedAt))} <span class="unix">(${item.hashedAt})</span></p>
      <p class="hint">This is not <code>sha256sum</code> of the file. It must match the sign command output.</p>
    </section>
    <dl>
      ${item.artifact ? dlRow('Artifact', item.artifact, { mono: true, breakable: true }) : ''}
      ${item.version ? dlRow('Version', item.version, { mono: true }) : ''}
      ${item.environment ? dlRow('Environment', item.environment, { mono: true, breakable: true }) : ''}
      ${dlRow('Request ID', item.requestId, { mono: true, breakable: true })}
      ${dlRow('Created', isoSeconds(item.createdAt))}
      ${dlRow('Expires', expiresLabel)}
    </dl>
    ${
      canAct
        ? `
    <div class="actions">
      <form method="POST" action="${escapeHtml(opts.approveAction)}" onsubmit="return confirm('Approve a KMS signature of this digest?');">
        <input type="hidden" name="token" value="${escapeHtml(opts.token || '')}"/>
        <input type="hidden" name="decision" value="approve"/>
        <button type="submit" class="btn btn-approve">Approve signature</button>
      </form>
      <form method="POST" action="${escapeHtml(opts.approveAction)}">
        <input type="hidden" name="token" value="${escapeHtml(opts.token || '')}"/>
        <input type="hidden" name="decision" value="reject"/>
        <button type="submit" class="btn btn-reject">Reject</button>
      </form>
    </div>`
        : next
          ? `<p class="next">${escapeHtml(next)}</p>`
          : ''
    }
    <footer>
      <span class="mono">${escapeHtml(item.requestId)}</span>
      <span>${escapeHtml(expiresLabel)}</span>
      <span>gpg-kms</span>
    </footer>`;
  } else {
    main = `
    ${identity}
    <p class="chip chip-FAILED">Error</p>
    <p class="next">${escapeHtml(opts.error || 'Unable to load approval page.')}</p>
    <footer><span>gpg-kms</span></footer>`;
  }

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1"/>
    <title>${escapeHtml(title)}</title>
    <style>
      :root {
        --ink: #1c1917;
        --muted: #57534e;
        --line: #e7e5e4;
        --card: #fff;
        --page: #f5f5f4;
        --chip-WAITING: #92400e;
        --chip-WAITING-bg: #fef3c7;
        --chip-SIGNING: #92400e;
        --chip-SIGNING-bg: #fef3c7;
        --chip-SIGNED: #14532d;
        --chip-SIGNED-bg: #dcfce7;
        --chip-REJECTED: #9f1239;
        --chip-REJECTED-bg: #ffe4e6;
        --chip-FAILED: #9f1239;
        --chip-FAILED-bg: #ffe4e6;
        --chip-expired: #44403c;
        --chip-expired-bg: #e7e5e4;
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        min-height: 100vh;
        font-family: system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
        background: var(--page);
        color: var(--ink);
        line-height: 1.5;
      }
      main {
        max-width: 36rem;
        margin: 0 auto;
        padding: 1.5rem 1.25rem 2.5rem;
      }
      .sheet {
        background: var(--card);
        border: 1px solid var(--line);
        border-radius: 12px;
        padding: 1.35rem 1.35rem 1.1rem;
      }
      .brand { margin-bottom: 1.1rem; }
      .wordmark {
        margin: 0 0 0.45rem;
        font-size: 0.75rem;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: var(--muted);
      }
      h1 {
        margin: 0 0 0.45rem;
        font-size: 1.35rem;
        font-weight: 650;
        letter-spacing: -0.02em;
      }
      .uid { margin: 0; font-weight: 600; overflow-wrap: break-word; }
      .fpr {
        margin: 0.4rem 0 0;
        padding: 0;
        border: 0;
        background: none;
        font-size: 0.8rem;
        line-height: 1.45;
        color: var(--muted);
        white-space: pre-wrap;
      }
      .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
      .chip {
        display: inline-block;
        margin: 0 0 0.85rem;
        padding: 0.2rem 0.6rem;
        border-radius: 999px;
        font-size: 0.8rem;
        font-weight: 600;
      }
      .chip-WAITING { color: var(--chip-WAITING); background: var(--chip-WAITING-bg); }
      .chip-SIGNING { color: var(--chip-SIGNING); background: var(--chip-SIGNING-bg); }
      .chip-SIGNED { color: var(--chip-SIGNED); background: var(--chip-SIGNED-bg); }
      .chip-REJECTED { color: var(--chip-REJECTED); background: var(--chip-REJECTED-bg); }
      .chip-FAILED { color: var(--chip-FAILED); background: var(--chip-FAILED-bg); }
      .chip-expired { color: var(--chip-expired); background: var(--chip-expired-bg); }
      .lede { margin: 0 0 1rem; }
      .digest {
        background: var(--page);
        border: 1px solid var(--line);
        border-radius: 8px;
        padding: 1rem 1.1rem;
        margin: 0 0 1.15rem;
      }
      .digest h2 { margin: 0 0 0.6rem; font-size: 0.8rem; font-weight: 600; color: var(--muted); }
      .digest-hex {
        margin: 0;
        padding: 0;
        border: 0;
        background: none;
        font-size: 0.98rem;
        font-weight: 600;
        line-height: 1.55;
        white-space: pre-wrap;
        user-select: all;
      }
      .hashed { margin: 0.75rem 0 0; }
      .hashed .lbl { color: var(--muted); font-size: 0.85rem; margin-right: 0.35rem; }
      .hashed .unix { color: var(--muted); }
      .hint { margin: 0.35rem 0 0; color: var(--muted); font-size: 0.9rem; }
      .hint code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.88em; }
      dl { margin: 0 0 1.25rem; }
      .row {
        display: grid;
        grid-template-columns: 6.75rem minmax(0, 1fr);
        gap: 0.35rem 0.85rem;
        padding: 0.55rem 0;
      }
      .row + .row { border-top: 1px solid var(--line); }
      dt { color: var(--muted); font-size: 0.85rem; padding-top: 0.1rem; }
      dd { margin: 0; overflow-wrap: break-word; }
      .actions { display: flex; flex-wrap: wrap; gap: 0.75rem; align-items: center; }
      .btn {
        appearance: none;
        min-width: 8.5rem;
        padding: 0.55rem 1rem;
        border-radius: 6px;
        font: inherit;
        font-weight: 600;
        cursor: pointer;
      }
      .btn-approve { background: var(--ink); color: #fff; border: 1px solid var(--ink); }
      .btn-reject { background: #fff; color: var(--ink); border: 1px solid var(--ink); }
      .next { margin: 0 0 1.25rem; }
      footer {
        display: flex;
        flex-wrap: wrap;
        gap: 0.5rem 1rem;
        margin-top: 1.5rem;
        padding-top: 0.75rem;
        border-top: 1px solid var(--line);
        color: var(--muted);
        font-size: 0.8rem;
      }
      footer .mono { overflow-wrap: anywhere; }
    </style>
  </head>
  <body>
    <main>
      <article class="sheet">
      ${main}
      </article>
    </main>
  </body>
</html>`;
}
