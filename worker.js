/**
 * DISC Paradigm™ — Cloudflare Worker Backend
 * KSWhite Consulting, LLC
 *
 * Deploy to Cloudflare Workers. Requires:
 *   - KV Namespace: DISC_KV  (bind in wrangler.toml)
 *   - Environment Variables (set in Cloudflare dashboard):
 *       ADMIN_PASSWORD     = your chosen admin password
 *       RESEND_API_KEY     = from resend.com (free tier)
 *       FROM_EMAIL         = noreply@discparadigm.net
 *       ADMIN_EMAIL        = your email for result notifications
 *       JWT_SECRET         = any long random string (32+ chars)
 */

// ═══════════════════════════════════════════════════════════
// CORS HEADERS
// ═══════════════════════════════════════════════════════════
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS },
  });
}

function err(msg, status = 400) {
  return json({ error: msg, message: msg }, status);
}

// ═══════════════════════════════════════════════════════════
// MAIN ROUTER
// ═══════════════════════════════════════════════════════════
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // Handle preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS });
    }

    try {
      // ── PUBLIC ROUTES ──────────────────────────────────
      if (path === '/validate-code' && request.method === 'POST')
        return await handleValidateCode(request, env);

      if (path === '/send-otp' && request.method === 'POST')
        return await handleSendOtp(request, env);

      if (path === '/verify-otp' && request.method === 'POST')
        return await handleVerifyOtp(request, env);

      if (path === '/save-result' && request.method === 'POST')
        return await handleSaveResult(request, env);

      if (path === '/send-report' && request.method === 'POST')
        return await handleSendReport(request, env);

      // ── ADMIN ROUTES ────────────────────────────────────
      if (path === '/admin/login' && request.method === 'POST')
        return await handleAdminLogin(request, env);

      if (path.startsWith('/admin/')) {
        const authed = await verifyAdminToken(request, env);
        if (!authed) return err('Unauthorized', 401);

        if (path === '/admin/results') return await handleGetResults(env);
        if (path === '/admin/orgs') return await handleGetOrgs(env);
        if (path === '/admin/create-org' && request.method === 'POST')
          return await handleCreateOrg(request, env);
        if (path === '/admin/deactivate-org' && request.method === 'POST')
          return await handleDeactivateOrg(request, env);
      }

      return err('Not found', 404);
    } catch (e) {
      console.error(e);
      return err('Internal server error', 500);
    }
  },
};

// ═══════════════════════════════════════════════════════════
// VALIDATE ACCESS CODE
// ═══════════════════════════════════════════════════════════
async function handleValidateCode(request, env) {
  const { code } = await request.json();
  if (!code) return err('Code is required');

  const orgData = await env.DISC_KV.get(`org:code:${code.toUpperCase()}`);
  if (!orgData) return json({ valid: false, message: 'Invalid access code. Please check with your administrator.' });

  const org = JSON.parse(orgData);
  if (!org.active) return json({ valid: false, message: 'This access code has been deactivated.' });

  // Check max participants
  if (org.maxParticipants > 0) {
    const countKey = `org:count:${org.id}`;
    const count = parseInt(await env.DISC_KV.get(countKey) || '0');
    if (count >= org.maxParticipants) {
      return json({ valid: false, message: 'This organization has reached its maximum number of participants.' });
    }
  }

  return json({ valid: true, orgId: org.id, orgName: org.name });
}

// ═══════════════════════════════════════════════════════════
// SEND OTP (EMAIL VERIFICATION)
// ═══════════════════════════════════════════════════════════
async function handleSendOtp(request, env) {
  const { email, name } = await request.json();
  if (!email) return err('Email is required');

  // Generate 6-digit OTP
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const token = crypto.randomUUID();
  const expires = Date.now() + 15 * 60 * 1000; // 15 minutes

  // Store OTP in KV (TTL 15 minutes)
  await env.DISC_KV.put(`otp:${token}`, JSON.stringify({ otp, email, expires }), { expirationTtl: 900 });

  // Send verification email via Resend
  await sendEmail(env, {
    to: email,
    subject: 'DISC Paradigm™ — Verify Your Email',
    html: buildOtpEmail(name, otp),
  });

  return json({ token, message: 'Verification code sent' });
}

// ═══════════════════════════════════════════════════════════
// VERIFY OTP
// ═══════════════════════════════════════════════════════════
async function handleVerifyOtp(request, env) {
  const { token, code } = await request.json();
  if (!token || !code) return err('Token and code are required');

  const stored = await env.DISC_KV.get(`otp:${token}`);
  if (!stored) return json({ valid: false, message: 'Code expired or not found. Please request a new code.' });

  const { otp, expires } = JSON.parse(stored);
  if (Date.now() > expires) return json({ valid: false, message: 'Code has expired. Please request a new one.' });
  if (otp !== code) return json({ valid: false, message: 'Incorrect code. Please try again.' });

  // Delete used OTP
  await env.DISC_KV.delete(`otp:${token}`);
  return json({ valid: true });
}

// ═══════════════════════════════════════════════════════════
// SAVE ASSESSMENT RESULT
// ═══════════════════════════════════════════════════════════
async function handleSaveResult(request, env) {
  const result = await request.json();
  const id = crypto.randomUUID();
  const timestamp = result.timestamp || new Date().toISOString();

  const record = { id, ...result, timestamp, savedAt: new Date().toISOString() };

  // Store individual result
  await env.DISC_KV.put(`result:${id}`, JSON.stringify(record));

  // Add to org results index
  const orgKey = `org:results:${result.orgId}`;
  const existing = await env.DISC_KV.get(orgKey);
  const ids = existing ? JSON.parse(existing) : [];
  ids.push(id);
  await env.DISC_KV.put(orgKey, JSON.stringify(ids));

  // Add to global results index
  const globalKey = 'results:all';
  const globalExisting = await env.DISC_KV.get(globalKey);
  const globalIds = globalExisting ? JSON.parse(globalExisting) : [];
  globalIds.push(id);
  await env.DISC_KV.put(globalKey, JSON.stringify(globalIds));

  // Increment org participant count
  const countKey = `org:count:${result.orgId}`;
  const count = parseInt(await env.DISC_KV.get(countKey) || '0');
  await env.DISC_KV.put(countKey, String(count + 1));

  // Notify admin
  await sendEmail(env, {
    to: env.ADMIN_EMAIL,
    subject: `DISC Paradigm™ — New Result: ${result.name} (${result.orgName})`,
    html: buildAdminNotificationEmail(record),
  });

  return json({ success: true, id });
}

// ═══════════════════════════════════════════════════════════
// SEND DETAILED RESULTS REPORT TO USER
// ═══════════════════════════════════════════════════════════
async function handleSendReport(request, env) {
  const data = await request.json();
  const STYLE_NAMES = { D: 'Command', I: 'Cohesion', S: 'Stability', C: 'Precision' };

  await sendEmail(env, {
    to: data.email,
    subject: `Your DISC Paradigm™ Results — ${STYLE_NAMES[data.primary]} / ${STYLE_NAMES[data.secondary]}`,
    html: buildResultsEmail(data),
  });

  return json({ success: true });
}

// ═══════════════════════════════════════════════════════════
// ADMIN: LOGIN
// ═══════════════════════════════════════════════════════════
async function handleAdminLogin(request, env) {
  const { password } = await request.json();
  if (password !== env.ADMIN_PASSWORD) return json({ token: null, error: 'Invalid password' }, 401);

  const token = btoa(JSON.stringify({ admin: true, exp: Date.now() + 8 * 60 * 60 * 1000 }));
  // Sign token with secret
  const signature = await sign(token, env.JWT_SECRET);
  return json({ token: `${token}.${signature}` });
}

async function verifyAdminToken(request, env) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader?.startsWith('Bearer ')) return false;
  const [token, sig] = authHeader.slice(7).split('.');
  if (!token || !sig) return false;
  const expected = await sign(token, env.JWT_SECRET);
  if (sig !== expected) return false;
  const payload = JSON.parse(atob(token));
  return payload.admin && Date.now() < payload.exp;
}

async function sign(data, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

// ═══════════════════════════════════════════════════════════
// ADMIN: GET ALL RESULTS
// ═══════════════════════════════════════════════════════════
async function handleGetResults(env) {
  const globalKey = 'results:all';
  const idsRaw = await env.DISC_KV.get(globalKey);
  if (!idsRaw) return json([]);

  const ids = JSON.parse(idsRaw);
  // Fetch in parallel (batches of 20 to avoid timeout)
  const results = [];
  for (let i = 0; i < ids.length; i += 20) {
    const batch = ids.slice(i, i + 20);
    const fetched = await Promise.all(batch.map(id => env.DISC_KV.get(`result:${id}`)));
    fetched.forEach(r => { if (r) results.push(JSON.parse(r)); });
  }
  return json(results.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)));
}

// ═══════════════════════════════════════════════════════════
// ADMIN: GET ALL ORGS
// ═══════════════════════════════════════════════════════════
async function handleGetOrgs(env) {
  const idsRaw = await env.DISC_KV.get('orgs:all');
  if (!idsRaw) return json([]);
  const ids = JSON.parse(idsRaw);
  const orgs = await Promise.all(ids.map(id => env.DISC_KV.get(`org:${id}`)));
  return json(orgs.filter(Boolean).map(o => JSON.parse(o)).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)));
}

// ═══════════════════════════════════════════════════════════
// ADMIN: CREATE ORG
// ═══════════════════════════════════════════════════════════
async function handleCreateOrg(request, env) {
  const { name, type, maxParticipants, notes } = await request.json();
  if (!name) return err('Organization name is required');

  const id = crypto.randomUUID();
  const code = generateCode();
  const org = {
    id, name, type: type || 'other',
    maxParticipants: maxParticipants || 0,
    notes: notes || '',
    code,
    active: true,
    createdAt: new Date().toISOString(),
  };

  // Store org data
  await env.DISC_KV.put(`org:${id}`, JSON.stringify(org));
  // Index by code for fast lookup
  await env.DISC_KV.put(`org:code:${code}`, JSON.stringify(org));
  // Add to global orgs index
  const idsRaw = await env.DISC_KV.get('orgs:all');
  const ids = idsRaw ? JSON.parse(idsRaw) : [];
  ids.push(id);
  await env.DISC_KV.put('orgs:all', JSON.stringify(ids));

  return json(org);
}

function generateCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  return Array.from({ length: 8 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
}

// ═══════════════════════════════════════════════════════════
// ADMIN: DEACTIVATE ORG
// ═══════════════════════════════════════════════════════════
async function handleDeactivateOrg(request, env) {
  const { orgId } = await request.json();
  const orgRaw = await env.DISC_KV.get(`org:${orgId}`);
  if (!orgRaw) return err('Organization not found');
  const org = JSON.parse(orgRaw);
  org.active = false;
  await env.DISC_KV.put(`org:${orgId}`, JSON.stringify(org));
  await env.DISC_KV.put(`org:code:${org.code}`, JSON.stringify(org));
  return json({ success: true });
}

// ═══════════════════════════════════════════════════════════
// EMAIL SENDER (Resend API)
// ═══════════════════════════════════════════════════════════
async function sendEmail(env, { to, subject, html }) {
  if (!env.RESEND_API_KEY) return; // Skip in dev
  await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: env.FROM_EMAIL || 'noreply@discparadigm.net',
      to,
      subject,
      html,
    }),
  });
}

// ═══════════════════════════════════════════════════════════
// EMAIL TEMPLATES
// ═══════════════════════════════════════════════════════════
function emailBase(content) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"/>
  <style>body{font-family:Arial,sans-serif;background:#080E18;margin:0;padding:0;}
  .wrap{max-width:600px;margin:0 auto;background:#0F1C2E;border-radius:8px;overflow:hidden;}
  .header{background:#0D2340;padding:2rem;text-align:center;}
  .header h1{font-size:1.4rem;font-weight:900;text-transform:uppercase;letter-spacing:.06em;color:#F5A623;margin:0;}
  .header h1 span{color:#F4F1EC;}
  .body{padding:2rem;color:#C8C4BB;font-size:.95rem;line-height:1.65;}
  .body h2{color:#F4F1EC;font-size:1.1rem;margin-bottom:.5rem;}
  .body p{margin-bottom:1rem;}
  .score-row{display:flex;align-items:center;gap:1rem;margin-bottom:.75rem;}
  .score-label{width:90px;font-weight:700;font-size:.85rem;}
  .score-bar{flex:1;height:8px;background:rgba(255,255,255,.08);border-radius:4px;overflow:hidden;}
  .score-fill{height:100%;border-radius:4px;}
  .score-pct{width:40px;text-align:right;font-size:.85rem;color:#F5A623;}
  .badge{display:inline-block;background:rgba(245,166,35,.15);border:1px solid rgba(245,166,35,.3);color:#F5A623;padding:.35rem 1rem;border-radius:4px;font-size:.85rem;font-weight:700;text-transform:uppercase;letter-spacing:.08em;}
  .footer{background:#04080F;padding:1.25rem 2rem;text-align:center;font-size:.75rem;color:rgba(244,241,236,.25);}
  </style></head><body>
  <div style="padding:2rem;">
  <div class="wrap">
  <div class="header"><h1>DISC <span>Paradigm™</span></h1></div>
  <div class="body">${content}</div>
  <div class="footer">DISC Paradigm™ · KSWhite Consulting, LLC · www.discparadigm.net<br/>
  Copyright © 2025 All Rights Reserved</div>
  </div></div></body></html>`;
}

function buildOtpEmail(name, otp) {
  return emailBase(`
    <h2>Hello${name ? ', ' + name : ''}!</h2>
    <p>Your verification code for the DISC Paradigm™ Assessment is:</p>
    <div style="font-size:2.5rem;font-weight:900;letter-spacing:.35em;color:#F5A623;text-align:center;padding:1.5rem;background:rgba(245,166,35,.08);border:1px solid rgba(245,166,35,.2);border-radius:6px;margin:1.5rem 0;">${otp}</div>
    <p>This code expires in <strong style="color:#F4F1EC;">15 minutes</strong>.</p>
    <p>If you did not request this code, you can ignore this email.</p>
  `);
}

function buildResultsEmail(data) {
  const STYLE_NAMES = { D: 'Command', I: 'Cohesion', S: 'Stability', C: 'Precision' };
  const STYLE_COLORS = { D: '#1A5A8A', I: '#F5A623', S: '#2E8B57', C: '#E85D1A' };
  const scoreRows = ['D','I','S','C'].map(s => `
    <div class="score-row">
      <div class="score-label" style="color:${STYLE_COLORS[s]}">${STYLE_NAMES[s]}</div>
      <div class="score-bar"><div class="score-fill" style="width:${data.scores[s]}%;background:${STYLE_COLORS[s]}"></div></div>
      <div class="score-pct">${data.scores[s]}%</div>
    </div>
  `).join('');

  return emailBase(`
    <h2>Your DISC Paradigm™ Results</h2>
    <p>Thank you for completing the assessment, <strong style="color:#F4F1EC;">${data.name}</strong>. Here is your complete profile.</p>
    <div style="display:flex;gap:1rem;margin:1.5rem 0;">
      <div style="flex:1;background:rgba(245,166,35,.08);border:1px solid rgba(245,166,35,.25);border-radius:6px;padding:1rem;text-align:center;">
        <div style="font-size:.72rem;letter-spacing:.12em;text-transform:uppercase;color:rgba(244,241,236,.4);margin-bottom:.3rem;">Primary Style</div>
        <div style="font-size:1.4rem;font-weight:900;text-transform:uppercase;color:${STYLE_COLORS[data.primary]}">${STYLE_NAMES[data.primary]}</div>
        <div style="font-size:.8rem;color:rgba(244,241,236,.4);">${data.scores[data.primary]}%</div>
      </div>
      <div style="flex:1;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.09);border-radius:6px;padding:1rem;text-align:center;">
        <div style="font-size:.72rem;letter-spacing:.12em;text-transform:uppercase;color:rgba(244,241,236,.4);margin-bottom:.3rem;">Secondary Style</div>
        <div style="font-size:1.4rem;font-weight:900;text-transform:uppercase;color:${STYLE_COLORS[data.secondary]}">${STYLE_NAMES[data.secondary]}</div>
        <div style="font-size:.8rem;color:rgba(244,241,236,.4);">${data.scores[data.secondary]}%</div>
      </div>
    </div>
    <h2>Full Score Breakdown</h2>
    ${scoreRows}
    <p style="margin-top:1.5rem;">To view your complete profile including communication tips, stress triggers, and your 30-Day Action Plan, visit:</p>
    <p style="text-align:center;"><a href="https://app.discparadigm.net" style="color:#F5A623;">app.discparadigm.net</a></p>
    <hr style="border:none;border-top:1px solid rgba(255,255,255,.08);margin:1.5rem 0;"/>
    <p style="font-size:.82rem;color:rgba(244,241,236,.4);">Organization: ${data.orgName || '—'} · Track: ${data.track === 'military' ? 'Military' : 'Corporate'}</p>
  `);
}

function buildAdminNotificationEmail(record) {
  const STYLE_NAMES = { D: 'Command', I: 'Cohesion', S: 'Stability', C: 'Precision' };
  return emailBase(`
    <h2>New Assessment Completed</h2>
    <p><strong style="color:#F4F1EC;">${record.name}</strong> (${record.email}) completed the assessment.</p>
    <table style="width:100%;border-collapse:collapse;font-size:.88rem;margin:1rem 0;">
      <tr><td style="padding:.4rem .6rem;color:rgba(244,241,236,.5);">Organization</td><td style="padding:.4rem .6rem;color:#F4F1EC;">${record.orgName}</td></tr>
      <tr><td style="padding:.4rem .6rem;color:rgba(244,241,236,.5);">Role</td><td style="padding:.4rem .6rem;color:#F4F1EC;">${record.role}</td></tr>
      <tr><td style="padding:.4rem .6rem;color:rgba(244,241,236,.5);">Track</td><td style="padding:.4rem .6rem;color:#F4F1EC;">${record.track === 'military' ? '🎖️ Military' : '🏢 Corporate'}</td></tr>
      <tr><td style="padding:.4rem .6rem;color:rgba(244,241,236,.5);">Primary Style</td><td style="padding:.4rem .6rem;color:#F5A623;font-weight:700;">${STYLE_NAMES[record.primary]}</td></tr>
      <tr><td style="padding:.4rem .6rem;color:rgba(244,241,236,.5);">Secondary Style</td><td style="padding:.4rem .6rem;color:#F4F1EC;">${STYLE_NAMES[record.secondary]}</td></tr>
      <tr><td style="padding:.4rem .6rem;color:rgba(244,241,236,.5);">Scores</td><td style="padding:.4rem .6rem;color:#F4F1EC;">D:${record.scores?.D}% I:${record.scores?.I}% S:${record.scores?.S}% C:${record.scores?.C}%</td></tr>
    </table>
    <p><a href="https://app.discparadigm.net/admin.html" style="color:#F5A623;">View in Admin Dashboard →</a></p>
  `);
}
