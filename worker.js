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

  return json({ success: true, token, message: 'Verification code sent' });
}

// ═══════════════════════════════════════════════════════════
// VERIFY OTP
// ═══════════════════════════════════════════════════════════
async function handleVerifyOtp(request, env) {
  const body = await request.json();
  const { token, code, email, otp } = body;
  
  // Support both old format (email+otp) and new format (token+code)
  if (!token && !email) return err('Token or email is required');
  if (!code && !otp) return err('Code is required');

  // If using email format, find the token
  let otpToken = token;
  if (!otpToken && email) {
    // Search for OTP by email (less efficient but works)
    const keys = await env.DISC_KV.list({ prefix: 'otp:' });
    for (const key of keys.keys) {
      const stored = await env.DISC_KV.get(key.name);
      if (stored) {
        const data = JSON.parse(stored);
        if (data.email === email) {
          otpToken = key.name.replace('otp:', '');
          break;
        }
      }
    }
    if (!otpToken) return json({ valid: false, message: 'Code expired or not found. Please request a new code.' });
  }

  const stored = await env.DISC_KV.get(`otp:${otpToken}`);
  if (!stored) return json({ valid: false, message: 'Code expired or not found. Please request a new code.' });

  const { otp: storedOtp, expires } = JSON.parse(stored);
  if (Date.now() > expires) return json({ valid: false, message: 'Code has expired. Please request a new one.' });
  
  const submittedCode = code || otp;
  if (storedOtp !== submittedCode) return json({ valid: false, message: 'Incorrect code. Please try again.' });

  // Delete used OTP
  await env.DISC_KV.delete(`otp:${otpToken}`);
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
  
  const isMilitary = data.track === 'military';
  const primary = data.primary;
  const secondary = data.secondary;
  
  // Full style profile descriptions
  const styleProfiles = {
    D: {
      name: 'Command',
      military: 'You are decisive and action-oriented, preferring to take charge and drive results. You thrive in high-pressure environments and aren\'t afraid to challenge the status quo to accomplish the mission. You make rapid decisions with available information and adapt as you execute.',
      corporate: 'You are decisive and results-driven, preferring to take charge and drive outcomes. You thrive in high-pressure environments and aren\'t afraid to challenge conventional approaches to achieve goals. You make quick decisions with available information and course-correct as needed.',
      strengths: ['Decisive under pressure', 'Takes initiative', 'Drives results', 'Comfortable with risk', 'Challenges inefficiency'],
      growth: ['Can be impatient with process', 'May overlook details', 'Sometimes dismisses input', 'Can appear overly direct'],
      stress: ['Losing control or autonomy', 'Bureaucratic delays', 'Being micromanaged', 'Indecisive leadership'],
      stressResponse: 'Becomes more direct and forceful, may bypass procedures, pushes harder for immediate action.',
      communication: 'Be direct and concise. Focus on outcomes and solutions. Don\'t waste their time with excessive background. Give them autonomy and room to execute.'
    },
    I: {
      name: 'Cohesion',
      military: 'You energize teams and build strong unit cohesion through positive relationships. You inspire others and create morale that carries through challenging missions. You are the glue that holds teams together and naturally lift spirits during difficult times.',
      corporate: 'You energize teams and build strong collaboration through positive relationships. You inspire others and create engagement that drives performance. You are the connector who brings people together and naturally create positive momentum.',
      strengths: ['Builds strong relationships', 'Energizes teams', 'Communicates enthusiasm', 'Resolves interpersonal conflicts', 'Creates positive culture'],
      growth: ['May avoid difficult conversations', 'Can be overly optimistic', 'Sometimes prioritizes harmony over accountability', 'May struggle with details'],
      stress: ['Social isolation or rejection', 'Negative team dynamics', 'Being publicly criticized', 'Lack of recognition'],
      stressResponse: 'Becomes more talkative or withdrawn, seeks reassurance from others, may avoid conflict even when necessary.',
      communication: 'Give them time to process verbally. Recognize their contributions publicly. Maintain a positive tone even when delivering hard feedback. Allow relationship-building time before jumping into tasks.'
    },
    S: {
      name: 'Stability',
      military: 'You provide calm and steady leadership, especially during transitions. You are patient, loyal, and help others adapt to change at a sustainable pace. You are the anchor that keeps teams grounded and creates psychological safety for others.',
      corporate: 'You provide calm and consistent leadership, especially during change. You are patient, reliable, and help teams adapt to transitions smoothly. You are the steady hand that maintains stability and creates trust through predictability.',
      strengths: ['Calm under pressure', 'Patient and supportive', 'Loyal and reliable', 'Helps others through change', 'Creates team stability'],
      growth: ['May resist necessary change', 'Can be conflict-avoidant', 'Sometimes overly accommodating', 'May not advocate strongly for own needs'],
      stress: ['Sudden, unplanned change', 'High-conflict environments', 'Being rushed or pressured', 'Lack of clarity or direction'],
      stressResponse: 'Withdraws or becomes passive, avoids rocking the boat, may absorb stress from others without addressing own needs.',
      communication: 'Give advance notice of changes. Provide clear expectations and timelines. Create space for questions and processing. Show appreciation for their steadiness and don\'t mistake calm for lack of engagement.'
    },
    C: {
      name: 'Precision',
      military: 'You prioritize accuracy, thoroughness, and adherence to standards. You analyze situations carefully and ensure quality execution of procedures. You are the guardian of quality and compliance, catching errors others miss.',
      corporate: 'You prioritize accuracy, quality, and systematic approaches. You analyze situations carefully and ensure thorough execution of processes. You are the champion of excellence and precision, maintaining high standards consistently.',
      strengths: ['Detail-oriented and thorough', 'Maintains high quality standards', 'Analytical and systematic', 'Catches errors early', 'Documents processes well'],
      growth: ['Can overanalyze decisions', 'May be overly critical', 'Sometimes resists acting without complete information', 'Can appear distant or impersonal'],
      stress: ['Being rushed to decide', 'Lack of data or clarity', 'Being publicly criticized for mistakes', 'Ambiguous expectations'],
      stressResponse: 'Becomes more withdrawn, overly critical of self and others, seeks more data before acting, may appear rigid or inflexible.',
      communication: 'Provide clear, written expectations. Give time for analysis and questions. Respect their need for accuracy. Frame feedback objectively with specific examples rather than generalities.'
    }
  };

  // Blend profiles (how primary + secondary work together)
  const blendProfiles = {
    'D+I': 'You combine decisive action with relationship-building. You drive results while keeping people energized and engaged. This makes you an effective leader who can push hard while maintaining team morale.',
    'D+S': 'You balance urgency with patience. You can push for results while also helping others adjust to change at a sustainable pace. This combination allows you to drive initiatives without burning out your team.',
    'D+C': 'You pair decisiveness with analytical rigor. You make bold moves but also ensure quality and accuracy. This creates a powerful combination of speed and precision in execution.',
    'I+D': 'You blend enthusiasm with assertiveness. You inspire people while also driving toward concrete outcomes. This makes you a compelling leader who motivates action.',
    'I+S': 'You combine warmth with steadiness. You build strong relationships while creating stability and trust. This makes you a supportive presence who brings people together consistently.',
    'I+C': 'You balance enthusiasm with attention to detail. You engage people while also maintaining standards and quality. This helps you create positive momentum without sacrificing accuracy.',
    'S+D': 'You pair stability with decisiveness. You provide calm consistency while still taking action when needed. This allows you to be both reliable and responsive.',
    'S+I': 'You combine patience with positivity. You create a steady, supportive environment while also building strong relationships. This makes you a trusted team anchor.',
    'S+C': 'You blend reliability with precision. You provide consistent, thorough support with high attention to detail. This makes you the dependable expert others turn to.',
    'C+D': 'You combine analytical depth with decisiveness. You analyze carefully but still move forward with confidence. This creates sound decisions backed by solid reasoning.',
    'C+I': 'You balance precision with relationship-building. You maintain high standards while also engaging people positively. This helps you drive quality without appearing overly critical.',
    'C+S': 'You pair thoroughness with patience. You analyze carefully while also providing steady, reliable support. This makes you the calm expert who gets things right.'
  };

  // Working with other styles
  const workingWithOthers = {
    D: { tip: 'Be direct, focus on results, move quickly, give autonomy' },
    I: { tip: 'Be enthusiastic, allow relationship time, recognize contributions, keep it positive' },
    S: { tip: 'Give advance notice, be patient, create stability, show appreciation for consistency' },
    C: { tip: 'Provide data and details, allow analysis time, be specific, respect their standards' }
  };

  // 30-Day Action Plan
  const actionPlan = {
    week1: {
      title: 'Self-Awareness',
      military: 'Observe how your ' + STYLE_NAMES[primary] + ' style shows up in daily interactions. Notice when you default to your natural patterns and when you adapt. Journal one example each day.',
      corporate: 'Track how your ' + STYLE_NAMES[primary] + ' style influences your work approach. Notice your default patterns in meetings, emails, and decisions. Log one observation daily.'
    },
    week2: {
      title: 'Strengths Application',
      military: 'Intentionally leverage one ' + STYLE_NAMES[primary] + ' strength each day. At week\'s end, identify which situations benefit most from your natural style.',
      corporate: 'Deliberately apply one ' + STYLE_NAMES[primary] + ' strength daily. By Friday, determine which contexts maximize your natural abilities.'
    },
    week3: {
      title: 'Style Flex Practice',
      military: 'Identify someone with a different primary style. Practice adapting your communication with them three times this week. Note what feels uncomfortable and what works.',
      corporate: 'Choose a colleague with a different dominant style. Adapt your approach in three interactions. Reflect on what challenged you and what succeeded.'
    },
    week4: {
      title: 'Growth Edge Challenge',
      military: 'Focus on one growth area from your profile. Take one small action daily to develop this capacity. Share your progress with a trusted peer or mentor.',
      corporate: 'Target one development area from your profile. Implement one micro-practice daily to build this skill. Discuss your experience with a colleague or coach.'
    }
  };

  const primaryProfile = styleProfiles[primary];
  const secondaryProfile = styleProfiles[secondary];
  const blendKey = primary + '+' + secondary;
  const blend = blendProfiles[blendKey] || '';

  const scoreRows = ['D','I','S','C'].map(s => `
    <div style="display:flex;align-items:center;gap:1rem;margin:.75rem 0;padding:.75rem;background:rgba(255,255,255,.02);border-radius:6px;">
      <div style="min-width:90px;font-weight:600;color:${STYLE_COLORS[s]}">${STYLE_NAMES[s]}</div>
      <div style="flex:1;height:24px;background:rgba(255,255,255,.08);border-radius:12px;overflow:hidden;">
        <div style="height:100%;background:${STYLE_COLORS[s]};width:${data.percentages[s]}%;transition:width .3s;"></div>
      </div>
      <div style="min-width:50px;text-align:right;font-weight:700;color:${STYLE_COLORS[s]}">${data.percentages[s]}%</div>
    </div>
  `).join('');

  return emailBase(`
    <div style="text-align:center;margin-bottom:2rem;">
      <h1 style="font-size:2rem;margin-bottom:.5rem;background:linear-gradient(135deg, #e67e22, #f39c12);-webkit-background-clip:text;-webkit-text-fill-color:transparent;">Your DISC Paradigm™ Results</h1>
      <p style="color:rgba(244,241,236,.6);">Thank you for completing the assessment, <strong style="color:#F4F1EC;">${data.name}</strong>.</p>
    </div>

    <!-- SECTION 1: RESULTS SUMMARY -->
    <div style="margin:2rem 0;">
      <h2 style="font-size:1.5rem;margin-bottom:1rem;border-bottom:2px solid rgba(245,166,35,.3);padding-bottom:.5rem;">📊 Results Summary</h2>
      
      <div style="display:flex;gap:1rem;margin:1.5rem 0;">
        <div style="flex:1;background:rgba(245,166,35,.08);border:2px solid ${STYLE_COLORS[primary]};border-radius:8px;padding:1.5rem;text-align:center;">
          <div style="font-size:.75rem;letter-spacing:.15em;text-transform:uppercase;color:rgba(244,241,236,.5);margin-bottom:.5rem;">PRIMARY STYLE</div>
          <div style="font-size:2rem;font-weight:900;text-transform:uppercase;color:${STYLE_COLORS[primary]};margin-bottom:.25rem;">${STYLE_NAMES[primary]}</div>
          <div style="font-size:1rem;color:rgba(244,241,236,.6);">${data.percentages[primary]}%</div>
        </div>
        <div style="flex:1;background:rgba(255,255,255,.04);border:2px solid rgba(255,255,255,.15);border-radius:8px;padding:1.5rem;text-align:center;">
          <div style="font-size:.75rem;letter-spacing:.15em;text-transform:uppercase;color:rgba(244,241,236,.5);margin-bottom:.5rem;">SECONDARY STYLE</div>
          <div style="font-size:2rem;font-weight:900;text-transform:uppercase;color:${STYLE_COLORS[secondary]};margin-bottom:.25rem;">${STYLE_NAMES[secondary]}</div>
          <div style="font-size:1rem;color:rgba(244,241,236,.6);">${data.percentages[secondary]}%</div>
        </div>
      </div>

      <h3 style="font-size:1.1rem;margin:1.5rem 0 1rem;color:#F5A623;">Full Score Breakdown</h3>
      ${scoreRows}
    </div>

    <!-- SECTION 2: PROFILE OVERVIEW -->
    <div style="margin:2rem 0;">
      <h2 style="font-size:1.5rem;margin-bottom:1rem;border-bottom:2px solid rgba(245,166,35,.3);padding-bottom:.5rem;">👤 Your Profile Overview</h2>
      
      <h3 style="font-size:1.2rem;margin:1.5rem 0 .75rem;color:${STYLE_COLORS[primary]};">Primary Style: ${STYLE_NAMES[primary]}</h3>
      <p style="line-height:1.7;margin-bottom:1rem;">${isMilitary ? primaryProfile.military : primaryProfile.corporate}</p>
      
      <h3 style="font-size:1.2rem;margin:1.5rem 0 .75rem;color:${STYLE_COLORS[secondary]};">Secondary Style: ${STYLE_NAMES[secondary]}</h3>
      <p style="line-height:1.7;margin-bottom:1rem;">${isMilitary ? secondaryProfile.military : secondaryProfile.corporate}</p>
      
      ${blend ? `<h3 style="font-size:1.2rem;margin:1.5rem 0 .75rem;color:#F5A623;">Your Blend: ${STYLE_NAMES[primary]} + ${STYLE_NAMES[secondary]}</h3>
      <p style="line-height:1.7;background:rgba(245,166,35,.08);padding:1rem;border-left:3px solid #F5A623;border-radius:4px;">${blend}</p>` : ''}
    </div>

    <!-- SECTION 3: COMMUNICATION TIPS -->
    <div style="margin:2rem 0;">
      <h2 style="font-size:1.5rem;margin-bottom:1rem;border-bottom:2px solid rgba(245,166,35,.3);padding-bottom:.5rem;">💬 Communication Tips</h2>
      
      <h3 style="font-size:1.1rem;margin:1.5rem 0 .75rem;color:#F5A623;">How to Communicate With You</h3>
      <p style="line-height:1.7;background:rgba(255,255,255,.04);padding:1rem;border-radius:6px;margin-bottom:1rem;">${primaryProfile.communication}</p>
      
      <h3 style="font-size:1.1rem;margin:1.5rem 0 .75rem;color:#F5A623;">Working With Other DISC Styles</h3>
      ${Object.entries(workingWithOthers).map(([style, info]) => `
        <div style="margin:.75rem 0;padding:.75rem;background:rgba(255,255,255,.02);border-left:3px solid ${STYLE_COLORS[style]};border-radius:4px;">
          <strong style="color:${STYLE_COLORS[style]}">${STYLE_NAMES[style]}:</strong> ${info.tip}
        </div>
      `).join('')}
    </div>

    <!-- SECTION 4: STRESS TRIGGERS & RESPONSES -->
    <div style="margin:2rem 0;">
      <h2 style="font-size:1.5rem;margin-bottom:1rem;border-bottom:2px solid rgba(245,166,35,.3);padding-bottom:.5rem;">⚡ Stress Triggers & Responses</h2>
      
      <h3 style="font-size:1.1rem;margin:1.5rem 0 .75rem;color:#F5A623;">What Causes Stress for You</h3>
      <ul style="line-height:1.8;margin-left:1.5rem;">
        ${primaryProfile.stress.map(s => `<li>${s}</li>`).join('')}
      </ul>
      
      <h3 style="font-size:1.1rem;margin:1.5rem 0 .75rem;color:#F5A623;">How You Respond Under Pressure</h3>
      <p style="line-height:1.7;background:rgba(231,76,60,.08);padding:1rem;border-left:3px solid #e74c3c;border-radius:4px;">${primaryProfile.stressResponse}</p>
      
      <h3 style="font-size:1.1rem;margin:1.5rem 0 .75rem;color:#F5A623;">Managing Stress Effectively</h3>
      <p style="line-height:1.7;">Recognize your stress triggers early. When pressure builds, pause and assess whether your response is serving you. Leverage your ${STYLE_NAMES[secondary]} secondary style as a counterbalance—it offers different strengths you can draw on when your primary approach isn't working.</p>
    </div>

    <!-- SECTION 5: STRENGTHS & GROWTH AREAS -->
    <div style="margin:2rem 0;">
      <h2 style="font-size:1.5rem;margin-bottom:1rem;border-bottom:2px solid rgba(245,166,35,.3);padding-bottom:.5rem;">💪 Strengths & Growth Areas</h2>
      
      <h3 style="font-size:1.1rem;margin:1.5rem 0 .75rem;color:#2ecc71;">Your Natural Strengths</h3>
      <ul style="line-height:1.8;margin-left:1.5rem;">
        ${primaryProfile.strengths.map(s => `<li style="color:rgba(244,241,236,.9);">${s}</li>`).join('')}
      </ul>
      
      <h3 style="font-size:1.1rem;margin:1.5rem 0 .75rem;color:#F5A623;">Areas for Development</h3>
      <ul style="line-height:1.8;margin-left:1.5rem;">
        ${primaryProfile.growth.map(g => `<li style="color:rgba(244,241,236,.8);">${g}</li>`).join('')}
      </ul>
      
      <p style="line-height:1.7;background:rgba(46,204,113,.08);padding:1rem;border-left:3px solid #2ecc71;border-radius:4px;margin-top:1rem;">
        <strong>Leverage Strategy:</strong> Your strengths are most powerful when deployed intentionally. Use your ${STYLE_NAMES[primary]} capabilities in situations that demand them, and flex to your ${STYLE_NAMES[secondary]} style when different strengths are needed.
      </p>
    </div>

    <!-- SECTION 6: 30-DAY ACTION PLAN -->
    <div style="margin:2rem 0;">
      <h2 style="font-size:1.5rem;margin-bottom:1rem;border-bottom:2px solid rgba(245,166,35,.3);padding-bottom:.5rem;">📅 30-Day Action Plan</h2>
      <p style="line-height:1.7;margin-bottom:1.5rem;color:rgba(244,241,236,.8);">This plan helps you apply your DISC insights immediately. Complete one focus area each week.</p>
      
      ${Object.entries(actionPlan).map(([week, content], idx) => `
        <div style="margin:1.5rem 0;padding:1.25rem;background:rgba(255,255,255,.04);border-left:4px solid #F5A623;border-radius:6px;">
          <h3 style="font-size:1.1rem;margin-bottom:.75rem;color:#F5A623;">Week ${idx + 1}: ${content.title}</h3>
          <p style="line-height:1.7;">${isMilitary ? content.military : content.corporate}</p>
        </div>
      `).join('')}
      
      <div style="margin:1.5rem 0;padding:1.25rem;background:rgba(245,166,35,.08);border-radius:6px;border:1px solid rgba(245,166,35,.2);">
        <p style="line-height:1.7;margin:0;"><strong style="color:#F5A623;">Pro Tip:</strong> Share this plan with a colleague or mentor. Regular check-ins dramatically increase follow-through and deepen your learning.</p>
      </div>
    </div>

    <!-- FOOTER -->
    <div style="margin:3rem 0 1rem;padding-top:2rem;border-top:1px solid rgba(255,255,255,.1);text-align:center;">
      <p style="margin-bottom:1rem;">Access your results anytime at <a href="https://app.discparadigm.net" style="color:#F5A623;text-decoration:none;">app.discparadigm.net</a></p>
      <p style="font-size:.85rem;color:rgba(244,241,236,.5);line-height:1.6;">
        Questions about your profile? Want to schedule coaching?<br/>
        Contact us at <a href="mailto:contact@discparadigm.net" style="color:#F5A623;text-decoration:none;">contact@discparadigm.net</a> or 
        <a href="https://meetings-na2.hubspot.com/kswhite" style="color:#F5A623;text-decoration:none;">book a consultation</a>
      </p>
      <p style="font-size:.75rem;color:rgba(244,241,236,.4);margin-top:1.5rem;">
        Organization: ${data.orgName || 'Individual'} · Track: ${isMilitary ? 'Military' : 'Corporate'} · Completed: ${new Date(data.timestamp).toLocaleDateString()}
      </p>
    </div>
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
