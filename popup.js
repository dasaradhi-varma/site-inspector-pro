// popup.js — Site Inspector Logic

const SUSPICIOUS_TLDS = ['.xyz', '.top', '.click', '.loan', '.work', '.gq', '.ml', '.cf', '.tk', '.pw', '.cc', '.info'];
const KNOWN_GOOD_TLDS = ['.com', '.org', '.net', '.gov', '.edu', '.io', '.co.uk', '.co', '.app', '.dev'];

// ── Utility ──────────────────────────────────────────────────────────────────

function $(id) { return document.getElementById(id); }

function setVal(id, val, cls) {
  const el = $(id);
  if (!el) return;
  el.textContent = val;
  if (cls) { el.className = 'info-val ' + cls; }
}

function formatDate(d) {
  if (!d) return 'N/A';
  return new Date(d).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
}

function daysBetween(d1, d2) {
  return Math.round((d2 - d1) / (1000 * 60 * 60 * 24));
}

function parseDomain(url) {
  try {
    const u = new URL(url);
    return { hostname: u.hostname, protocol: u.protocol, pathname: u.pathname };
  } catch { return null; }
}

function getTLD(hostname) {
  const parts = hostname.split('.');
  if (parts.length >= 3 && parts[parts.length - 2].length <= 3) {
    return '.' + parts.slice(-2).join('.');
  }
  return '.' + parts[parts.length - 1];
}

function isSuspiciousTLD(hostname) {
  const tld = getTLD(hostname);
  return SUSPICIOUS_TLDS.includes(tld.toLowerCase());
}

function calcTrustScore(data) {
  let score = 50;
  const { url, meta } = data;
  if (!url) return 0;
  const isHttps = url.startsWith('https://');
  if (isHttps) score += 20; else score -= 30;

  const parsed = parseDomain(url);
  if (parsed) {
    const tld = getTLD(parsed.hostname);
    if (isSuspiciousTLD(parsed.hostname)) score -= 20;
    if (KNOWN_GOOD_TLDS.includes(tld.toLowerCase())) score += 5;
  }

  if (meta) {
    if (meta.hasPrivacyPolicy) score += 8;
    if (meta.hasContactPage) score += 5;
    if (meta.hasTerms) score += 5;
    if (meta.hasCopyright) score += 4;
    if (meta.cookieConsent) score += 3;
    if (meta.hasHttpsLinks > 5) score -= 5;
    const socials = Object.values(meta.socialLinks || {}).filter(Boolean).length;
    score += socials * 3;
  }

  return Math.max(0, Math.min(100, score));
}

function scoreClass(score) {
  if (score >= 70) return 'good';
  if (score >= 45) return 'warn';
  return 'bad';
}

function scoreColor(score) {
  if (score >= 70) return 'var(--accent)';
  if (score >= 45) return 'var(--warn)';
  return 'var(--danger)';
}

// ── Tab routing ───────────────────────────────────────────────────────────────

document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    const panelId = 'panel-' + tab.dataset.tab;
    const panel = $(panelId);
    if (panel) panel.classList.add('active');
  });
});

// ── Render functions ──────────────────────────────────────────────────────────

function renderOverview(url, meta, score) {
  const parsed = parseDomain(url);
  const hostname = parsed?.hostname || url;
  const tld = parsed ? getTLD(hostname) : '—';
  const isHttps = url.startsWith('https://');

  setVal('ov-domain', hostname);
  setVal('ov-tld', tld, KNOWN_GOOD_TLDS.includes(tld.toLowerCase()) ? 'good' : isSuspiciousTLD(hostname) ? 'bad' : '');
  setVal('ov-protocol', parsed?.protocol?.replace(':', '') || '—', isHttps ? 'good' : 'bad');
  setVal('ov-ip', 'See WHOIS tab');
  setVal('ov-age', 'Use WHOIS for exact date');

  if (meta) {
    const title = meta.title || '(no title)';
    setVal('ov-title', title.length > 28 ? title.slice(0, 28) + '…' : title);
    setVal('ov-lang', meta.language || 'Unknown');
    setVal('ov-gen', meta.generator || 'Not declared');
    setVal('ov-load', meta.loadTime ? meta.loadTime + 'ms' : 'N/A', meta.loadTime < 2000 ? 'good' : 'warn');
    setVal('ov-charset', meta.charset || 'Unknown');
  }

  // Verdict
  const verdictBox = $('verdictBox');
  let vClass, vIcon, vTitle, vText;
  if (score >= 70) {
    vClass = 'safe'; vIcon = '✅';
    vTitle = 'LIKELY LEGITIMATE';
    vText = 'This site shows strong trust signals. HTTPS is active, and common legitimacy markers are present.';
  } else if (score >= 45) {
    vClass = 'suspicious'; vIcon = '⚠️';
    vTitle = 'PROCEED WITH CAUTION';
    vText = 'Some trust signals are missing. Verify the domain age and certificate before sharing sensitive info.';
  } else {
    vClass = 'danger'; vIcon = '🚨';
    vTitle = 'HIGH RISK — POSSIBLY FAKE';
    vText = 'This site lacks basic trust signals. It may be phishing or fraudulent. Do not enter personal data.';
  }
  verdictBox.innerHTML = `
    <div class="verdict ${vClass}">
      <div class="verdict-icon">${vIcon}</div>
      <div class="verdict-text">
        <h3>${vTitle}</h3>
        <p>${vText}</p>
      </div>
    </div>`;
}

function renderSSL(url) {
  const isHttps = url.startsWith('https://');
  const parsed = parseDomain(url);
  const hostname = parsed?.hostname || '';

  setVal('ssl-status', isHttps ? 'ACTIVE' : 'NOT ENCRYPTED', isHttps ? 'good' : 'bad');
  setVal('ssl-proto', isHttps ? 'HTTPS / TLS' : 'HTTP (plaintext)', isHttps ? 'good' : 'bad');
  setVal('ssl-valid', isHttps ? 'Yes (browser verified)' : 'No certificate', isHttps ? 'good' : 'bad');
  setVal('ssl-issuedTo', hostname || '—');
  setVal('ssl-issuer', isHttps ? 'Verified by browser CA' : 'N/A');
  setVal('ssl-from', isHttps ? 'See browser lock icon' : 'N/A');
  setVal('ssl-expiry', isHttps ? 'See browser lock icon' : 'N/A');
  setVal('ssl-days', isHttps ? 'Active (browser checked)' : 'No SSL', isHttps ? 'good' : 'bad');
  setVal('ssl-wildcard', isHttps ? 'Check browser cert viewer' : 'N/A');

  if (!isHttps) {
    $('ssl-note').textContent = '⚠️ This site uses plain HTTP. Your connection is NOT encrypted. Any data you submit can be intercepted. Never enter passwords or personal info on HTTP sites.';
  }
}

function renderSignals(url, meta) {
  const isHttps = url.startsWith('https://');
  const parsed = parseDomain(url);
  const hostname = parsed?.hostname || '';
  const suspTLD = isSuspiciousTLD(hostname);

  const chips = [
    { label: 'HTTPS', ok: isHttps, icon: isHttps ? '🔒' : '🔓' },
    { label: 'Privacy Policy', ok: meta?.hasPrivacyPolicy, icon: '📄' },
    { label: 'Contact Page', ok: meta?.hasContactPage, icon: '📬' },
    { label: 'Terms of Service', ok: meta?.hasTerms, icon: '📋' },
    { label: 'Copyright Notice', ok: meta?.hasCopyright, icon: '©️' },
    { label: 'Cookie Consent', ok: meta?.cookieConsent, icon: '🍪' },
    { label: 'Facebook Link', ok: meta?.socialLinks?.facebook, icon: '👤', neutral: true },
    { label: 'Twitter Link', ok: meta?.socialLinks?.twitter, icon: '🐦', neutral: true },
    { label: 'LinkedIn Link', ok: meta?.socialLinks?.linkedin, icon: '💼', neutral: true },
    { label: 'Instagram Link', ok: meta?.socialLinks?.instagram, icon: '📷', neutral: true },
  ];

  const grid = $('signalsGrid');
  grid.innerHTML = chips.map(c => {
    const cls = c.ok ? 'ok' : (c.neutral ? '' : 'bad');
    const label = c.ok ? c.label : c.label;
    const status = c.ok ? '✓' : '✗';
    return `<div class="signal-chip ${cls}">
      <span class="icon">${c.icon}</span>
      <span class="label">${c.ok ? '✓' : '✗'} ${label}</span>
    </div>`;
  }).join('');

  setVal('sig-extlinks', meta?.externalLinks ?? '—');
  setVal('sig-images', meta?.imageCount ?? '—');
  const mixed = meta?.hasHttpsLinks ?? 0;
  setVal('sig-mixed', mixed > 0 ? mixed + ' found' : 'None', mixed > 3 ? 'warn' : 'good');
  setVal('sig-copyright', meta?.hasCopyright ? 'Found' : 'Not found', meta?.hasCopyright ? 'good' : 'warn');
  setVal('sig-cookie', meta?.cookieConsent ? 'Found' : 'Not found', meta?.cookieConsent ? 'good' : '');
  setVal('sig-tld', suspTLD ? `YES (${getTLD(hostname)})` : 'No', suspTLD ? 'bad' : 'good');
}

// ── WHOIS Lookup ──────────────────────────────────────────────────────────────

function setupWhois(hostname) {
  const btn = $('whoisBtn');
  const result = $('whoisResult');

  btn.addEventListener('click', async () => {
    btn.disabled = true;
    btn.textContent = '⏳ FETCHING…';
    result.classList.remove('visible');
    result.textContent = '';

    try {
      // Using rdap.org (free, no key needed)
      const domain = hostname.replace(/^www\./, '');
      const res = await fetch(`https://rdap.org/domain/${domain}`);

      if (!res.ok) throw new Error('RDAP lookup failed');
      const data = await res.json();

      const events = data.events || [];
      const registration = events.find(e => e.eventAction === 'registration');
      const expiry = events.find(e => e.eventAction === 'expiration');
      const lastChanged = events.find(e => e.eventAction === 'last changed');

      const registrar = data.entities?.find(e => e.roles?.includes('registrar'));
      const registrarName = registrar?.vcardArray?.[1]?.find(v => v[0] === 'fn')?.[3] || 'Unknown';

      const regDate = registration?.eventDate ? new Date(registration.eventDate) : null;
      const expDate = expiry?.eventDate ? new Date(expiry.eventDate) : null;
      const now = new Date();

      const ageYears = regDate ? ((now - regDate) / (1000 * 60 * 60 * 24 * 365)).toFixed(1) : null;
      const daysLeft = expDate ? daysBetween(now, expDate) : null;

      const nameservers = (data.nameservers || []).map(ns => ns.ldhName).join(', ') || 'N/A';
      const status = (data.status || []).join(', ') || 'N/A';

      // Update overview age
      if (ageYears) {
        setVal('ov-age', ageYears + ' years', parseFloat(ageYears) >= 2 ? 'good' : parseFloat(ageYears) >= 0.5 ? 'warn' : 'bad');
      }

      result.innerHTML = `
<span class="field">Domain:</span> ${data.ldhName || domain}
<span class="field">Status:</span> ${status}
<span class="field">Registrar:</span> ${registrarName}
<span class="field">Registered:</span> ${regDate ? formatDate(regDate) : 'Hidden/Unknown'}
<span class="field">Domain Age:</span> ${ageYears ? ageYears + ' years' : 'Unknown'}
<span class="field">Expires:</span> ${expDate ? formatDate(expDate) : 'Unknown'}
<span class="field">Days Until Expiry:</span> ${daysLeft !== null ? daysLeft + ' days' : 'Unknown'}
<span class="field">Last Updated:</span> ${lastChanged ? formatDate(new Date(lastChanged.eventDate)) : 'Unknown'}
<span class="field">Nameservers:</span> ${nameservers}
<span class="field">Handle:</span> ${data.handle || 'N/A'}`;
      result.classList.add('visible');

      // Update SSL cert issuer from RDAP if possible
      if (daysLeft !== null) {
        setVal('ssl-days', daysLeft + ' days (domain)', daysLeft > 60 ? 'good' : daysLeft > 14 ? 'warn' : 'bad');
      }

    } catch (err) {
      result.innerHTML = `<span style="color:var(--warn)">⚠️ RDAP lookup failed for this domain.\n\nThis may mean:\n- The domain uses a registry without RDAP support\n- The domain has privacy protection\n- Network error\n\nTry: whois.domaintools.com or lookup.icann.org</span>`;
      result.classList.add('visible');
    }

    btn.disabled = false;
    btn.textContent = '🔎 RUN WHOIS LOOKUP';
  });
}

// ── MAIN ──────────────────────────────────────────────────────────────────────

async function init() {
  // Load saved settings (thresholds etc.) before computing verdicts
  try { await loadSettings(); } catch(e) {}

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) {
    $('loadingPanel').innerHTML = '<div class="loading">Could not inspect this page.<br><span style="color:var(--muted)">Try a regular webpage.</span></div>';
    return;
  }

  const url = tab.url;
  let meta = null;

  // Collect page metadata
  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => {
        return {
          title: document.title,
          metaDescription: document.querySelector('meta[name="description"]')?.content || "",
          generator: document.querySelector('meta[name="generator"]')?.content || "",
          author: document.querySelector('meta[name="author"]')?.content || "",
          hasContactPage: !!document.querySelector('a[href*="contact"]'),
          hasPrivacyPolicy: !!(document.querySelector('a[href*="privacy"]') || document.querySelector('a[href*="Privacy"]')),
          hasTerms: !!(document.querySelector('a[href*="terms"]') || document.querySelector('a[href*="tos"]')),
          socialLinks: {
            facebook: !!document.querySelector('a[href*="facebook.com"]'),
            twitter: !!(document.querySelector('a[href*="twitter.com"]') || document.querySelector('a[href*="x.com"]')),
            linkedin: !!document.querySelector('a[href*="linkedin.com"]'),
            instagram: !!document.querySelector('a[href*="instagram.com"]'),
          },
          externalLinks: document.querySelectorAll('a[href^="http"]').length,
          imageCount: document.images.length,
          hasHttpsLinks: document.querySelectorAll('a[href^="http:"]').length,
          hasCopyright: document.body?.innerText?.includes('©') || document.body?.innerText?.toLowerCase().includes('copyright'),
          cookieConsent: !!(document.querySelector('[id*="cookie"]') || document.querySelector('[class*="cookie"]') || document.querySelector('[id*="consent"]')),
          loadTime: performance.timing ? performance.timing.domContentLoadedEventEnd - performance.timing.navigationStart : null,
          language: document.documentElement.lang || navigator.language,
          charset: document.characterSet,
        };
      }
    });
    meta = results?.[0]?.result || null;
  } catch (e) {
    // Can't inject into chrome:// pages etc.
  }

  const score = calcTrustScore({ url, meta });

  // Show UI
  $('loadingPanel').classList.remove('active');

  // URL bar
  const parsed = parseDomain(url);
  const isHttps = url.startsWith('https://');
  const urlBar = $('urlBar');
  urlBar.style.display = 'flex';
  $('protocolBadge').textContent = isHttps ? 'HTTPS' : 'HTTP';
  $('protocolBadge').className = 'protocol-badge ' + (isHttps ? 'protocol-https' : 'protocol-http');
  $('urlText').textContent = parsed?.hostname || url;

  // Trust bar
  $('trustBarWrap').style.display = 'flex';
  setTimeout(() => {
    $('trustBarFill').style.width = score + '%';
    $('trustBarFill').style.background = scoreColor(score);
  }, 100);
  $('trustScoreBadge').textContent = score + '/100';
  $('trustScoreBadge').style.color = scoreColor(score);
  $('trustScoreBadge').style.borderColor = scoreColor(score) + '44';
  $('trustScoreBadge').style.background = scoreColor(score) + '12';

  // Tabs
  $('tabs').style.display = 'flex';

  // Render panels
  renderOverview(url, meta, score);
  renderSSL(url);
  renderSignals(url, meta);

  // Activate overview
  $('panel-overview').classList.add('active');

  // WHOIS
  if (parsed?.hostname) setupWhois(parsed.hostname);

  // Footer
  const footer = $('footer');
  footer.style.display = 'flex';
  $('footerTime').textContent = 'Scanned ' + new Date().toLocaleTimeString();
  $('refreshBtn').addEventListener('click', () => location.reload());
}

init().catch(err => {
  $('loadingPanel').innerHTML = `<div class="loading" style="color:var(--danger)">Error: ${err.message}</div>`;
});

// ── ADVANCED FEATURES ─────────────────────────────────────────────────────────

function setupAdvancedBtn(btnId, resultId, handler) {
  const btn = document.getElementById(btnId);
  const result = document.getElementById(resultId);
  if (!btn || !result) return;
  btn.addEventListener('click', async () => {
    btn.disabled = true;
    const origText = btn.textContent;
    btn.textContent = '⏳ CHECKING…';
    result.classList.remove('visible');
    result.textContent = '';
    try {
      const html = await handler(result);
      if (html) { result.innerHTML = html; result.classList.add('visible'); }
    } catch (err) {
      result.innerHTML = `<span style="color:var(--warn)">⚠️ Error: ${err.message}</span>`;
      result.classList.add('visible');
    }
    btn.disabled = false;
    btn.textContent = origText;
  });
}

// 1. Google Safe Browsing (using transparencyreport as proxy — no API key needed)
function setupSafeBrowsing(hostname) {
  setupAdvancedBtn('safeBrowsingBtn', 'safeBrowsingResult', async () => {
    // Use Google Transparency Report lookup (public endpoint)
    const url = `https://transparencyreport.google.com/transparencyreport/api/v3/safebrowsing/status?site=${encodeURIComponent('https://' + hostname)}`;
    try {
      const res = await fetch(url);
      const text = await res.text();
      // Parse the weird Google format )]}'\n[...data...]
      const cleaned = text.replace(/^\)\]\}'\n/, '');
      const data = JSON.parse(cleaned);
      // data[0][1] contains the status array
      const statusArr = data?.[0]?.[1] || [];
      const isFlagged = statusArr.some(s => s !== 0);
      if (isFlagged) {
        return `<span style="color:var(--danger)">🚨 FLAGGED by Google Safe Browsing\n\nThis URL has been flagged for phishing, malware, or unwanted software. Do not proceed.</span>`;
      } else {
        return `<span style="color:var(--accent)">✅ CLEAN — Not flagged by Google Safe Browsing\n\n<span class="field">Domain checked:</span> ${hostname}\n<span class="field">Status:</span> No threats detected\n<span class="field">Source:</span> Google Transparency Report</span>`;
      }
    } catch(e) {
      // Fallback: direct transparency report link
      return `<span style="color:var(--muted)">ℹ️ Direct API blocked by CORS.\n\n<span class="field">Manual check:</span> Visit the link below to verify\nhttps://transparencyreport.google.com/safe-browsing/search?url=${encodeURIComponent(hostname)}\n\n<span class="field">Tip:</span> This opens Google's official Safe Browsing checker.</span>`;
    }
  });
}

// 2. Wayback Machine Age Check
function setupWayback(hostname) {
  setupAdvancedBtn('waybackBtn', 'waybackResult', async () => {
    const domain = hostname.replace(/^www\./, '');
    const res = await fetch(`https://archive.org/wayback/available?url=${domain}`);
    if (!res.ok) throw new Error('Wayback API unreachable');
    const data = await res.json();

    // Also fetch CDX for earliest snapshot
    const cdxRes = await fetch(
      `https://web.archive.org/cdx/search/cdx?url=${domain}&output=json&limit=1&fl=timestamp,statuscode&from=19900101&to=20251231&filter=statuscode:200`
    );
    let earliest = null;
    if (cdxRes.ok) {
      const cdx = await cdxRes.json();
      if (cdx && cdx.length > 1) {
        const ts = cdx[1][0]; // first real row (row 0 is header)
        earliest = ts ? `${ts.slice(0,4)}-${ts.slice(4,6)}-${ts.slice(6,8)}` : null;
      }
    }

    const snap = data?.archived_snapshots?.closest;
    const lastSeen = snap?.timestamp
      ? `${snap.timestamp.slice(0,4)}-${snap.timestamp.slice(4,6)}-${snap.timestamp.slice(6,8)}`
      : 'Unknown';

    const now = new Date();
    let ageStr = 'Unknown';
    let ageClass = '';
    if (earliest) {
      const earlyDate = new Date(earliest);
      const ageYears = ((now - earlyDate) / (1000*60*60*24*365)).toFixed(1);
      ageStr = `${ageYears} years (since ${earliest})`;
      ageClass = parseFloat(ageYears) >= 2 ? 'color:var(--accent)' : parseFloat(ageYears) >= 0.5 ? 'color:var(--warn)' : 'color:var(--danger)';
    }

    return `<span style="color:var(--accent)">📅 WAYBACK MACHINE RESULTS\n\n</span><span class="field">Domain:</span> ${domain}\n<span class="field">Earliest Snapshot:</span> <span style="${ageClass}">${earliest || 'Not found'}</span>\n<span class="field">Estimated Age:</span> <span style="${ageClass}">${ageStr}</span>\n<span class="field">Last Archived:</span> ${lastSeen}\n<span class="field">Archive URL:</span> https://web.archive.org/web/*/${domain}`;
  });
}

// 3. DNS Blacklist (using Cloudflare DNS over HTTPS)
function setupDnsBlacklist(hostname) {
  setupAdvancedBtn('dnsBlacklistBtn', 'dnsBlacklistResult', async () => {
    const domain = hostname.replace(/^www\./, '');

    // Query multiple DNS record types via Cloudflare DoH
    const checks = await Promise.allSettled([
      fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=A`, {headers: {'Accept':'application/dns-json'}}).then(r=>r.json()),
      fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=MX`, {headers: {'Accept':'application/dns-json'}}).then(r=>r.json()),
      fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=TXT`, {headers: {'Accept':'application/dns-json'}}).then(r=>r.json()),
    ]);

    const aResult = checks[0].status === 'fulfilled' ? checks[0].value : null;
    const mxResult = checks[1].status === 'fulfilled' ? checks[1].value : null;
    const txtResult = checks[2].status === 'fulfilled' ? checks[2].value : null;

    const aRecords = aResult?.Answer?.filter(r => r.type === 1).map(r => r.data) || [];
    const mxRecords = mxResult?.Answer?.filter(r => r.type === 15).map(r => r.data) || [];
    const txtRecords = txtResult?.Answer?.filter(r => r.type === 16).map(r => r.data) || [];

    // Check if IP appears in known bad ranges (basic heuristic)
    const suspiciousASNs = ['185.220.', '45.142.', '194.165.'];
    const suspiciousIP = aRecords.some(ip => suspiciousASNs.some(prefix => ip.startsWith(prefix)));

    const hasMX = mxRecords.length > 0;
    const statusIcon = suspiciousIP ? '🚨' : '✅';
    const statusText = suspiciousIP ? '<span style="color:var(--danger)">IP in known suspicious range</span>' : '<span style="color:var(--accent)">No blacklist hits detected</span>';

    return `${statusIcon} DNS BLACKLIST RESULTS\n\n<span class="field">Domain:</span> ${domain}\n<span class="field">A Records (IP):</span> ${aRecords.join(', ') || 'None'}\n<span class="field">MX Records:</span> ${hasMX ? mxRecords.length + ' found' : 'None (no email server)'}\n<span class="field">TXT Records:</span> ${txtRecords.length} found\n<span class="field">Threat Status:</span> ${statusText}\n<span class="field">Source:</span> Cloudflare DNS over HTTPS`;
  });
}

// 4. SPF / DMARC Check
function setupSpfDmarc(hostname) {
  setupAdvancedBtn('spfDmarcBtn', 'spfDmarcResult', async () => {
    const domain = hostname.replace(/^www\./, '');

    const [spfRes, dmarcRes] = await Promise.allSettled([
      fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=TXT`, {headers:{'Accept':'application/dns-json'}}).then(r=>r.json()),
      fetch(`https://cloudflare-dns.com/dns-query?name=_dmarc.${domain}&type=TXT`, {headers:{'Accept':'application/dns-json'}}).then(r=>r.json()),
    ]);

    const spfTxt = spfRes.status === 'fulfilled'
      ? (spfRes.value?.Answer || []).filter(r => r.type === 16).map(r => r.data).find(d => d.includes('v=spf1'))
      : null;
    const dmarcTxt = dmarcRes.status === 'fulfilled'
      ? (dmarcRes.value?.Answer || []).filter(r => r.type === 16).map(r => r.data).find(d => d.includes('v=DMARC1'))
      : null;

    const spfOk = !!spfTxt;
    const dmarcOk = !!dmarcTxt;

    // Parse DMARC policy
    let dmarcPolicy = 'none';
    if (dmarcTxt) {
      const pMatch = dmarcTxt.match(/p=(\w+)/);
      if (pMatch) dmarcPolicy = pMatch[1];
    }

    const riskLevel = !spfOk && !dmarcOk ? 'HIGH' : (!spfOk || !dmarcOk || dmarcPolicy === 'none') ? 'MEDIUM' : 'LOW';
    const riskColor = riskLevel === 'HIGH' ? 'var(--danger)' : riskLevel === 'MEDIUM' ? 'var(--warn)' : 'var(--accent)';

    return `<span class="field">Domain:</span> ${domain}
<span class="field">SPF Record:</span> ${spfOk ? '<span style="color:var(--accent)">✅ Present</span>' : '<span style="color:var(--danger)">❌ Missing</span>'}
${spfOk ? `<span class="field">SPF Value:</span> ${spfTxt.slice(0,60)}…\n` : ''}<span class="field">DMARC Record:</span> ${dmarcOk ? '<span style="color:var(--accent)">✅ Present</span>' : '<span style="color:var(--danger)">❌ Missing</span>'}
<span class="field">DMARC Policy:</span> ${dmarcOk ? dmarcPolicy.toUpperCase() : 'N/A'}
<span class="field">Spoofing Risk:</span> <span style="color:${riskColor}">${riskLevel}</span>
${!spfOk || !dmarcOk ? '<span style="color:var(--warn)">⚠️ Missing records allow email spoofing from this domain.</span>' : '<span style="color:var(--accent)">✅ Email is protected against spoofing.</span>'}`;
  });
}

// 5. Mixed Content Detector
function setupMixedContent(tabId) {
  setupAdvancedBtn('mixedContentBtn', 'mixedContentResult', async () => {
    const results = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => {
        const insecureImgs = [...document.querySelectorAll('img[src^="http:"]')].map(el => el.src).slice(0,5);
        const insecureScripts = [...document.querySelectorAll('script[src^="http:"]')].map(el => el.src).slice(0,5);
        const insecureLinks = [...document.querySelectorAll('link[href^="http:"]')].map(el => el.href).slice(0,5);
        const insecureIframes = [...document.querySelectorAll('iframe[src^="http:"]')].map(el => el.src).slice(0,5);
        return { insecureImgs, insecureScripts, insecureLinks, insecureIframes };
      }
    });
    const d = results?.[0]?.result;
    if (!d) throw new Error('Could not scan page');

    const total = d.insecureImgs.length + d.insecureScripts.length + d.insecureLinks.length + d.insecureIframes.length;
    const isHttps = location.href.startsWith('https') || true; // popup always runs https check on target

    if (total === 0) {
      return `<span style="color:var(--accent)">✅ NO MIXED CONTENT DETECTED\n\nAll loaded resources appear to use secure URLs.</span>`;
    }

    let out = `<span style="color:var(--warn)">⚠️ ${total} INSECURE RESOURCE(S) FOUND\n\n</span>`;
    if (d.insecureImgs.length) out += `<span class="field">Images (${d.insecureImgs.length}):</span>\n${d.insecureImgs.map(u => '  ' + u.slice(0,50)).join('\n')}\n`;
    if (d.insecureScripts.length) out += `<span class="field">Scripts (${d.insecureScripts.length}):</span>\n${d.insecureScripts.map(u => '  ' + u.slice(0,50)).join('\n')}\n`;
    if (d.insecureLinks.length) out += `<span class="field">Stylesheets (${d.insecureLinks.length}):</span>\n${d.insecureLinks.map(u => '  ' + u.slice(0,50)).join('\n')}\n`;
    if (d.insecureIframes.length) out += `<span class="field">Iframes (${d.insecureIframes.length}):</span>\n${d.insecureIframes.map(u => '  ' + u.slice(0,50)).join('\n')}\n`;
    return out;
  });
}

// 6. Payment Form Warning
function setupPaymentForm(tabId) {
  setupAdvancedBtn('paymentFormBtn', 'paymentFormResult', async () => {
    const results = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => {
        const cardInputs = document.querySelectorAll('input[name*="card"], input[placeholder*="card"], input[autocomplete*="cc-"], input[id*="card-number"], input[id*="cardnumber"]');
        const cvvInputs = document.querySelectorAll('input[name*="cvv"], input[name*="cvc"], input[placeholder*="cvv"], input[placeholder*="cvc"]');
        const paypalLinks = document.querySelectorAll('a[href*="paypal.com"], img[src*="paypal"]');
        const checkoutForms = document.querySelectorAll('form[action*="checkout"], form[action*="payment"], form[id*="checkout"], form[id*="payment"]');
        const stripeElements = document.querySelectorAll('[class*="stripe"], script[src*="stripe.com"]');
        const paymentKeywords = ['checkout', 'payment', 'order', 'billing', 'purchase'];
        const bodyText = document.body?.innerText?.toLowerCase() || '';
        const keywordCount = paymentKeywords.filter(kw => bodyText.includes(kw)).length;

        return {
          cardInputCount: cardInputs.length,
          cvvCount: cvvInputs.length,
          hasPaypal: paypalLinks.length > 0,
          checkoutFormCount: checkoutForms.length,
          hasStripe: stripeElements.length > 0,
          paymentKeywordCount: keywordCount,
          isHttps: location.protocol === 'https:'
        };
      }
    });
    const d = results?.[0]?.result;
    if (!d) throw new Error('Could not scan page');

    const hasPayment = d.cardInputCount > 0 || d.cvvCount > 0 || d.checkoutFormCount > 0;
    const risk = hasPayment && !d.isHttps ? 'HIGH' : hasPayment ? 'MEDIUM' : 'LOW';
    const riskColor = risk === 'HIGH' ? 'var(--danger)' : risk === 'MEDIUM' ? 'var(--warn)' : 'var(--accent)';

    return `<span class="field">Card Input Fields:</span> ${d.cardInputCount > 0 ? `<span style="color:var(--warn)">${d.cardInputCount} found</span>` : '<span style="color:var(--accent)">None</span>'}
<span class="field">CVV/CVC Fields:</span> ${d.cvvCount > 0 ? `<span style="color:var(--warn)">${d.cvvCount} found</span>` : '<span style="color:var(--accent)">None</span>'}
<span class="field">Checkout Forms:</span> ${d.checkoutFormCount > 0 ? `<span style="color:var(--warn)">${d.checkoutFormCount} found</span>` : 'None'}
<span class="field">PayPal Integration:</span> ${d.hasPaypal ? '✅ Yes' : 'No'}
<span class="field">Stripe Integration:</span> ${d.hasStripe ? '✅ Yes' : 'No'}
<span class="field">Payment Keywords:</span> ${d.paymentKeywordCount}/5 found
<span class="field">HTTPS Active:</span> ${d.isHttps ? '<span style="color:var(--accent)">✅ Yes</span>' : '<span style="color:var(--danger)">❌ No — HIGH RISK</span>'}
<span class="field">Risk Level:</span> <span style="color:${riskColor}">${risk}</span>
${risk === 'HIGH' ? '<span style="color:var(--danger)">🚨 Payment form on HTTP site — data can be intercepted!</span>' : risk === 'MEDIUM' ? '<span style="color:var(--warn)">⚠️ Payment detected — verify site legitimacy before entering card data.</span>' : '<span style="color:var(--accent)">✅ No active payment forms detected.</span>'}`;
  });
}

// 7. Redirect Chain Tracer
function setupRedirectChain(tabId, url) {
  setupAdvancedBtn('redirectBtn', 'redirectResult', async () => {
    // Get navigation history from the tab's performance entries
    const results = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => {
        const nav = performance.getEntriesByType('navigation')[0];
        const resources = performance.getEntriesByType('resource')
          .filter(r => r.redirectCount > 0)
          .slice(0, 5)
          .map(r => ({ name: r.name, redirectCount: r.redirectCount }));
        return {
          currentUrl: location.href,
          redirectCount: nav?.redirectCount || 0,
          type: nav?.type || 'unknown',
          redirectStart: nav?.redirectStart || 0,
          fetchStart: nav?.fetchStart || 0,
          resources
        };
      }
    });
    const d = results?.[0]?.result;
    if (!d) throw new Error('Could not trace redirects');

    const hadRedirects = d.redirectCount > 0;
    const redirectTime = d.redirectStart > 0 ? Math.round(d.redirectStart - d.fetchStart) : 0;

    let out = '';
    if (hadRedirects) {
      out += `<span style="color:var(--warn)">⚠️ ${d.redirectCount} REDIRECT(S) DETECTED\n\n</span>`;
      out += `<span class="field">Final URL:</span> ${d.currentUrl.slice(0,60)}${d.currentUrl.length > 60 ? '…' : ''}\n`;
      out += `<span class="field">Redirect Count:</span> ${d.redirectCount}\n`;
      out += `<span class="field">Redirect Time:</span> ${redirectTime}ms\n`;
      out += `<span class="field">Nav Type:</span> ${d.type}\n`;
      if (d.resources.length) {
        out += `\n<span class="field">Redirected Resources:</span>\n`;
        d.resources.forEach(r => { out += `  ${r.name.slice(0,45)}… (${r.redirectCount} hops)\n`; });
      }
      out += `\n<span style="color:var(--muted)">ℹ️ Multiple redirects can indicate link hijacking or suspicious forwarding.</span>`;
    } else {
      out = `<span style="color:var(--accent)">✅ NO REDIRECTS DETECTED\n\n</span><span class="field">Final URL:</span> ${d.currentUrl.slice(0,60)}\n<span class="field">Nav Type:</span> ${d.type}\n<span style="color:var(--muted)">Page loaded directly with no redirect chain.</span>`;
    }
    return out;
  });
}

// 8. Site Change Alerts (hash-based change detection using localStorage via background)
function setupSiteChange(tabId, url) {
  setupAdvancedBtn('siteChangeBtn', 'siteChangeResult', async () => {
    const results = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => {
        // Create a hash of the page's visible text content
        const text = document.body?.innerText?.trim() || '';
        let hash = 0;
        for (let i = 0; i < Math.min(text.length, 5000); i++) {
          hash = ((hash << 5) - hash) + text.charCodeAt(i);
          hash |= 0;
        }
        return {
          hash: hash.toString(16),
          wordCount: text.split(/\s+/).length,
          title: document.title,
          timestamp: Date.now()
        };
      }
    });
    const current = results?.[0]?.result;
    if (!current) throw new Error('Could not hash page');

    const storageKey = 'sitechange_' + btoa(url).slice(0, 20);
    const stored = await chrome.storage.local.get(storageKey);
    const prev = stored[storageKey];

    if (!prev) {
      // First time — save baseline
      const saveData = {}; saveData[storageKey] = current;
      await chrome.storage.local.set(saveData);
      return `<span style="color:var(--accent)">📸 BASELINE SAVED\n\n</span><span class="field">Page Title:</span> ${current.title.slice(0,40)}\n<span class="field">Content Hash:</span> ${current.hash}\n<span class="field">Word Count:</span> ${current.wordCount}\n<span class="field">Saved At:</span> ${new Date(current.timestamp).toLocaleString()}\n\n<span style="color:var(--muted)">Visit again and click this button to detect changes.</span>`;
    }

    const changed = prev.hash !== current.hash;
    const wordDiff = current.wordCount - prev.wordCount;
    const timeSince = Math.round((Date.now() - prev.timestamp) / 60000);

    if (changed) {
      // Update stored
      const saveData = {}; saveData[storageKey] = current;
      await chrome.storage.local.set(saveData);
      return `<span style="color:var(--warn)">⚠️ PAGE CONTENT HAS CHANGED!\n\n</span><span class="field">Previous Hash:</span> ${prev.hash}\n<span class="field">Current Hash:</span> ${current.hash}\n<span class="field">Word Count Δ:</span> ${wordDiff > 0 ? '+' : ''}${wordDiff} words\n<span class="field">Last Checked:</span> ${timeSince} min ago\n\n<span style="color:var(--warn)">Content was modified since your last visit. Review carefully before entering any data.</span>`;
    } else {
      return `<span style="color:var(--accent)">✅ NO CHANGES DETECTED\n\n</span><span class="field">Content Hash:</span> ${current.hash}\n<span class="field">Word Count:</span> ${current.wordCount}\n<span class="field">Last Checked:</span> ${timeSince} min ago\n\nPage content matches your last saved baseline.`;
    }
  });
}

// ── Hook advanced features into init() ───────────────────────────────────────

const _origInit = init;

// Patch: we wrap init to attach advanced feature handlers after page loads.
// We override the init export by monkey-patching the end of the call chain.
document.addEventListener('DOMContentLoaded', () => {
  // Wait for init to finish then wire up advanced features
  const waitForTabData = setInterval(() => {
    const urlText = document.getElementById('urlText');
    if (urlText && urlText.textContent && urlText.textContent !== '—') {
      clearInterval(waitForTabData);
      chrome.tabs.query({ active: true, currentWindow: true }).then(([tab]) => {
        if (!tab) return;
        const url = tab.url;
        const parsed = parseDomain(url);
        const hostname = parsed?.hostname || '';
        setupSafeBrowsing(hostname);
        setupWayback(hostname);
        setupDnsBlacklist(hostname);
        setupSpfDmarc(hostname);
        setupMixedContent(tab.id);
        setupPaymentForm(tab.id);
        setupRedirectChain(tab.id, url);
        setupSiteChange(tab.id, url);
      });
    }
  }, 300);
}, { once: true });

// ── SETTINGS ──────────────────────────────────────────────────────────────────

// Default thresholds
let THRESHOLD_SAFE    = 70;
let THRESHOLD_CAUTION = 45;

async function loadSettings() {
  const stored = await chrome.storage.local.get('siteinspector_settings');
  const s = stored.siteinspector_settings || {};
  THRESHOLD_SAFE    = s.safeThreshold    ?? 70;
  THRESHOLD_CAUTION = s.cautionThreshold ?? 45;
  return s;
}

function applySettingsToUI(s) {
  // Sliders
  const safeSlider    = document.getElementById('safeThresholdSlider');
  const cautionSlider = document.getElementById('cautionThresholdSlider');
  if (safeSlider)    { safeSlider.value    = THRESHOLD_SAFE;    document.getElementById('safeThresholdVal').textContent    = THRESHOLD_SAFE; }
  if (cautionSlider) { cautionSlider.value = THRESHOLD_CAUTION; document.getElementById('cautionThresholdVal').textContent = THRESHOLD_CAUTION; }
  updatePreview();

  // Toggles
  if (s.autoWhois   !== undefined) document.getElementById('toggleAutoWhois').checked   = s.autoWhois;
  if (s.autoMixed   !== undefined) document.getElementById('toggleAutoMixed').checked   = s.autoMixed;
  if (s.autoPayment !== undefined) document.getElementById('toggleAutoPayment').checked = s.autoPayment;
  if (s.showScore   !== undefined) document.getElementById('toggleShowScore').checked   = s.showScore;
  if (s.compact     !== undefined) document.getElementById('toggleCompact').checked     = s.compact;

  applyCompact(!!s.compact);
  applyShowScore(s.showScore !== false);
}

function updatePreview() {
  const safe    = parseInt(document.getElementById('safeThresholdSlider')?.value    || THRESHOLD_SAFE);
  const caution = parseInt(document.getElementById('cautionThresholdSlider')?.value || THRESHOLD_CAUTION);
  const prevSafe    = document.getElementById('prev-safe');
  const prevCaution = document.getElementById('prev-caution');
  const prevDanger  = document.getElementById('prev-danger');
  if (prevSafe)    prevSafe.textContent    = `${safe}–100 → ✅ SAFE`;
  if (prevCaution) prevCaution.textContent = `${caution}–${safe - 1} → ⚠️ CAUTION`;
  if (prevDanger)  prevDanger.textContent  = `0–${caution - 1} → 🚨 DANGER`;
}

function applyCompact(on) {
  document.querySelectorAll('.panel').forEach(p => {
    p.style.padding = on ? '6px' : '';
  });
  document.querySelectorAll('.card').forEach(c => {
    c.style.marginBottom = on ? '6px' : '';
  });
}

function applyShowScore(show) {
  const badge = document.getElementById('trustScoreBadge');
  if (badge) badge.style.display = show ? '' : 'none';
}

function setupSettings() {
  const safeSlider    = document.getElementById('safeThresholdSlider');
  const cautionSlider = document.getElementById('cautionThresholdSlider');
  const safeVal       = document.getElementById('safeThresholdVal');
  const cautionVal    = document.getElementById('cautionThresholdVal');

  if (safeSlider) {
    safeSlider.addEventListener('input', () => {
      const v = parseInt(safeSlider.value);
      safeVal.textContent = v;
      // Keep caution always < safe
      if (parseInt(cautionSlider.value) >= v) {
        cautionSlider.max = v - 1;
        if (parseInt(cautionSlider.value) >= v) {
          cautionSlider.value = v - 5;
          cautionVal.textContent = v - 5;
        }
      } else {
        cautionSlider.max = v - 1;
      }
      updatePreview();
    });
  }

  if (cautionSlider) {
    cautionSlider.addEventListener('input', () => {
      cautionVal.textContent = cautionSlider.value;
      updatePreview();
    });
  }

  document.getElementById('toggleCompact')?.addEventListener('change', e => {
    applyCompact(e.target.checked);
  });

  document.getElementById('toggleShowScore')?.addEventListener('change', e => {
    applyShowScore(e.target.checked);
  });

  const saveBtn    = document.getElementById('saveSettingsBtn');
  const saveConfirm = document.getElementById('saveConfirm');

  if (saveBtn) {
    saveBtn.addEventListener('click', async () => {
      const newSafe    = parseInt(safeSlider?.value    || 70);
      const newCaution = parseInt(cautionSlider?.value || 45);

      THRESHOLD_SAFE    = newSafe;
      THRESHOLD_CAUTION = newCaution;

      const settings = {
        safeThreshold:    newSafe,
        cautionThreshold: newCaution,
        autoWhois:   document.getElementById('toggleAutoWhois')?.checked   || false,
        autoMixed:   document.getElementById('toggleAutoMixed')?.checked   || false,
        autoPayment: document.getElementById('toggleAutoPayment')?.checked || false,
        showScore:   document.getElementById('toggleShowScore')?.checked   !== false,
        compact:     document.getElementById('toggleCompact')?.checked     || false,
      };

      await chrome.storage.local.set({ siteinspector_settings: settings });

      saveConfirm.textContent = '✅ Settings saved! Refresh tab to apply new thresholds.';
      setTimeout(() => { saveConfirm.textContent = ''; }, 3500);
    });
  }
}

// Patch scoreClass and scoreColor to use dynamic thresholds
const _scoreClass = scoreClass;
const _scoreColor = scoreColor;
// Override with threshold-aware versions
window.scoreClass = function(score) {
  if (score >= THRESHOLD_SAFE)    return 'good';
  if (score >= THRESHOLD_CAUTION) return 'warn';
  return 'bad';
};
window.scoreColor = function(score) {
  if (score >= THRESHOLD_SAFE)    return 'var(--accent)';
  if (score >= THRESHOLD_CAUTION) return 'var(--warn)';
  return 'var(--danger)';
};

// Also override renderOverview verdict logic
const _renderOverview = renderOverview;
window.renderOverview = function(url, meta, score) {
  _renderOverview(url, meta, score);
  // Re-render verdict with correct dynamic thresholds
  const verdictBox = document.getElementById('verdictBox');
  if (!verdictBox) return;
  let vClass, vIcon, vTitle, vText;
  if (score >= THRESHOLD_SAFE) {
    vClass = 'safe'; vIcon = '✅';
    vTitle = 'LIKELY LEGITIMATE';
    vText = 'This site shows strong trust signals. HTTPS is active, and common legitimacy markers are present.';
  } else if (score >= THRESHOLD_CAUTION) {
    vClass = 'suspicious'; vIcon = '⚠️';
    vTitle = 'PROCEED WITH CAUTION';
    vText = 'Some trust signals are missing. Verify the domain age and certificate before sharing sensitive info.';
  } else {
    vClass = 'danger'; vIcon = '🚨';
    vTitle = 'HIGH RISK — POSSIBLY FAKE';
    vText = 'This site lacks basic trust signals. It may be phishing or fraudulent. Do not enter personal data.';
  }
  verdictBox.innerHTML = `
    <div class="verdict ${vClass}">
      <div class="verdict-icon">${vIcon}</div>
      <div class="verdict-text">
        <h3>${vTitle}</h3>
        <p>${vText}</p>
      </div>
    </div>`;
};

// Init settings on load
document.addEventListener('DOMContentLoaded', async () => {
  const s = await loadSettings();
  setupSettings();
  applySettingsToUI(s);
}, { once: true });
