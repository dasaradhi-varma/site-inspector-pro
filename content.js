// content.js — Auto Safety Popup injected on every page load

(function () {
  // Don't run in iframes
  if (window.self !== window.top) return;
  // Don't run on extension pages
  if (location.protocol === 'chrome-extension:') return;
  // Only run on http/https
  if (!location.protocol.startsWith('http')) return;

  // ── Config ──────────────────────────────────────────────────────────────────
  const SUSPICIOUS_TLDS = ['.xyz','.top','.click','.loan','.work','.gq','.ml','.cf','.tk','.pw','.cc'];
  const SUSPICIOUS_KEYWORDS = ['secure-','verify-','login-','account-','update-','confirm-','paypal','bank','signin','password'];
  const KNOWN_BRANDS = ['paypal','amazon','google','facebook','apple','microsoft','netflix','instagram'];

  // ── Collect signals ─────────────────────────────────────────────────────────
  function collectSignals() {
    const host = location.hostname.toLowerCase();
    const isHttps = location.protocol === 'https:';
    const tld = '.' + host.split('.').slice(-1)[0];
    const suspTLD = SUSPICIOUS_TLDS.includes(tld);

    // Typosquatting check — domain contains brand name but isn't that brand
    const brandSpoof = KNOWN_BRANDS.some(brand => {
      return host.includes(brand) && !host.endsWith(brand + '.com') && !host.endsWith(brand + '.net');
    });

    // Suspicious keywords in subdomain or path
    const suspKeyword = SUSPICIOUS_KEYWORDS.some(k => host.includes(k));

    // Excessive subdomains (e.g. secure.login.update.example.xyz)
    const subdomainCount = host.split('.').length - 2;

    // Page signals
    const hasPrivacyPolicy = !!document.querySelector('a[href*="privacy"], a[href*="Privacy"]');
    const hasContact = !!document.querySelector('a[href*="contact"], a[href*="Contact"]');
    const hasCopyright = document.body?.innerText?.includes('©') || document.body?.innerText?.toLowerCase().includes('copyright');
    const hasForms = document.querySelectorAll('input[type="password"]').length > 0;
    const hasCookieBanner = !!(document.querySelector('[id*="cookie"],[class*="cookie"],[id*="consent"],[class*="consent"]'));

    // ── Score ──────────────────────────────────────────────────────────────────
    let score = 50;
    let flags = [];
    let positives = [];

    if (isHttps) { score += 20; positives.push('🔒 Secure HTTPS connection'); }
    else { score -= 35; flags.push('🔓 No SSL — connection is NOT encrypted'); }

    if (suspTLD) { score -= 20; flags.push(`⚠️ Risky domain extension (${tld})`); }
    if (brandSpoof) { score -= 30; flags.push('🎭 Domain mimics a known brand'); }
    if (suspKeyword) { score -= 15; flags.push('🚩 Suspicious words in domain name'); }
    if (subdomainCount > 2) { score -= 10; flags.push('🔗 Unusually deep subdomains'); }

    if (hasPrivacyPolicy) { score += 8; positives.push('📄 Privacy policy found'); }
    if (hasContact) { score += 5; positives.push('📬 Contact page found'); }
    if (hasCopyright) { score += 4; positives.push('© Copyright notice present'); }
    if (hasCookieBanner) { score += 3; positives.push('🍪 Cookie consent shown'); }

    // Warn about password forms on http
    if (hasForms && !isHttps) { score -= 25; flags.push('🔑 Password form on unencrypted page!'); }

    score = Math.max(0, Math.min(100, score));

    let level, label, emoji, color, glow;
    if (score >= 70) {
      level = 'SAFE'; label = 'This site appears legitimate'; emoji = '✅';
      color = '#00ff88'; glow = 'rgba(0,255,136,0.25)';
    } else if (score >= 45) {
      level = 'CAUTION'; label = 'Verify before sharing data'; emoji = '⚠️';
      color = '#f59e0b'; glow = 'rgba(245,158,11,0.25)';
    } else {
      level = 'DANGER'; label = 'Possible phishing or fake site!'; emoji = '🚨';
      color = '#ef4444'; glow = 'rgba(239,68,68,0.3)';
    }

    return { score, level, label, emoji, color, glow, flags, positives, isHttps, host };
  }

  // ── Build popup ─────────────────────────────────────────────────────────────
  function buildPopup(s) {
    const wrap = document.createElement('div');
    wrap.id = '__site_inspector_popup__';

    const flagsHTML = s.flags.slice(0, 3).map(f =>
      `<div style="display:flex;align-items:center;gap:6px;padding:4px 0;font-size:11px;color:#ef4444;font-family:'Space Mono',monospace;">${f}</div>`
    ).join('');

    const posHTML = s.positives.slice(0, 3).map(p =>
      `<div style="display:flex;align-items:center;gap:6px;padding:4px 0;font-size:11px;color:#00ff88;font-family:'Space Mono',monospace;">${p}</div>`
    ).join('');

    // Arc score ring
    const pct = s.score / 100;
    const r = 28, circ = 2 * Math.PI * r;
    const dash = pct * circ;

    wrap.innerHTML = `
<style>
  @import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Syne:wght@700;800&display=swap');
  #__site_inspector_popup__ {
    position: fixed;
    bottom: 24px;
    right: 24px;
    z-index: 2147483647;
    width: 300px;
    background: #0e0e18;
    border: 1px solid ${s.color}44;
    border-radius: 16px;
    box-shadow: 0 8px 40px rgba(0,0,0,0.7), 0 0 0 1px ${s.color}22, 0 0 24px ${s.glow};
    font-family: 'Syne', sans-serif;
    overflow: hidden;
    animation: __si_slideIn__ 0.45s cubic-bezier(0.34,1.56,0.64,1) both;
    transform-origin: bottom right;
  }
  @keyframes __si_slideIn__ {
    from { opacity:0; transform: scale(0.7) translateY(20px); }
    to   { opacity:1; transform: scale(1) translateY(0); }
  }
  @keyframes __si_fadeOut__ {
    from { opacity:1; transform: scale(1); }
    to   { opacity:0; transform: scale(0.85) translateY(10px); }
  }
  #__site_inspector_popup__.hiding {
    animation: __si_fadeOut__ 0.3s ease forwards;
  }
  #__si_close__ {
    position: absolute;
    top: 10px; right: 12px;
    background: rgba(255,255,255,0.06);
    border: none; color: #888;
    width: 22px; height: 22px;
    border-radius: 50%;
    cursor: pointer;
    font-size: 12px;
    display: flex; align-items: center; justify-content: center;
    transition: background 0.2s, color 0.2s;
    font-family: monospace;
  }
  #__si_close__:hover { background: rgba(255,255,255,0.12); color: #fff; }
  #__si_toggle__ {
    width: 100%;
    background: none;
    border: none;
    border-top: 1px solid rgba(255,255,255,0.05);
    color: #555;
    font-family: 'Space Mono', monospace;
    font-size: 9px;
    letter-spacing: 0.8px;
    padding: 7px;
    cursor: pointer;
    transition: color 0.2s, background 0.2s;
    text-align: center;
  }
  #__si_toggle__:hover { color: #888; background: rgba(255,255,255,0.03); }
  #__si_details__ { display: none; padding: 0 14px 4px; }
  #__si_details__.open { display: block; }
  .si-sep { height: 1px; background: rgba(255,255,255,0.05); margin: 6px 0; }
</style>

<!-- Header strip -->
<div style="background:linear-gradient(135deg,${s.color}18,${s.color}06);padding:14px 38px 14px 14px;display:flex;align-items:center;gap:12px;">
  <!-- Score ring -->
  <div style="position:relative;flex-shrink:0;width:64px;height:64px;">
    <svg width="64" height="64" viewBox="0 0 64 64">
      <circle cx="32" cy="32" r="${r}" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="5"/>
      <circle cx="32" cy="32" r="${r}" fill="none" stroke="${s.color}" stroke-width="5"
        stroke-dasharray="${dash.toFixed(1)} ${circ.toFixed(1)}"
        stroke-linecap="round"
        transform="rotate(-90 32 32)"
        style="filter:drop-shadow(0 0 4px ${s.color})"/>
    </svg>
    <div style="position:absolute;inset:0;display:flex;align-items:center;justify-content:center;flex-direction:column;">
      <span style="font-size:18px;line-height:1;">${s.emoji}</span>
    </div>
  </div>

  <!-- Text -->
  <div style="flex:1;min-width:0;">
    <div style="font-size:8px;font-family:'Space Mono',monospace;letter-spacing:2px;color:#555;margin-bottom:3px;">SITE INSPECTOR</div>
    <div style="font-size:18px;font-weight:800;color:${s.color};letter-spacing:-0.5px;line-height:1.1;">${s.level}</div>
    <div style="font-size:10px;color:#888;font-family:'Space Mono',monospace;margin-top:3px;">${s.label}</div>
  </div>

  <!-- Score badge -->
  <div style="flex-shrink:0;text-align:center;">
    <div style="font-size:20px;font-weight:800;color:${s.color};font-family:'Space Mono',monospace;line-height:1;">${s.score}</div>
    <div style="font-size:8px;color:#444;font-family:'Space Mono',monospace;">/100</div>
  </div>
</div>

<!-- Domain pill -->
<div style="padding:6px 14px;">
  <div style="background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.07);border-radius:6px;padding:5px 10px;display:flex;align-items:center;gap:8px;">
    <span style="font-size:10px;padding:2px 6px;border-radius:4px;font-family:'Space Mono',monospace;font-weight:700;background:${s.isHttps?'rgba(0,255,136,0.1)':'rgba(239,68,68,0.1)'};color:${s.isHttps?'#00ff88':'#ef4444'};border:1px solid ${s.isHttps?'rgba(0,255,136,0.2)':'rgba(239,68,68,0.2)'};">${s.isHttps?'HTTPS':'HTTP'}</span>
    <span style="font-family:'Space Mono',monospace;font-size:10px;color:#666;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:180px;">${s.host}</span>
  </div>
</div>

<!-- Quick flags -->
${(s.flags.length > 0 || s.positives.length > 0) ? `
<div style="padding:2px 14px 8px;">
  ${s.flags.length > 0 ? `<div style="margin-bottom:2px;">${flagsHTML}</div>` : ''}
  ${s.positives.length > 0 ? `<div>${posHTML}</div>` : ''}
</div>` : ''}

<!-- Expandable details -->
<div id="__si_details__">
  <div class="si-sep"></div>
  <div style="font-size:9px;letter-spacing:1.5px;color:#444;font-family:'Space Mono',monospace;margin-bottom:6px;">ALL SIGNALS</div>
  ${[...s.positives, ...s.flags].map(item => `<div style="font-size:10px;font-family:'Space Mono',monospace;color:#666;padding:3px 0;border-bottom:1px solid rgba(255,255,255,0.03);">${item}</div>`).join('')}
  <div style="height:6px;"></div>
</div>

<button id="__si_toggle__">▾ DETAILS</button>
<button id="__si_close__">✕</button>
`;

    // Close button
    wrap.querySelector('#__si_close__').addEventListener('click', () => {
      wrap.classList.add('hiding');
      setTimeout(() => wrap.remove(), 300);
    });

    // Toggle details
    const toggle = wrap.querySelector('#__si_toggle__');
    const details = wrap.querySelector('#__si_details__');
    toggle.addEventListener('click', () => {
      const open = details.classList.toggle('open');
      toggle.textContent = open ? '▴ HIDE' : '▾ DETAILS';
    });

    // Auto-dismiss after 7s if safe
    if (s.level === 'SAFE') {
      setTimeout(() => {
        if (wrap.parentNode) {
          wrap.classList.add('hiding');
          setTimeout(() => wrap.remove(), 300);
        }
      }, 7000);
    }

    return wrap;
  }

  // ── Inject ───────────────────────────────────────────────────────────────────
  function inject() {
    if (document.getElementById('__site_inspector_popup__')) return;
    const signals = collectSignals();
    const popup = buildPopup(signals);
    document.body.appendChild(popup);
  }

  // Wait for body to be ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', inject);
  } else {
    inject();
  }
})();
