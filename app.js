/**
 * ScamGuard - Indian Cyber Fraud & Scam Message Checker
 * app.js - Plain browser JavaScript (no libraries, no external calls)
 *
 * Level 1: rule scoring, risk gauge, highlighted message, advice line
 * Level 2: link (URL) checks judged by text only (links are never opened)
 * Level 3: "why risky" list, English/Hindi toggle, Read Aloud
 * Level 4 (image text reading): skipped for now
 */

// ---------------------------------------------------------------------------
// SECTION 1: Settings
// ---------------------------------------------------------------------------

// Risk bands: 0-30 Low, 31-60 Medium, 61-100 High
const RISK_THRESHOLDS = {
  LOW: { min: 0, max: 30, level: 'low', verdict: 'Low' },
  MEDIUM: { min: 31, max: 60, level: 'medium', verdict: 'Medium' },
  HIGH: { min: 61, max: 100, level: 'high', verdict: 'High' }
};

// rules.json has no separate "weight" field, so a SCAM rule's points come
// from its "priority" (priority x factor). Rules whose label is not SCAM add 0.
const SCAM_WEIGHT_FACTOR = 0.7;
// Extra points when a matched SCAM rule also has a "supporting_any" hit.
const SUPPORTING_BONUS = 5;

// Cache for loaded rules (rules.json is fetched only once)
let cachedRules = null;

// Current language ("en" or "hi") and the last result (so we can re-render without re-scanning)
let lang = 'en';
let lastResult = null;

// Text for both languages
const STRINGS = {
  en: {
    pasteFirst: 'Paste a message first',
    couldNotLoad: 'Could not load rules',
    why: 'Why this looks risky',
    none: 'No strong scam signs found.',
    readAloudUnsupported: 'Read Aloud is not supported on this device',
    toggleLabel: 'हिन्दी',
    scoreWord: 'Risk'
  },
  hi: {
    pasteFirst: 'पहले संदेश पेस्ट करें',
    couldNotLoad: 'नियम लोड नहीं हो सके',
    why: 'यह जोखिम भरा क्यों लगता है',
    none: 'ठगी के कोई मजबूत संकेत नहीं मिले।',
    readAloudUnsupported: 'इस डिवाइस पर सुनाने की सुविधा उपलब्ध नहीं है',
    toggleLabel: 'English',
    scoreWord: 'जोखिम'
  }
};

const RISK_LABELS = {
  low: { en: 'Low', hi: 'कम' },
  medium: { en: 'Medium', hi: 'मध्यम' },
  high: { en: 'High', hi: 'ज्यादा' }
};

const ADVICE = {
  high: {
    en: 'Do not click links or share OTP/PIN. Block and report on 1930.',
    hi: 'लिंक पर क्लिक न करें और OTP/PIN किसी को न बताएं। ब्लॉक करें और 1930 पर रिपोर्ट करें।'
  },
  medium: {
    en: 'Be careful. Verify with the official app or number.',
    hi: 'सावधान रहें। आधिकारिक ऐप या नंबर से जाँच करें।'
  },
  low: {
    en: 'No strong scam signs found, but stay careful.',
    hi: 'ठगी के कोई मजबूत संकेत नहीं मिले, फिर भी सावधान रहें।'
  }
};

// ---------------------------------------------------------------------------
// SECTION 2: Small helpers (verdict, escaping, rules loading)
// ---------------------------------------------------------------------------

/**
 * Returns the risk level key ("low" | "medium" | "high") for a score.
 * @param {number} score - 0-100
 * @returns {string}
 */
function getLevel(score) {
  if (score <= RISK_THRESHOLDS.LOW.max) {
    return RISK_THRESHOLDS.LOW.level;
  }
  if (score <= RISK_THRESHOLDS.MEDIUM.max) {
    return RISK_THRESHOLDS.MEDIUM.level;
  }
  return RISK_THRESHOLDS.HIGH.level;
}

/**
 * Determines the English risk verdict label for a score.
 * @param {number} score - The bounded risk score (0-100).
 * @returns {string} The verdict label.
 */
function getVerdict(score) {
  if (score <= RISK_THRESHOLDS.LOW.max) {
    return RISK_THRESHOLDS.LOW.verdict;
  }
  if (score <= RISK_THRESHOLDS.MEDIUM.max) {
    return RISK_THRESHOLDS.MEDIUM.verdict;
  }
  return RISK_THRESHOLDS.HIGH.verdict;
}

/**
 * Escapes text so pasted content can never inject HTML/JS.
 * @param {string} text
 * @returns {string}
 */
function escapeHtml(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Validates the structure of the loaded rules.json object.
 * Expected shape: { rules: [ { id, label, category, priority, match_any, match_all,
 *                              exclude_any, supporting_any, reason, reason_hi? } ], ... }
 * @param {Object} data - Parsed JSON object from rules.json.
 * @throws {Error} If the structure does not match expected format.
 */
function validateRulesData(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new Error('rules.json must be a JSON object.');
  }

  if (!Array.isArray(data.rules) || data.rules.length === 0) {
    throw new Error('rules.json must contain a non-empty "rules" array.');
  }
}

/**
 * Loads the scam detection dictionary from rules.json.
 * Supports caching with optional force reload.
 * @param {boolean} [forceReload=false] - Whether to bypass cached rules.
 * @returns {Promise<Object>} The parsed rules object.
 */
async function loadRules(forceReload = false) {
  if (cachedRules && !forceReload) {
    return cachedRules;
  }

  let response;
  try {
    response = await fetch('rules.json');
  } catch (networkError) {
    throw new Error('Failed to load rules.json. Ensure the file is placed in the correct path and accessible via a web server (avoid file:/// protocol restrictions).');
  }

  if (!response.ok) {
    throw new Error(`Failed to load rules.json: HTTP ${response.status} ${response.statusText}`);
  }

  let data;
  try {
    data = await response.json();
  } catch (jsonError) {
    throw new Error(`Invalid JSON syntax in rules.json: ${jsonError.message}`);
  }

  validateRulesData(data);
  cachedRules = data;
  return cachedRules;
}

// ---------------------------------------------------------------------------
// SECTION 3: Rule matching (rules.json fields: match_any / match_all / exclude_any / supporting_any)
// ---------------------------------------------------------------------------

/**
 * Tests a list of regex pattern strings against text.
 * @param {string[]} patterns - Regex source strings from rules.json.
 * @param {string} text - Message text to test.
 * @param {boolean} requireAll - If true, every pattern must match.
 * @returns {boolean}
 */
function testRegexList(patterns, text, requireAll) {
  if (!Array.isArray(patterns) || patterns.length === 0) {
    return !requireAll;
  }

  const results = patterns.map((source) => {
    if (typeof source !== 'string' || !source) {
      return false;
    }
    try {
      return new RegExp(source, 'i').test(text);
    } catch (regexError) {
      console.error('Scam Detector Error: invalid regex in rules.json:', source, regexError);
      return false;
    }
  });

  return requireAll ? results.every(Boolean) : results.some(Boolean);
}

/**
 * Evaluates one rules.json rule against a message.
 * match_any: at least one regex must match when present.
 * match_all: every regex must match when present.
 * exclude_any: if any regex matches, the rule is skipped.
 * @param {Object} rule
 * @param {string} text
 * @returns {boolean}
 */
function ruleMatches(rule, text) {
  if (!rule || typeof rule !== 'object') {
    return false;
  }

  if (Array.isArray(rule.exclude_any) && rule.exclude_any.length > 0) {
    if (testRegexList(rule.exclude_any, text, false)) {
      return false;
    }
  }

  const hasAny = Array.isArray(rule.match_any) && rule.match_any.length > 0;
  const hasAll = Array.isArray(rule.match_all) && rule.match_all.length > 0;

  if (!hasAny && !hasAll) {
    return false;
  }

  if (hasAny && !testRegexList(rule.match_any, text, false)) {
    return false;
  }

  if (hasAll && !testRegexList(rule.match_all, text, true)) {
    return false;
  }

  return true;
}

/**
 * Finds every match of each regex and records its position (used for highlighting).
 * @param {string[]} patterns
 * @param {string} text
 * @param {Array<{start:number,end:number}>} spans - Output list (appended to).
 */
function collectSpans(patterns, text, spans) {
  if (!Array.isArray(patterns)) {
    return;
  }

  for (const source of patterns) {
    if (typeof source !== 'string' || !source) {
      continue;
    }
    let re;
    try {
      re = new RegExp(source, 'gi');
    } catch (regexError) {
      continue;
    }
    let m;
    let guard = 0;
    while ((m = re.exec(text)) !== null && guard < 200) {
      guard += 1;
      if (m[0].length === 0) {
        re.lastIndex += 1;
        continue;
      }
      spans.push({ start: m.index, end: m.index + m[0].length });
    }
  }
}

/**
 * Sorts spans and merges overlapping ones so highlighting never nests.
 * @param {Array<{start:number,end:number}>} spans
 * @returns {Array<{start:number,end:number}>}
 */
function mergeSpans(spans) {
  const sorted = spans.slice().sort((a, b) => a.start - b.start || a.end - b.end);
  const merged = [];
  for (const s of sorted) {
    const last = merged[merged.length - 1];
    if (last && s.start <= last.end) {
      if (s.end > last.end) {
        last.end = s.end;
      }
    } else {
      merged.push({ start: s.start, end: s.end });
    }
  }
  return merged;
}

// ---------------------------------------------------------------------------
// SECTION 4: Link (URL) checks - text only, links are never fetched or opened
// ---------------------------------------------------------------------------

const SHORTENER_HOSTS = ['bit.ly', 'tinyurl.com', 't.co', 'cutt.ly', 'rb.gy', 'is.gd'];
const SUSPICIOUS_TLDS = ['xyz', 'top', 'click', 'tk', 'ml', 'gq', 'cf', 'icu', 'rest'];
const SUSPICIOUS_PATH_WORDS = /(login|verify|kyc|update|reward)/i;
const TWO_PART_SUFFIXES = ['co.in', 'org.in', 'net.in', 'gov.in', 'ac.in', 'nic.in', 'co.uk', 'com.au'];

// Real domains for the brands we watch. A host that contains the brand name
// but whose main domain is not in this list is treated as a look-alike.
const BRAND_DOMAINS = {
  sbi: ['sbi.co.in', 'onlinesbi.sbi', 'sbi.bank.in', 'sbicard.com', 'sbilife.co.in'],
  hdfc: ['hdfcbank.com', 'hdfc.com', 'hdfclife.com', 'hdfcergo.com', 'hdfcsec.com'],
  icici: ['icicibank.com', 'icicilombard.com', 'iciciprulife.com', 'icicidirect.com'],
  paytm: ['paytm.com', 'paytmbank.com'],
  phonepe: ['phonepe.com'],
  amazon: ['amazon.in', 'amazon.com', 'amazon.co.in'],
  flipkart: ['flipkart.com'],
  jio: ['jio.com', 'jiomart.com', 'jiosaavn.com'],
  airtel: ['airtel.in', 'airtel.com']
};

// Finds http(s) / www links plus bare shortener or risky-ending links
const URL_REGEX = /(?:https?:\/\/|www\.)[^\s<>"']+|\b(?:[a-z0-9-]+\.)+(?:xyz|top|click|tk|ml|gq|cf|icu|rest)\b(?:\/[^\s<>"']*)?|\b(?:bit\.ly|tinyurl\.com|t\.co|cutt\.ly|rb\.gy|is\.gd)\/[^\s<>"']*/gi;

/**
 * Returns the main (registered) domain of a host, e.g. "login.sbi.co.in" -> "sbi.co.in".
 * @param {string} host
 * @returns {string}
 */
function getRegisteredDomain(host) {
  const labels = host.split('.');
  if (labels.length <= 2) {
    return host;
  }
  const lastTwo = labels.slice(-2).join('.');
  if (TWO_PART_SUFFIXES.indexOf(lastTwo) !== -1) {
    return labels.slice(-3).join('.');
  }
  return lastTwo;
}

/**
 * Looks at every link in the message and returns risk findings.
 * Each distinct finding is counted once, even if several links share it.
 * @param {string} text
 * @returns {{reasons: Array<Object>, spans: Array<Object>, points: number}}
 */
function analyzeUrls(text) {
  const found = {};
  const spans = [];
  const re = new RegExp(URL_REGEX.source, 'gi');
  let m;
  let guard = 0;

  while ((m = re.exec(text)) !== null && guard < 50) {
    guard += 1;
    let url = m[0];
    // Drop trailing punctuation that is not part of the link
    const stripped = url.replace(/[.,;:!?)\]]+$/, '');
    if (stripped.length === 0) {
      continue;
    }
    url = stripped;

    const flags = [];

    const schemeMatch = url.match(/^(https?):\/\//i);
    const scheme = schemeMatch ? schemeMatch[1].toLowerCase() : '';
    const rest = schemeMatch ? url.slice(schemeMatch[0].length) : url;
    const authEnd = rest.search(/[\/?#]/);
    const authority = authEnd < 0 ? rest : rest.slice(0, authEnd);
    const pathPart = authEnd < 0 ? '' : rest.slice(authEnd);
    const atInAuthority = authority.indexOf('@') !== -1;
    const hostPart = atInAuthority ? authority.slice(authority.lastIndexOf('@') + 1) : authority;
    const host = hostPart.replace(/:\d+$/, '').toLowerCase().replace(/^www\./, '');
    const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);

    if (SHORTENER_HOSTS.indexOf(host) !== -1) {
      flags.push({
        key: 'short', points: 25,
        en: 'A shortened link hides where it really goes.',
        hi: 'छोटा किया हुआ लिंक असली वेबसाइट छिपा देता है।'
      });
    }
    if (isIp) {
      flags.push({
        key: 'ip', points: 30,
        en: 'The link uses a number address instead of a normal website name.',
        hi: 'लिंक में सामान्य वेबसाइट नाम की जगह नंबर वाला पता है।'
      });
    }
    if (scheme === 'http') {
      flags.push({
        key: 'http', points: 15,
        en: 'The link is not secure (it starts with http, not https).',
        hi: 'लिंक सुरक्षित नहीं है (यह https नहीं, http से शुरू होता है)।'
      });
    }
    const tld = host.split('.').pop();
    if (!isIp && SUSPICIOUS_TLDS.indexOf(tld) !== -1) {
      flags.push({
        key: 'tld', points: 25,
        en: 'The link ends in .' + tld + ', which is often used in scam websites.',
        hi: 'लिंक .' + tld + ' पर खत्म होता है, जो ठगी वाली वेबसाइटों में अक्सर दिखता है।'
      });
    }
    const hyphenCount = (host.match(/-/g) || []).length;
    if (hyphenCount >= 2 || host.length > 30) {
      flags.push({
        key: 'host', points: 15,
        en: 'The website name has many hyphens or is unusually long.',
        hi: 'वेबसाइट के नाम में बहुत सारे हाइफ़न हैं या वह असामान्य रूप से लंबा है।'
      });
    }
    if (url.indexOf('@') !== -1) {
      flags.push({
        key: 'at', points: 25,
        en: 'The link contains an @ sign, a trick used to hide the real website.',
        hi: 'लिंक में @ का निशान है, जिससे असली वेबसाइट छिपाई जाती है।'
      });
    }
    if (!isIp && host) {
      const registered = getRegisteredDomain(host);
      for (const brand of Object.keys(BRAND_DOMAINS)) {
        if (host.indexOf(brand) !== -1 && BRAND_DOMAINS[brand].indexOf(registered) === -1) {
          flags.push({
            key: 'brand-' + brand, points: 35,
            en: 'The link uses the name ' + brand.toUpperCase() + ' but is not the real ' + brand.toUpperCase() + ' website.',
            hi: 'लिंक में ' + brand.toUpperCase() + ' का नाम है, लेकिन यह असली ' + brand.toUpperCase() + ' वेबसाइट नहीं है।'
          });
        }
      }
    }
    if (SUSPICIOUS_PATH_WORDS.test(pathPart)) {
      flags.push({
        key: 'path', points: 10,
        en: 'The link asks for login, verify, KYC, update or reward actions.',
        hi: 'लिंक में लॉगिन, वेरिफाई, KYC, अपडेट या इनाम जैसी बातें हैं।'
      });
    }

    if (flags.length > 0) {
      spans.push({ start: m.index, end: m.index + url.length });
      for (const f of flags) {
        if (!found[f.key]) {
          found[f.key] = f;
        }
      }
    }
  }

  const reasons = [];
  let points = 0;
  for (const key of Object.keys(found)) {
    reasons.push({ en: found[key].en, hi: found[key].hi, points: found[key].points, source: 'url' });
    points += found[key].points;
  }

  return { reasons: reasons, spans: spans, points: points };
}

// ---------------------------------------------------------------------------
// SECTION 5: Scoring (pure function: message + rules in, result out)
// ---------------------------------------------------------------------------

/**
 * Scans a message with the rules and link checks.
 * @param {string} rawMessage
 * @param {Object} rulesData - Parsed rules.json
 * @returns {Object} { rawScore, riskScore, level, verdict, reasons, spans }
 */
function scanMessage(rawMessage, rulesData) {
  // Newlines become spaces (same length) so regexes using "." can cross lines
  // and match positions stay valid for highlighting.
  const matchText = rawMessage.replace(/[\r\n]/g, ' ');
  const spans = [];
  const reasons = [];
  let rawScore = 0;

  const ruleList = Array.isArray(rulesData.rules) ? rulesData.rules.slice() : [];
  ruleList.sort((a, b) => (Number(b.priority) || 0) - (Number(a.priority) || 0));

  for (const rule of ruleList) {
    if (!ruleMatches(rule, matchText)) {
      continue;
    }

    const label = typeof rule.label === 'string' ? rule.label.toUpperCase() : '';
    if (label !== 'SCAM') {
      continue; // genuine / promo / spam rules never add risk
    }

    let points = Math.round((Number(rule.priority) || 0) * SCAM_WEIGHT_FACTOR);
    if (Array.isArray(rule.supporting_any) && rule.supporting_any.length > 0 &&
        testRegexList(rule.supporting_any, matchText, false)) {
      points += SUPPORTING_BONUS;
    }

    collectSpans(rule.match_any, matchText, spans);
    collectSpans(rule.match_all, matchText, spans);
    collectSpans(rule.supporting_any, matchText, spans);

    const english = rule.reason || 'This message matches a known scam pattern.';
    reasons.push({
      en: english,
      hi: rule.reason_hi || english, // fall back to English when no Hindi text yet
      points: points,
      source: 'rule',
      id: rule.id || ''
    });
    rawScore += points;
  }

  // Link checks
  const urlResult = analyzeUrls(matchText);
  for (const r of urlResult.reasons) {
    reasons.push(r);
  }
  for (const s of urlResult.spans) {
    spans.push(s);
  }
  rawScore += urlResult.points;

  const riskScore = Math.min(100, Math.max(0, rawScore));

  return {
    rawScore: rawScore,
    riskScore: riskScore,
    level: getLevel(riskScore),
    verdict: getVerdict(riskScore),
    reasons: reasons,
    spans: mergeSpans(spans)
  };
}

// ---------------------------------------------------------------------------
// SECTION 6: Showing results (gauge, message, reasons, advice)
// ---------------------------------------------------------------------------

/**
 * Writes plain text into resultText whether it is a textarea or a content element.
 * @param {HTMLElement} resultElement
 * @param {string} text
 */
function setResultText(resultElement, text) {
  if (!resultElement) return;

  if (resultElement.tagName && resultElement.tagName.toLowerCase() === 'textarea') {
    resultElement.value = text;
  } else {
    resultElement.textContent = text;
  }
}

/**
 * Updates the gauge: bar width/value, risk-low/medium/high class, and the text "score/100 - Label".
 * Supports a native <progress> element or a track container with an inner fill bar.
 * @param {HTMLElement|null} gaugeElement - The DOM element with id "riskGauge".
 * @param {number} score - The bounded risk score (0-100).
 * @param {string} [level] - "low" | "medium" | "high"
 * @param {string} [labelText] - Text shown inside the gauge.
 */
function updateRiskGauge(gaugeElement, score, level, labelText) {
  if (!gaugeElement) return;

  const boundedScore = Math.max(0, Math.min(100, Math.round(score)));
  const tag = gaugeElement.tagName ? gaugeElement.tagName.toLowerCase() : '';

  if (tag === 'progress') {
    gaugeElement.max = 100;
    gaugeElement.value = boundedScore;
    if (labelText) {
      gaugeElement.textContent = labelText; // fallback text inside <progress>
      gaugeElement.title = labelText;
    }
  } else {
    const isTrackContainer =
      gaugeElement.classList.contains('gauge') ||
      gaugeElement.querySelector('.gauge-ticks, .gauge-scan, .progress-bar, .bar') !== null;

    if (isTrackContainer) {
      let innerBar = gaugeElement.querySelector('.progress-bar, .bar');
      if (!innerBar) {
        innerBar = document.createElement('div');
        innerBar.className = 'progress-bar';
        innerBar.style.position = 'absolute';
        innerBar.style.left = '0';
        innerBar.style.top = '0';
        innerBar.style.bottom = '0';
        innerBar.style.width = '0';
        innerBar.style.borderRadius = 'inherit';
        innerBar.style.background = 'linear-gradient(90deg, #67d4ea, #8f84f0)';
        innerBar.style.transition = 'width 0.3s ease';
        innerBar.style.pointerEvents = 'none';
        gaugeElement.insertBefore(innerBar, gaugeElement.firstChild);
      }

      if (innerBar.tagName && innerBar.tagName.toLowerCase() === 'progress') {
        innerBar.max = 100;
        innerBar.value = boundedScore;
      } else {
        innerBar.style.width = `${boundedScore}%`;
      }
      innerBar.setAttribute('aria-valuenow', String(boundedScore));

      // Text label sits in its own span so the bar is not wiped out
      if (labelText) {
        let labelSpan = gaugeElement.querySelector('.gauge-label');
        if (!labelSpan) {
          labelSpan = document.createElement('span');
          labelSpan.className = 'gauge-label';
          labelSpan.style.position = 'relative';
          labelSpan.style.zIndex = '1';
          gaugeElement.appendChild(labelSpan);
        }
        labelSpan.textContent = labelText;
      }
    } else {
      gaugeElement.style.width = `${boundedScore}%`;
      if (labelText) {
        gaugeElement.textContent = labelText;
      }
    }
  }

  // Colour classes
  gaugeElement.classList.remove('risk-low', 'risk-medium', 'risk-high');
  if (level) {
    gaugeElement.classList.add('risk-' + level);
  }

  gaugeElement.setAttribute('aria-valuenow', String(boundedScore));
  gaugeElement.setAttribute('aria-valuemin', '0');
  gaugeElement.setAttribute('aria-valuemax', '100');
  gaugeElement.setAttribute('aria-valuetext', labelText || `${boundedScore} out of 100`);
}

/**
 * Builds the message as safe HTML: text is escaped first, then flagged parts are wrapped.
 * @param {string} text - Original message
 * @param {Array<{start:number,end:number}>} spans - Merged, sorted positions
 * @returns {string}
 */
function buildHighlightedHtml(text, spans) {
  let html = '';
  let pos = 0;
  for (const s of spans) {
    html += escapeHtml(text.slice(pos, s.start));
    html += '<span class="scam-word">' + escapeHtml(text.slice(s.start, s.end)) + '</span>';
    pos = s.end;
  }
  html += escapeHtml(text.slice(pos));
  return html;
}

/**
 * Draws the last result in the current language (gauge, message, reasons, advice).
 * Does NOT re-scan the message.
 */
function renderResult() {
  if (!lastResult) return;

  const riskGauge = document.getElementById('riskGauge');
  const resultText = document.getElementById('resultText');
  const adviceText = document.getElementById('adviceText');
  const r = lastResult;
  const t = STRINGS[lang];
  const levelLabel = RISK_LABELS[r.level][lang];

  // Gauge: number + label
  updateRiskGauge(riskGauge, r.riskScore, r.level, `${r.riskScore}/100 · ${levelLabel}`);

  // Advice line
  if (adviceText) {
    adviceText.textContent = ADVICE[r.level][lang];
  }

  if (!resultText) return;

  // A textarea cannot show HTML, so fall back to plain text there
  if (resultText.tagName && resultText.tagName.toLowerCase() === 'textarea') {
    const plain = [r.message, '', t.why + ':'];
    if (r.reasons.length === 0) {
      plain.push(t.none);
    } else {
      r.reasons.forEach((x) => plain.push('- ' + x[lang]));
    }
    setResultText(resultText, plain.join('\n'));
    return;
  }

  // Message (escaped, with flagged parts highlighted)
  let html = '<div class="scanned-message" style="white-space:pre-wrap;word-break:break-word;">' +
    buildHighlightedHtml(r.message, r.spans) + '</div>';

  // Why this looks risky
  html += '<div class="why-risky"><strong>' + escapeHtml(t.why) + '</strong>';
  if (r.reasons.length === 0) {
    html += '<p>' + escapeHtml(t.none) + '</p>';
  } else {
    html += '<ul>';
    for (const item of r.reasons) {
      html += '<li>' + escapeHtml(item[lang] || item.en) + '</li>';
    }
    html += '</ul>';
  }
  html += '</div>';

  resultText.innerHTML = html;
}

/**
 * Clears the gauge, advice and result colour for an error or empty state.
 */
function resetOutputs() {
  const riskGauge = document.getElementById('riskGauge');
  const adviceText = document.getElementById('adviceText');
  if (riskGauge) {
    updateRiskGauge(riskGauge, 0, null, '');
  }
  if (adviceText) {
    adviceText.textContent = '';
  }
}

/**
 * Updates the language button text to show the language it will switch to.
 */
function updateToggleLabel() {
  const langToggle = document.getElementById('langToggle');
  if (langToggle) {
    langToggle.textContent = STRINGS[lang].toggleLabel;
  }
}

// ---------------------------------------------------------------------------
// SECTION 7: Main action - Analyze button
// ---------------------------------------------------------------------------

/**
 * Reads the input, scans it, stores the result and shows it.
 * Invoked when the user clicks "Analyze".
 */
async function analyzeMessage() {
  const scamInput = document.getElementById('scamInput');
  const resultText = document.getElementById('resultText');

  if (!scamInput) {
    console.error('Scam Detector Error: Element with id "scamInput" not found in the DOM.');
    if (resultText) {
      setResultText(resultText, 'Configuration Error: Input element with id "scamInput" is missing.');
    }
    return;
  }

  if (!resultText) {
    console.error('Scam Detector Error: Element with id "resultText" not found in the DOM.');
    return;
  }

  const rawMessage = scamInput.value !== undefined ? scamInput.value : (scamInput.textContent || '');

  // Empty input
  if (!rawMessage || rawMessage.trim().length === 0) {
    lastResult = null;
    resetOutputs();
    setResultText(resultText, STRINGS[lang].pasteFirst);
    return;
  }

  // Load rules (only fetched once)
  let rulesData;
  try {
    rulesData = await loadRules();
  } catch (error) {
    console.error('Scam Detector Error:', error);
    lastResult = null;
    resetOutputs();
    setResultText(resultText, STRINGS[lang].couldNotLoad);
    return;
  }

  const result = scanMessage(rawMessage, rulesData);
  result.message = rawMessage;
  lastResult = result;

  renderResult();

  return {
    rawScore: result.rawScore,
    riskScore: result.riskScore,
    verdict: result.verdict,
    reasons: result.reasons
  };
}

// ---------------------------------------------------------------------------
// SECTION 8: Language toggle
// ---------------------------------------------------------------------------

/**
 * Switches between English and Hindi and redraws the last result (no re-scan).
 */
function toggleLanguage() {
  lang = lang === 'en' ? 'hi' : 'en';
  stopSpeaking();
  showReadAloudMessage('');
  updateToggleLabel();
  if (lastResult) {
    renderResult();
  }
}

// ---------------------------------------------------------------------------
// SECTION 9: Read Aloud
// ---------------------------------------------------------------------------

/**
 * Stops any speech in progress (safe if speech is not supported).
 */
function stopSpeaking() {
  if (typeof window !== 'undefined' && window.speechSynthesis) {
    try {
      window.speechSynthesis.cancel();
    } catch (e) {
      // ignore
    }
  }
}

/**
 * Shows (or clears) a small message next to the Read Aloud button.
 * @param {string} text
 */
function showReadAloudMessage(text) {
  const btn = document.getElementById('readAloudBtn');
  if (!btn) return;

  let msg = document.getElementById('readAloudMsg');
  if (!msg) {
    if (!text) return;
    msg = document.createElement('small');
    msg.id = 'readAloudMsg';
    msg.setAttribute('role', 'status');
    msg.style.display = 'block';
    msg.style.marginTop = '4px';
    if (btn.parentNode) {
      btn.parentNode.insertBefore(msg, btn.nextSibling);
    }
  }
  msg.textContent = text;
}

/**
 * Gets the voice list; some browsers load voices a moment after page load.
 * @returns {Promise<SpeechSynthesisVoice[]>}
 */
function getVoicesAsync() {
  return new Promise((resolve) => {
    const synth = window.speechSynthesis;
    const now = synth.getVoices();
    if (now && now.length > 0) {
      resolve(now);
      return;
    }
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      resolve(synth.getVoices() || []);
    };
    try {
      synth.addEventListener('voiceschanged', finish, { once: true });
    } catch (e) {
      // older browsers: rely on the timer below
    }
    setTimeout(finish, 700);
  });
}

/**
 * Picks a voice that matches the current language (Hindi: hi-IN, English: en-IN preferred).
 * @param {SpeechSynthesisVoice[]} voices
 * @returns {SpeechSynthesisVoice|null}
 */
function pickVoice(voices) {
  const exact = lang === 'hi' ? 'hi-in' : 'en-in';
  const prefix = lang === 'hi' ? 'hi' : 'en';
  const norm = (v) => String(v.lang || '').toLowerCase().replace('_', '-');

  let found = voices.find((v) => norm(v) === exact);
  if (!found) {
    found = voices.find((v) => norm(v).indexOf(prefix) === 0);
  }
  return found || null;
}

/**
 * Speaks the advice line plus the top reasons in the current language.
 */
async function readAloud() {
  showReadAloudMessage('');

  if (!lastResult) {
    showReadAloudMessage(STRINGS[lang].pasteFirst);
    return;
  }

  const supported = typeof window !== 'undefined' &&
    window.speechSynthesis && typeof window.SpeechSynthesisUtterance === 'function';
  if (!supported) {
    showReadAloudMessage(STRINGS[lang].readAloudUnsupported);
    return;
  }

  stopSpeaking(); // cancel old speech first

  let voices;
  try {
    voices = await getVoicesAsync();
  } catch (e) {
    voices = [];
  }
  const voice = pickVoice(voices);
  if (!voice) {
    showReadAloudMessage(STRINGS[lang].readAloudUnsupported);
    return;
  }

  const parts = [ADVICE[lastResult.level][lang]];
  lastResult.reasons.slice(0, 3).forEach((x) => {
    const line = x[lang] || x.en;
    parts.push(line);
  });

  try {
    const utterance = new window.SpeechSynthesisUtterance(parts.join(' '));
    utterance.lang = lang === 'hi' ? 'hi-IN' : 'en-IN';
    utterance.voice = voice;
    utterance.rate = 0.95;
    stopSpeaking(); // make sure nothing is still playing
    window.speechSynthesis.speak(utterance);
  } catch (e) {
    showReadAloudMessage(STRINGS[lang].readAloudUnsupported);
  }
}

// ---------------------------------------------------------------------------
// SECTION 10: Page setup (buttons)
// ---------------------------------------------------------------------------

if (typeof window !== 'undefined') {
  window.analyzeMessage = analyzeMessage;
}

if (typeof document !== 'undefined') {
  document.addEventListener('DOMContentLoaded', () => {
    // Fallback highlight style, placed first in <head> so the site's own CSS wins
    if (document.head && !document.getElementById('scamguard-base-styles')) {
      const style = document.createElement('style');
      style.id = 'scamguard-base-styles';
      style.textContent = '.scam-word{color:#d32f2f;background:rgba(211,47,47,.12);border-radius:3px;padding:0 2px;font-weight:600;}';
      document.head.insertBefore(style, document.head.firstChild);
    }

    const analyzeBtn = document.getElementById('analyzeBtn');
    if (analyzeBtn && !analyzeBtn.getAttribute('onclick')) {
      analyzeBtn.addEventListener('click', (event) => {
        event.preventDefault();
        analyzeMessage();
      });
    }

    const langToggle = document.getElementById('langToggle');
    if (langToggle) {
      langToggle.addEventListener('click', (event) => {
        event.preventDefault();
        toggleLanguage();
      });
      updateToggleLabel();
    }

    const readAloudBtn = document.getElementById('readAloudBtn');
    if (readAloudBtn) {
      readAloudBtn.addEventListener('click', (event) => {
        event.preventDefault();
        readAloud();
      });
    }

    // imageUpload: reserved for Level 4 (skipped for now)
  });
}
