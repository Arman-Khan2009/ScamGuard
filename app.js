/**
 * Indian Cyber Fraud & Scam Detection Engine - Rules Engineer
 * app.js - Complete Vanilla JavaScript Implementation
 *
 * Deliverable for Task 2: The Rules Engineer.
 * Implements message normalization, dictionary matching, risk scoring,
 * dual-mode risk gauge updates, and secure DOM output rendering.
 */

// Configurable Risk Verdict Thresholds (easy to modify)
const RISK_THRESHOLDS = {
  LOW: { min: 0, max: 29, verdict: 'LOW RISK' },
  MEDIUM: { min: 30, max: 59, verdict: 'MEDIUM RISK' },
  HIGH: { min: 60, max: 100, verdict: 'HIGH RISK' }
};

// Cache for loaded rules to optimize performance across multiple analyses
let cachedRules = null;

/**
 * Determines the risk verdict based on the calculated risk score.
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
 * Validates the structure of the loaded rules.json object.
 * Expected shape: { rules: [ { id, label, category, priority, match_any, match_all, exclude_any, reason } ] }
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
 * Writes text into resultText whether it is a textarea or a content element.
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
 * Updates the progress element or div-based gauge safely.
 * Supports both:
 * 1. Native HTML <progress> element (max=100, value=score).
 * 2. Track container (#riskGauge.gauge) with an inner fill bar.
 * @param {HTMLElement|null} gaugeElement - The DOM element with id "riskGauge".
 * @param {number} score - The bounded risk score (0-100).
 */
function updateRiskGauge(gaugeElement, score) {
  if (!gaugeElement) return;

  const boundedScore = Math.max(0, Math.min(100, Math.round(score)));
  const tag = gaugeElement.tagName ? gaugeElement.tagName.toLowerCase() : '';

  if (tag === 'progress') {
    gaugeElement.max = 100;
    gaugeElement.value = boundedScore;
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
    } else {
      gaugeElement.style.width = `${boundedScore}%`;
    }
  }

  gaugeElement.setAttribute('aria-valuenow', String(boundedScore));
  gaugeElement.setAttribute('aria-valuemin', '0');
  gaugeElement.setAttribute('aria-valuemax', '100');
  gaugeElement.setAttribute('aria-valuetext', `${boundedScore} out of 100`);
}

/**
 * Safely renders the analysis results into the resultText element.
 * Uses .value for textarea and textContent otherwise (no innerHTML).
 * @param {HTMLElement} resultElement - The DOM element with id "resultText".
 * @param {number} score - The bounded risk score.
 * @param {string} verdict - The verdict string.
 * @param {Array<Object>} matchedIndicators - Array of matched rule indicator objects.
 */
function displayResult(resultElement, score, verdict, matchedIndicators) {
  if (!resultElement) return;

  if (resultElement.style) {
    resultElement.style.whiteSpace = 'pre-line';
  }

  const lines = [
    `Risk Score: ${score}/100`,
    '',
    `Verdict: ${verdict}`,
    '',
    'Matched Indicators:'
  ];

  if (matchedIndicators.length > 0) {
    for (const item of matchedIndicators) {
      const detail = item.reason ? ` — ${item.reason}` : ` — ${item.points} points`;
      lines.push(`- ${item.category}: "${item.phrase}"${detail}`);
    }
  } else {
    lines.push('None (No scam indicators matched).');
  }

  setResultText(resultElement, lines.join('\n'));
}

/**
 * Main application function: Reads input, normalizes, executes dictionary matching,
 * computes score, updates gauge, and renders verdict.
 * Invoked when the user triggers the "Analyze" action.
 */
async function analyzeMessage() {
  const scamInput = document.getElementById('scamInput');
  const riskGauge = document.getElementById('riskGauge');
  const resultText = document.getElementById('resultText');
  const imageUpload = document.getElementById('imageUpload');

  if (imageUpload) {
    // Reserved for future OCR; present so the required ID is wired.
  }

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

  if (!rawMessage || rawMessage.trim().length === 0) {
    setResultText(resultText, 'Please enter a message to analyze.');
    if (riskGauge) {
      updateRiskGauge(riskGauge, 0);
    }
    return;
  }

  const normalizedMessage = rawMessage.toLowerCase();

  let rulesData;
  try {
    rulesData = await loadRules();
  } catch (error) {
    console.error('Scam Detector Error:', error);
    setResultText(resultText, `Error loading rules: ${error.message}`);
    if (riskGauge) {
      updateRiskGauge(riskGauge, 0);
    }
    return;
  }

  const matchedIndicators = [];
  let rawScore = 0;
  const ruleList = Array.isArray(rulesData.rules) ? rulesData.rules.slice() : [];

  ruleList.sort((a, b) => (Number(b.priority) || 0) - (Number(a.priority) || 0));

  for (const rule of ruleList) {
    if (!ruleMatches(rule, normalizedMessage)) {
      continue;
    }

    const label = typeof rule.label === 'string' ? rule.label.toUpperCase() : '';
    const points = label === 'SCAM' ? (Number(rule.priority) || 0) : 0;

    matchedIndicators.push({
      category: rule.category || label || 'unknown',
      phrase: rule.id || rule.category || 'matched rule',
      points: points,
      reason: rule.reason || ''
    });

    rawScore += points;
  }

  const riskScore = matchedIndicators.length === 0 ? 0 : Math.min(100, Math.max(0, rawScore));
  const verdict = getVerdict(riskScore);

  if (riskGauge) {
    updateRiskGauge(riskGauge, riskScore);
  }

  displayResult(resultText, riskScore, verdict, matchedIndicators);

  return {
    rawScore: rawScore,
    riskScore: riskScore,
    verdict: verdict,
    matchedIndicators: matchedIndicators
  };
}

if (typeof window !== 'undefined') {
  window.analyzeMessage = analyzeMessage;
}

if (typeof document !== 'undefined') {
  document.addEventListener('DOMContentLoaded', () => {
    const analyzeBtn = document.getElementById('analyzeBtn');

    if (analyzeBtn && !analyzeBtn.getAttribute('onclick')) {
      analyzeBtn.addEventListener('click', (event) => {
        event.preventDefault();
        analyzeMessage();
      });
    }
  });
}