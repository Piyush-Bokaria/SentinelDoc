/**
 * SentinelDoc — Frontend Application (v2)
 *
 * Vanilla JS client for the SentinelDoc sensitive data detection &
 * compliance assistant. Communicates with the FastAPI backend via
 * fetch() using relative URLs (same-origin).
 *
 * Screens: Upload → Processing → Results Dashboard
 * Integrates: /upload, /report, /ask, /download-redacted,
 *             /anonymize (configurable strategy), /audit-log
 */

// =============================================================================
// State
// =============================================================================

/** @type {{ docId: string|null, filename: string|null, report: object|null,
 *           uploadData: object|null, chatHistory: Array, isAsking: boolean,
 *           currentStrategy: string, anonymizedText: string|null }} */
const state = {
  docId: null,
  filename: null,
  report: null,
  uploadData: null,
  chatHistory: [],
  isAsking: false,
  currentStrategy: 'replace',    // Active anonymization strategy
  anonymizedText: null,           // Cached anonymized output for download
};

// =============================================================================
// DOM References
// =============================================================================

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

const dom = {
  // Screens
  uploadScreen:     $('#upload-screen'),
  processingScreen: $('#processing-screen'),
  resultsScreen:    $('#results-screen'),

  // Top bar
  topbarDoc:        $('#topbar-doc'),
  topbarFilename:   $('#topbar-filename'),
  newAnalysisBtn:   $('#new-analysis-btn'),

  // Upload
  dropZone:         $('#drop-zone'),
  fileInput:        $('#file-input'),
  filePreview:      $('#file-preview'),
  previewName:      $('#preview-name'),
  previewSize:      $('#preview-size'),
  removeFileBtn:    $('#remove-file-btn'),
  analyzeBtn:       $('#analyze-btn'),
  uploadError:      $('#upload-error'),
  uploadErrorMsg:   $('#upload-error-msg'),

  // Processing
  stages:           $$('.processing-stage'),

  // Results — risk card
  riskCard:         $('#risk-card'),
  riskBadge:        $('#risk-badge'),
  riskScoreNum:     $('#risk-score-num'),
  riskLevelText:    $('#risk-level-text'),
  riskDetailText:   $('#risk-detail-text'),
  breakdownHigh:    $('#breakdown-high'),
  breakdownMedium:  $('#breakdown-medium'),
  breakdownLow:     $('#breakdown-low'),
  downloadBtn:      $('#download-btn'),
  viewReportBtn:    $('#view-report-btn'),

  // Findings
  totalFindings:    $('#total-findings-count'),
  entityGrid:       $('#entity-grid'),
  findingsList:     $('#findings-list'),
  findingsItems:    $('#findings-items'),

  // Summary
  summaryPanels:    $('#summary-panels'),

  // Anonymizer
  anonymizerPreview:    $('#anonymizer-preview'),
  strategySelector:     $('#strategy-selector'),
  anonymizeDownloadBtn: $('#anonymize-download-btn'),

  // Chat
  chatMessages:     $('#chat-messages'),
  chatEmpty:        $('#chat-empty'),
  suggestedQs:      $('#suggested-questions'),
  chatInput:        $('#chat-input'),
  chatSendBtn:      $('#chat-send-btn'),

  // Audit
  auditPanel:       $('#audit-panel'),
  auditToggle:      $('#audit-toggle'),
  auditList:        $('#audit-list'),
};

// =============================================================================
// Utilities
// =============================================================================

/**
 * Format byte sizes into human-readable strings.
 * @param {number} bytes
 * @returns {string}
 */
function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

/**
 * Map risk_level string to a short key for CSS classes.
 * @param {string} riskLevel
 * @returns {'high'|'medium'|'low'}
 */
function riskKey(riskLevel) {
  if (riskLevel.toLowerCase().includes('high')) return 'high';
  if (riskLevel.toLowerCase().includes('medium')) return 'medium';
  return 'low';
}

/**
 * Determine the predominant risk tier for an entity type.
 * @param {string} entityType
 * @param {Array} findings
 * @returns {'high'|'medium'|'low'}
 */
function entityTier(entityType, findings) {
  if (!findings) return 'low';
  const tiers = findings
    .filter(f => f.entity_type === entityType)
    .map(f => f.risk_tier);
  if (tiers.includes('high')) return 'high';
  if (tiers.includes('medium')) return 'medium';
  return 'low';
}

/**
 * Lightweight markdown parser for the compliance summary.
 * Handles: ## headers, **bold**, *italic*, `code`, bullet lists, paragraphs.
 * @param {string} md
 * @returns {string} HTML string
 */
function parseMarkdown(md) {
  if (!md) return '';
  const lines = md.split('\n');
  let html = '';
  let inList = false;

  for (let i = 0; i < lines.length; i++) {
    let line = lines[i];

    // Close list if current line isn't a bullet
    if (inList && !/^\s*[-*•]\s/.test(line)) {
      html += '</ul>';
      inList = false;
    }

    if (line.trim() === '') continue;

    // Headers
    if (/^###\s+/.test(line)) {
      html += `<h4>${escapeHtml(line.replace(/^###\s+/, ''))}</h4>`;
      continue;
    }
    if (/^##\s+/.test(line)) {
      continue; // Section splitting handled separately
    }

    // Bullet points
    if (/^\s*[-*•]\s/.test(line)) {
      if (!inList) { html += '<ul>'; inList = true; }
      const content = line.replace(/^\s*[-*•]\s+/, '');
      html += `<li>${inlineFormat(content)}</li>`;
      continue;
    }

    html += `<p>${inlineFormat(line)}</p>`;
  }

  if (inList) html += '</ul>';
  return html;
}

/**
 * Apply inline markdown formatting: bold, italic, code.
 * @param {string} text
 * @returns {string}
 */
function inlineFormat(text) {
  let s = escapeHtml(text);
  s = s.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  s = s.replace(/\*(.+?)\*/g, '<em>$1</em>');
  s = s.replace(/`(.+?)`/g, '<code>$1</code>');
  return s;
}

/**
 * Escape HTML special characters.
 * @param {string} str
 * @returns {string}
 */
function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

/**
 * Format ISO timestamp to a readable local time string.
 * @param {string} iso
 * @returns {string}
 */
function formatTime(iso) {
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
      + ' ' + d.toLocaleDateString([], { month: 'short', day: 'numeric' });
  } catch {
    return iso;
  }
}

/**
 * Map audit action codes to human-readable labels.
 * @param {string} action
 * @returns {string}
 */
function actionLabel(action) {
  const map = {
    upload:            'Document uploaded',
    detect:            'Sensitive data detected',
    summarize:         'Compliance summary generated',
    ask:               'Question asked',
    view_report:       'Report viewed',
    download_redacted: 'Redacted document downloaded',
    anonymize:         'Document anonymized',
  };
  return map[action] || action;
}

// =============================================================================
// Screen Management
// =============================================================================

/**
 * Switch the visible screen.
 * @param {'upload'|'processing'|'results'} screen
 */
function showScreen(screen) {
  dom.uploadScreen.style.display = screen === 'upload' ? '' : 'none';
  dom.processingScreen.classList.toggle('visible', screen === 'processing');
  dom.resultsScreen.classList.toggle('visible', screen === 'results');

  const hasDoc = screen === 'results';
  dom.topbarDoc.classList.toggle('hidden', !hasDoc);
  dom.newAnalysisBtn.classList.toggle('hidden', !hasDoc);
}

// =============================================================================
// Upload Flow
// =============================================================================

/** @type {File|null} */
let selectedFile = null;

const ALLOWED_EXTENSIONS = ['.pdf', '.txt', '.csv'];

/**
 * Validate and display a selected file.
 * @param {File} file
 */
function selectFile(file) {
  hideError();

  const ext = '.' + file.name.split('.').pop().toLowerCase();
  if (!ALLOWED_EXTENSIONS.includes(ext)) {
    showError(`Unsupported file type "${ext}". Please upload a PDF, TXT, or CSV file.`);
    return;
  }

  selectedFile = file;
  dom.previewName.textContent = file.name;
  dom.previewSize.textContent = formatBytes(file.size);
  dom.filePreview.classList.add('visible');
  dom.analyzeBtn.classList.add('visible');
}

/** Clear the selected file and reset the upload form. */
function clearFile() {
  selectedFile = null;
  dom.fileInput.value = '';
  dom.filePreview.classList.remove('visible');
  dom.analyzeBtn.classList.remove('visible');
  hideError();
}

/**
 * Show an error message below the upload zone.
 * @param {string} message
 */
function showError(message) {
  dom.uploadErrorMsg.textContent = message;
  dom.uploadError.classList.add('visible');
}

/** Hide the upload error. */
function hideError() {
  dom.uploadError.classList.remove('visible');
}

// -- Event listeners --

dom.fileInput.addEventListener('change', (e) => {
  if (e.target.files.length > 0) selectFile(e.target.files[0]);
});

dom.dropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dom.dropZone.classList.add('drop-zone--dragover');
});
dom.dropZone.addEventListener('dragleave', () => {
  dom.dropZone.classList.remove('drop-zone--dragover');
});
dom.dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dom.dropZone.classList.remove('drop-zone--dragover');
  if (e.dataTransfer.files.length > 0) selectFile(e.dataTransfer.files[0]);
});

dom.removeFileBtn.addEventListener('click', (e) => {
  e.stopPropagation();
  clearFile();
});

dom.analyzeBtn.addEventListener('click', () => {
  if (selectedFile) uploadFile(selectedFile);
});

dom.newAnalysisBtn.addEventListener('click', resetToUpload);

// =============================================================================
// Upload & Processing
// =============================================================================

const STAGE_IDS = ['stage-extract', 'stage-detect', 'stage-risk', 'stage-summary'];
let stageTimer = null;

/**
 * Advance the processing stages visually.
 * @param {number} index
 */
function advanceStage(index) {
  STAGE_IDS.forEach((id, i) => {
    const el = document.getElementById(id);
    el.classList.remove('active', 'done');
    if (i < index)  el.classList.add('done');
    if (i === index) el.classList.add('active');
  });
}

/** Reset all processing stages. */
function resetStages() {
  STAGE_IDS.forEach(id => {
    document.getElementById(id).classList.remove('active', 'done');
  });
}

/**
 * Upload the file and handle the full pipeline.
 * @param {File} file
 */
async function uploadFile(file) {
  hideError();
  dom.analyzeBtn.disabled = true;

  resetStages();
  showScreen('processing');

  // Staged animation — one step every ~1.5s
  let currentStage = 0;
  advanceStage(currentStage);
  stageTimer = setInterval(() => {
    currentStage++;
    if (currentStage < STAGE_IDS.length) {
      advanceStage(currentStage);
    } else {
      clearInterval(stageTimer);
    }
  }, 1500);

  const formData = new FormData();
  formData.append('file', file);

  try {
    const res = await fetch('/upload', {
      method: 'POST',
      body: formData,
    });

    // Mark all stages done
    clearInterval(stageTimer);
    STAGE_IDS.forEach(id => {
      const el = document.getElementById(id);
      el.classList.remove('active');
      el.classList.add('done');
    });

    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      const msg = errBody.detail || `Upload failed with status ${res.status}`;
      throw new Error(msg);
    }

    const data = await res.json();
    state.docId = data.doc_id;
    state.filename = data.filename;
    state.uploadData = data;
    state.chatHistory = [];
    state.anonymizedText = null;

    // Brief pause so user sees completion
    await new Promise(r => setTimeout(r, 600));

    // Fetch detailed report
    await fetchReport(data.doc_id);

    // Render dashboard
    renderResults(data);
    showScreen('results');
    fetchAuditLog();

    // Auto-load the default anonymization strategy
    fetchAnonymized('replace');

  } catch (err) {
    clearInterval(stageTimer);
    resetStages();
    showScreen('upload');
    showError(err.message || 'An unexpected error occurred during analysis.');
    dom.analyzeBtn.disabled = false;
  }
}

/**
 * Fetch the detailed report from the backend.
 * @param {string} docId
 */
async function fetchReport(docId) {
  try {
    const res = await fetch(`/report/${docId}`);
    if (res.ok) state.report = await res.json();
  } catch {
    // Non-critical
  }
}

// =============================================================================
// Results Rendering
// =============================================================================

/**
 * Render the full results dashboard.
 * @param {object} data - Upload response from POST /upload
 */
function renderResults(data) {
  const key = riskKey(data.risk_level);

  // Top bar
  dom.topbarFilename.textContent = data.filename;

  // Risk card — add modifier class for the left accent strip + glow
  dom.riskCard.className = `risk-card risk-card--${key}`;
  dom.riskBadge.className = `risk-badge risk-badge--${key}`;
  dom.riskScoreNum.textContent = data.risk_score;
  dom.riskLevelText.className = `risk-level risk-level--${key}`;
  dom.riskLevelText.textContent = data.risk_level;

  const total = data.total_findings;
  const types = Object.keys(data.counts_by_type).length;
  dom.riskDetailText.textContent =
    `${total} sensitive ${total === 1 ? 'finding' : 'findings'} detected across ${types} entity ${types === 1 ? 'type' : 'types'} in "${data.filename}"`;

  dom.breakdownHigh.textContent = data.risk_breakdown.high_risk_findings;
  dom.breakdownMedium.textContent = data.risk_breakdown.medium_risk_findings;
  dom.breakdownLow.textContent = data.risk_breakdown.low_risk_findings;

  // Findings grid
  dom.totalFindings.textContent = `${total} total`;
  renderEntityGrid(data.counts_by_type);

  // Findings detail list
  if (state.report && state.report.findings) {
    renderFindingsList(state.report.findings);
  }

  // AI Summary
  renderSummary(data.summary);

  // Reset anonymizer
  resetAnonymizerUI();

  // Chat reset
  dom.chatMessages.innerHTML = '';
  dom.chatMessages.appendChild(dom.chatEmpty);
  dom.chatEmpty.style.display = '';
  dom.chatInput.value = '';
  dom.chatSendBtn.disabled = true;
  dom.suggestedQs.style.display = '';

  dom.analyzeBtn.disabled = false;
}

/**
 * Render entity type stat cards.
 * @param {Object<string, number>} countsByType
 */
function renderEntityGrid(countsByType) {
  const findings = state.report ? state.report.findings : [];
  dom.entityGrid.innerHTML = '';

  const entries = Object.entries(countsByType).sort((a, b) => b[1] - a[1]);

  for (const [type, count] of entries) {
    const tier = entityTier(type, findings);
    const card = document.createElement('div');
    card.className = 'entity-card';
    card.innerHTML = `
      <div class="entity-card__indicator entity-card__indicator--${tier}"></div>
      <div class="entity-card__info">
        <div class="entity-card__type" title="${escapeHtml(type)}">${escapeHtml(type)}</div>
        <div class="entity-card__count">${count}</div>
      </div>
    `;
    dom.entityGrid.appendChild(card);
  }
}

/**
 * Render individual findings in a scrollable list.
 * @param {Array} findings
 */
function renderFindingsList(findings) {
  dom.findingsList.classList.remove('hidden');
  dom.findingsItems.innerHTML = '';

  for (const f of findings) {
    const row = document.createElement('div');
    row.className = 'finding-row';
    row.innerHTML = `
      <span class="finding-row__type" title="${escapeHtml(f.entity_type)}">${escapeHtml(f.entity_type)}</span>
      <span class="finding-row__tier finding-row__tier--${f.risk_tier}">${f.risk_tier}</span>
      <span class="finding-row__confidence">${(f.confidence * 100).toFixed(0)}%</span>
      <span class="finding-row__masked" title="${escapeHtml(f.masked_value)}">${escapeHtml(f.masked_value)}</span>
    `;
    dom.findingsItems.appendChild(row);
  }
}

/**
 * Parse and render the markdown summary into visual panels.
 * @param {string} summaryMd
 */
function renderSummary(summaryMd) {
  dom.summaryPanels.innerHTML = '';

  if (!summaryMd) {
    dom.summaryPanels.innerHTML = '<p style="color:var(--text-tertiary)">No summary available.</p>';
    return;
  }

  // Split by ## headers
  const sections = [];
  const lines = summaryMd.split('\n');
  let currentSection = null;

  for (const line of lines) {
    const headerMatch = line.match(/^##\s+(.+)/);
    if (headerMatch) {
      if (currentSection) sections.push(currentSection);
      currentSection = { title: headerMatch[1].trim(), body: '' };
    } else if (currentSection) {
      currentSection.body += line + '\n';
    }
  }
  if (currentSection) sections.push(currentSection);

  if (sections.length === 0) {
    sections.push({ title: 'Summary', body: summaryMd });
  }

  const iconMap = {
    'compliance observations': { class: 'observations', icon: clipboardIcon() },
    'security risks':          { class: 'risks',        icon: alertIcon() },
    'suggested remediation steps': { class: 'remediation', icon: checkCircleIcon() },
  };

  for (const section of sections) {
    const key = section.title.toLowerCase();
    const meta = iconMap[key] || { class: 'observations', icon: clipboardIcon() };

    const panel = document.createElement('div');
    panel.className = 'summary-panel';
    panel.innerHTML = `
      <div class="summary-panel__icon summary-panel__icon--${meta.class}">
        ${meta.icon}
      </div>
      <h3 class="summary-panel__title">${escapeHtml(section.title)}</h3>
      <div class="summary-panel__content">${parseMarkdown(section.body)}</div>
    `;
    dom.summaryPanels.appendChild(panel);
  }
}

// -- SVG icon helpers --

function clipboardIcon() {
  return `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/>
    <rect x="8" y="2" width="8" height="4" rx="1" ry="1"/>
  </svg>`;
}

function alertIcon() {
  return `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
    <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
  </svg>`;
}

function checkCircleIcon() {
  return `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
    <polyline points="22 4 12 14.01 9 11.01"/>
  </svg>`;
}

// =============================================================================
// Anonymizer — /anonymize/{doc_id}?strategy=
// =============================================================================

/**
 * Reset the anonymizer UI to initial state.
 */
function resetAnonymizerUI() {
  state.currentStrategy = 'replace';
  state.anonymizedText = null;
  dom.anonymizeDownloadBtn.disabled = true;

  // Reset strategy buttons
  dom.strategySelector.querySelectorAll('.strategy-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.strategy === 'replace');
  });
}

// Strategy button clicks
dom.strategySelector.addEventListener('click', (e) => {
  const btn = e.target.closest('.strategy-btn');
  if (!btn || !state.docId) return;

  const strategy = btn.dataset.strategy;
  state.currentStrategy = strategy;

  // Update active state
  dom.strategySelector.querySelectorAll('.strategy-btn').forEach(b => {
    b.classList.toggle('active', b === btn);
  });

  // Fetch anonymized text for this strategy
  fetchAnonymized(strategy);
});

/**
 * Fetch anonymized text from the backend for a given strategy.
 * @param {string} strategy - 'replace' | 'mask' | 'hash' | 'redact'
 */
async function fetchAnonymized(strategy) {
  if (!state.docId) return;

  // Show loading state
  dom.anonymizerPreview.innerHTML = `
    <div class="anonymizer-preview--loading">
      <div class="stage-spinner" style="display:block"></div>
      <span>Applying ${escapeHtml(strategy)} strategy…</span>
    </div>
  `;
  dom.anonymizerPreview.classList.remove('anonymizer-preview--error');
  dom.anonymizeDownloadBtn.disabled = true;

  try {
    const res = await fetch(`/anonymize/${state.docId}?strategy=${strategy}`);

    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      throw new Error(errBody.detail || `Anonymization failed (${res.status})`);
    }

    const text = await res.text();
    state.anonymizedText = text;

    // Render the anonymized text (plain text, monospace, preserving whitespace)
    dom.anonymizerPreview.textContent = text;
    dom.anonymizeDownloadBtn.disabled = false;

    // Refresh audit log to show anonymize action
    fetchAuditLog();

  } catch (err) {
    dom.anonymizerPreview.innerHTML = `
      <span style="color:var(--risk-high)">${escapeHtml(err.message)}</span>
    `;
    state.anonymizedText = null;
    dom.anonymizeDownloadBtn.disabled = true;
  }
}

// Download anonymized document
dom.anonymizeDownloadBtn.addEventListener('click', () => {
  if (!state.anonymizedText || !state.filename) return;

  const blob = new Blob([state.anonymizedText], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);

  const a = document.createElement('a');
  a.href = url;
  const baseName = state.filename.replace(/\.[^.]+$/, '');
  a.download = `${baseName}_anonymized_${state.currentStrategy}.txt`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
});

// =============================================================================
// Download Redacted Document
// =============================================================================

dom.downloadBtn.addEventListener('click', async () => {
  if (!state.docId) return;

  try {
    const res = await fetch(`/download-redacted/${state.docId}`);
    if (!res.ok) throw new Error('Download failed');

    const text = await res.text();
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    const baseName = state.filename.replace(/\.[^.]+$/, '');
    a.download = `${baseName}_redacted.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    fetchAuditLog();
  } catch (err) {
    console.error('Download error:', err);
  }
});

// =============================================================================
// View Full Report (toggles detail list)
// =============================================================================

dom.viewReportBtn.addEventListener('click', async () => {
  if (!dom.findingsList.classList.contains('hidden')) {
    dom.findingsList.classList.add('hidden');
    return;
  }

  if (!state.report && state.docId) {
    await fetchReport(state.docId);
    if (state.report) renderFindingsList(state.report.findings);
  }

  dom.findingsList.classList.remove('hidden');
  dom.findingsList.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  fetchAuditLog();
});

// =============================================================================
// Chat / Q&A
// =============================================================================

dom.chatInput.addEventListener('input', () => {
  dom.chatSendBtn.disabled = dom.chatInput.value.trim() === '' || state.isAsking;
});

dom.chatInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    if (!dom.chatSendBtn.disabled) sendQuestion();
  }
});

dom.chatSendBtn.addEventListener('click', sendQuestion);

dom.suggestedQs.addEventListener('click', (e) => {
  const chip = e.target.closest('.suggested-q');
  if (chip) {
    dom.chatInput.value = chip.dataset.q;
    dom.chatSendBtn.disabled = false;
    sendQuestion();
  }
});

/**
 * Send a question to the Q&A endpoint.
 */
async function sendQuestion() {
  const question = dom.chatInput.value.trim();
  if (!question || !state.docId || state.isAsking) return;

  state.isAsking = true;
  dom.chatSendBtn.disabled = true;

  dom.chatEmpty.style.display = 'none';
  dom.suggestedQs.style.display = 'none';

  appendChatMessage('user', question);
  dom.chatInput.value = '';

  const loadingEl = appendChatLoading();

  try {
    const res = await fetch('/ask', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ doc_id: state.docId, question }),
    });

    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      throw new Error(errBody.detail || 'Failed to get answer');
    }

    const data = await res.json();
    loadingEl.remove();
    appendChatMessage('assistant', data.answer);

    fetchAuditLog();
  } catch (err) {
    loadingEl.remove();
    appendChatMessage('assistant', `Sorry, something went wrong: ${err.message}`);
  } finally {
    state.isAsking = false;
    dom.chatSendBtn.disabled = dom.chatInput.value.trim() === '';
  }
}

/**
 * Append a chat message.
 * @param {'user'|'assistant'} role
 * @param {string} text
 */
function appendChatMessage(role, text) {
  state.chatHistory.push({ role, text });

  const msgEl = document.createElement('div');
  msgEl.className = `chat-msg chat-msg--${role}`;

  const avatarLabel = role === 'user' ? 'You' : 'AI';
  const bubbleContent = role === 'assistant' ? parseMarkdown(text) : escapeHtml(text);

  msgEl.innerHTML = `
    <div class="chat-msg__avatar">${avatarLabel}</div>
    <div class="chat-msg__bubble">${bubbleContent}</div>
  `;

  dom.chatMessages.appendChild(msgEl);
  dom.chatMessages.scrollTop = dom.chatMessages.scrollHeight;
}

/**
 * Append a loading indicator.
 * @returns {HTMLElement}
 */
function appendChatLoading() {
  const msgEl = document.createElement('div');
  msgEl.className = 'chat-msg chat-msg--assistant';
  msgEl.innerHTML = `
    <div class="chat-msg__avatar">AI</div>
    <div class="chat-msg__bubble">
      <div class="chat-loading">
        <div class="chat-loading__dot"></div>
        <div class="chat-loading__dot"></div>
        <div class="chat-loading__dot"></div>
      </div>
    </div>
  `;
  dom.chatMessages.appendChild(msgEl);
  dom.chatMessages.scrollTop = dom.chatMessages.scrollHeight;
  return msgEl;
}

// =============================================================================
// Audit Log
// =============================================================================

dom.auditToggle.addEventListener('click', () => {
  dom.auditPanel.classList.toggle('open');
  if (dom.auditPanel.classList.contains('open')) {
    fetchAuditLog();
  }
});

/**
 * Fetch and render the audit log for the current document.
 */
async function fetchAuditLog() {
  if (!state.docId) return;

  try {
    const res = await fetch(`/audit-log?doc_id=${state.docId}`);
    if (!res.ok) return;
    const entries = await res.json();
    renderAuditLog(entries);
  } catch {
    // Silent failure
  }
}

/**
 * Render audit log entries.
 * @param {Array} entries
 */
function renderAuditLog(entries) {
  dom.auditList.innerHTML = '';

  if (entries.length === 0) {
    dom.auditList.innerHTML = '<div class="audit-empty">No activity recorded yet.</div>';
    return;
  }

  for (const entry of entries) {
    const el = document.createElement('div');
    el.className = 'audit-entry';
    el.innerHTML = `
      <div class="audit-entry__dot"></div>
      <div class="audit-entry__content">
        <div class="audit-entry__action">${escapeHtml(actionLabel(entry.action))}</div>
        ${entry.detail ? `<div class="audit-entry__detail">${escapeHtml(entry.detail)}</div>` : ''}
      </div>
      <div class="audit-entry__time">${formatTime(entry.timestamp)}</div>
    `;
    dom.auditList.appendChild(el);
  }
}

// =============================================================================
// Reset to Upload
// =============================================================================

/** Reset the entire app to the upload screen. */
function resetToUpload() {
  state.docId = null;
  state.filename = null;
  state.report = null;
  state.uploadData = null;
  state.chatHistory = [];
  state.isAsking = false;
  state.anonymizedText = null;
  state.currentStrategy = 'replace';

  clearFile();
  resetStages();
  showScreen('upload');

  // Chat
  dom.chatMessages.innerHTML = '';
  dom.chatMessages.appendChild(dom.chatEmpty);
  dom.chatEmpty.style.display = '';
  dom.suggestedQs.style.display = '';

  // Audit
  dom.auditPanel.classList.remove('open');
  dom.auditList.innerHTML = '';

  // Findings
  dom.findingsList.classList.add('hidden');
  dom.findingsItems.innerHTML = '';

  // Anonymizer
  resetAnonymizerUI();
  dom.anonymizerPreview.innerHTML =
    '<span style="color:var(--text-tertiary)">Select a strategy above to preview the anonymized document.</span>';
}

// =============================================================================
// Initialization
// =============================================================================

showScreen('upload');
