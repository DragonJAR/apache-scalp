"""Modern, responsive, 100% self-contained (Zero-CDN) HTML5 reporter for Scalp."""
from collections import Counter
from datetime import datetime
import html
import json
import time
from typing import Any, Dict, List, Optional, Tuple
from scalp.core.engine import ScanResult
from scalp.core.rules import ATTACK_NAMES
from scalp.reporters.base import BaseReporter

# -----------------------------------------------------------------------------
# Zero-CDN Inline CSS Styles (Dark Security Aesthetic)
# -----------------------------------------------------------------------------
CSS_STYLES = """
:root {
  --bg-base: #0a0e17;
  --bg-card: #111827;
  --bg-card-hover: #162032;
  --bg-header: #0d1321;
  --bg-surface: #1f2937;
  --bg-surface-2: #374151;
  --border: #1f2937;
  --border-light: #2d3748;
  --border-focus: #06b6d4;
  --text-main: #f9fafb;
  --text-muted: #9ca3af;
  --text-dim: #6b7280;
  --accent: #06b6d4;
  --accent-glow: rgba(6, 182, 212, 0.25);
  --danger: #f43f5e;
  --danger-bg: rgba(244, 63, 94, 0.12);
  --danger-border: rgba(244, 63, 94, 0.35);
  --warning: #f59e0b;
  --warning-bg: rgba(245, 158, 11, 0.12);
  --warning-border: rgba(245, 158, 11, 0.35);
  --success: #10b981;
  --success-bg: rgba(16, 185, 129, 0.12);
  --success-border: rgba(16, 185, 129, 0.35);
  --info: #38bdf8;
  --info-bg: rgba(56, 189, 248, 0.12);
  --purple: #818cf8;
  --purple-bg: rgba(129, 140, 248, 0.12);
  --code-bg: #030712;
  --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
  --radius-sm: 4px;
  --radius-md: 8px;
  --radius-lg: 12px;
  --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.5), 0 2px 4px -2px rgba(0, 0, 0, 0.5);
}

*, *::before, *::after {
  box-sizing: border-box;
}

html, body {
  margin: 0;
  padding: 0;
  background-color: var(--bg-base);
  color: var(--text-main);
  font-family: var(--font-sans);
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}

.container {
  max-width: 1440px;
  margin: 0 auto;
  padding: 24px 20px 48px;
}

/* Header & Banner */
.app-header {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: 24px;
  margin-bottom: 24px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 16px;
  box-shadow: var(--shadow);
}

.brand-wrapper {
  display: flex;
  align-items: center;
  gap: 16px;
}

.brand-icon {
  width: 48px;
  height: 48px;
  background: var(--accent-glow);
  border: 1px solid var(--accent);
  border-radius: var(--radius-md);
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--accent);
}

.brand-title h1 {
  margin: 0 0 4px 0;
  font-size: 1.6rem;
  font-weight: 800;
  letter-spacing: -0.5px;
  color: var(--text-main);
}

.brand-title h1 span.accent {
  color: var(--accent);
}

.brand-meta {
  color: var(--text-muted);
  font-size: 0.875rem;
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  align-items: center;
}

.header-status-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 6px 14px;
  border-radius: 9999px;
  font-size: 0.8rem;
  font-weight: 700;
  letter-spacing: 0.5px;
  text-transform: uppercase;
}

/* KPI Cards */
.kpi-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
}

.kpi-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: 18px 20px;
  position: relative;
  overflow: hidden;
  box-shadow: var(--shadow);
  transition: transform 0.15s ease, border-color 0.15s ease;
}

.kpi-card:hover {
  transform: translateY(-2px);
  border-color: var(--border-light);
}

.kpi-card::before {
  content: "";
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 3px;
  background: var(--accent);
}

.kpi-card.card-danger::before { background: var(--danger); }
.kpi-card.card-warning::before { background: var(--warning); }
.kpi-card.card-success::before { background: var(--success); }
.kpi-card.card-purple::before { background: var(--purple); }

.kpi-val {
  font-size: 2rem;
  font-weight: 800;
  line-height: 1.1;
  margin-bottom: 6px;
  color: var(--text-main);
  font-feature-settings: "tnum";
}

.kpi-label {
  font-size: 0.8rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.75px;
  color: var(--text-muted);
  margin-bottom: 4px;
}

.kpi-sub {
  font-size: 0.775rem;
  color: var(--text-dim);
}

/* Panels */
.panel {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  margin-bottom: 24px;
  overflow: hidden;
  box-shadow: var(--shadow);
}

.panel-header {
  padding: 16px 20px;
  background: var(--bg-header);
  border-bottom: 1px solid var(--border);
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 12px;
}

.panel-title {
  display: flex;
  align-items: center;
  gap: 10px;
  margin: 0;
  font-size: 1.15rem;
  font-weight: 700;
  color: var(--text-main);
}

.panel-title svg {
  color: var(--accent);
}

.panel-body {
  padding: 20px;
}

/* Anathema Section */
.anathema-panel {
  border-color: rgba(244, 63, 94, 0.3);
}

.anathema-header-title svg {
  color: var(--danger);
}

.anathema-actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

.banned-ips-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 12px;
  margin-top: 16px;
}

.banned-ip-card {
  background: var(--bg-surface);
  border: 1px solid var(--danger-border);
  border-radius: var(--radius-md);
  padding: 12px 14px;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.banned-ip-text {
  font-family: var(--font-mono);
  font-size: 0.95rem;
  font-weight: 700;
  color: var(--danger);
}

.banned-ip-meta {
  font-size: 0.75rem;
  color: var(--text-muted);
}

.violators-table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 16px;
  font-size: 0.85rem;
}

.violators-table th {
  text-align: left;
  padding: 8px 12px;
  background: var(--bg-surface);
  color: var(--text-muted);
  font-weight: 600;
  border-bottom: 1px solid var(--border);
}

.violators-table td {
  padding: 8px 12px;
  border-bottom: 1px solid var(--border);
}

/* Statistics Grid */
.stats-cards-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
  gap: 20px;
  margin-bottom: 24px;
}

.stat-item-row {
  margin-bottom: 14px;
}

.stat-item-row:last-child {
  margin-bottom: 0;
}

.stat-item-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 0.85rem;
  margin-bottom: 6px;
  gap: 8px;
}

.stat-item-name {
  font-weight: 600;
  color: var(--text-main);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.stat-item-name.mono {
  font-family: var(--font-mono);
}

.stat-item-counts {
  display: flex;
  align-items: center;
  gap: 8px;
  white-space: nowrap;
  font-size: 0.8rem;
  color: var(--text-muted);
}

.stat-bar-track {
  width: 100%;
  height: 8px;
  background: var(--bg-surface-2);
  border-radius: 9999px;
  overflow: hidden;
}

.stat-bar-fill {
  height: 100%;
  border-radius: 9999px;
  transition: width 0.3s ease;
}

/* Interactive Explorer */
.explorer-toolbar {
  display: flex;
  flex-direction: column;
  gap: 14px;
  margin-bottom: 16px;
}

.search-and-actions {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
  justify-content: space-between;
  align-items: center;
}

.search-box-wrapper {
  position: relative;
  flex: 1;
  min-width: 280px;
}

.search-icon {
  position: absolute;
  left: 12px;
  top: 50%;
  transform: translateY(-50%);
  color: var(--text-dim);
  pointer-events: none;
}

.search-input {
  width: 100%;
  background: var(--bg-surface);
  border: 1px solid var(--border-light);
  border-radius: var(--radius-md);
  padding: 10px 38px 10px 38px;
  color: var(--text-main);
  font-family: var(--font-sans);
  font-size: 0.9rem;
  transition: border-color 0.15s ease, box-shadow 0.15s ease;
}

.search-input:focus {
  outline: none;
  border-color: var(--accent);
  box-shadow: 0 0 0 2px var(--accent-glow);
}

.btn-clear-search {
  position: absolute;
  right: 10px;
  top: 50%;
  transform: translateY(-50%);
  background: none;
  border: none;
  color: var(--text-dim);
  cursor: pointer;
  padding: 4px;
  display: none;
  font-size: 1.1rem;
  line-height: 1;
}

.btn-clear-search:hover {
  color: var(--text-main);
}

.filter-dropdowns {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
  align-items: center;
}

.select-wrapper {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.select-label {
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--text-dim);
  font-weight: 600;
}

.custom-select {
  background: var(--bg-surface);
  border: 1px solid var(--border-light);
  border-radius: var(--radius-md);
  padding: 8px 12px;
  color: var(--text-main);
  font-family: var(--font-sans);
  font-size: 0.85rem;
  cursor: pointer;
  min-width: 130px;
}

.custom-select:focus {
  outline: none;
  border-color: var(--accent);
}

/* Buttons */
.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: 8px 14px;
  border-radius: var(--radius-md);
  font-size: 0.85rem;
  font-weight: 600;
  cursor: pointer;
  border: 1px solid transparent;
  transition: all 0.15s ease;
  font-family: var(--font-sans);
  white-space: nowrap;
}

.btn-secondary {
  background: var(--bg-surface);
  border-color: var(--border-light);
  color: var(--text-main);
}

.btn-secondary:hover {
  background: var(--bg-surface-2);
  border-color: var(--accent);
  color: var(--accent);
}

.btn-danger {
  background: var(--danger-bg);
  border-color: var(--danger-border);
  color: var(--danger);
}

.btn-danger:hover {
  background: rgba(244, 63, 94, 0.25);
}

.btn-ghost {
  background: transparent;
  color: var(--text-muted);
}

.btn-ghost:hover {
  background: var(--bg-surface);
  color: var(--text-main);
}

.btn-copy {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  background: transparent;
  border: none;
  color: var(--text-dim);
  cursor: pointer;
  padding: 4px;
  border-radius: var(--radius-sm);
  transition: color 0.15s ease, background 0.15s ease;
}

.btn-copy:hover {
  color: var(--accent);
  background: rgba(6, 182, 212, 0.1);
}

.btn-copy.copied {
  color: var(--success);
}

/* Table */
.table-responsive {
  width: 100%;
  overflow-x: auto;
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  background: var(--bg-card);
}

.matches-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.85rem;
  text-align: left;
}

.matches-table thead th {
  background: var(--bg-header);
  padding: 12px 14px;
  font-weight: 700;
  color: var(--text-muted);
  border-bottom: 1px solid var(--border);
  white-space: nowrap;
}

.matches-table tbody tr.match-row {
  border-bottom: 1px solid var(--border);
  cursor: pointer;
  transition: background-color 0.1s ease;
}

.matches-table tbody tr.match-row:hover {
  background-color: var(--bg-card-hover);
}

.matches-table tbody td {
  padding: 10px 14px;
  vertical-align: middle;
}

/* Cells */
.cell-num {
  color: var(--text-dim);
  font-size: 0.8rem;
  width: 40px;
}

.cell-time {
  white-space: nowrap;
  font-family: var(--font-mono);
  font-size: 0.8rem;
  color: var(--text-muted);
}

.ip-wrapper, .target-wrapper, .payload-wrapper {
  display: flex;
  align-items: center;
  gap: 6px;
}

.mono {
  font-family: var(--font-mono);
}

.method-badge {
  font-family: var(--font-mono);
  font-weight: 700;
  font-size: 0.75rem;
  margin-right: 4px;
}

.target-url {
  max-width: 260px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--text-main);
}

.payload-snippet {
  max-width: 280px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  background: var(--code-bg);
  border: 1px solid var(--border);
  padding: 2px 6px;
  border-radius: var(--radius-sm);
  color: #fb7185;
  font-family: var(--font-mono);
  font-size: 0.8rem;
}

/* Badges */
.badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 9999px;
  font-size: 0.75rem;
  font-weight: 700;
  white-space: nowrap;
}

.badge-danger {
  background: var(--danger-bg);
  color: var(--danger);
  border: 1px solid var(--danger-border);
}

.badge-warning {
  background: var(--warning-bg);
  color: var(--warning);
  border: 1px solid var(--warning-border);
}

.badge-info {
  background: var(--info-bg);
  color: var(--info);
  border: 1px solid rgba(56, 189, 248, 0.3);
}

.badge-success {
  background: var(--success-bg);
  color: var(--success);
  border: 1px solid var(--success-border);
}

.badge-purple {
  background: var(--purple-bg);
  color: var(--purple);
  border: 1px solid rgba(129, 140, 248, 0.3);
}

.badge-vector {
  background: var(--bg-surface-2);
  color: var(--text-muted);
  font-size: 0.7rem;
  text-transform: uppercase;
  font-weight: 600;
}

.cat-pill {
  font-weight: 600;
  color: var(--text-main);
  font-size: 0.85rem;
}

.rule-ref {
  font-size: 0.75rem;
  color: var(--text-dim);
  max-width: 240px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* Detail Row */
.detail-row td {
  background: var(--bg-header);
  padding: 16px 20px;
  border-bottom: 1px solid var(--border);
}

.detail-panel {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.detail-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 16px;
}

.detail-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.detail-label {
  font-size: 0.725rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--text-dim);
}

.detail-box {
  background: var(--code-bg);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 8px 12px;
  font-family: var(--font-mono);
  font-size: 0.8rem;
  color: #e2e8f0;
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 8px;
  word-break: break-all;
}

/* Pagination Bar */
.pagination-bar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 12px;
  padding-top: 16px;
}

.pagination-size {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 0.85rem;
  color: var(--text-muted);
}

.pagination-controls {
  display: flex;
  align-items: center;
  gap: 6px;
}

.btn-page {
  background: var(--bg-surface);
  border: 1px solid var(--border-light);
  color: var(--text-main);
  padding: 6px 12px;
  border-radius: var(--radius-sm);
  font-size: 0.85rem;
  cursor: pointer;
  transition: all 0.15s ease;
}

.btn-page:hover:not(:disabled) {
  background: var(--bg-surface-2);
  border-color: var(--accent);
}

.btn-page:disabled {
  opacity: 0.35;
  cursor: not-allowed;
}

.page-indicator {
  font-size: 0.85rem;
  color: var(--text-muted);
  padding: 0 8px;
}

/* Empty State */
.empty-state {
  text-align: center;
  padding: 40px 20px;
  color: var(--text-muted);
  font-style: italic;
}

/* Floating Toast */
.scalp-toast {
  position: fixed;
  bottom: 24px;
  right: 24px;
  background: var(--bg-card);
  color: var(--accent);
  border: 1px solid var(--accent);
  box-shadow: 0 10px 25px rgba(0,0,0,0.8), 0 0 15px var(--accent-glow);
  padding: 10px 18px;
  border-radius: var(--radius-md);
  font-size: 0.875rem;
  font-weight: 600;
  z-index: 99999;
  opacity: 0;
  transform: translateY(10px);
  transition: opacity 0.2s ease, transform 0.2s ease;
  pointer-events: none;
}

.scalp-toast.show {
  opacity: 1;
  transform: translateY(0);
}

/* Footer */
footer {
  text-align: center;
  margin-top: 40px;
  padding-top: 20px;
  border-top: 1px solid var(--border);
  color: var(--text-dim);
  font-size: 0.85rem;
}

footer a {
  color: var(--accent);
  text-decoration: none;
}

footer a:hover {
  text-decoration: underline;
}

/* Responsive adjustments */
@media (max-width: 768px) {
  .container {
    padding: 16px 12px;
  }
  .app-header {
    flex-direction: column;
    align-items: flex-start;
  }
  .search-and-actions {
    flex-direction: column;
    align-items: stretch;
  }
  .filter-dropdowns {
    width: 100%;
  }
  .custom-select {
    flex: 1;
  }
  .target-url {
    max-width: 160px;
  }
  .payload-snippet {
    max-width: 160px;
  }
}
"""

# -----------------------------------------------------------------------------
# Zero-CDN Vanilla JavaScript Engine (<15 KB, Offline-Friendly)
# -----------------------------------------------------------------------------
JS_SCRIPT = r"""
(function() {
  'use strict';

  // Read embedded dataset safely
  const dataScript = document.getElementById('scalp-data');
  if (!dataScript) return;

  let reportData = { matches: [], banned_ips: [] };
  try {
    reportData = JSON.parse(dataScript.textContent);
  } catch (err) {
    console.error('Scalp: Failed to parse embedded JSON data', err);
    return;
  }

  const allMatches = reportData.matches || [];
  let filteredMatches = allMatches.slice();
  let currentPage = 1;
  let pageSize = 25;
  let openDetailId = null;

  // DOM references
  const searchInput = document.getElementById('search-input');
  const btnClearSearch = document.getElementById('btn-clear-search');
  const filterCat = document.getElementById('filter-category');
  const filterSev = document.getElementById('filter-severity');
  const filterStatus = document.getElementById('filter-status');
  const filterVector = document.getElementById('filter-vector');
  const btnReset = document.getElementById('btn-reset-filters');
  const pageSizeSelect = document.getElementById('page-size');
  const tableBody = document.getElementById('matches-tbody');
  const recordsBadge = document.getElementById('records-count');
  const pageIndicator = document.getElementById('page-indicator');
  const btnFirst = document.getElementById('btn-first');
  const btnPrev = document.getElementById('btn-prev');
  const btnNext = document.getElementById('btn-next');
  const btnLast = document.getElementById('btn-last');
  const btnExportCsv = document.getElementById('btn-export-csv');
  const btnExportJson = document.getElementById('btn-export-json');
  const toastEl = document.getElementById('scalp-toast');

  let toastTimer = null;
  function showToast(msg) {
    if (!toastEl) return;
    toastEl.textContent = msg;
    toastEl.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      toastEl.classList.remove('show');
    }, 2000);
  }

  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function copyTextToClipboard(text, successMsg) {
    if (!text) return;
    function notify() {
      showToast(successMsg || 'Copied to clipboard!');
    }
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(notify).catch(() => fallbackCopy(text, notify));
    } else {
      fallbackCopy(text, notify);
    }
  }

  function fallbackCopy(text, callback) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    ta.style.top = '0';
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    try {
      document.execCommand('copy');
      if (callback) callback();
    } catch (e) {
      console.error('Fallback copy failed', e);
    }
    document.body.removeChild(ta);
  }

  // Filter application
  let searchDebounce = null;
  function applyFilters() {
    const q = (searchInput?.value || '').trim().toLowerCase();
    const cat = filterCat?.value || 'all';
    const sev = filterSev?.value || 'all';
    const status = filterStatus?.value || 'all';
    const vec = filterVector?.value || 'all';

    if (btnClearSearch) {
      btnClearSearch.style.display = q.length > 0 ? 'block' : 'none';
    }

    filteredMatches = allMatches.filter(m => {
      if (cat !== 'all' && m.tag !== cat && m.cat !== cat) return false;
      if (status !== 'all' && String(m.status) !== status) return false;
      if (vec !== 'all' && m.vector !== vec) return false;
      if (sev === 'critical' && m.impact < 7) return false;
      if (sev === 'medium' && (m.impact < 4 || m.impact > 6)) return false;
      if (sev === 'low' && m.impact > 3) return false;

      if (q) {
        const inIp = m.ip && m.ip.toLowerCase().includes(q);
        const inTarget = m.target && m.target.toLowerCase().includes(q);
        const inRule = m.rule && String(m.rule).toLowerCase().includes(q);
        const inDesc = m.desc && m.desc.toLowerCase().includes(q);
        const inMatch = m.match && m.match.toLowerCase().includes(q);
        const inUa = m.ua && m.ua.toLowerCase().includes(q);
        if (!inIp && !inTarget && !inRule && !inDesc && !inMatch && !inUa) return false;
      }
      return true;
    });

    currentPage = 1;
    openDetailId = null;
    render();
  }

  function render() {
    const total = filteredMatches.length;
    const totalPages = Math.max(1, Math.ceil(total / pageSize));
    if (currentPage > totalPages) currentPage = totalPages;
    if (currentPage < 1) currentPage = 1;

    const startIdx = (currentPage - 1) * pageSize;
    const endIdx = Math.min(startIdx + pageSize, total);
    const pageItems = filteredMatches.slice(startIdx, endIdx);

    // Update counter
    if (recordsBadge) {
      if (allMatches.length === 0) {
        recordsBadge.textContent = '0 attacks detected';
      } else if (total === allMatches.length) {
        recordsBadge.textContent = `Showing ${total === 0 ? 0 : startIdx + 1}–${endIdx} of ${total} attacks`;
      } else {
        recordsBadge.textContent = `Showing ${total === 0 ? 0 : startIdx + 1}–${endIdx} of ${total} filtered attacks (${allMatches.length} total)`;
      }
    }

    // Update pagination indicators
    if (pageIndicator) {
      pageIndicator.textContent = `Page ${currentPage} of ${totalPages}`;
    }
    if (btnFirst) btnFirst.disabled = currentPage <= 1;
    if (btnPrev) btnPrev.disabled = currentPage <= 1;
    if (btnNext) btnNext.disabled = currentPage >= totalPages;
    if (btnLast) btnLast.disabled = currentPage >= totalPages;

    if (!tableBody) return;

    if (pageItems.length === 0) {
      tableBody.innerHTML = `<tr><td colspan="8" class="empty-state">No attack records matching the current filters.</td></tr>`;
      return;
    }

    const rows = [];
    pageItems.forEach((m, idx) => {
      const rowNum = startIdx + idx + 1;
      const sevBadgeClass = m.impact >= 7 ? 'badge-danger' : (m.impact >= 4 ? 'badge-warning' : 'badge-info');
      const statusBadgeClass = (m.status >= 200 && m.status < 300) || m.status === 500 ? 'badge-danger' : (m.status >= 300 && m.status < 400 ? 'badge-warning' : 'badge-info');

      rows.push(`
        <tr class="match-row" data-id="${m.id}">
          <td class="cell-num">${rowNum}</td>
          <td class="cell-time">${escapeHtml(m.time || '-')}</td>
          <td>
            <div class="ip-wrapper">
              <span class="mono">${escapeHtml(m.ip)}</span>
              <button type="button" class="btn-copy" data-copy-action="ip" title="Copy IP" aria-label="Copy IP">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
              </button>
            </div>
          </td>
          <td>
            <span class="method-badge">${escapeHtml(m.method || '-')}</span>
            <span class="badge ${statusBadgeClass}">${escapeHtml(String(m.status))}</span>
          </td>
          <td>
            <span class="badge ${sevBadgeClass}">Impact ${m.impact}</span>
          </td>
          <td>
            <div class="cat-pill">${escapeHtml(m.cat || m.tag)}</div>
            <div class="rule-ref" title="${escapeHtml(m.desc)}">[${escapeHtml(String(m.rule))}] ${escapeHtml(m.desc)}</div>
          </td>
          <td>
            <div class="target-wrapper">
              <span class="badge badge-vector">${escapeHtml(m.vector || 'url')}</span>
              <span class="target-url mono" title="${escapeHtml(m.target)}">${escapeHtml(m.target)}</span>
              <button type="button" class="btn-copy" data-copy-action="target" title="Copy Target" aria-label="Copy Target">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
              </button>
            </div>
          </td>
          <td>
            <div class="payload-wrapper">
              <code class="payload-snippet" title="${escapeHtml(m.match)}">${escapeHtml(m.match)}</code>
              <button type="button" class="btn-copy" data-copy-action="payload" title="Copy Payload" aria-label="Copy Payload">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
              </button>
            </div>
          </td>
        </tr>
      `);

      if (openDetailId === m.id) {
        rows.push(`
          <tr class="detail-row" data-detail-for="${m.id}">
            <td colspan="8">
              <div class="detail-panel">
                <div class="detail-grid">
                  <div class="detail-item">
                    <span class="detail-label">Full Target URL</span>
                    <div class="detail-box">
                      <code>${escapeHtml(m.target)}</code>
                      <button type="button" class="btn-copy" data-copy-action="target" title="Copy Target">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                      </button>
                    </div>
                  </div>
                  <div class="detail-item">
                    <span class="detail-label">Matched Payload / Token</span>
                    <div class="detail-box">
                      <code style="color: var(--danger); font-weight: bold;">${escapeHtml(m.match)}</code>
                      <button type="button" class="btn-copy" data-copy-action="payload" title="Copy Payload">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                      </button>
                    </div>
                  </div>
                  <div class="detail-item">
                    <span class="detail-label">User-Agent</span>
                    <div class="detail-box"><code>${escapeHtml(m.ua || 'None provided')}</code></div>
                  </div>
                  <div class="detail-item">
                    <span class="detail-label">Referrer</span>
                    <div class="detail-box"><code>${escapeHtml(m.ref || 'None provided')}</code></div>
                  </div>
                </div>
                <div class="detail-item">
                  <span class="detail-label">Raw Log Record</span>
                  <div class="detail-box">
                    <code>${escapeHtml(m.raw || '')}</code>
                    <button type="button" class="btn-copy" data-copy-action="raw" title="Copy Raw Record">
                      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                    </button>
                  </div>
                </div>
              </div>
            </td>
          </tr>
        `);
      }
    });

    tableBody.innerHTML = rows.join('');
  }

  // Event handlers
  if (searchInput) {
    searchInput.addEventListener('input', () => {
      clearTimeout(searchDebounce);
      searchDebounce = setTimeout(applyFilters, 150);
    });
  }

  if (btnClearSearch) {
    btnClearSearch.addEventListener('click', () => {
      if (searchInput) searchInput.value = '';
      applyFilters();
    });
  }

  [filterCat, filterSev, filterStatus, filterVector].forEach(sel => {
    if (sel) sel.addEventListener('change', applyFilters);
  });

  if (btnReset) {
    btnReset.addEventListener('click', () => {
      if (searchInput) searchInput.value = '';
      if (filterCat) filterCat.value = 'all';
      if (filterSev) filterSev.value = 'all';
      if (filterStatus) filterStatus.value = 'all';
      if (filterVector) filterVector.value = 'all';
      applyFilters();
    });
  }

  if (pageSizeSelect) {
    pageSizeSelect.addEventListener('change', (e) => {
      pageSize = parseInt(e.target.value, 10) || 25;
      currentPage = 1;
      render();
    });
  }

  if (btnFirst) btnFirst.addEventListener('click', () => { currentPage = 1; render(); });
  if (btnPrev) btnPrev.addEventListener('click', () => { if (currentPage > 1) { currentPage--; render(); } });
  if (btnNext) btnNext.addEventListener('click', () => { currentPage++; render(); });
  if (btnLast) btnLast.addEventListener('click', () => { currentPage = Math.ceil(filteredMatches.length / pageSize); render(); });

  // Table click delegation (Copy buttons & Row expansion)
  if (tableBody) {
    tableBody.addEventListener('click', (e) => {
      const copyBtn = e.target.closest('.btn-copy');
      const row = e.target.closest('tr.match-row');

      if (copyBtn) {
        e.stopPropagation();
        const tr = copyBtn.closest('tr');
        const id = tr.dataset.id ? parseInt(tr.dataset.id, 10) : (tr.dataset.detailFor ? parseInt(tr.dataset.detailFor, 10) : null);
        const matchObj = allMatches.find(x => x.id === id);
        if (!matchObj) return;

        const action = copyBtn.dataset.copyAction;
        if (action === 'ip') copyTextToClipboard(matchObj.ip, `Copied IP: ${matchObj.ip}`);
        else if (action === 'target') copyTextToClipboard(matchObj.target, 'Copied Target URL');
        else if (action === 'payload') copyTextToClipboard(matchObj.match, 'Copied Payload');
        else if (action === 'raw') copyTextToClipboard(matchObj.raw, 'Copied Raw Log Line');
        return;
      }

      if (row) {
        const id = parseInt(row.dataset.id, 10);
        openDetailId = (openDetailId === id) ? null : id;
        render();
      }
    });
  }

  // Export handlers
  function downloadBlob(content, mimeType, filename) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function escapeCsvField(val) {
    const str = String(val === null || val === undefined ? '' : val);
    if (str.includes('"') || str.includes(',') || str.includes('\n') || str.includes('\r')) {
      return '"' + str.replace(/"/g, '""') + '"';
    }
    return str;
  }

  if (btnExportCsv) {
    btnExportCsv.addEventListener('click', () => {
      if (!filteredMatches.length) {
        showToast('No filtered attacks to export');
        return;
      }
      const headers = ['ID', 'Timestamp', 'Client IP', 'Method', 'Status Code', 'Impact', 'Tag', 'Category', 'Rule ID', 'Description', 'Vector', 'Target', 'Matched Payload', 'User Agent', 'Referrer', 'Raw Line'];
      const lines = [headers.map(escapeCsvField).join(',')];
      filteredMatches.forEach(m => {
        lines.push([
          m.id,
          m.time || '',
          m.ip || '',
          m.method || '',
          m.status || '',
          m.impact || '',
          m.tag || '',
          m.cat || '',
          m.rule || '',
          m.desc || '',
          m.vector || '',
          m.target || '',
          m.match || '',
          m.ua || '',
          m.ref || '',
          m.raw || ''
        ].map(escapeCsvField).join(','));
      });
      downloadBlob(lines.join('\r\n'), 'text/csv;charset=utf-8;', 'scalp_filtered_attacks.csv');
      showToast(`Exported ${filteredMatches.length} attack records to CSV`);
    });
  }

  if (btnExportJson) {
    btnExportJson.addEventListener('click', () => {
      if (!filteredMatches.length) {
        showToast('No filtered attacks to export');
        return;
      }
      const jsonStr = JSON.stringify(filteredMatches, null, 2);
      downloadBlob(jsonStr, 'application/json;charset=utf-8;', 'scalp_filtered_attacks.json');
      showToast(`Exported ${filteredMatches.length} attack records to JSON`);
    });
  }

  // Global utilities attached for Anathema copy toolbar
  window.ScalpReport = {
    copyBannedIps: function(format) {
      const ips = reportData.banned_ips || [];
      if (!ips.length) {
        showToast('No banned IPs to copy');
        return;
      }
      let content = '';
      if (format === 'iptables') {
        content = ips.map(ip => `iptables -A INPUT -s ${ip} -j DROP`).join('\n');
      } else if (format === 'ipset') {
        content = ips.map(ip => `ipset add blacklist ${ip}`).join('\n');
      } else if (format === 'cidr') {
        content = ips.map(ip => ip.includes(':') ? `${ip}/128` : `${ip}/32`).join('\n');
      } else {
        content = ips.join('\n');
      }
      copyTextToClipboard(content, `Copied ${ips.length} banned IP(s) (${format || 'list'})!`);
    },
    copySingleIp: function(ip) {
      copyTextToClipboard(ip, `Copied IP: ${ip}`);
    }
  };

  // Initial render
  render();
})();
"""


class HtmlReporter(BaseReporter):
    """World-class, 2026-standard, responsive, 100% self-contained HTML5 security reporter."""

    @classmethod
    def generate(cls, result: ScanResult, output_path: str, source_name: str = "") -> None:
        source_display = source_name or "access.log"
        curtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        total_matches = len(result.matches)
        processed_lines = result.processed_lines
        threat_ratio = (total_matches / processed_lines * 100.0) if processed_lines > 0 else 0.0

        # Behavioral intelligence / Anathema metrics
        has_anathema = result.anathema is not None
        banned_ips = sorted(list(result.anathema.banned_ips)) if has_anathema else []
        violators_dict = (
            {ip: len(entries) for ip, entries in result.anathema.violators.items()}
            if has_anathema
            else {}
        )

        # Threat Level Badge
        if total_matches == 0:
            status_badge_html = '<span class="header-status-badge badge-success">CLEAN / NO THREATS</span>'
        elif len(banned_ips) > 0 or threat_ratio >= 15.0:
            status_badge_html = '<span class="header-status-badge badge-danger">CRITICAL THREAT LEVEL</span>'
        elif threat_ratio >= 5.0:
            status_badge_html = '<span class="header-status-badge badge-warning">ELEVATED ATTACK LEVEL</span>'
        else:
            status_badge_html = '<span class="header-status-badge badge-info">ATTACK ACTIVITY DETECTED</span>'

        # Precompute Forensics Aggregates
        ip_counts = Counter(m.entry.ip for m in result.matches)
        top_ips = ip_counts.most_common(8)

        # Map IP to primary tag
        ip_tag_counts: Dict[str, Counter] = {}
        for m in result.matches:
            ip_tag_counts.setdefault(m.entry.ip, Counter())[m.tag] += 1

        target_counts = Counter(m.entry.url for m in result.matches)
        top_targets = target_counts.most_common(8)
        target_tag_counts: Dict[str, Counter] = {}
        for m in result.matches:
            target_tag_counts.setdefault(m.entry.url, Counter())[m.tag] += 1

        cat_counts = Counter(m.tag for m in result.matches)
        top_cats = cat_counts.most_common()

        status_counts = Counter(m.entry.status_code for m in result.matches)
        top_statuses = sorted(status_counts.items(), key=lambda x: x[1], reverse=True)

        vector_counts = Counter(getattr(m, "matched_field", "url") for m in result.matches)

        # Prepare JSON matches dataset
        json_matches = []
        for idx, m in enumerate(result.matches, 1):
            ts_str = m.entry.timestamp.strftime("%Y-%m-%d %H:%M:%S") if m.entry.timestamp else ""
            json_matches.append({
                "id": idx,
                "time": ts_str,
                "ip": m.entry.ip,
                "method": m.entry.method,
                "status": m.entry.status_code,
                "impact": int(m.rule.impact or 0),
                "tag": m.tag,
                "cat": ATTACK_NAMES.get(m.tag.lower(), m.tag.upper()),
                "rule": m.rule.rule_id,
                "desc": m.rule.description,
                "target": m.entry.url,
                "vector": getattr(m, "matched_field", "url"),
                "match": m.matched_string,
                "ua": m.entry.user_agent or "",
                "ref": m.entry.referrer or "",
                "raw": m.entry.raw_line,
            })

        json_payload = {
            "metadata": {
                "generator": "Scalp! Modernized Edition",
                "source": source_display,
                "generated_at": curtime,
            },
            "summary": {
                "total_lines": result.total_lines,
                "processed_lines": processed_lines,
                "total_matches": total_matches,
                "threat_ratio": round(threat_ratio, 2),
                "elapsed_seconds": round(result.elapsed_seconds, 4),
                "banned_ips_count": len(banned_ips),
                "violators_count": len(violators_dict),
            },
            "banned_ips": banned_ips,
            "violators": violators_dict,
            "matches": json_matches,
        }

        # Safe serialization preventing </script> breakout
        embedded_json = json.dumps(json_payload, ensure_ascii=False).replace("</", "<\\/")

        # Build HTML parts
        kpi_cards_html = cls._build_kpi_cards(
            processed_lines=processed_lines,
            total_lines=result.total_lines,
            total_matches=total_matches,
            threat_ratio=threat_ratio,
            elapsed_seconds=result.elapsed_seconds,
            has_anathema=has_anathema,
            banned_count=len(banned_ips),
        )

        anathema_section_html = cls._build_anathema_section(
            has_anathema=has_anathema,
            banned_ips=banned_ips,
            violators=violators_dict,
        )

        top_stats_html = cls._build_top_stats(
            total_matches=total_matches,
            top_ips=top_ips,
            ip_tag_counts=ip_tag_counts,
            banned_ips=banned_ips,
            violators=violators_dict,
            top_targets=top_targets,
            target_tag_counts=target_tag_counts,
            top_cats=top_cats,
            top_statuses=top_statuses,
        )

        filter_options_html = cls._build_filter_options(
            top_cats=top_cats,
            top_statuses=top_statuses,
            vector_counts=vector_counts,
        )

        initial_rows_html = cls._build_initial_rows_fallback(result.matches[:25])

        doc = [
            '<!DOCTYPE html>',
            '<html lang="en">',
            '<head>',
            '  <meta charset="UTF-8">',
            '  <meta name="viewport" content="width=device-width, initial-scale=1.0">',
            '  <meta name="generator" content="Scalp Security Analyzer">',
            f'  <title>Scalp Report — {html.escape(source_display)}</title>',
            f'  <style>{CSS_STYLES}</style>',
            '</head>',
            '<body>',
            '  <div class="container">',
            '    <header class="app-header">',
            '      <div class="brand-wrapper">',
            '        <div class="brand-icon">',
            '          <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
            '        </div>',
            '        <div class="brand-title">',
            '          <h1>Scalp Report <span class="accent">Forensic Intelligence</span></h1>',
            '          <div class="brand-meta">',
            f'            <span>Target Log: <b>{html.escape(source_display)}</b></span>',
            '            <span>&bull;</span>',
            f'            <span>Generated: {html.escape(curtime)}</span>',
            '            <span>&bull;</span>',
            '            <span>Engine: Scalp Modernized 2026</span>',
            '          </div>',
            '        </div>',
            '      </div>',
            f'      <div>{status_badge_html}</div>',
            '    </header>',
            kpi_cards_html,
            anathema_section_html,
            top_stats_html,
            cls._build_explorer_markup(filter_options_html, total_matches, initial_rows_html),
            '    <footer>',
            '      Scalp! Modernized Edition &bull; Maintained by <a href="https://www.DragonJAR.org" target="_blank" rel="noopener noreferrer">DragonJAR SAS</a> &bull; 100% Offline / Zero-CDN Self-Contained Security Report',
            '    </footer>',
            '  </div>',
            f'  <div id="scalp-toast" class="scalp-toast"></div>',
            f'  <script id="scalp-data" type="application/json">{embedded_json}</script>',
            f'  <script>{JS_SCRIPT}</script>',
            '</body>',
            '</html>',
        ]

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(doc))

    # -------------------------------------------------------------------------
    # Helper Builders
    # -------------------------------------------------------------------------
    @classmethod
    def _build_kpi_cards(
        cls,
        processed_lines: int,
        total_lines: int,
        total_matches: int,
        threat_ratio: float,
        elapsed_seconds: float,
        has_anathema: bool,
        banned_count: int,
    ) -> str:
        ratio_class = "card-danger" if threat_ratio >= 10.0 else ("card-warning" if threat_ratio >= 1.0 else "card-success")
        rate = (processed_lines / elapsed_seconds) if elapsed_seconds > 0 else 0
        total_sub = f"of {total_lines:,} total log records" if total_lines > 0 else "complete scan"

        anathema_val = f"{banned_count:,}" if has_anathema else "N/A"
        anathema_sub = (
            f"Severity &ge; 10 automatically banned"
            if has_anathema
            else "Module inactive (run with --anathema)"
        )
        anathema_class = "card-danger" if (has_anathema and banned_count > 0) else "card-purple"

        return f"""
    <div class="kpi-grid">
      <div class="kpi-card">
        <div class="kpi-label">Lines Analyzed</div>
        <div class="kpi-val">{processed_lines:,}</div>
        <div class="kpi-sub">{total_sub}</div>
      </div>
      <div class="kpi-card card-danger">
        <div class="kpi-label">Detected Attacks</div>
        <div class="kpi-val">{total_matches:,}</div>
        <div class="kpi-sub">Total pattern matches</div>
      </div>
      <div class="kpi-card {ratio_class}">
        <div class="kpi-label">Threat Ratio</div>
        <div class="kpi-val">{threat_ratio:.2f}%</div>
        <div class="kpi-sub">Attacks per analyzed line</div>
      </div>
      <div class="kpi-card card-purple">
        <div class="kpi-label">Scan Duration</div>
        <div class="kpi-val">{elapsed_seconds:.2f}s</div>
        <div class="kpi-sub">{rate:,.0f} lines/second</div>
      </div>
      <div class="kpi-card {anathema_class}">
        <div class="kpi-label">Anathema Banned IPs</div>
        <div class="kpi-val">{anathema_val}</div>
        <div class="kpi-sub">{anathema_sub}</div>
      </div>
    </div>
"""

    @classmethod
    def _build_anathema_section(
        cls,
        has_anathema: bool,
        banned_ips: List[str],
        violators: Dict[str, int],
    ) -> str:
        if not has_anathema:
            return """
    <div class="panel">
      <div class="panel-header">
        <h2 class="panel-title">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          Anathema Behavioral Intelligence &amp; Heuristics
        </h2>
        <span class="badge badge-info">Inactive</span>
      </div>
      <div class="panel-body">
        <p style="color: var(--text-muted); margin: 0;">
          Anathema behavioral intelligence module was not enabled for this scan. Run Scalp with <code>--anathema</code> to detect automated scanners, track behavioral threat scores, and generate automated firewall blacklists.
        </p>
      </div>
    </div>
"""

        if not banned_ips and not violators:
            return """
    <div class="panel">
      <div class="panel-header">
        <h2 class="panel-title">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          Anathema Behavioral Threat Intelligence
        </h2>
        <span class="badge badge-success">Clean Traffic</span>
      </div>
      <div class="panel-body">
        <p style="color: var(--success); margin: 0; font-weight: 600;">
          No behavioral heuristic anomalies or scanner patterns detected. All client IP behaviors were within standard operational thresholds.
        </p>
      </div>
    </div>
"""

        # Banned IP cards
        cards = []
        for ip in banned_ips:
            v_count = violators.get(ip, 1)
            cards.append(f"""
          <div class="banned-ip-card">
            <div>
              <div class="banned-ip-text">{html.escape(ip)}</div>
              <div class="banned-ip-meta">Score: 10/10 (Banned) &bull; {v_count} violation(s)</div>
            </div>
            <button type="button" class="btn-copy" onclick="ScalpReport.copySingleIp('{html.escape(ip)}')" title="Copy IP" aria-label="Copy IP">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            </button>
          </div>
""")

        # Non-banned violators
        other_violators = [ip for ip in violators if ip not in banned_ips]
        violators_rows = []
        for ip in other_violators[:10]:
            violators_rows.append(f"""
          <tr>
            <td class="mono">{html.escape(ip)}</td>
            <td><span class="badge badge-warning">Violator</span></td>
            <td>{violators[ip]} request(s)</td>
            <td>
              <button type="button" class="btn-copy" onclick="ScalpReport.copySingleIp('{html.escape(ip)}')" title="Copy IP">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
              </button>
            </td>
          </tr>
""")

        violators_section = ""
        if violators_rows:
            violators_section = f"""
        <h3 style="font-size: 0.95rem; margin: 20px 0 10px 0; color: var(--text-main);">Additional Suspicious Behavioral Violators</h3>
        <table class="violators-table">
          <thead>
            <tr><th>IP Address</th><th>Status</th><th>Violation Hits</th><th>Actions</th></tr>
          </thead>
          <tbody>
            {"".join(violators_rows)}
          </tbody>
        </table>
"""

        return f"""
    <div class="panel anathema-panel">
      <div class="panel-header">
        <h2 class="panel-title anathema-header-title">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          Anathema Behavioral Intelligence &amp; Blacklist ({len(banned_ips)} Banned IPs)
        </h2>
        <div class="anathema-actions">
          <button type="button" class="btn btn-danger" onclick="ScalpReport.copyBannedIps('raw')">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            Copy Banned IPs
          </button>
          <button type="button" class="btn btn-secondary" onclick="ScalpReport.copyBannedIps('iptables')">
            Copy iptables Rules
          </button>
          <button type="button" class="btn btn-secondary" onclick="ScalpReport.copyBannedIps('ipset')">
            Copy ipset Rules
          </button>
        </div>
      </div>
      <div class="panel-body">
        <div class="banned-ips-grid">
          {"".join(cards)}
        </div>
        {violators_section}
      </div>
    </div>
"""

    @classmethod
    def _build_top_stats(
        cls,
        total_matches: int,
        top_ips: List[Tuple[str, int]],
        ip_tag_counts: Dict[str, Counter],
        banned_ips: List[str],
        violators: Dict[str, int],
        top_targets: List[Tuple[str, int]],
        target_tag_counts: Dict[str, Counter],
        top_cats: List[Tuple[str, int]],
        top_statuses: List[Tuple[int, int]],
    ) -> str:
        if total_matches == 0:
            return """
    <div class="panel">
      <div class="panel-body" style="text-align: center; color: var(--success); font-weight: 700; padding: 32px;">
        No attack patterns detected. The analyzed log is 100% clean.
      </div>
    </div>
"""

        # Card 1: Top Attacker IPs
        max_ip_val = top_ips[0][1] if top_ips else 1
        ip_rows = []
        for ip, count in top_ips:
            pct = (count / max_ip_val) * 100.0
            primary_tag = ip_tag_counts[ip].most_common(1)[0][0] if ip in ip_tag_counts else "attack"
            primary_name = ATTACK_NAMES.get(primary_tag.lower(), primary_tag.upper())

            if ip in banned_ips:
                status_pill = '<span class="badge badge-danger">BANNED (10/10)</span>'
                bar_color = "var(--danger)"
            elif ip in violators:
                status_pill = '<span class="badge badge-warning">VIOLATOR</span>'
                bar_color = "var(--warning)"
            else:
                status_pill = f'<span class="badge badge-info">{html.escape(primary_name)}</span>'
                bar_color = "var(--accent)"

            ip_rows.append(f"""
          <div class="stat-item-row">
            <div class="stat-item-header">
              <span class="stat-item-name mono">{html.escape(ip)}</span>
              <div class="stat-item-counts">
                {status_pill}
                <b>{count:,} attacks</b>
              </div>
            </div>
            <div class="stat-bar-track">
              <div class="stat-bar-fill" style="width: {pct:.1f}%; background: {bar_color};"></div>
            </div>
          </div>
""")

        # Card 2: Top Attacked Endpoints
        max_target_val = top_targets[0][1] if top_targets else 1
        target_rows = []
        for target, count in top_targets:
            pct = (count / max_target_val) * 100.0
            top_tag = target_tag_counts[target].most_common(1)[0][0] if target in target_tag_counts else "attack"
            top_name = ATTACK_NAMES.get(top_tag.lower(), top_tag.upper())

            target_rows.append(f"""
          <div class="stat-item-row">
            <div class="stat-item-header">
              <span class="stat-item-name mono" title="{html.escape(target)}">{html.escape(target)}</span>
              <div class="stat-item-counts">
                <span class="badge badge-vector">{html.escape(top_name)}</span>
                <b>{count:,}</b>
              </div>
            </div>
            <div class="stat-bar-track">
              <div class="stat-bar-fill" style="width: {pct:.1f}%; background: var(--purple);"></div>
            </div>
          </div>
""")

        # Card 3: Attack Distribution by Category
        cat_rows = []
        palette = ["var(--danger)", "var(--accent)", "var(--warning)", "var(--purple)", "var(--info)", "var(--success)"]
        for idx, (tag, count) in enumerate(top_cats[:8]):
            pct = (count / total_matches) * 100.0
            cat_name = ATTACK_NAMES.get(tag.lower(), tag.upper())
            color = palette[idx % len(palette)]

            cat_rows.append(f"""
          <div class="stat-item-row">
            <div class="stat-item-header">
              <span class="stat-item-name">{html.escape(cat_name)} <span style="color: var(--text-dim); font-size: 0.75rem;">({html.escape(tag)})</span></span>
              <div class="stat-item-counts">
                <span>{pct:.1f}%</span>
                <b>{count:,}</b>
              </div>
            </div>
            <div class="stat-bar-track">
              <div class="stat-bar-fill" style="width: {pct:.1f}%; background: {color};"></div>
            </div>
          </div>
""")

        # Card 4: HTTP Status Code Distribution
        status_rows = []
        for code, count in top_statuses[:8]:
            pct = (count / total_matches) * 100.0
            if (code >= 200 and code < 300) or code == 500:
                color = "var(--danger)"
                badge_class = "badge-danger"
            elif code in (301, 302):
                color = "var(--warning)"
                badge_class = "badge-warning"
            else:
                color = "var(--info)"
                badge_class = "badge-info"

            status_rows.append(f"""
          <div class="stat-item-row">
            <div class="stat-item-header">
              <div style="display: flex; align-items: center; gap: 8px;">
                <span class="badge {badge_class}">HTTP {code}</span>
              </div>
              <div class="stat-item-counts">
                <span>{pct:.1f}%</span>
                <b>{count:,}</b>
              </div>
            </div>
            <div class="stat-bar-track">
              <div class="stat-bar-fill" style="width: {pct:.1f}%; background: {color};"></div>
            </div>
          </div>
""")

        return f"""
    <div class="stats-cards-grid">
      <div class="panel" style="margin-bottom: 0;">
        <div class="panel-header">
          <h2 class="panel-title">Top Attacker IPs</h2>
        </div>
        <div class="panel-body">
          {"".join(ip_rows)}
        </div>
      </div>

      <div class="panel" style="margin-bottom: 0;">
        <div class="panel-header">
          <h2 class="panel-title">Top Attacked Targets</h2>
        </div>
        <div class="panel-body">
          {"".join(target_rows)}
        </div>
      </div>

      <div class="panel" style="margin-bottom: 0;">
        <div class="panel-header">
          <h2 class="panel-title">Attack Categories</h2>
        </div>
        <div class="panel-body">
          {"".join(cat_rows)}
        </div>
      </div>

      <div class="panel" style="margin-bottom: 0;">
        <div class="panel-header">
          <h2 class="panel-title">HTTP Status Distribution</h2>
        </div>
        <div class="panel-body">
          {"".join(status_rows)}
        </div>
      </div>
    </div>
    <div style="margin-bottom: 24px;"></div>
"""

    @classmethod
    def _build_filter_options(
        cls,
        top_cats: List[Tuple[str, int]],
        top_statuses: List[Tuple[int, int]],
        vector_counts: Counter,
    ) -> Dict[str, str]:
        cat_options = ['<option value="all">All Categories</option>']
        for tag, count in top_cats:
            name = ATTACK_NAMES.get(tag.lower(), tag.upper())
            cat_options.append(f'<option value="{html.escape(tag)}">{html.escape(name)} ({count:,})</option>')

        status_options = ['<option value="all">All Statuses</option>']
        for code, count in top_statuses:
            status_options.append(f'<option value="{code}">HTTP {code} ({count:,})</option>')

        vector_options = ['<option value="all">All Vectors</option>']
        for vec, count in vector_counts.most_common():
            vector_options.append(f'<option value="{html.escape(vec)}">{html.escape(vec.upper())} ({count:,})</option>')

        return {
            "cat_options": "\n".join(cat_options),
            "status_options": "\n".join(status_options),
            "vector_options": "\n".join(vector_options),
        }

    @classmethod
    def _build_initial_rows_fallback(cls, sample_matches: List[Any]) -> str:
        """Generates fallback rows for noscript environments."""
        if not sample_matches:
            return '<tr><td colspan="8" class="empty-state">No attack records found.</td></tr>'

        rows = []
        for idx, m in enumerate(sample_matches, 1):
            sev_badge = "badge-danger" if m.rule.impact >= 7 else ("badge-warning" if m.rule.impact >= 4 else "badge-info")
            cat_name = ATTACK_NAMES.get(m.tag.lower(), m.tag.upper())
            rows.append(f"""
          <tr class="match-row" data-id="{idx}">
            <td class="cell-num">{idx}</td>
            <td class="cell-time">{html.escape(m.entry.timestamp.strftime("%Y-%m-%d %H:%M:%S") if m.entry.timestamp else "-")}</td>
            <td><span class="mono">{html.escape(m.entry.ip)}</span></td>
            <td><span class="method-badge">{html.escape(m.entry.method)}</span> <span class="badge badge-info">{m.entry.status_code}</span></td>
            <td><span class="badge {sev_badge}">Impact {m.rule.impact}</span></td>
            <td>
              <div class="cat-pill">{html.escape(cat_name)}</div>
              <div class="rule-ref">[{html.escape(m.rule.rule_id)}] {html.escape(m.rule.description)}</div>
            </td>
            <td><span class="mono">{html.escape(m.entry.url)}</span></td>
            <td><code class="payload-snippet">{html.escape(m.matched_string)}</code></td>
          </tr>
""")
        return "".join(rows)

    @classmethod
    def _build_explorer_markup(
        cls,
        options: Dict[str, str],
        total_matches: int,
        initial_rows_html: str,
    ) -> str:
        return f"""
    <div class="panel">
      <div class="panel-header">
        <h2 class="panel-title">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          Interactive Attack Explorer
        </h2>
        <div style="display: flex; gap: 8px;">
          <button type="button" id="btn-export-csv" class="btn btn-secondary">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
            Export CSV
          </button>
          <button type="button" id="btn-export-json" class="btn btn-secondary">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
            Export JSON
          </button>
        </div>
      </div>
      <div class="panel-body">
        <div class="explorer-toolbar">
          <div class="search-and-actions">
            <div class="search-box-wrapper">
              <svg class="search-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
              <input type="text" id="search-input" class="search-input" placeholder="Real-time search IP, URL, Rule ID, payload, User-Agent..." autocomplete="off">
              <button type="button" id="btn-clear-search" class="btn-clear-search" title="Clear search">&times;</button>
            </div>
            <span id="records-count" class="badge badge-info">Total Attacks: {total_matches:,}</span>
          </div>

          <div class="filter-dropdowns">
            <div class="select-wrapper">
              <label class="select-label" for="filter-category">Category</label>
              <select id="filter-category" class="custom-select">
                {options["cat_options"]}
              </select>
            </div>

            <div class="select-wrapper">
              <label class="select-label" for="filter-severity">Severity</label>
              <select id="filter-severity" class="custom-select">
                <option value="all">All Severities</option>
                <option value="critical">Critical (Impact &ge; 7)</option>
                <option value="medium">Medium (Impact 4&ndash;6)</option>
                <option value="low">Low (Impact 1&ndash;3)</option>
              </select>
            </div>

            <div class="select-wrapper">
              <label class="select-label" for="filter-status">HTTP Status</label>
              <select id="filter-status" class="custom-select">
                {options["status_options"]}
              </select>
            </div>

            <div class="select-wrapper">
              <label class="select-label" for="filter-vector">Vector</label>
              <select id="filter-vector" class="custom-select">
                {options["vector_options"]}
              </select>
            </div>

            <div class="select-wrapper" style="align-self: flex-end;">
              <button type="button" id="btn-reset-filters" class="btn btn-ghost">Reset</button>
            </div>
          </div>
        </div>

        <div class="table-responsive">
          <table class="matches-table">
            <thead>
              <tr>
                <th>#</th>
                <th>Timestamp</th>
                <th>Client IP</th>
                <th>Method / Status</th>
                <th>Impact</th>
                <th>Category &amp; Rule</th>
                <th>Vector &amp; Target</th>
                <th>Matched Payload</th>
              </tr>
            </thead>
            <tbody id="matches-tbody">
              {initial_rows_html}
            </tbody>
          </table>
        </div>

        <div class="pagination-bar">
          <div class="pagination-size">
            <label for="page-size">Per page:</label>
            <select id="page-size" class="custom-select" style="min-width: 70px; padding: 4px 8px;">
              <option value="25" selected>25</option>
              <option value="50">50</option>
              <option value="100">100</option>
            </select>
          </div>

          <div class="pagination-controls">
            <button type="button" id="btn-first" class="btn-page" title="First Page">&laquo;</button>
            <button type="button" id="btn-prev" class="btn-page" title="Previous Page">&lsaquo;</button>
            <span id="page-indicator" class="page-indicator">Page 1 of 1</span>
            <button type="button" id="btn-next" class="btn-page" title="Next Page">&rsaquo;</button>
            <button type="button" id="btn-last" class="btn-page" title="Last Page">&raquo;</button>
          </div>
        </div>
      </div>
    </div>
"""
