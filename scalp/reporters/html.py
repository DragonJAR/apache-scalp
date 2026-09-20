"""Modern, responsive, 100% self-contained (Zero-CDN) HTML5 reporter for Scalp."""
from collections import Counter, defaultdict
import html
import json
import time
from typing import Any, Dict, List, Tuple
from scalp.core.engine import ScanResult
from scalp.core.rules import ATTACK_NAMES
from scalp.reporters.base import BaseReporter

# -----------------------------------------------------------------------------
# Zero-CDN Inline CSS Styles (Dark Security Aesthetic)
# -----------------------------------------------------------------------------
CSS_STYLES = """
:root {
  color-scheme: light;
  --bg-base: #f6f6f4;
  --bg-card: #ffffff;
  --bg-card-hover: #fbfbfa;
  --bg-header: #f9fafb;
  --bg-surface: #f3f4f6;
  --bg-surface-2: #e5e7eb;
  --border: #e5e7eb;
  --border-light: #d8dbe0;
  --border-focus: #06b6d4;
  --text-main: #0f172a;
  --text-muted: #64748b;
  --text-dim: #94a3b8;
  --accent: #06b6d4;
  --accent-glow: rgba(6, 182, 212, 0.25);
  --accent-wash: rgba(6, 182, 212, 0.12);
  --danger: #f43f5e;
  --danger-bg: rgba(244, 63, 94, 0.12);
  --danger-border: rgba(244, 63, 94, 0.35);
  --danger-text: #dc2626;
  --danger-strong: #e11d48;
  --danger-strong-2: #be123c;
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
  --code-bg: #f1f5f9;
  --code-text: #1e293b;
  --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
  --radius-sm: 6px;
  --radius-md: 12px;
  --radius-lg: 18px;
  --shadow: 0 1px 2px rgba(16, 24, 40, 0.06), 0 1px 3px rgba(16, 24, 40, 0.1);
}

/* Dark theme: OS preference (unless the viewer forces light) ... */
@media (prefers-color-scheme: dark) {
  :root:where(:not([data-theme="light"])) {
    color-scheme: dark;
    --bg-base: #0a0e17;
    --bg-card: #111827;
    --bg-card-hover: #162032;
    --bg-header: #0d1321;
    --bg-surface: #1f2937;
    --bg-surface-2: #374151;
    --border: #1f2937;
    --border-light: #2d3748;
    --text-main: #f9fafb;
    --text-muted: #9ca3af;
    --text-dim: #6b7280;
    --accent-wash: rgba(6, 182, 212, 0.15);
    --danger-text: #fb7185;
    --code-bg: #030712;
    --code-text: #e2e8f0;
    --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.5), 0 2px 4px -2px rgba(0, 0, 0, 0.5);
  }
}

/* Dark theme: explicit viewer toggle, must win over both OS setting and default */
:root[data-theme="dark"] {
  color-scheme: dark;
  --bg-base: #0a0e17;
  --bg-card: #111827;
  --bg-card-hover: #162032;
  --bg-header: #0d1321;
  --bg-surface: #1f2937;
  --bg-surface-2: #374151;
  --border: #1f2937;
  --border-light: #2d3748;
  --text-main: #f9fafb;
  --text-muted: #9ca3af;
  --text-dim: #6b7280;
  --accent-wash: rgba(6, 182, 212, 0.15);
  --danger-text: #fb7185;
  --code-bg: #030712;
  --code-text: #e2e8f0;
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

.stat-dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  margin-right: 8px;
  vertical-align: middle;
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
  height: 6px;
  background: var(--bg-surface-2);
  border-radius: 9999px;
  overflow: hidden;
}

.stat-bar-fill {
  height: 100%;
  border-radius: 9999px;
  transition: width 0.3s ease;
}

/* Breach / Exploitation Success Triage Panel */
.breach-triage-panel {
  background: rgba(244, 63, 94, 0.07);
  border: 1px solid var(--danger-border);
  border-radius: var(--radius-lg);
  margin-bottom: 24px;
  overflow: hidden;
  box-shadow: 0 4px 14px rgba(244, 63, 94, 0.15);
  position: relative;
}

.breach-triage-panel::before {
  content: "";
  position: absolute;
  top: 0;
  left: 0;
  bottom: 0;
  width: 4px;
  background: var(--danger);
}

.breach-triage-clean {
  background: var(--success-bg);
  border: 1px solid var(--success-border);
  box-shadow: var(--shadow);
}

.breach-triage-clean::before {
  background: var(--success);
}

.breach-triage-header {
  padding: 16px 20px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 16px;
  border-bottom: 1px solid rgba(244, 63, 94, 0.2);
}

.breach-triage-clean .breach-triage-header {
  border-bottom: 1px solid var(--success-border);
}

.breach-triage-title-group {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
}

.breach-triage-title {
  margin: 0;
  font-size: 1.15rem;
  font-weight: 700;
  color: var(--text-main);
  display: flex;
  align-items: center;
  gap: 10px;
}

.breach-triage-body {
  padding: 20px;
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 20px;
  align-items: start;
}

.breach-triage-stat {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.breach-triage-stat-val {
  font-size: 2.2rem;
  font-weight: 900;
  color: var(--danger);
  line-height: 1.1;
  font-feature-settings: "tnum";
}

.breach-triage-clean .breach-triage-stat-val {
  color: var(--success);
}

.breach-triage-stat-label {
  font-size: 0.82rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--text-main);
}

.breach-triage-stat-sub {
  font-size: 0.775rem;
  color: var(--text-muted);
  line-height: 1.4;
}

.breach-triage-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 6px;
}

.btn-triage {
  background: var(--danger);
  color: #fff;
  border: 1px solid rgba(255, 255, 255, 0.2);
  padding: 9px 16px;
  font-size: 0.85rem;
  font-weight: 700;
  border-radius: var(--radius-md);
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  gap: 8px;
  transition: background 0.15s ease, transform 0.15s ease, box-shadow 0.15s ease;
  box-shadow: 0 4px 10px rgba(244, 63, 94, 0.4);
}

.btn-triage:hover {
  background: var(--danger-strong);
  transform: translateY(-1px);
  box-shadow: 0 6px 14px rgba(244, 63, 94, 0.5);
}

.btn-triage.active {
  background: var(--danger-strong-2);
  box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.4);
}

/* Attack Activity Timeline */
.timeline-panel {
  position: relative;
}

.timeline-view-toggles {
  display: flex;
  gap: 2px;
  align-items: center;
  padding: 3px;
  background: var(--bg-surface);
  border-radius: 9999px;
}

.btn-sm {
  padding: 4px 10px;
  font-size: 0.775rem;
  border-radius: var(--radius-sm);
}

.timeline-view-toggles .btn {
  background: transparent;
  border-color: transparent;
  color: var(--text-muted);
  border-radius: 9999px;
}

.timeline-view-toggles .btn:hover {
  color: var(--text-main);
}

.timeline-view-toggles .btn.active {
  background: var(--bg-card);
  color: var(--text-main);
  font-weight: 700;
  border-color: transparent;
  box-shadow: 0 1px 2px rgba(16, 24, 40, 0.15);
}

.timeline-chart-wrapper {
  position: relative;
  width: 100%;
  padding: 8px 0 4px 0;
  user-select: none;
  overflow-x: auto;
}

.timeline-svg {
  width: 100%;
  height: auto;
  overflow: visible;
  display: block;
}

.timeline-grid-line {
  stroke: var(--border-light);
  stroke-dasharray: 4 4;
  stroke-width: 1;
  pointer-events: none;
}

.timeline-axis-text {
  fill: var(--text-dim);
  font-size: 11px;
  font-family: var(--font-mono);
  pointer-events: none;
}

.timeline-val-text {
  fill: var(--text-muted);
  font-size: 10px;
  font-family: var(--font-mono);
  font-weight: 600;
  text-anchor: middle;
}

/* Invisible full-height hit column per bucket — keeps the existing hover/
   click-to-filter JS (which targets .timeline-bar) working unchanged while
   the visible chart becomes a line + gradient area. */
.timeline-bar {
  fill: transparent;
  cursor: pointer;
  transition: fill 0.15s ease;
}

.timeline-bar:hover {
  fill: var(--accent-wash);
}

.timeline-bar.selected {
  fill: rgba(244, 63, 94, 0.14) !important;
}

.timeline-line {
  fill: none;
  stroke: var(--accent);
  stroke-width: 2.5;
  stroke-linecap: round;
  stroke-linejoin: round;
  pointer-events: none;
}

.timeline-area {
  stroke: none;
  pointer-events: none;
}

.timeline-marker {
  fill: var(--accent);
  stroke: var(--bg-card);
  stroke-width: 2;
  transition: r 0.15s ease, fill 0.15s ease;
  pointer-events: none;
}

.timeline-bar:hover + .timeline-marker {
  r: 5.5;
}

.timeline-bar.selected + .timeline-marker {
  fill: var(--danger);
  r: 5.5;
}

.timeline-peak-callout {
  pointer-events: none;
}

.timeline-peak-callout rect {
  fill: var(--accent);
}

.timeline-peak-callout text {
  fill: #ffffff;
  font-size: 11px;
  font-weight: 700;
  font-family: var(--font-sans);
  text-anchor: middle;
}

.timeline-tooltip {
  position: absolute;
  pointer-events: none;
  z-index: 1000;
  opacity: 0;
  background: var(--bg-card);
  border: 1px solid var(--border-focus);
  border-radius: var(--radius-md);
  padding: 10px 14px;
  font-size: 0.8rem;
  color: var(--text-main);
  box-shadow: var(--shadow);
  backdrop-filter: blur(8px);
  transition: opacity 0.1s ease;
  min-width: 220px;
  max-width: 320px;
}

.timeline-tooltip-title {
  font-weight: 700;
  font-size: 0.85rem;
  color: var(--accent);
  margin-bottom: 6px;
  border-bottom: 1px solid var(--border);
  padding-bottom: 4px;
}

.timeline-tooltip-row {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 3px;
  font-size: 0.775rem;
}

.timeline-tooltip-row span {
  color: var(--text-muted);
}

.timeline-tooltip-row b, .timeline-tooltip-row code {
  color: var(--text-main);
  text-align: right;
}

.timeline-tooltip-hint {
  margin-top: 6px;
  font-size: 0.72rem;
  color: var(--text-dim);
  font-style: italic;
  text-align: center;
}

/* Adversary Intelligence in Top Attackers */
.actor-profile-row {
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: 12px 14px;
  margin-bottom: 12px;
  transition: border-color 0.15s ease, transform 0.15s ease;
}

.actor-profile-row:hover {
  border-color: var(--border-light);
  transform: translateX(2px);
}

.actor-ip-col {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.actor-meta-row {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin-top: 8px;
  padding-top: 8px;
  border-top: 1px solid rgba(255, 255, 255, 0.05);
  font-size: 0.75rem;
  color: var(--text-muted);
}

.actor-meta-item {
  display: flex;
  align-items: center;
  gap: 5px;
}

.actor-meta-item svg {
  color: var(--text-dim);
  flex-shrink: 0;
}

.actor-target {
  flex: 1;
  min-width: 140px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.actor-target .mono {
  font-family: var(--font-mono);
  font-size: 0.72rem;
  color: var(--purple);
}

.badge-subtle {
  background: var(--bg-surface-2);
  color: var(--text-muted);
  border: 1px solid var(--border-light);
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

.kbd-hint {
  position: absolute;
  right: 12px;
  top: 50%;
  transform: translateY(-50%);
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 20px;
  height: 20px;
  font-family: var(--font-mono);
  font-size: 0.75rem;
  font-weight: 700;
  color: var(--text-dim);
  background: var(--bg-surface-2);
  border: 1px solid var(--border-light);
  border-radius: var(--radius-sm);
  pointer-events: none;
  transition: opacity 0.15s ease;
}

.search-input:focus ~ .kbd-hint,
.search-input:not(:placeholder-shown) ~ .kbd-hint {
  opacity: 0;
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
  overflow-y: auto;
  max-height: 72vh;
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  background: var(--bg-card);
  position: relative;
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
  position: sticky;
  top: 0;
  z-index: 10;
  box-shadow: 0 1px 0 var(--border);
}

.matches-table thead th.sortable {
  cursor: pointer;
  user-select: none;
  transition: background-color 0.15s ease, color 0.15s ease;
}

.matches-table thead th.sortable:hover {
  background: var(--bg-card-hover);
  color: var(--text-main);
}

.th-content {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 6px;
  width: 100%;
}

.sort-indicator {
  display: inline-flex;
  align-items: center;
  font-size: 0.68rem;
  color: var(--text-dim);
  opacity: 0.35;
  transition: opacity 0.15s ease, color 0.15s ease;
}

.sort-indicator::after {
  content: '▲';
}

.matches-table thead th.sorted-asc .sort-indicator {
  opacity: 1;
  color: var(--accent);
}

.matches-table thead th.sorted-asc .sort-indicator::after {
  content: '▲';
}

.matches-table thead th.sorted-desc .sort-indicator {
  opacity: 1;
  color: var(--accent);
}

.matches-table thead th.sorted-desc .sort-indicator::after {
  content: '▼';
}

.matches-table thead th.sortable:hover .sort-indicator {
  opacity: 0.75;
  color: var(--text-main);
}

/* Column Resizer */
.col-resizer {
  position: absolute;
  top: 0;
  right: 0;
  bottom: 0;
  width: 8px;
  cursor: col-resize;
  user-select: none;
  touch-action: none;
  z-index: 15;
}

.col-resizer::after {
  content: '';
  position: absolute;
  top: 25%;
  bottom: 25%;
  right: 2px;
  width: 2px;
  background-color: var(--border-light);
  border-radius: 1px;
  transition: background-color 0.15s ease;
}

.col-resizer:hover::after,
.col-resizer.active::after {
  background-color: var(--accent);
}

.col-resizer.active {
  background-color: var(--accent-wash);
}

body.col-resizing {
  cursor: col-resize !important;
  user-select: none !important;
  -webkit-user-select: none !important;
}

th.resizing {
  border-right: 2px solid var(--accent);
}

/* Table Density Toggle & Modes */
.btn-density-toggle {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 0.8rem;
}

.btn-density-toggle.active {
  background: var(--accent-glow);
  border-color: var(--accent);
  color: var(--accent);
}

.matches-table.density-compact thead th {
  padding: 7px 10px;
  font-size: 0.8rem;
}

.matches-table.density-compact tbody td {
  padding: 5px 10px;
  font-size: 0.8rem;
}

.matches-table.density-compact .badge {
  padding: 1px 6px;
  font-size: 0.72rem;
}

.matches-table.density-compact .cat-pill {
  font-size: 0.78rem;
}

.matches-table.density-compact .rule-ref {
  font-size: 0.7rem;
  max-width: 180px;
}

.matches-table.density-compact .payload-snippet {
  padding: 1px 4px;
  font-size: 0.75rem;
}

.matches-table.density-compact .cell-time {
  font-size: 0.75rem;
}

/* Active Filter Badges Bar */
.active-filters-bar {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
  padding: 8px 12px;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  margin-bottom: 12px;
}

.active-filters-label {
  font-size: 0.78rem;
  font-weight: 700;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.active-filters-list {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 6px;
}

.active-filter-pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 3px 9px;
  background: var(--bg-surface);
  border: 1px solid var(--border-light);
  border-radius: 9999px;
  font-size: 0.75rem;
  color: var(--text-main);
}

.btn-remove-pill {
  background: none;
  border: none;
  color: var(--text-dim);
  cursor: pointer;
  padding: 0;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 1rem;
  line-height: 1;
  width: 14px;
  height: 14px;
  border-radius: 50%;
  transition: color 0.15s ease, background-color 0.15s ease;
}

.btn-remove-pill:hover {
  color: var(--danger);
  background-color: var(--danger-bg);
}

.btn-clear-all-filters {
  background: none;
  border: none;
  color: var(--accent);
  cursor: pointer;
  font-size: 0.75rem;
  font-weight: 600;
  padding: 3px 8px;
  border-radius: var(--radius-sm);
  margin-left: auto;
  transition: color 0.15s ease, background-color 0.15s ease;
}

.btn-clear-all-filters:hover {
  color: var(--accent);
  text-decoration: underline;
}

/* Click-to-filter on Table Entities */
.filterable-ip {
  cursor: pointer;
  transition: color 0.15s ease;
}

.filterable-ip:hover {
  color: var(--accent);
  text-decoration: underline;
}

.filterable-status {
  cursor: pointer;
  transition: transform 0.1s ease, filter 0.1s ease;
}

.filterable-status:hover {
  filter: brightness(1.25);
  transform: translateY(-1px);
}

.filterable-cat {
  cursor: pointer;
  transition: transform 0.1s ease, filter 0.1s ease;
}

.filterable-cat:hover {
  filter: brightness(1.25);
  transform: translateY(-1px);
}

/* Visual Match Highlight */
mark.hl-match {
  background-color: rgba(244, 63, 94, 0.25);
  color: var(--danger-text);
  border-bottom: 2px solid var(--danger);
  border-radius: 2px;
  padding: 0 2px;
  font-weight: 700;
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
  color: var(--danger-text);
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
  color: var(--code-text);
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
  box-shadow: var(--shadow), 0 0 15px var(--accent-glow);
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

/* Theme Toggle */
.btn-theme-toggle {
  padding: 8px;
  width: 36px;
  height: 36px;
}

.btn-theme-toggle .icon-moon {
  display: none;
}

@media (prefers-color-scheme: dark) {
  :root:where(:not([data-theme="light"])) .btn-theme-toggle .icon-sun {
    display: none;
  }
  :root:where(:not([data-theme="light"])) .btn-theme-toggle .icon-moon {
    display: inline;
  }
}

:root[data-theme="dark"] .btn-theme-toggle .icon-sun {
  display: none;
}

:root[data-theme="dark"] .btn-theme-toggle .icon-moon {
  display: inline;
}

:root[data-theme="light"] .btn-theme-toggle .icon-sun {
  display: inline;
}

:root[data-theme="light"] .btn-theme-toggle .icon-moon {
  display: none;
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
  let currentSort = { column: 'id', order: 'asc' };
  let isCompact = false;
  let isExploit200Active = false;
  let activeTimelineBucket = null;

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
  const btnThemeToggle = document.getElementById('btn-theme-toggle');
  const btnDensityToggle = document.getElementById('btn-density-toggle');
  const densityToggleText = document.getElementById('density-toggle-text');
  const matchesTable = document.querySelector('.matches-table');
  const activeFiltersBar = document.getElementById('active-filters-bar');
  const activeFiltersList = document.getElementById('active-filters-list');
  const btnTriage200 = document.getElementById('btn-triage-200');

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

  // Visual match highlighting inside target URL
  function highlightMatch(target, match) {
    if (!target) return '';
    if (!match) return escapeHtml(target);
    const targetLower = target.toLowerCase();
    const matchLower = match.toLowerCase();
    const idx = targetLower.indexOf(matchLower);
    if (idx !== -1) {
      const before = target.slice(0, idx);
      const matched = target.slice(idx, idx + match.length);
      const after = target.slice(idx + match.length);
      return `${escapeHtml(before)}<mark class="hl-match">${escapeHtml(matched)}</mark>${escapeHtml(after)}`;
    }
    return escapeHtml(target);
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

  // ---------------------------------------------------------------------------
  // Sorting Engine (Type-aware, Stable)
  // ---------------------------------------------------------------------------
  function sortMatches(list) {
    if (!currentSort.column) return list;
    const col = currentSort.column;
    const dir = currentSort.order === 'desc' ? -1 : 1;

    list.sort((a, b) => {
      let res = 0;
      if (col === 'id') {
        res = (a.id || 0) - (b.id || 0);
      } else if (col === 'status') {
        res = (Number(a.status) || 0) - (Number(b.status) || 0);
      } else if (col === 'impact') {
        res = (Number(a.impact) || 0) - (Number(b.impact) || 0);
      } else if (col === 'time') {
        const ta = a.time ? Date.parse(a.time.replace(' ', 'T')) || 0 : 0;
        const tb = b.time ? Date.parse(b.time.replace(' ', 'T')) || 0 : 0;
        res = ta - tb;
      } else if (col === 'ip') {
        res = String(a.ip || '').localeCompare(String(b.ip || ''), undefined, { numeric: true, sensitivity: 'base' });
      } else if (col === 'cat') {
        const ca = String(a.cat || a.tag || '');
        const cb = String(b.cat || b.tag || '');
        res = ca.localeCompare(cb);
      } else if (col === 'target') {
        res = String(a.target || '').localeCompare(String(b.target || ''));
      } else if (col === 'match') {
        res = String(a.match || '').localeCompare(String(b.match || ''));
      }
      if (res === 0) {
        res = (a.id || 0) - (b.id || 0);
      }
      return res * dir;
    });
    return list;
  }

  function updateSortHeaders() {
    const allTh = document.querySelectorAll('.matches-table thead th.sortable');
    allTh.forEach(th => {
      const col = th.dataset.sort;
      th.classList.remove('sorted-asc', 'sorted-desc');
      th.removeAttribute('aria-sort');
      if (col === currentSort.column) {
        th.classList.add(currentSort.order === 'asc' ? 'sorted-asc' : 'sorted-desc');
        th.setAttribute('aria-sort', currentSort.order === 'asc' ? 'ascending' : 'descending');
      }
    });
  }

  // ---------------------------------------------------------------------------
  // Active Filter Badges
  // ---------------------------------------------------------------------------
  function updateTriageButton() {
    if (!btnTriage200) return;
    const count = (reportData.summary && reportData.summary.exploit_200_count) || 0;
    if (isExploit200Active) {
      btnTriage200.innerHTML = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg> Clear Exploit 200 Triage Filter';
      btnTriage200.classList.add('active');
    } else {
      btnTriage200.innerHTML = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"></polygon></svg> Filter High-Severity HTTP 200 Exploits (' + Number(count).toLocaleString() + ')';
      btnTriage200.classList.remove('active');
    }
  }

  function updateActiveFilterBadges() {
    if (!activeFiltersBar || !activeFiltersList) return;

    const q = (searchInput?.value || '').trim();
    const cat = filterCat?.value || 'all';
    const sev = filterSev?.value || 'all';
    const status = filterStatus?.value || 'all';
    const vec = filterVector?.value || 'all';

    const badges = [];

    if (isExploit200Active) {
      badges.push({
        type: 'exploit200',
        label: '🚨 Triage: High-Severity HTTP 200 Exploits',
      });
    }
    if (activeTimelineBucket) {
      badges.push({
        type: 'timeline',
        label: `📅 Time: ${escapeHtml(activeTimelineBucket.label)}`,
      });
    }
    if (q) {
      badges.push({
        type: 'search',
        label: `Search: "${escapeHtml(q)}"`,
      });
    }
    if (cat !== 'all') {
      const rawText = filterCat.options[filterCat.selectedIndex]?.text || cat;
      const cleanText = rawText.replace(/\s*\(\d+[\d,]*\)$/, '');
      badges.push({
        type: 'category',
        label: `Category: ${escapeHtml(cleanText)}`,
      });
    }
    if (sev !== 'all') {
      const rawText = filterSev.options[filterSev.selectedIndex]?.text || sev;
      badges.push({
        type: 'severity',
        label: `Severity: ${escapeHtml(rawText)}`,
      });
    }
    if (status !== 'all') {
      const rawText = filterStatus.options[filterStatus.selectedIndex]?.text || status;
      const cleanText = rawText.replace(/\s*\(\d+[\d,]*\)$/, '');
      badges.push({
        type: 'status',
        label: `Status: ${escapeHtml(cleanText)}`,
      });
    }
    if (vec !== 'all') {
      const rawText = filterVector.options[filterVector.selectedIndex]?.text || vec;
      const cleanText = rawText.replace(/\s*\(\d+[\d,]*\)$/, '');
      badges.push({
        type: 'vector',
        label: `Vector: ${escapeHtml(cleanText)}`,
      });
    }

    if (badges.length === 0) {
      activeFiltersBar.style.display = 'none';
      activeFiltersList.innerHTML = '';
      return;
    }

    activeFiltersBar.style.display = 'flex';
    activeFiltersList.innerHTML = badges.map(b => `
      <span class="active-filter-pill" data-filter-type="${b.type}">
        <span>${b.label}</span>
        <button type="button" class="btn-remove-pill" data-remove-filter="${b.type}" title="Remove filter" aria-label="Remove filter">&times;</button>
      </span>
    `).join('');
  }

  // ---------------------------------------------------------------------------
  // Filter Application
  // ---------------------------------------------------------------------------
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
      if (isExploit200Active && !m.is_exploit_200) return false;
      if (activeTimelineBucket && (!m.time || !m.time.startsWith(activeTimelineBucket.key))) return false;
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

    sortMatches(filteredMatches);
    currentPage = 1;
    openDetailId = null;
    render();
    updateActiveFilterBadges();
  }

  // ---------------------------------------------------------------------------
  // Table Rendering
  // ---------------------------------------------------------------------------
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
      const targetHighlighted = highlightMatch(m.target, m.match);

      rows.push(`
        <tr class="match-row" data-id="${m.id}">
          <td class="cell-num">${rowNum}</td>
          <td class="cell-time">${escapeHtml(m.time || '-')}</td>
          <td>
            <div class="ip-wrapper">
              <span class="mono filterable-ip" data-filter-ip="${escapeHtml(m.ip)}" title="Click to filter by IP: ${escapeHtml(m.ip)}">${escapeHtml(m.ip)}</span>
              <button type="button" class="btn-copy" data-copy-action="ip" title="Copy IP" aria-label="Copy IP">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
              </button>
            </div>
          </td>
          <td>
            <span class="method-badge">${escapeHtml(m.method || '-')}</span>
            <span class="badge ${statusBadgeClass} filterable-status" data-filter-status="${escapeHtml(String(m.status))}" title="Click to filter by HTTP ${escapeHtml(String(m.status))}">${escapeHtml(String(m.status))}</span>
          </td>
          <td>
            <span class="badge ${sevBadgeClass}">Impact ${m.impact}</span>
          </td>
          <td>
            <div class="cat-pill filterable-cat" data-filter-cat="${escapeHtml(m.tag)}" title="Click to filter by category: ${escapeHtml(m.cat || m.tag)}">${escapeHtml(m.cat || m.tag)}</div>
            <div class="rule-ref" title="${escapeHtml(m.desc)}">[${escapeHtml(String(m.rule))}] ${escapeHtml(m.desc)}</div>
          </td>
          <td>
            <div class="target-wrapper">
              <span class="badge badge-vector">${escapeHtml(m.vector || 'url')}</span>
              <span class="target-url mono" title="${escapeHtml(m.target)}">${targetHighlighted}</span>
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
                      <code>${targetHighlighted}</code>
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

  // ---------------------------------------------------------------------------
  // Pointer Events Column Resizer
  // ---------------------------------------------------------------------------
  function initColumnResizing() {
    const table = document.querySelector('.matches-table');
    if (!table) return;
    const resizers = table.querySelectorAll('.col-resizer');

    resizers.forEach(resizer => {
      resizer.addEventListener('pointerdown', (e) => {
        e.preventDefault();
        e.stopPropagation();

        const th = resizer.closest('th');
        if (!th) return;

        if (table.style.tableLayout !== 'fixed') {
          const allTh = table.querySelectorAll('thead th');
          allTh.forEach(h => {
            h.style.width = `${h.getBoundingClientRect().width}px`;
          });
          table.style.tableLayout = 'fixed';
        }

        const startX = e.clientX;
        const startWidth = th.getBoundingClientRect().width;
        const minWidth = parseInt(th.dataset.minWidth, 10) || 50;

        resizer.setPointerCapture(e.pointerId);
        resizer.classList.add('active');
        th.classList.add('resizing');
        document.body.classList.add('col-resizing');

        function onPointerMove(moveEvent) {
          if (moveEvent.pointerId !== e.pointerId) return;
          const deltaX = moveEvent.clientX - startX;
          const newWidth = Math.max(minWidth, startWidth + deltaX);
          th.style.width = `${newWidth}px`;
        }

        function onPointerUp(upEvent) {
          if (upEvent.pointerId !== e.pointerId) return;
          resizer.classList.remove('active');
          th.classList.remove('resizing');
          document.body.classList.remove('col-resizing');

          try {
            resizer.releasePointerCapture(upEvent.pointerId);
          } catch (err) {}

          resizer.removeEventListener('pointermove', onPointerMove);
          resizer.removeEventListener('pointerup', onPointerUp);
          resizer.removeEventListener('pointercancel', onPointerUp);
        }

        resizer.addEventListener('pointermove', onPointerMove);
        resizer.addEventListener('pointerup', onPointerUp);
        resizer.addEventListener('pointercancel', onPointerUp);
      });
    });
  }

  // ---------------------------------------------------------------------------
  // Column Header Sorting Interaction
  // ---------------------------------------------------------------------------
  function initColumnSorting() {
    const thead = document.querySelector('.matches-table thead');
    if (!thead) return;

    thead.addEventListener('click', (e) => {
      if (e.target.closest('.col-resizer')) return;

      const th = e.target.closest('th.sortable');
      if (!th) return;

      const col = th.dataset.sort;
      if (!col) return;

      if (currentSort.column === col) {
        currentSort.order = currentSort.order === 'asc' ? 'desc' : 'asc';
      } else {
        currentSort.column = col;
        currentSort.order = (col === 'impact' || col === 'status') ? 'desc' : 'asc';
      }

      updateSortHeaders();
      sortMatches(filteredMatches);
      currentPage = 1;
      render();
    });

    updateSortHeaders();
  }

  // ---------------------------------------------------------------------------
  // Light / Dark Theme Toggle
  // ---------------------------------------------------------------------------
  function initThemeToggle() {
    if (!btnThemeToggle) return;

    btnThemeToggle.addEventListener('click', () => {
      const isDark = document.documentElement.getAttribute('data-theme') === 'dark' ||
        (!document.documentElement.hasAttribute('data-theme') &&
          window.matchMedia('(prefers-color-scheme: dark)').matches);
      const next = isDark ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      try {
        localStorage.setItem('scalp-theme', next);
      } catch (err) {
        // Storage unavailable (private mode) — theme still applies for this view.
      }
      showToast('Switched to ' + next + ' theme');
    });
  }

  // ---------------------------------------------------------------------------
  // Table Density Toggle
  // ---------------------------------------------------------------------------
  function initDensityToggle() {
    if (!btnDensityToggle || !matchesTable) return;

    btnDensityToggle.addEventListener('click', () => {
      isCompact = !isCompact;
      if (isCompact) {
        matchesTable.classList.add('density-compact');
        if (densityToggleText) densityToggleText.textContent = 'Density: Compact';
        btnDensityToggle.classList.add('active');
        showToast('Switched to Compact table density');
      } else {
        matchesTable.classList.remove('density-compact');
        if (densityToggleText) densityToggleText.textContent = 'Density: Comfortable';
        btnDensityToggle.classList.remove('active');
        showToast('Switched to Comfortable table density');
      }
    });
  }

  // ---------------------------------------------------------------------------
  // Active Filter Badges Removal Delegation
  // ---------------------------------------------------------------------------
  function initActiveFilters() {
    if (!activeFiltersBar) return;

    activeFiltersBar.addEventListener('click', (e) => {
      const removeBtn = e.target.closest('.btn-remove-pill');
      if (removeBtn) {
        const ftype = removeBtn.dataset.removeFilter;
        if (ftype === 'search' && searchInput) searchInput.value = '';
        if (ftype === 'category' && filterCat) filterCat.value = 'all';
        if (ftype === 'severity' && filterSev) filterSev.value = 'all';
        if (ftype === 'status' && filterStatus) filterStatus.value = 'all';
        if (ftype === 'vector' && filterVector) filterVector.value = 'all';
        if (ftype === 'exploit200') {
          isExploit200Active = false;
          updateTriageButton();
        }
        if (ftype === 'timeline') {
          activeTimelineBucket = null;
          document.querySelectorAll('.timeline-bar.selected').forEach(b => b.classList.remove('selected'));
        }
        applyFilters();
        return;
      }

      const clearAllBtn = e.target.closest('#btn-clear-all-filters');
      if (clearAllBtn) {
        if (searchInput) searchInput.value = '';
        if (filterCat) filterCat.value = 'all';
        if (filterSev) filterSev.value = 'all';
        if (filterStatus) filterStatus.value = 'all';
        if (filterVector) filterVector.value = 'all';
        isExploit200Active = false;
        activeTimelineBucket = null;
        document.querySelectorAll('.timeline-bar.selected').forEach(b => b.classList.remove('selected'));
        updateTriageButton();
        applyFilters();
      }
    });
  }

  // ---------------------------------------------------------------------------
  // Keyboard Shortcuts Navigation
  // ---------------------------------------------------------------------------
  function initKeyboardShortcuts() {
    window.addEventListener('keydown', (e) => {
      const activeEl = document.activeElement;
      const isInputFocused = activeEl && ['INPUT', 'TEXTAREA', 'SELECT'].includes(activeEl.tagName);

      // '/' focuses search
      if (e.key === '/' && !isInputFocused) {
        e.preventDefault();
        if (searchInput) {
          searchInput.focus();
          searchInput.select();
        }
        return;
      }

      // 'Escape' clears search or closes expanded detail row
      if (e.key === 'Escape') {
        if (activeEl === searchInput) {
          if (searchInput.value) {
            searchInput.value = '';
            applyFilters();
          } else {
            searchInput.blur();
          }
          return;
        }
        if (openDetailId !== null) {
          openDetailId = null;
          render();
          return;
        }
        if (searchInput && searchInput.value) {
          searchInput.value = '';
          applyFilters();
          return;
        }
      }

      // '[' and ']' or Left/Right arrows page back and forward
      if (!isInputFocused) {
        const total = filteredMatches.length;
        const totalPages = Math.max(1, Math.ceil(total / pageSize));

        if (e.key === '[' || e.key === 'ArrowLeft') {
          if (currentPage > 1) {
            e.preventDefault();
            currentPage--;
            render();
          }
        } else if (e.key === ']' || e.key === 'ArrowRight') {
          if (currentPage < totalPages) {
            e.preventDefault();
            currentPage++;
            render();
          }
        }
      }
    });
  }

  // ---------------------------------------------------------------------------
  // Event Handlers & Delegation
  // ---------------------------------------------------------------------------
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
      isExploit200Active = false;
      activeTimelineBucket = null;
      document.querySelectorAll('.timeline-bar.selected').forEach(b => b.classList.remove('selected'));
      updateTriageButton();
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

  // Table click delegation (Copy buttons, Filter clicks & Row expansion)
  if (tableBody) {
    tableBody.addEventListener('click', (e) => {
      // 1. Copy buttons
      const copyBtn = e.target.closest('.btn-copy');
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

      // 2. Click-to-filter on IP
      const filterIpEl = e.target.closest('.filterable-ip');
      if (filterIpEl) {
        e.stopPropagation();
        const ip = filterIpEl.dataset.filterIp;
        if (ip && searchInput) {
          searchInput.value = ip;
          applyFilters();
          showToast(`Filtered by IP: ${ip}`);
        }
        return;
      }

      // 3. Click-to-filter on Category
      const filterCatEl = e.target.closest('.filterable-cat');
      if (filterCatEl) {
        e.stopPropagation();
        const cat = filterCatEl.dataset.filterCat;
        if (cat && filterCat) {
          const opt = Array.from(filterCat.options).find(o => o.value === cat);
          if (opt) {
            filterCat.value = cat;
          } else if (searchInput) {
            searchInput.value = cat;
          }
          applyFilters();
          showToast(`Filtered by Category: ${cat}`);
        }
        return;
      }

      // 4. Click-to-filter on Status
      const filterStatusEl = e.target.closest('.filterable-status');
      if (filterStatusEl) {
        e.stopPropagation();
        const st = filterStatusEl.dataset.filterStatus;
        if (st && filterStatus) {
          const opt = Array.from(filterStatus.options).find(o => o.value === st);
          if (opt) {
            filterStatus.value = st;
          } else if (searchInput) {
            searchInput.value = st;
          }
          applyFilters();
          showToast(`Filtered by HTTP ${st}`);
        }
        return;
      }

      // 5. Row expansion
      const row = e.target.closest('tr.match-row');
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

  // ---------------------------------------------------------------------------
  // Timeline Hover Tooltip & Click-to-filter
  // ---------------------------------------------------------------------------
  function initTimelineInteractions() {
    const tooltip = document.getElementById('timeline-tooltip');
    const chartWrapper = document.querySelector('.timeline-chart-wrapper');
    if (!chartWrapper || !tooltip) return;

    chartWrapper.addEventListener('mousemove', (e) => {
      const bar = e.target.closest('.timeline-bar');
      if (!bar) {
        tooltip.style.opacity = '0';
        return;
      }
      const label = bar.dataset.label || '';
      const count = bar.dataset.count || '0';
      const pct = bar.dataset.pct || '';
      const cat = bar.dataset.cat || '';
      const ip = bar.dataset.ip || '';

      tooltip.innerHTML = `
        <div class="timeline-tooltip-title">📅 ${escapeHtml(label)}</div>
        <div class="timeline-tooltip-row"><span>Attacks:</span> <b>${escapeHtml(count)}</b> ${pct ? '(' + escapeHtml(pct) + ')' : ''}</div>
        <div class="timeline-tooltip-row"><span>Top Category:</span> <b>${escapeHtml(cat)}</b></div>
        <div class="timeline-tooltip-row"><span>Peak Adversary:</span> <code>${escapeHtml(ip)}</code></div>
        <div class="timeline-tooltip-hint">👆 Click bar to filter table to this time slice</div>
      `;

      const wrapperRect = chartWrapper.getBoundingClientRect();
      const x = e.clientX - wrapperRect.left + 15;
      const y = e.clientY - wrapperRect.top - 10;
      tooltip.style.left = `${Math.max(10, Math.min(x, wrapperRect.width - 260))}px`;
      tooltip.style.top = `${Math.max(10, y)}px`;
      tooltip.style.opacity = '1';
    });

    chartWrapper.addEventListener('mouseleave', () => {
      tooltip.style.opacity = '0';
    });

    chartWrapper.addEventListener('click', (e) => {
      const bar = e.target.closest('.timeline-bar');
      if (!bar) return;
      const key = bar.dataset.bucketKey;
      const label = bar.dataset.label || key;
      if (!key) return;

      if (activeTimelineBucket && activeTimelineBucket.key === key) {
        activeTimelineBucket = null;
        document.querySelectorAll('.timeline-bar.selected').forEach(b => b.classList.remove('selected'));
        applyFilters();
        showToast('Cleared timeline filter');
      } else {
        activeTimelineBucket = { key: key, label: label };
        document.querySelectorAll('.timeline-bar.selected').forEach(b => b.classList.remove('selected'));
        document.querySelectorAll(`.timeline-bar[data-bucket-key="${key}"]`).forEach(b => b.classList.add('selected'));
        applyFilters();
        showToast(`Filtered to ${label}`);
        const exp = document.getElementById('interactive-explorer');
        if (exp) exp.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    });
  }

  // Global utilities attached for UI interactions
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
    },
    filterExploit200: function() {
      isExploit200Active = !isExploit200Active;
      updateTriageButton();
      applyFilters();
      if (isExploit200Active) {
        showToast('Filtered to High-Severity HTTP 200 Exploits');
        const exp = document.getElementById('interactive-explorer');
        if (exp) exp.scrollIntoView({ behavior: 'smooth', block: 'start' });
      } else {
        showToast('Cleared Exploit 200 triage filter');
      }
    },
    switchTimelineView: function(view) {
      const dailySvg = document.getElementById('timeline-svg-daily');
      const hourlySvg = document.getElementById('timeline-svg-hourly');
      const btnDaily = document.getElementById('btn-timeline-daily');
      const btnHourly = document.getElementById('btn-timeline-hourly');

      if (view === 'daily') {
        if (dailySvg) dailySvg.style.display = 'block';
        if (hourlySvg) hourlySvg.style.display = 'none';
        if (btnDaily) btnDaily.classList.add('active');
        if (btnHourly) btnHourly.classList.remove('active');
        showToast('Switched to Daily Timeline view');
      } else {
        if (dailySvg) dailySvg.style.display = 'none';
        if (hourlySvg) hourlySvg.style.display = 'block';
        if (btnDaily) btnDaily.classList.remove('active');
        if (btnHourly) btnHourly.classList.add('active');
        showToast('Switched to Hourly Timeline breakdown');
      }
    }
  };

  // Initialization
  initColumnResizing();
  initColumnSorting();
  initThemeToggle();
  initDensityToggle();
  initActiveFilters();
  initKeyboardShortcuts();
  initTimelineInteractions();
  sortMatches(filteredMatches);
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

        # Precompute Forensics Aggregates & Build JSON dataset in a single O(N) pass
        ip_counts = Counter()
        ip_tag_counts: Dict[str, Counter] = defaultdict(Counter)
        target_counts = Counter()
        target_tag_counts: Dict[str, Counter] = defaultdict(Counter)
        cat_counts = Counter()
        status_counts = Counter()
        vector_counts = Counter()
        json_matches = []

        for idx, m in enumerate(result.matches, 1):
            ip = m.entry.ip
            url = m.entry.url
            tag = m.tag
            status = m.entry.status_code
            vector = getattr(m, "matched_field", "url")
            impact = int(m.rule.impact or 0)

            ip_counts[ip] += 1
            ip_tag_counts[ip][tag] += 1
            target_counts[url] += 1
            target_tag_counts[url][tag] += 1
            cat_counts[tag] += 1
            status_counts[status] += 1
            vector_counts[vector] += 1

            ts_str = m.entry.timestamp.strftime("%Y-%m-%d %H:%M:%S") if m.entry.timestamp else ""
            json_matches.append({
                "id": idx,
                "time": ts_str,
                "ip": ip,
                "method": m.entry.method,
                "status": status,
                "impact": impact,
                "tag": tag,
                "cat": ATTACK_NAMES.get(tag.lower(), tag.upper()),
                "rule": m.rule.rule_id,
                "desc": m.rule.description,
                "target": url,
                "vector": vector,
                "match": m.matched_string,
                "ua": m.entry.user_agent or "",
                "ref": m.entry.referrer or "",
                "raw": m.entry.raw_line,
                "is_exploit_200": bool(status == 200 and impact >= 7),
            })

        top_ips = ip_counts.most_common(8)
        top_targets = target_counts.most_common(8)
        top_cats = cat_counts.most_common()
        top_statuses = sorted(status_counts.items(), key=lambda x: x[1], reverse=True)

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

        breach_triage_html = cls._build_breach_triage_panel(result.matches)
        timeline_section_html = cls._build_timeline_section(result.matches)

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
            "  <script>(function(){try{var t=localStorage.getItem('scalp-theme');"
            "if(t==='light'||t==='dark'){document.documentElement.setAttribute('data-theme',t);}"
            "}catch(e){}})();</script>",
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
            '      <div style="display: flex; align-items: center; gap: 12px;">',
            f'        <div>{status_badge_html}</div>',
            '        <button type="button" id="btn-theme-toggle" class="btn btn-secondary btn-theme-toggle" title="Toggle light / dark theme" aria-label="Toggle theme">',
            '          <svg class="icon-sun" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/></svg>',
            '          <svg class="icon-moon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>',
            '        </button>',
            '      </div>',
            '    </header>',
            kpi_cards_html,
            breach_triage_html,
            timeline_section_html,
            anathema_section_html,
            top_stats_html,
            cls._build_explorer_markup(filter_options_html, total_matches, initial_rows_html),
            '    <footer>',
            '      Scalp! Modernized Edition &bull; Maintained by <a href="https://www.DragonJAR.org" target="_blank" rel="noopener noreferrer">DragonJAR SAS</a>',
            '    </footer>',
            '  </div>',
            '  <div id="scalp-toast" class="scalp-toast"></div>',
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
        if total_lines > 0:
            if processed_lines == total_lines:
                total_sub = f"100% of {total_lines:,} total log records"
            elif processed_lines < total_lines:
                sample_rate = (processed_lines / total_lines) * 100.0
                total_sub = f"Sampled: {sample_rate:.1f}% ({processed_lines:,} of {total_lines:,} records)"
            else:
                total_sub = f"of {total_lines:,} total log records"
        else:
            total_sub = "Complete scan"

        anathema_val = f"{banned_count:,}" if has_anathema else "N/A"
        anathema_sub = (
            "Severity &ge; 10 automatically banned"
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
    def _build_breach_triage_panel(cls, matches: List[Any]) -> str:
        exploit_matches = [
            m for m in matches
            if m.entry.status_code == 200 and int(m.rule.impact or 0) >= 7
        ]
        exploit_count = len(exploit_matches)

        if exploit_count == 0:
            return """
    <div class="breach-triage-panel breach-triage-clean">
      <div class="breach-triage-header">
        <div class="breach-triage-title-group">
          <h3 class="breach-triage-title">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
            Exploitation Outcome Triage — No High-Severity HTTP 200 Responses
          </h3>
          <span class="badge badge-success">Clean Outcome</span>
        </div>
      </div>
      <div class="breach-triage-body">
        <div class="breach-triage-stat">
          <div class="breach-triage-stat-val">0</div>
          <div class="breach-triage-stat-label">HTTP 200 Exploitation Events</div>
          <div class="breach-triage-stat-sub">No high-severity attacks (impact &ge; 7) returned HTTP 200 OK. All attacks were blocked or failed.</div>
        </div>
      </div>
    </div>
"""

        target_count = len(set(m.entry.url for m in exploit_matches))
        actor_count = len(set(m.entry.ip for m in exploit_matches))
        top_cats = Counter(m.tag for m in exploit_matches).most_common(5)

        tag_badges = "".join(
            f'<span class="badge badge-danger">{html.escape(ATTACK_NAMES.get(tag.lower(), tag.upper()))}: {count:,}</span>'
            for tag, count in top_cats
        )

        return f"""
    <div class="breach-triage-panel">
      <div class="breach-triage-header">
        <div class="breach-triage-title-group">
          <h3 class="breach-triage-title">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            Exploitation Outcome Triage — High Risk HTTP 200 Responses
          </h3>
          <span class="badge badge-danger">High Breach Risk ({exploit_count:,} events)</span>
        </div>
        <div class="breach-triage-actions">
          <button type="button" id="btn-triage-200" class="btn-triage" data-count="{exploit_count}" onclick="ScalpReport.filterExploit200()">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"></polygon></svg>
            Filter High-Severity HTTP 200 Exploits ({exploit_count:,})
          </button>
        </div>
      </div>
      <div class="breach-triage-body">
        <div class="breach-triage-stat">
          <div class="breach-triage-stat-val">{exploit_count:,}</div>
          <div class="breach-triage-stat-label">HTTP 200 Exploitation Events</div>
          <div class="breach-triage-stat-sub">High-severity rules (impact &ge; 7) returning 200 OK — priority forensic review</div>
        </div>
        <div class="breach-triage-stat">
          <div class="breach-triage-stat-val" style="color: var(--warning);">{target_count:,}</div>
          <div class="breach-triage-stat-label">Target Endpoints</div>
          <div class="breach-triage-stat-sub">Distinct vulnerable application URLs receiving HTTP 200 responses</div>
        </div>
        <div class="breach-triage-stat">
          <div class="breach-triage-stat-val" style="color: var(--purple);">{actor_count:,}</div>
          <div class="breach-triage-stat-label">Adversary Sources</div>
          <div class="breach-triage-stat-sub">Distinct client IPs executing successful exploit attempts</div>
        </div>
        <div class="breach-triage-stat">
          <div class="breach-triage-stat-label">Critical Attack Vectors</div>
          <div class="breach-triage-tags">
            {tag_badges}
          </div>
          <div class="breach-triage-stat-sub" style="margin-top: 6px;">Top attack classes yielding HTTP 200 responses</div>
        </div>
      </div>
    </div>
"""

    @classmethod
    def _build_timeline_section(cls, matches: List[Any]) -> str:
        day_buckets_dict: Dict[str, List[Any]] = defaultdict(list)
        hour_buckets_dict: Dict[str, List[Any]] = defaultdict(list)

        for m in matches:
            if not m.entry.timestamp:
                continue
            day_key = m.entry.timestamp.strftime("%Y-%m-%d")
            hour_key = m.entry.timestamp.strftime("%Y-%m-%d %H")
            day_buckets_dict[day_key].append(m)
            hour_buckets_dict[hour_key].append(m)

        if not day_buckets_dict:
            return """
    <div class="section-card timeline-panel">
      <div class="section-header">
        <h2 class="section-title">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
          Attack Activity Timeline &amp; Campaign Distribution
        </h2>
      </div>
      <div style="padding: 24px; text-align: center; color: var(--text-dim);">
        No timestamp metadata found in analyzed log records to construct temporal distribution.
      </div>
    </div>
"""

        total_matches = len(matches)

        # Prepare daily buckets
        daily_buckets = []
        for d_key in sorted(day_buckets_dict.keys()):
            d_matches = day_buckets_dict[d_key]
            d_count = len(d_matches)
            top_cat_tag = Counter(m.tag for m in d_matches).most_common(1)[0][0]
            top_cat_name = ATTACK_NAMES.get(top_cat_tag.lower(), top_cat_tag.upper())
            peak_ip = Counter(m.entry.ip for m in d_matches).most_common(1)[0][0]
            first_dt = d_matches[0].entry.timestamp
            daily_buckets.append({
                "key": d_key,
                "label": first_dt.strftime("%d/%b (%a)") if first_dt else d_key,
                "count": d_count,
                "pct": (d_count / total_matches * 100.0) if total_matches > 0 else 0.0,
                "cat": top_cat_name,
                "ip": peak_ip,
            })

        # Prepare hourly buckets
        hourly_buckets = []
        for h_key in sorted(hour_buckets_dict.keys()):
            h_matches = hour_buckets_dict[h_key]
            h_count = len(h_matches)
            top_cat_tag = Counter(m.tag for m in h_matches).most_common(1)[0][0]
            top_cat_name = ATTACK_NAMES.get(top_cat_tag.lower(), top_cat_tag.upper())
            peak_ip = Counter(m.entry.ip for m in h_matches).most_common(1)[0][0]
            first_dt = h_matches[0].entry.timestamp
            hourly_buckets.append({
                "key": h_key,
                "label": first_dt.strftime("%d/%b %H:00") if first_dt else h_key,
                "count": h_count,
                "pct": (h_count / total_matches * 100.0) if total_matches > 0 else 0.0,
                "cat": top_cat_name,
                "ip": peak_ip,
            })

        daily_svg = cls._render_timeline_svg(daily_buckets, svg_id="timeline-svg-daily", is_hourly=False)
        hourly_svg = cls._render_timeline_svg(hourly_buckets, svg_id="timeline-svg-hourly", is_hourly=True)

        return f"""
    <div class="section-card timeline-panel">
      <div class="section-header">
        <h2 class="section-title">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
          Attack Activity Timeline &amp; Campaign Distribution
        </h2>
        <div class="timeline-view-toggles">
          <button type="button" id="btn-timeline-daily" class="btn btn-sm btn-secondary active" onclick="ScalpReport.switchTimelineView('daily')">Daily View ({len(daily_buckets)}d)</button>
          <button type="button" id="btn-timeline-hourly" class="btn btn-sm btn-secondary" onclick="ScalpReport.switchTimelineView('hourly')">Hourly Breakdown ({len(hourly_buckets)}h)</button>
        </div>
      </div>
      <div class="timeline-chart-wrapper">
        <div id="timeline-tooltip" class="timeline-tooltip"></div>
        {daily_svg}
        {hourly_svg}
      </div>
    </div>
"""

    @classmethod
    def _render_timeline_svg(cls, buckets: List[Dict[str, Any]], svg_id: str, is_hourly: bool = False) -> str:
        """Renders a smooth gradient-filled line chart (Copilot Money-style trend
        line) with an invisible per-bucket hit column for hover/click-to-filter.
        The hit columns keep the ``.timeline-bar`` class and ``data-*`` attributes
        the JS interaction layer already expects, so no JS changes are needed."""
        n_buckets = len(buckets)
        if n_buckets == 0:
            return ""

        max_count = max(b["count"] for b in buckets)
        max_count_safe = max(1, max_count)

        padding_left = 65.0
        padding_right = 35.0

        if is_hourly:
            col_w = 16.0
            svg_width = max(960.0, padding_left + padding_right + (n_buckets * col_w))
            svg_style = f"display: none; min-width: {int(svg_width)}px;" if svg_width > 960 else "display: none; width: 100%;"
        else:
            svg_width = 960.0
            chart_w = svg_width - padding_left - padding_right
            col_w = chart_w / max(1, n_buckets)
            svg_style = "display: block; width: 100%;"

        svg_height = 220.0
        padding_top = 28.0
        padding_bottom = 44.0
        chart_h = svg_height - padding_top - padding_bottom
        baseline_y = padding_top + chart_h

        # Grid lines and Y-axis labels
        grid_lines = []
        for frac in [1.0, 0.75, 0.5, 0.25, 0.0]:
            y = padding_top + chart_h - (frac * chart_h)
            val = int(round(frac * max_count_safe))
            grid_lines.append(
                f'<line class="timeline-grid-line" x1="{padding_left}" y1="{y:.1f}" x2="{svg_width - padding_right}" y2="{y:.1f}"/>\n'
                f'        <text class="timeline-axis-text" x="{padding_left - 8}" y="{y + 4:.1f}" text-anchor="end">{val:,}</text>'
            )
        grid_markup = "\n        ".join(grid_lines)

        # One coordinate per bucket, centered in its column
        points: List[Tuple[float, float]] = []
        for idx, b in enumerate(buckets):
            cx = padding_left + (idx * col_w) + (col_w / 2.0)
            cy = baseline_y - ((b["count"] / max_count_safe) * chart_h if max_count_safe > 0 else 0.0)
            points.append((cx, cy))

        # Smooth line through the points (quadratic bezier via midpoints)
        line_parts = [f"M {points[0][0]:.1f},{points[0][1]:.1f}"]
        for i in range(1, n_buckets):
            x0, y0 = points[i - 1]
            x1, y1 = points[i]
            mx, my = (x0 + x1) / 2.0, (y0 + y1) / 2.0
            line_parts.append(f"Q {x0:.1f},{y0:.1f} {mx:.1f},{my:.1f}")
        line_parts.append(f"L {points[-1][0]:.1f},{points[-1][1]:.1f}")
        line_path = " ".join(line_parts)
        area_path = (
            f"{line_path} L {points[-1][0]:.1f},{baseline_y:.1f} "
            f"L {points[0][0]:.1f},{baseline_y:.1f} Z"
        )

        grad_id = f"{svg_id}-grad"
        defs_markup = f"""<defs>
          <linearGradient id="{grad_id}" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" style="stop-color: var(--accent); stop-opacity: 0.28"/>
            <stop offset="100%" style="stop-color: var(--accent); stop-opacity: 0"/>
          </linearGradient>
        </defs>"""

        # Peak-value callout, mirroring the floating value pill in the reference dashboard
        peak_idx = max(range(n_buckets), key=lambda i: buckets[i]["count"])
        peak_count = buckets[peak_idx]["count"]
        peak_callout = ""
        if peak_count > 0:
            px, py = points[peak_idx]
            label = f"Peak: {peak_count:,} attacks"
            est_w = max(90.0, 16.0 + len(label) * 6.2)
            bx = min(max(px, padding_left + est_w / 2.0), svg_width - padding_right - est_w / 2.0)
            by = max(14.0, py - 34.0)
            peak_callout = f"""
        <g class="timeline-peak-callout">
          <rect x="{bx - est_w / 2.0:.1f}" y="{by:.1f}" width="{est_w:.1f}" height="22" rx="11"/>
          <text x="{bx:.1f}" y="{by + 15.0:.1f}">{html.escape(label)}</text>
        </g>"""

        # Hit columns (hover/click) + point markers + axis labels
        points_markup = []
        for idx, b in enumerate(buckets):
            x = padding_left + (idx * col_w)
            cx, cy = points[idx]
            marker_r = 4.5 if idx == n_buckets - 1 else 3.0

            show_axis = True
            if is_hourly and n_buckets > 24:
                label_str = b["label"]
                show_axis = (idx % 6 == 0) or ("00:00" in label_str) or ("12:00" in label_str)
            axis_text = (
                f'<text class="timeline-axis-text" x="{cx:.1f}" y="{padding_top + chart_h + 18:.1f}" '
                f'text-anchor="middle">{html.escape(b["label"])}</text>'
                if show_axis else ""
            )

            points_markup.append(f"""        <g>
          <rect class="timeline-bar"
                x="{x:.1f}" y="{padding_top:.1f}"
                width="{col_w:.1f}" height="{chart_h:.1f}"
                data-bucket-key="{html.escape(b['key'])}"
                data-label="{html.escape(b['label'])}"
                data-count="{b['count']:,}"
                data-pct="{b['pct']:.1f}%"
                data-cat="{html.escape(b['cat'])}"
                data-ip="{html.escape(b['ip'])}"/>
          <circle class="timeline-marker" cx="{cx:.1f}" cy="{cy:.1f}" r="{marker_r}"/>
          {axis_text}
        </g>""")

        points_html = "\n".join(points_markup)

        return f"""
      <svg id="{svg_id}" class="timeline-svg" viewBox="0 0 {int(svg_width)} {int(svg_height)}" style="{svg_style}">
        {defs_markup}
        {grid_markup}
        <path class="timeline-area" d="{area_path}" fill="url(#{grad_id})"/>
        <path class="timeline-line" d="{line_path}"/>
{points_html}
        {peak_callout}
      </svg>"""

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
              <span class="stat-item-name mono"><span class="stat-dot" style="background: {bar_color};"></span>{html.escape(ip)}</span>
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
              <span class="stat-item-name mono" title="{html.escape(target)}"><span class="stat-dot" style="background: var(--purple);"></span>{html.escape(target)}</span>
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
              <span class="stat-item-name"><span class="stat-dot" style="background: {color};"></span>{html.escape(cat_name)} <span style="color: var(--text-dim); font-size: 0.75rem;">({html.escape(tag)})</span></span>
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
                <span class="stat-dot" style="background: {color};"></span>
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
    def _highlight_match(cls, target: str, match: str) -> str:
        """Safely highlights the matched exploit substring in the target URL."""
        if not target:
            return ""
        if not match:
            return html.escape(target)
        idx = target.lower().find(match.lower())
        if idx != -1:
            before = html.escape(target[:idx])
            matched_part = html.escape(target[idx:idx + len(match)])
            after = html.escape(target[idx + len(match):])
            return f'{before}<mark class="hl-match">{matched_part}</mark>{after}'
        return html.escape(target)

    @classmethod
    def _build_initial_rows_fallback(cls, sample_matches: List[Any]) -> str:
        """Generates fallback rows for noscript environments."""
        if not sample_matches:
            return '<tr><td colspan="8" class="empty-state">No attack records found.</td></tr>'

        rows = []
        for idx, m in enumerate(sample_matches, 1):
            impact_val = int(m.rule.impact or 0)
            sev_badge = "badge-danger" if impact_val >= 7 else ("badge-warning" if impact_val >= 4 else "badge-info")
            cat_name = ATTACK_NAMES.get(m.tag.lower(), m.tag.upper())
            status_code = int(m.entry.status_code or 0)
            status_class = "badge-danger" if ((status_code >= 200 and status_code < 300) or status_code == 500) else ("badge-warning" if (status_code >= 300 and status_code < 400) else "badge-info")
            target_hl = cls._highlight_match(m.entry.url, m.matched_string)

            rows.append(f"""
          <tr class="match-row" data-id="{idx}">
            <td class="cell-num">{idx}</td>
            <td class="cell-time">{html.escape(m.entry.timestamp.strftime("%Y-%m-%d %H:%M:%S") if m.entry.timestamp else "-")}</td>
            <td><span class="mono filterable-ip" data-filter-ip="{html.escape(m.entry.ip)}" title="Click to filter by IP: {html.escape(m.entry.ip)}">{html.escape(m.entry.ip)}</span></td>
            <td><span class="method-badge">{html.escape(m.entry.method)}</span> <span class="badge {status_class} filterable-status" data-filter-status="{status_code}" title="Click to filter by HTTP {status_code}">{status_code}</span></td>
            <td><span class="badge {sev_badge}">Impact {m.rule.impact}</span></td>
            <td>
              <div class="cat-pill filterable-cat" data-filter-cat="{html.escape(m.tag)}" title="Click to filter by category: {html.escape(cat_name)}">{html.escape(cat_name)}</div>
              <div class="rule-ref" title="{html.escape(m.rule.description)}">[{html.escape(m.rule.rule_id)}] {html.escape(m.rule.description)}</div>
            </td>
            <td><span class="target-url mono" title="{html.escape(m.entry.url)}">{target_hl}</span></td>
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
        <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
          <button type="button" id="btn-density-toggle" class="btn btn-secondary btn-density-toggle" title="Toggle table row density (Comfortable / Compact)" aria-label="Toggle density">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
            <span id="density-toggle-text">Density: Comfortable</span>
          </button>
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
              <input type="text" id="search-input" class="search-input" placeholder="Real-time search IP, URL, Rule ID, payload, User-Agent... (Press / to focus)" autocomplete="off">
              <span class="kbd-hint" title="Press / to focus search">/</span>
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

        <div id="active-filters-bar" class="active-filters-bar" style="display: none;">
          <span class="active-filters-label">Active Filters:</span>
          <div id="active-filters-list" class="active-filters-list"></div>
          <button type="button" id="btn-clear-all-filters" class="btn-clear-all-filters">Clear all</button>
        </div>

        <div class="table-responsive">
          <table class="matches-table">
            <thead>
              <tr>
                <th class="sortable" data-sort="id" data-min-width="50" title="Sort by ID">
                  <div class="th-content">
                    <span>#</span>
                    <span class="sort-indicator" aria-hidden="true"></span>
                  </div>
                  <span class="col-resizer"></span>
                </th>
                <th class="sortable" data-sort="time" data-min-width="130" title="Sort by Timestamp">
                  <div class="th-content">
                    <span>Timestamp</span>
                    <span class="sort-indicator" aria-hidden="true"></span>
                  </div>
                  <span class="col-resizer"></span>
                </th>
                <th class="sortable" data-sort="ip" data-min-width="120" title="Sort by Client IP">
                  <div class="th-content">
                    <span>Client IP</span>
                    <span class="sort-indicator" aria-hidden="true"></span>
                  </div>
                  <span class="col-resizer"></span>
                </th>
                <th class="sortable" data-sort="status" data-min-width="110" title="Sort by Status Code">
                  <div class="th-content">
                    <span>Method / Status</span>
                    <span class="sort-indicator" aria-hidden="true"></span>
                  </div>
                  <span class="col-resizer"></span>
                </th>
                <th class="sortable" data-sort="impact" data-min-width="85" title="Sort by Severity Impact">
                  <div class="th-content">
                    <span>Impact</span>
                    <span class="sort-indicator" aria-hidden="true"></span>
                  </div>
                  <span class="col-resizer"></span>
                </th>
                <th class="sortable" data-sort="cat" data-min-width="140" title="Sort by Category">
                  <div class="th-content">
                    <span>Category &amp; Rule</span>
                    <span class="sort-indicator" aria-hidden="true"></span>
                  </div>
                  <span class="col-resizer"></span>
                </th>
                <th class="sortable" data-sort="target" data-min-width="160" title="Sort by Target URL">
                  <div class="th-content">
                    <span>Vector &amp; Target</span>
                    <span class="sort-indicator" aria-hidden="true"></span>
                  </div>
                  <span class="col-resizer"></span>
                </th>
                <th class="sortable" data-sort="match" data-min-width="140" title="Sort by Matched Payload">
                  <div class="th-content">
                    <span>Matched Payload</span>
                    <span class="sort-indicator" aria-hidden="true"></span>
                  </div>
                  <span class="col-resizer"></span>
                </th>
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
            <button type="button" id="btn-prev" class="btn-page" title="Previous Page (or press [ / &larr;)">&lsaquo;</button>
            <span id="page-indicator" class="page-indicator">Page 1 of 1</span>
            <button type="button" id="btn-next" class="btn-page" title="Next Page (or press ] / &rarr;)">&rsaquo;</button>
            <button type="button" id="btn-last" class="btn-page" title="Last Page">&raquo;</button>
          </div>
        </div>
      </div>
    </div>
"""
