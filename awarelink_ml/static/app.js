'use strict';

(() => {
  const $ = (id) => document.getElementById(id);
  const KIND_NAMES = { url: 'Website link', news: 'News & text', screenshot: 'Screenshot' };
  const LABEL_NAMES = { high_risk: 'Higher risk', review: 'Needs review', low_risk: 'Lower risk' };
  const STAGES = ['queued', 'extracting', 'classifying', 'saving'];
  const BUTTON_LABELS = { url: 'Check this link', news: 'Check this text', screenshot: 'Check this screenshot' };
  const state = {
    ready: false, kind: 'url', csrf: '', admin: false, adminConfigured: true, capabilities: {}, history: [],
    limits: { max_image_bytes: 2000000, max_text_chars: 12000, max_url_chars: 2048 },
    currentResult: null, controller: null, selectedFile: null, previewUrl: null,
    feedbackAccurate: true, toastTimer: null, adminData: null,
  };

  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function visible(id, show) { $(id).hidden = !show; }
  function errorMessage(error) { return error && error.message ? error.message : 'The request could not be completed. Please try again.'; }
  function numericScore(value) { return Math.min(100, Math.max(0, Math.round(Number(value) || 0))); }
  function labelName(value) { return LABEL_NAMES[value] || 'Needs review'; }
  function kindName(value) { return KIND_NAMES[value] || 'Check'; }

  function showToast(message) {
    $('toast').textContent = message;
    visible('toast', true);
    clearTimeout(state.toastTimer);
    state.toastTimer = setTimeout(() => visible('toast', false), 4000);
  }

  function showFormError(message) {
    $('form-error').textContent = message;
    visible('form-error', Boolean(message));
  }

  function formatDate(value) {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return 'Date unavailable';
    return new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }).format(date);
  }

  function relativeDate(value) {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return '';
    const minutes = Math.max(0, Math.floor((Date.now() - date.getTime()) / 60000));
    if (minutes < 1) return 'Just now';
    if (minutes < 60) return `${minutes} min ago`;
    if (minutes < 1440) return `${Math.floor(minutes / 60)} h ago`;
    return new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric' }).format(date);
  }

  function mutationHeaders(json = true) {
    const headers = { 'X-CSRF-Token': state.csrf };
    if (json) headers['Content-Type'] = 'application/json';
    return headers;
  }

  async function fetchJson(path, options = {}) {
    const response = await fetch(path, { credentials: 'same-origin', ...options });
    let data;
    try { data = await response.json(); }
    catch (_) { throw new Error(response.ok ? 'The server returned an unreadable response.' : `The server could not complete the request (${response.status}).`); }
    if (!response.ok || data.error) {
      const message = typeof data.error === 'string' ? data.error : data.error?.message;
      const error = new Error(message || data.message || `The request could not be completed (${response.status}).`);
      error.status = response.status;
      throw error;
    }
    return data;
  }

  function setKind(kind, focus = false) {
    if (state.controller || !KIND_NAMES[kind]) return;
    state.kind = kind;
    document.querySelectorAll('[data-kind]').forEach((tab) => {
      const selected = tab.dataset.kind === kind;
      tab.classList.toggle('active', selected);
      tab.setAttribute('aria-selected', String(selected));
      tab.tabIndex = selected ? 0 : -1;
      visible(`panel-${tab.dataset.kind}`, selected);
    });
    $('url-input').disabled = kind !== 'url';
    $('url-input').required = kind === 'url';
    $('news-input').disabled = kind !== 'news';
    $('news-input').required = kind === 'news';
    $('screenshot-input').disabled = kind !== 'screenshot' || !state.capabilities.ocr;
    $('analyze-label').textContent = BUTTON_LABELS[kind];
    $('analyze-button').disabled = !state.ready || (kind === 'screenshot' && !state.capabilities.ocr);
    showFormError('');
    if (focus) $(`tab-${kind}`).focus();
  }

  function setupTabKeyboard(selector, activate) {
    const tabs = [...document.querySelectorAll(selector)];
    tabs.forEach((tab, index) => {
      tab.addEventListener('keydown', (event) => {
        if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
        event.preventDefault();
        let next = index;
        if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
        if (event.key === 'ArrowLeft') next = (index - 1 + tabs.length) % tabs.length;
        if (event.key === 'Home') next = 0;
        if (event.key === 'End') next = tabs.length - 1;
        activate(tabs[next]);
      });
    });
  }

  function setBusy(busy) {
    document.querySelectorAll('[data-kind]').forEach((tab) => { tab.disabled = busy; });
    $('analyze-button').disabled = busy || !state.ready || (state.kind === 'screenshot' && !state.capabilities.ocr);
    $('url-input').disabled = busy || state.kind !== 'url';
    $('news-input').disabled = busy || state.kind !== 'news';
    $('inspect-input').disabled = busy || !state.capabilities.website_checks;
    $('screenshot-input').disabled = busy || state.kind !== 'screenshot' || !state.capabilities.ocr;
    $('clear-file').disabled = busy;
    $('result-panel').setAttribute('aria-busy', String(busy));
    visible('cancel-button', busy);
    $('analyze-label').textContent = busy ? 'Checking…' : BUTTON_LABELS[state.kind];
  }

  function setStage(stage, message, complete = false) {
    const index = STAGES.indexOf(stage === 'inspecting' ? 'classifying' : stage);
    document.querySelectorAll('#pipeline-steps li').forEach((step, stepIndex) => {
      step.classList.toggle('current', !complete && stepIndex === index);
      step.classList.toggle('complete', complete || (index >= 0 && stepIndex < index));
    });
    $('progress-message').textContent = message || 'Checking…';
  }

  function updateFile(file) {
    if (state.controller) return;
    showFormError('');
    if (state.previewUrl) URL.revokeObjectURL(state.previewUrl);
    state.previewUrl = null;
    state.selectedFile = null;
    visible('upload-preview', false);
    $('preview-image').removeAttribute('src');
    if (!file) { $('screenshot-input').value = ''; return; }
    if (!['image/png', 'image/jpeg', 'image/webp'].includes(file.type)) {
      $('screenshot-input').value = '';
      showFormError('Choose a PNG, JPEG, or WebP screenshot.');
      return;
    }
    if (file.size > state.limits.max_image_bytes) {
      $('screenshot-input').value = '';
      showFormError(`This image is larger than ${state.limits.max_image_bytes / 1000000} MB. Choose a smaller screenshot.`);
      return;
    }
    state.selectedFile = file;
    state.previewUrl = URL.createObjectURL(file);
    $('preview-image').src = state.previewUrl;
    $('preview-filename').textContent = file.name;
    visible('upload-preview', true);
  }

  async function runAnalysis(event) {
    event.preventDefault();
    if (state.controller || !state.ready) return;
    showFormError('');
    let body;
    let headers;
    if (state.kind === 'screenshot') {
      if (!state.selectedFile) { showFormError('Choose a screenshot first.'); $('screenshot-input').focus(); return; }
      body = new FormData();
      body.append('kind', 'screenshot');
      body.append('file', state.selectedFile);
      headers = mutationHeaders(false);
    } else {
      const input = (state.kind === 'url' ? $('url-input') : $('news-input')).value.trim();
      if (!input) { showFormError('Add something to check first.'); return; }
      body = JSON.stringify({ kind: state.kind, input, ...(state.kind === 'url' ? { inspect: $('inspect-input').checked } : {}) });
      headers = mutationHeaders();
    }
    const controller = new AbortController();
    state.controller = controller;
    setBusy(true);
    $('result-type').textContent = state.currentResult ? 'Previous result · checking…' : 'Check in progress';
    setStage('queued', 'Your check is starting.');
    let hasResult = false;
    let streamError = null;
    let reader = null;
    try {
      const response = await fetch('/api/analyze', { method: 'POST', credentials: 'same-origin', headers, body, signal: controller.signal });
      if (!response.ok) {
        let data = {};
        try { data = await response.json(); } catch (_) { /* A plain error response has no details. */ }
        throw new Error(data.error?.message || data.message || `The check could not start (${response.status}).`);
      }
      if (!response.body) throw new Error('This browser cannot read live progress. Try a current browser.');
      const contentType = response.headers.get('Content-Type') || '';
      if (!contentType.includes('ndjson')) throw new Error('The server returned an unexpected analysis response.');
      reader = response.body.getReader();
      const decoder = new TextDecoder();
      let pending = '';
      const handleLine = (line) => {
        if (!line.trim()) return;
        let data;
        try { data = JSON.parse(line); }
        catch (_) { throw new Error('The analysis stream was interrupted. Please try again.'); }
        if (data.event === 'stage') setStage(data.stage, data.message);
        if (data.event === 'result') {
          if (!data.result || !data.result.id) throw new Error('The result was incomplete. Please try again.');
          hasResult = true;
          renderResult(data.result, true);
          if (new URLSearchParams(window.location.search).has('share')) {
            visible('shared-notice', false);
            const ownPage = new URL(window.location.href);
            ownPage.searchParams.delete('share');
            window.history.replaceState(null, '', `${ownPage.pathname}${ownPage.search}${ownPage.hash}`);
          }
          if (window.matchMedia('(max-width: 760px)').matches) {
            $('result-panel').scrollIntoView({ behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
          }
          addHistory(data.result);
          setStage('saving', 'Complete. Your findings are ready.', true);
        }
        if (data.event === 'error') streamError = new Error(data.error?.message || 'The check could not be completed.');
      };
      while (true) {
        const { done, value } = await reader.read();
        if (done) { pending += decoder.decode(); break; }
        pending += decoder.decode(value, { stream: true });
        if (pending.length > 2 * 1024 * 1024) throw new Error('The analysis response was too large. Try a smaller input.');
        let newline;
        while ((newline = pending.indexOf('\n')) >= 0) {
          handleLine(pending.slice(0, newline));
          pending = pending.slice(newline + 1);
        }
        if (streamError) throw streamError;
      }
      if (pending.trim()) handleLine(pending);
      if (streamError) throw streamError;
      if (!hasResult) throw new Error('The connection ended before the result arrived. Try again or refresh your history.');
    } catch (error) {
      if (error.name === 'AbortError') {
        setStage('', 'Connection canceled. A completed check may still appear in your history.');
      } else {
        showFormError(errorMessage(error));
        setStage('', 'The check did not complete.');
      }
    } finally {
      if (reader) { try { await reader.cancel(); } catch (_) { /* The connection may already be closed. */ } }
      if (state.controller === controller) state.controller = null;
      if (!hasResult) $('result-type').textContent = state.currentResult ? 'Previous findings' : 'A closer look';
      setBusy(false);
    }
  }

  function renderList(targetId, values, fallback) {
    const target = $(targetId);
    target.replaceChildren();
    const items = Array.isArray(values) && values.length ? values : [fallback];
    items.forEach((value) => target.append(element('li', '', value)));
  }

  function readableKey(key) { return String(key).replaceAll('_', ' ').replace(/\b\w/g, (letter) => letter.toUpperCase()); }
  function readableValue(value) {
    if (value === null || value === undefined) return 'Not available';
    if (typeof value === 'boolean') return value ? 'Yes' : 'No';
    if (Array.isArray(value)) return value.map(readableValue).join(', ') || 'None';
    if (typeof value === 'object') return JSON.stringify(value);
    return String(value);
  }

  function renderResult(result, focus = false, feedbackAllowed = true) {
    state.currentResult = result;
    visible('empty-result', false);
    visible('result-content', true);
    visible('share-fallback', false);
    visible('feedback-form', false);
    visible('feedback-status', false);
    visible('feedback-section', feedbackAllowed);
    if (!feedbackAllowed) {
      $('feedback-status').textContent = 'Run your own check to give feedback on its result.';
      visible('feedback-status', true);
    }
    $('feedback-yes').setAttribute('aria-pressed', 'false');
    $('feedback-no').setAttribute('aria-pressed', 'false');
    $('feedback-yes').disabled = false;
    $('feedback-no').disabled = false;
    $('feedback-submit').disabled = false;
    $('feedback-text').value = '';
    $('result-type').textContent = result.cached ? 'Previously checked' : 'Analysis complete';
    $('result-kind').textContent = kindName(result.kind);
    $('result-verdict').textContent = labelName(result.label);
    $('result-verdict').style.color = result.label === 'high_risk' ? 'var(--rust)' : result.label === 'review' ? 'var(--amber)' : 'var(--teal)';
    const score = numericScore(result.score);
    $('result-score').textContent = String(score);
    $('result-input').textContent = result.input_label || 'Your submitted content';
    $('risk-marker').style.left = `${Math.max(1, Math.min(99, score))}%`;
    $('risk-marker').parentElement.parentElement.setAttribute('aria-label', `Estimated risk: ${score} out of 100`);
    let summary = result.label === 'high_risk' ? 'The model found several patterns that warrant caution. Take time to verify before acting.' : result.label === 'review' ? 'Some patterns need a closer look. Verify the source and consider the context before acting.' : 'The model found fewer suspicious patterns in this input. Keep the context and the limits in mind.';
    if (result.kind !== 'url') summary += ' This checks message patterns, not whether a claim is true.';
    $('result-summary').textContent = summary;
    renderList('result-signals', result.signals, 'No specific pattern was reported by this check.');
    renderList('result-limitations', result.limitations, 'This estimate is based on detected patterns and may be incorrect.');
    const milliseconds = Number(result.elapsed_ms);
    const timing = Number.isFinite(milliseconds) ? (milliseconds < 1000 ? `${Math.round(milliseconds)} ms` : `${(milliseconds / 1000).toFixed(2)} s`) : '';
    $('result-timing').textContent = `${result.cached ? 'Saved result' : 'Local analysis'}${timing ? ` · ${timing}` : ''}`;
    $('share-button').disabled = !result.share_id;
    $('result-checks').replaceChildren();
    const checks = result.checks && typeof result.checks === 'object' ? Object.entries(result.checks) : [];
    visible('checks-details', checks.length > 0);
    checks.forEach(([key, value]) => {
      const row = element('div');
      row.append(element('dt', '', readableKey(key)), element('dd', '', readableValue(value)));
      $('result-checks').append(row);
    });
    const extracted = typeof result.extracted_text === 'string' ? result.extracted_text : '';
    visible('extracted-details', Boolean(extracted));
    $('extracted-text').textContent = extracted;
    document.querySelectorAll('.result-details').forEach((detail) => { detail.open = false; });
    if (focus) $('result-verdict').focus({ preventScroll: true });
  }

  function historyButton(result, index, feedbackAllowed = true) {
    const hasDetails = Boolean(result.id);
    const button = element(hasDetails ? 'button' : 'div', hasDetails ? 'history-row' : 'history-row static-row');
    if (hasDetails) button.type = 'button';
    button.setAttribute('aria-label', `${hasDetails ? 'View ' : ''}${kindName(result.kind)}: ${result.input_label || 'check'}, ${labelName(result.label)}, ${numericScore(result.score)} out of 100`);
    const chip = element('span', 'risk-chip', `${numericScore(result.score)} · ${labelName(result.label)}`);
    chip.dataset.label = result.label;
    const date = element('span', 'history-time', relativeDate(result.created_at));
    date.title = formatDate(result.created_at);
    button.append(element('span', 'history-number', String(index + 1).padStart(2, '0')), element('span', 'history-input', result.input_label || 'Submitted content'), element('span', 'history-kind', kindName(result.kind)), chip, date, element('span', 'history-arrow', hasDetails ? '↗' : ''));
    if (hasDetails) button.addEventListener('click', () => {
      renderResult(result, true, feedbackAllowed);
      $('result-panel').scrollIntoView({ behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'center' });
    });
    return button;
  }

  function renderHistory() {
    $('history-list').replaceChildren();
    if (!state.history.length) { $('history-list').append(element('p', 'history-empty', 'Your checks will appear here. No sign-up needed.')); return; }
    state.history.slice(0, 8).forEach((result, index) => $('history-list').append(historyButton(result, index)));
  }

  function addHistory(result) {
    state.history = [result, ...state.history.filter((item) => item.id !== result.id)].slice(0, 30);
    renderHistory();
  }

  async function refreshHistory() {
    $('history-refresh').disabled = true;
    try {
      const data = await fetchJson('/api/history');
      state.history = Array.isArray(data.history) ? data.history : [];
      renderHistory();
      showToast('Your history is up to date.');
    } catch (error) { showToast(errorMessage(error)); }
    finally { $('history-refresh').disabled = false; }
  }

  async function copyShareLink() {
    if (!state.currentResult?.share_id) return;
    const shareUrl = new URL('/', window.location.origin);
    shareUrl.searchParams.set('share', state.currentResult.share_id);
    try {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard unavailable');
      await navigator.clipboard.writeText(shareUrl.toString());
      showToast('Share link copied.');
    } catch (_) {
      $('share-url').value = shareUrl.toString();
      visible('share-fallback', true);
      $('share-url').focus();
      $('share-url').select();
      showToast('Copy the selected share link.');
    }
  }

  function chooseFeedback(accurate) {
    if (!state.currentResult) return;
    state.feedbackAccurate = accurate;
    $('feedback-yes').setAttribute('aria-pressed', String(accurate));
    $('feedback-no').setAttribute('aria-pressed', String(!accurate));
    $('feedback-reason').value = accurate ? 'helpful' : 'unclear';
    visible('feedback-form', true);
    visible('feedback-status', false);
    $('feedback-reason').focus();
  }

  async function sendFeedback(event) {
    event.preventDefault();
    if (!state.currentResult || !state.ready) return;
    $('feedback-submit').disabled = true;
    const analysisId = state.currentResult.id;
    try {
      await fetchJson('/api/feedback', { method: 'POST', headers: mutationHeaders(), body: JSON.stringify({ analysis_id: analysisId, accurate: state.feedbackAccurate, reason: $('feedback-reason').value, other_text: $('feedback-text').value.trim() }) });
      if (state.currentResult?.id === analysisId) {
        visible('feedback-form', false);
        $('feedback-yes').disabled = true;
        $('feedback-no').disabled = true;
        $('feedback-status').textContent = 'Thank you. Your feedback is saved for review.';
        visible('feedback-status', true);
      }
    } catch (error) {
      if (state.currentResult?.id === analysisId) {
        $('feedback-status').textContent = errorMessage(error);
        visible('feedback-status', true);
      }
    } finally { $('feedback-submit').disabled = false; }
  }

  async function loadNews() {
    $('news-load').disabled = true;
    $('news-status').textContent = 'Loading headlines from the security desk…';
    try {
      const data = await fetchJson('/api/news');
      const items = Array.isArray(data.items) ? data.items : [];
      $('news-list').replaceChildren();
      let displayed = 0;
      items.slice(0, 6).forEach((item) => {
        let url;
        try { url = new URL(item.link); } catch (_) { return; }
        if (!['https:', 'http:'].includes(url.protocol)) return;
        const link = element('a', 'news-item');
        link.href = url.href;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        link.append(element('span', 'news-source', item.source || 'Security news'), element('span', 'news-title', item.title || 'Read article'), element('span', 'news-arrow', 'Read at source ↗'));
        $('news-list').append(link);
        displayed++;
      });
      visible('news-list', displayed > 0);
      $('news-status').textContent = displayed ? `${data.cached ? 'Saved headlines' : 'Latest headlines'}. Articles open at their source; these are not model-verified claims.` : 'No headlines are available right now. Try again later.';
      $('news-load').textContent = 'Refresh headlines ↻';
    } catch (error) { $('news-status').textContent = errorMessage(error); }
    finally { $('news-load').disabled = false; }
  }

  function openLogin() {
    if (state.controller) { showToast('Finish or cancel the current check first.'); return; }
    if (state.admin) { openAdmin(); return; }
    $('login-error').textContent = '';
    visible('login-error', false);
    visible('login-form', state.adminConfigured);
    visible('login-unavailable', !state.adminConfigured);
    $('login-dialog').showModal();
  }

  async function login(event) {
    event.preventDefault();
    if (!state.ready) { $('login-error').textContent = 'The server is not ready. Refresh the page and try again.'; visible('login-error', true); return; }
    $('login-submit').disabled = true;
    visible('login-error', false);
    try {
      const data = await fetchJson('/api/login', { method: 'POST', headers: mutationHeaders(), body: JSON.stringify({ username: $('login-username').value, password: $('login-password').value }) });
      if (!data.ok) throw new Error('Sign-in could not be completed.');
      state.csrf = data.csrf_token || state.csrf;
      state.admin = true;
      $('login-password').value = '';
      $('login-dialog').close();
      await openAdmin();
    } catch (error) { $('login-error').textContent = errorMessage(error); visible('login-error', true); }
    finally { $('login-submit').disabled = false; }
  }

  async function openAdmin() {
    if (!state.admin) { openLogin(); return; }
    visible('workspace', false);
    visible('admin-view', true);
    $('admin-title').scrollIntoView({ block: 'start' });
    await refreshAdmin();
  }

  function closeAdmin() {
    visible('admin-view', false);
    visible('workspace', true);
    $('admin-open').focus({ preventScroll: true });
  }

  async function logout() {
    $('logout-button').disabled = true;
    try {
      const data = await fetchJson('/api/logout', { method: 'POST', headers: mutationHeaders(), body: JSON.stringify({}) });
      state.csrf = data.csrf_token || state.csrf;
      state.admin = false;
      state.adminData = null;
      closeAdmin();
      showToast('You are signed out.');
    } catch (error) { showToast(errorMessage(error)); }
    finally { $('logout-button').disabled = false; }
  }

  function setAdminTab(name, focus = false) {
    document.querySelectorAll('[data-admin-tab]').forEach((tab) => {
      const selected = tab.dataset.adminTab === name;
      tab.classList.toggle('active', selected);
      tab.setAttribute('aria-selected', String(selected));
      tab.tabIndex = selected ? 0 : -1;
      visible(`admin-${tab.dataset.adminTab}`, selected);
      if (selected && focus) tab.focus();
    });
  }

  async function refreshAdmin() {
    $('admin-refresh').disabled = true;
    $('admin-status').textContent = 'Loading the overview…';
    visible('admin-status', true);
    try {
      const data = await fetchJson('/api/admin/overview');
      state.adminData = data;
      $('stat-total').textContent = String(data.stats?.total || 0);
      $('stat-high').textContent = String(data.stats?.by_label?.high_risk || 0);
      $('stat-review').textContent = String(data.stats?.by_label?.review || 0);
      $('stat-feedback').textContent = String(data.stats?.feedback_total ?? data.feedback?.length ?? 0);
      renderAdminAnalyses();
      renderAdminFeedback();
      renderModels(data.models);
      visible('admin-status', false);
    } catch (error) {
      $('admin-status').textContent = errorMessage(error);
      if (error.status === 401 || error.status === 403) {
        state.admin = false;
        closeAdmin();
        openLogin();
      }
    } finally { $('admin-refresh').disabled = false; }
  }

  function tableCell(text, className) { return element('td', className || '', text); }

  function renderAdminAnalyses() {
    const kind = $('admin-kind-filter').value;
    const label = $('admin-label-filter').value;
    const all = Array.isArray(state.adminData?.analyses) ? state.adminData.analyses : [];
    const rows = all.filter((result) => (kind === 'all' || result.kind === kind) && (label === 'all' || result.label === label));
    $('admin-analysis-body').replaceChildren();
    $('admin-record-count').textContent = `${rows.length} shown${rows.length !== all.length ? ` of ${all.length}` : ''}`;
    visible('admin-analysis-empty', rows.length === 0);
    rows.forEach((result) => {
      const row = element('tr');
      const input = tableCell(result.input_label || 'Submitted content', 'record-input');
      input.append(element('span', 'record-id', result.id));
      const chip = element('span', 'risk-chip', `${numericScore(result.score)} · ${labelName(result.label)}`);
      chip.dataset.label = result.label;
      const risk = tableCell();
      risk.append(chip);
      const actionCell = tableCell();
      const actions = element('div', 'record-actions');
      const view = element('button', 'text-button', 'View');
      view.type = 'button';
      view.setAttribute('aria-label', `View analysis of ${result.input_label || 'submitted content'}`);
      view.addEventListener('click', () => { closeAdmin(); renderResult(result, true, state.history.some((item) => item.id === result.id)); $('result-panel').scrollIntoView({ block: 'center' }); });
      const remove = element('button', 'text-button delete-button', 'Delete');
      remove.type = 'button';
      remove.setAttribute('aria-label', `Delete analysis of ${result.input_label || 'submitted content'}`);
      remove.addEventListener('click', () => deleteRecord('analyses', result.id, remove));
      actions.append(view, remove);
      actionCell.append(actions);
      row.append(input, tableCell(kindName(result.kind)), risk, tableCell(formatDate(result.created_at)), actionCell);
      $('admin-analysis-body').append(row);
    });
  }

  function renderAdminFeedback() {
    const rows = Array.isArray(state.adminData?.feedback) ? state.adminData.feedback : [];
    $('admin-feedback-body').replaceChildren();
    visible('admin-feedback-empty', rows.length === 0);
    rows.forEach((feedback) => {
      const row = element('tr');
      const reason = tableCell(readableKey(feedback.reason || 'Feedback'), 'record-input');
      if (feedback.other_text || feedback.comment) reason.append(element('span', 'record-id', feedback.other_text || feedback.comment));
      const actions = tableCell();
      const remove = element('button', 'text-button delete-button', 'Delete');
      remove.type = 'button';
      remove.setAttribute('aria-label', `Delete feedback ${feedback.id}`);
      remove.addEventListener('click', () => deleteRecord('feedback', feedback.id, remove));
      actions.append(remove);
      row.append(tableCell(feedback.analysis_id || '—'), tableCell(feedback.accurate ? 'Looks right' : 'Needs review'), reason, tableCell(formatDate(feedback.created_at)), actions);
      $('admin-feedback-body').append(row);
    });
  }

  async function deleteRecord(type, id, button) {
    if (!id) return;
    button.disabled = true;
    try {
      await fetchJson(`/api/admin/${type}/${encodeURIComponent(id)}`, { method: 'DELETE', headers: mutationHeaders(false) });
      showToast(type === 'analyses' ? 'Analysis deleted.' : 'Feedback deleted.');
      if (type === 'analyses') {
        state.history = state.history.filter((result) => result.id !== id);
        renderHistory();
        if (state.currentResult?.id === id) { state.currentResult = null; visible('result-content', false); visible('empty-result', true); }
      }
      await refreshAdmin();
    } catch (error) { showToast(errorMessage(error)); button.disabled = false; }
  }

  function renderModels(models) {
    $('admin-model-cards').replaceChildren();
    if (!models || typeof models !== 'object' || !Object.keys(models).length) { $('admin-model-cards').append(element('p', 'history-empty', 'Model details are not available.')); return; }
    const entries = Array.isArray(models) ? models.map((model, index) => [model.name || `Model ${index + 1}`, model]) : Object.entries(models);
    entries.forEach(([name, model]) => {
      const card = element('article', 'model-card');
      card.append(element('h3', '', readableKey(name)));
      if (model && typeof model === 'object') {
        card.append(element('p', 'field-hint', model.description || model.name || 'Local machine learning model'));
        const list = element('dl');
        Object.entries(model).filter(([key, value]) => !['description', 'name'].includes(key) && typeof value !== 'object').forEach(([key, value]) => {
          const row = element('div');
          row.append(element('dt', '', readableKey(key)), element('dd', '', readableValue(value)));
          list.append(row);
        });
        card.append(list);
        const details = element('details');
        details.append(element('summary', '', 'Validation and training details'), element('pre', '', JSON.stringify(model, null, 2)));
        card.append(details);
      } else card.append(element('p', 'field-hint', readableValue(model)));
      $('admin-model-cards').append(card);
    });
  }

  async function loadSharedResult() {
    const shareId = new URLSearchParams(window.location.search).get('share');
    if (!shareId) return;
    visible('shared-notice', true);
    $('progress-message').textContent = 'Loading the shared analysis…';
    try {
      const data = await fetchJson(`/api/analyses/${encodeURIComponent(shareId)}`);
      if (!data.result) throw new Error('This shared result is unavailable.');
      renderResult(data.result, false, state.history.some((item) => item.id === data.result.id));
      $('progress-message').textContent = 'Shared result loaded. You can run your own check on the left.';
    } catch (error) {
      $('shared-notice').replaceChildren(element('span', '', errorMessage(error)));
      const home = element('a', '', 'Start a new check ↗');
      home.href = '/';
      $('shared-notice').append(home);
      $('progress-message').textContent = 'Ready when you are.';
    }
  }

  async function bootstrap() {
    $('analyze-button').disabled = true;
    try {
      const data = await fetchJson('/api/bootstrap');
      state.csrf = data.csrf_token || '';
      if (!state.csrf) throw new Error('The server did not initialize a secure session. Refresh the page and try again.');
      state.capabilities = data.capabilities || {};
      if (data.limits && typeof data.limits === 'object') {
        Object.keys(state.limits).forEach((key) => {
          const serverKey = { max_image_bytes: 'image_bytes', max_text_chars: 'text_chars', max_url_chars: 'url_chars' }[key];
          const value = Number(data.limits[serverKey] ?? data.limits[key]);
          if (Number.isFinite(value) && value > 0) state.limits[key] = Math.floor(value);
        });
      }
      $('url-input').maxLength = state.limits.max_url_chars;
      $('news-input').maxLength = state.limits.max_text_chars;
      $('upload-size-hint').textContent = `PNG, JPEG, or WebP · up to ${state.limits.max_image_bytes / 1000000} MB`;
      state.admin = Boolean(data.admin);
      state.adminConfigured = data.admin_configured !== false;
      state.history = Array.isArray(data.history) ? data.history : [];
      state.ready = true;
      renderHistory();
      const community = Array.isArray(data.community) ? data.community.filter((result) => result.kind === 'url') : [];
      $('community-list').replaceChildren();
      visible('community-section', community.length > 0);
      community.slice(0, 4).forEach((result, index) => $('community-list').append(historyButton(result, index, state.history.some((item) => item.id === result.id))));
      visible('ocr-notice', !state.capabilities.ocr);
      $('inspect-input').disabled = !state.capabilities.website_checks;
      if (!state.capabilities.website_checks) $('inspect-input').checked = false;
      setKind(state.kind);
      visible('connection-notice', false);
      if (new URLSearchParams(window.location.search).get('admin') === '1') openLogin();
    } catch (error) {
      state.ready = false;
      $('connection-notice').replaceChildren(element('span', '', `${errorMessage(error)} `));
      const retry = element('button', 'text-button', 'Try reconnecting');
      retry.type = 'button';
      retry.addEventListener('click', bootstrap);
      $('connection-notice').append(retry);
      visible('connection-notice', true);
    }
  }

  document.querySelectorAll('[data-kind]').forEach((tab) => tab.addEventListener('click', () => setKind(tab.dataset.kind)));
  setupTabKeyboard('[data-kind]', (tab) => setKind(tab.dataset.kind, true));
  document.querySelectorAll('[data-admin-tab]').forEach((tab) => tab.addEventListener('click', () => setAdminTab(tab.dataset.adminTab)));
  setupTabKeyboard('[data-admin-tab]', (tab) => setAdminTab(tab.dataset.adminTab, true));
  $('analysis-form').addEventListener('submit', runAnalysis);
  $('cancel-button').addEventListener('click', () => state.controller?.abort());
  $('screenshot-input').addEventListener('change', (event) => updateFile(event.target.files[0]));
  $('clear-file').addEventListener('click', () => updateFile(null));
  ['dragenter', 'dragover'].forEach((eventName) => $('upload-zone').addEventListener(eventName, (event) => {
    event.preventDefault();
    if (state.capabilities.ocr && !state.controller) $('upload-zone').classList.add('dragging');
  }));
  ['dragleave', 'drop'].forEach((eventName) => $('upload-zone').addEventListener(eventName, (event) => { event.preventDefault(); $('upload-zone').classList.remove('dragging'); }));
  $('upload-zone').addEventListener('drop', (event) => { if (state.capabilities.ocr && !state.controller) updateFile(event.dataTransfer.files[0]); });
  $('history-refresh').addEventListener('click', refreshHistory);
  $('share-button').addEventListener('click', copyShareLink);
  $('feedback-yes').addEventListener('click', () => chooseFeedback(true));
  $('feedback-no').addEventListener('click', () => chooseFeedback(false));
  $('feedback-form').addEventListener('submit', sendFeedback);
  $('news-load').addEventListener('click', loadNews);
  $('admin-open').addEventListener('click', openLogin);
  $('login-close').addEventListener('click', () => $('login-dialog').close());
  $('login-dialog').addEventListener('close', () => { $('login-password').value = ''; });
  $('login-form').addEventListener('submit', login);
  $('admin-close').addEventListener('click', closeAdmin);
  $('logout-button').addEventListener('click', logout);
  $('admin-refresh').addEventListener('click', refreshAdmin);
  $('admin-kind-filter').addEventListener('change', renderAdminAnalyses);
  $('admin-label-filter').addEventListener('change', renderAdminAnalyses);
  window.addEventListener('beforeunload', () => { if (state.previewUrl) URL.revokeObjectURL(state.previewUrl); });
  async function start() {
    await bootstrap();
    await loadSharedResult();
  }
  start();
})();
