// =============================================
// AUDIT.JS — Пакетный аудит паролей
// =============================================

const AuditState = {
    passwords: [],
    results: [],
    mode: 'simple',
    isRunning: false
};

// ----- Modal open/close -----

function openAuditModal() {
    resetAuditModal();
    const modal = document.getElementById('auditModal');
    modal.removeAttribute('hidden');
    document.body.style.overflow = 'hidden';
    if (window.lucide) lucide.createIcons();
}

function closeAuditModal() {
    if (AuditState.isRunning) {
        if (!confirm('Аудит выполняется. Прервать?')) return;
        AuditState.isRunning = false;
    }
    const modal = document.getElementById('auditModal');
    modal.setAttribute('hidden', '');
    document.body.style.overflow = '';
    resetAuditModal();
}

function softResetAudit() {
    AuditState.results = [];
    AuditState.isRunning = false;
    // Clear step 3 content
    const doneIcon = document.querySelector('#auditStep3 .audit-done-icon');
    if (doneIcon) doneIcon.classList.remove('animate');
    const doneText = document.getElementById('auditDoneText');
    if (doneText) doneText.textContent = '';
    const dlBtns = document.getElementById('auditDownloadBtns');
    if (dlBtns) dlBtns.innerHTML = '';
    // Clear step 2 content
    const progressFill = document.getElementById('auditProgressFill');
    const progressText = document.getElementById('auditProgressText');
    const progressSub = document.getElementById('auditProgressSub');
    if (progressFill) progressFill.style.width = '0%';
    if (progressText) progressText.textContent = '';
    if (progressSub) progressSub.textContent = '';
    showAuditStep(1);
}

function resetAuditModal() {
    AuditState.passwords = [];
    AuditState.results = [];
    AuditState.mode = 'simple';
    AuditState.isRunning = false;

    const doneIcon = document.querySelector('#auditStep3 .audit-done-icon');
    if (doneIcon) doneIcon.classList.remove('animate');

    const textarea = document.getElementById('auditTextarea');
    if (textarea) { textarea.value = ''; textarea.disabled = false; }

    const countHint = document.getElementById('auditPasswordCount');
    if (countHint) countHint.textContent = '';

    const startBtn = document.getElementById('auditStartBtn');
    if (startBtn) startBtn.disabled = true;

    // Unlock mode radios and reset
    document.querySelectorAll('input[name="auditMode"]').forEach(r => r.disabled = false);
    const simpleRadio = document.querySelector('input[name="auditMode"][value="simple"]');
    if (simpleRadio) simpleRadio.checked = true;

    showAuditStep(1);
}

const AUDIT_OUT_MS = 280;
const _hideTimers = new WeakMap();

function _hideStep(el) {
    if (!el || el.hasAttribute('hidden')) return;
    el.classList.remove('audit-step-enter');
    el.classList.add('audit-step-exit');
    const timer = setTimeout(() => {
        _hideTimers.delete(el);
        el.classList.remove('audit-step-exit');
        el.setAttribute('hidden', '');
    }, AUDIT_OUT_MS);
    _hideTimers.set(el, timer);
}

function _showStep(el) {
    if (!el) return;
    if (_hideTimers.has(el)) {
        clearTimeout(_hideTimers.get(el));
        _hideTimers.delete(el);
    }
    el.classList.remove('audit-step-exit', 'audit-step-enter');
    el.removeAttribute('hidden');
    void el.offsetWidth; // force reflow to restart animation
    el.classList.add('audit-step-enter');
}

function showAuditStep(n) {
    const step1 = document.getElementById('auditStep1');
    if (step1) step1.removeAttribute('hidden');
    const step2 = document.getElementById('auditStep2');
    const step3 = document.getElementById('auditStep3');
    if (step2) { if (n === 2) _showStep(step2); else _hideStep(step2); }
    if (step3) { if (n === 3) _showStep(step3); else _hideStep(step3); }
    if (window.lucide) lucide.createIcons();
}

// ----- Parse input -----

function parsePasswordInput(text) {
    const parts = text.split(/[\s\n]+/).filter(p => p.length > 0);
    return [...new Set(parts)];
}

function updatePasswordCount(passwords, originalCount) {
    const countHint = document.getElementById('auditPasswordCount');
    const startBtn = document.getElementById('auditStartBtn');
    if (!countHint || !startBtn) return;

    if (passwords.length === 0) {
        countHint.textContent = '';
        countHint.className = 'audit-count-hint';
        startBtn.disabled = true;
        return;
    }

    const MAX = 50;
    let msg = `Найдено паролей: ${passwords.length}`;
    const removed = originalCount - passwords.length;
    if (removed > 0) msg += ` (удалено дубликатов: ${removed})`;
    if (passwords.length > MAX) {
        msg += ` — будет взято первые ${MAX}`;
        countHint.className = 'audit-count-hint warn';
    } else {
        countHint.className = 'audit-count-hint';
    }

    countHint.textContent = msg;
    startBtn.disabled = false;
}

// ----- Pure HIBP check (no DOM side effects) -----

async function checkPwnedBatch(password) {
    try {
        const encoder = new TextEncoder();
        const data = encoder.encode(password);
        const hashBuffer = await crypto.subtle.digest('SHA-1', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

        // Reuse existing cache
        if (AppState.pwnedCache.has(hashHex)) {
            return AppState.pwnedCache.get(hashHex);
        }

        const prefix = hashHex.substring(0, 5).toUpperCase();
        const suffix = hashHex.substring(5).toUpperCase();

        let endpoints = [...HIBP_CONFIG.endpoints];
        if (HIBP_CONFIG.lastSuccessfulMethod) {
            const idx = endpoints.findIndex(e => e.name === HIBP_CONFIG.lastSuccessfulMethod);
            if (idx > 0) { const [last] = endpoints.splice(idx, 1); endpoints.unshift(last); }
        }

        for (let i = 0; i < endpoints.length; i++) {
            const endpoint = endpoints[i];
            try {
                const response = await fetchWithTimeout(endpoint.url(prefix), {
                    mode: 'cors',
                    headers: { 'User-Agent': 'KhodyrevGuard-Password-Analyzer' }
                }, endpoint.timeout);

                if (response.ok) {
                    const text = await response.text();
                    const count = parseHIBPResponse(text, suffix);
                    AppState.pwnedCache.set(hashHex, count);
                    try { sessionStorage.setItem('hibpCache', JSON.stringify(Object.fromEntries(AppState.pwnedCache))); } catch (e) {}
                    HIBP_CONFIG.lastSuccessfulMethod = endpoint.name;
                    return count;
                }
            } catch (err) {
                if (i === endpoints.length - 1) throw err;
            }
        }
        throw new Error('HIBP недоступен');
    } catch (e) {
        return -1;
    }
}

// ----- Analyse single password (no DOM updates) -----

async function analyzePasswordForBatch(password, includeHibp) {
    const zxcvbnAvailable = typeof zxcvbn === 'function';
    const zxcvbnResult = zxcvbnAvailable ? zxcvbn(password) : null;

    const analysis = analyzePassword(password, zxcvbnResult);
    const crackTimeResult = calculateCrackTimeNew(password);
    const { entropy, charsetSize, length } = crackTimeResult.patterns;
    const { combinations, seconds } = crackTimeResult;

    // Score — same formula as updatePasswordAnalysis()
    const positiveKeys = ['length', 'uppercase', 'lowercase', 'numbers', 'special'];
    const negativeKeys = ['sequences', 'repeating', 'dates', 'leetspeak'];
    const positiveBonus = positiveKeys.filter(k => analysis.criteria[k]).length * 4;
    const negativeBonus = negativeKeys.reduce((s, k) => s + (analysis.criteria[k] ? 4 : -4), 0);

    let finalScore;
    if (zxcvbnAvailable) {
        const zxcvbnBase = Math.min(64, Math.round((zxcvbnResult.guesses_log10 / 20) * 64));
        finalScore = Math.max(1, zxcvbnBase + positiveBonus + negativeBonus);
    } else {
        finalScore = Math.max(1, Math.round(entropy) + (4 * analysis.criteriaCount));
    }

    // HIBP
    let pwnedCount = 0;
    if (includeHibp) {
        pwnedCount = await checkPwnedBatch(password);
        if (pwnedCount >= 1000000)      finalScore = Math.round(finalScore * 0.2);
        else if (pwnedCount >= 100000)  finalScore = Math.round(finalScore * 0.4);
        else if (pwnedCount >= 10000)   finalScore = Math.round(finalScore * 0.6);
        else if (pwnedCount > 0)        finalScore = Math.round(finalScore * 0.8);
    }

    const score = Math.min(100, Math.max(1, finalScore));

    // Strength
    let strengthLevel, strengthClass;
    if (score < 40)       { strengthLevel = 'Слабый';        strengthClass = 'weak'; }
    else if (score < 70)  { strengthLevel = 'Средний';       strengthClass = 'medium'; }
    else if (score < 90)  { strengthLevel = 'Сильный';       strengthClass = 'strong'; }
    else                  { strengthLevel = 'Очень сильный'; strengthClass = 'very-strong'; }

    if (pwnedCount >= 1000000) { strengthLevel = 'Скомпрометирован'; strengthClass = 'weak'; }

    // Crack times (pass non-existent ID → no DOM side effects)
    const crackTimeData = formatCrackTime(seconds, '__audit_noop__');
    const zxcvbnCrackTimeData = zxcvbnAvailable
        ? formatCrackTime(zxcvbnResult.crack_times_seconds.offline_fast_hashing_1e10_per_second, '__audit_noop2__')
        : null;

    // Weak spots
    const weakSpots = [];
    const criteriaLabels = {
        length:    'Длина < 12',
        uppercase: 'Нет заглавных',
        lowercase: 'Нет строчных',
        numbers:   'Нет цифр',
        special:   'Нет спецсимволов',
        sequences: 'Паттерн клавиатуры',
        repeating: 'Повторяющиеся символы',
        dates:     'Содержит дату',
        leetspeak: 'Словарное слово'
    };
    for (const [key, label] of Object.entries(criteriaLabels)) {
        if (!analysis.criteria[key]) weakSpots.push(label);
    }
    if (pwnedCount > 0)  weakSpots.push(`Утечки: ${pwnedCount.toLocaleString()}`);
    if (pwnedCount === -1) weakSpots.push('Утечки: Н/Д');

    return {
        maskedPassword: '*'.repeat(password.length),
        length: password.length,
        score,
        strengthLevel,
        strengthClass,
        entropy: Math.round(entropy),
        charsetSize,
        combinations,
        crackTime: crackTimeData.text,
        zxcvbnCrackTime: zxcvbnCrackTimeData ? zxcvbnCrackTimeData.text : 'Н/Д',
        pwnedCount,
        criteria: analysis.criteria,
        weakSpots
    };
}

// ----- Main audit loop -----

const delay = ms => new Promise(r => setTimeout(r, ms));

async function runBatchAudit() {
    const textarea = document.getElementById('auditTextarea');
    if (!textarea) return;

    const raw = parsePasswordInput(textarea.value);
    const passwords = raw.slice(0, 50);
    if (passwords.length === 0) return;

    const modeRadio = document.querySelector('input[name="auditMode"]:checked');
    const mode = modeRadio ? modeRadio.value : 'simple';
    const includeHibp = mode === 'detailed';

    AuditState.passwords = passwords;
    AuditState.results = [];
    AuditState.mode = mode;
    AuditState.isRunning = true;

    // Lock inputs while running
    const textareaEl = document.getElementById('auditTextarea');
    const startBtnEl = document.getElementById('auditStartBtn');
    if (textareaEl) textareaEl.disabled = true;
    if (startBtnEl) startBtnEl.disabled = true;
    document.querySelectorAll('input[name="auditMode"]').forEach(r => r.disabled = true);

    // Clear any previous results from step 3
    document.querySelector('#auditStep3 .audit-done-icon')?.classList.remove('animate');
    const prevDoneText = document.getElementById('auditDoneText');
    if (prevDoneText) prevDoneText.textContent = '';
    const prevDlBtns = document.getElementById('auditDownloadBtns');
    if (prevDlBtns) prevDlBtns.innerHTML = '';

    showAuditStep(2);

    const total = passwords.length;
    const progressFill = document.getElementById('auditProgressFill');
    const progressText = document.getElementById('auditProgressText');
    const progressSub  = document.getElementById('auditProgressSub');
    if (progressFill) progressFill.style.width = '0%';
    if (progressText) progressText.textContent = `Обработано: 0 / ${total}`;
    if (progressSub) progressSub.textContent = '';

    for (let i = 0; i < total; i++) {
        if (!AuditState.isRunning) break;

        const pw = passwords[i];
        if (progressText) progressText.textContent = `Обработано: ${i} / ${total}`;
        if (progressFill) progressFill.style.width = `${(i / total) * 100}%`;
        if (progressSub && includeHibp) progressSub.textContent = 'Проверка утечек HIBP...';

        const result = await analyzePasswordForBatch(pw, includeHibp);
        AuditState.results.push(result);

        // Small delay between HIBP requests to be respectful of rate limits
        if (includeHibp && i < total - 1) await delay(120);
    }

    if (progressFill) progressFill.style.width = '100%';
    if (progressText) progressText.textContent = `Обработано: ${total} / ${total}`;
    if (progressSub) progressSub.textContent = '';

    AuditState.isRunning = false;

    // Unlock inputs so user can modify and re-run
    const textareaElDone = document.getElementById('auditTextarea');
    const startBtnElDone = document.getElementById('auditStartBtn');
    if (textareaElDone) textareaElDone.disabled = false;
    document.querySelectorAll('input[name="auditMode"]').forEach(r => r.disabled = false);
    // Re-enable start button only if textarea has content
    if (startBtnElDone) startBtnElDone.disabled = !textareaElDone || textareaElDone.value.trim() === '';

    // Show done step
    showAuditStep(3);

    // Animate check icon
    const doneIcon = document.querySelector('#auditStep3 .audit-done-icon');
    if (doneIcon) {
        doneIcon.classList.remove('animate');
        requestAnimationFrame(() => setTimeout(() => doneIcon.classList.add('animate'), 50));
    }

    const doneText = document.getElementById('auditDoneText');
    if (doneText) {
        const compromised = AuditState.results.filter(r => r.pwnedCount > 0).length;
        let msg = `Готово! ${AuditState.results.length} паролей проанализированы`;
        if (includeHibp && compromised > 0) msg += ` · Скомпрометировано: ${compromised}`;
        doneText.textContent = msg;
    }

    const dlBtns = document.getElementById('auditDownloadBtns');
    if (dlBtns) {
        dlBtns.innerHTML = '';
        if (mode === 'simple') {
            dlBtns.appendChild(createDownloadBtn('file-text', 'Скачать TXT', 'txt', 'btn-secondary'));
            dlBtns.appendChild(createDownloadBtn('table-2', 'Скачать CSV', 'csv', 'btn-secondary'));
        } else {
            dlBtns.appendChild(createDownloadBtn('globe', 'Скачать HTML', 'html', 'btn-primary'));
            dlBtns.appendChild(createDownloadBtn('braces', 'Скачать JSON', 'json', 'btn-secondary'));
        }
        if (window.lucide) lucide.createIcons();
    }
}

function createDownloadBtn(icon, label, format, btnClass) {
    const btn = document.createElement('button');
    btn.className = `btn ${btnClass}`;
    btn.innerHTML = `<i data-lucide="${icon}"></i> ${label}`;
    btn.addEventListener('click', () => triggerAuditExport(format));
    return btn;
}

function triggerAuditExport(format) {
    const results = AuditState.results;
    const mode = AuditState.mode;
    if (!results || results.length === 0) return;

    const now = new Date();
    const ts = now.toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const filename = `audit-report_${ts}.${format}`;

    if (format === 'csv') downloadFile(buildAuditCSV(results), filename, 'text/csv');
    if (format === 'txt') downloadFile(buildAuditTXT(results), filename, 'text/plain');
    if (format === 'html') downloadFile(buildAuditHTML(results, mode), filename, 'text/html');
    if (format === 'json') downloadFile(buildAuditJSON(results, mode), filename, 'application/json');
}

// ----- Export: CSV -----

function buildAuditCSV(results) {
    let csv = '\uFEFF'; // BOM for Excel Cyrillic
    csv += '#,Пароль,Длина,Оценка/100,Уровень\n';
    results.forEach((r, i) => {
        csv += `${i + 1},"${r.maskedPassword}",${r.length},${r.score},"${r.strengthLevel}"\n`;
    });
    return csv;
}

// ----- Export: TXT -----

function buildAuditTXT(results) {
    const date = new Date().toLocaleString('ru-RU');
    const counts = summarizeCounts(results);

    const line = '─'.repeat(62);
    let txt = '╔══════════════════════════════════════════════════════════════╗\n';
    txt += '║       АУДИТ ПАРОЛЕЙ — KHODYREVGUARD (УПРОЩЁННЫЙ)             ║\n';
    txt += '╚══════════════════════════════════════════════════════════════╝\n\n';
    txt += `Дата:           ${date}\n`;
    txt += `Всего паролей:  ${results.length}\n`;
    txt += `${line}\n\n`;

    // Table header
    const h = padR('#', 4) + padR('Маскированный пароль', 24) + padR('Длина', 7) + padR('Оценка', 8) + 'Уровень';
    txt += h + '\n';
    txt += '─'.repeat(4) + '┼' + '─'.repeat(23) + '┼' + '─'.repeat(6) + '┼' + '─'.repeat(7) + '┼' + '─'.repeat(18) + '\n';

    results.forEach((r, i) => {
        const row = padR(String(i + 1), 4) + padR(r.maskedPassword.slice(0, 22), 24) + padR(String(r.length), 7) + padR(String(r.score), 8) + r.strengthLevel;
        txt += row + '\n';
    });

    txt += `\n${line}\n`;
    txt += `ИТОГО:\n`;
    txt += `  Слабых:        ${counts.weak}\n`;
    txt += `  Средних:       ${counts.medium}\n`;
    txt += `  Сильных:       ${counts.strong}\n`;
    txt += `  Очень сильных: ${counts.veryStrong}\n`;

    return txt;
}

function padR(str, len) {
    return str.length >= len ? str.slice(0, len) : str + ' '.repeat(len - str.length);
}

// ----- Export: JSON -----

function buildAuditJSON(results, mode) {
    const counts = summarizeCounts(results);
    const compromised = results.filter(r => r.pwnedCount > 0).length;

    const output = {
        timestamp: new Date().toISOString(),
        mode,
        totalPasswords: results.length,
        summary: {
            weak: counts.weak,
            medium: counts.medium,
            strong: counts.strong,
            veryStrong: counts.veryStrong,
            compromised: mode === 'detailed' ? compromised : undefined
        },
        passwords: results.map((r, i) => ({
            index: i + 1,
            maskedPassword: r.maskedPassword,
            length: r.length,
            score: r.score,
            strengthLevel: r.strengthLevel,
            entropy: r.entropy,
            charsetSize: r.charsetSize,
            crackTime: r.crackTime,
            zxcvbnCrackTime: r.zxcvbnCrackTime,
            pwnedCount: mode === 'detailed' ? r.pwnedCount : undefined,
            criteria: r.criteria
        }))
    };

    return JSON.stringify(output, null, 2);
}

// ----- Export: HTML -----

function buildAuditHTML(results, mode) {
    const date = new Date().toLocaleString('ru-RU');
    const counts = summarizeCounts(results);
    const compromised = results.filter(r => r.pwnedCount > 0).length;
    const isDetailed = mode === 'detailed';

    function scoreColor(s) {
        if (s >= 90) return '#339af0';
        if (s >= 70) return '#51cf66';
        if (s >= 40) return '#f08c00';
        return '#e03131';
    }
    function scoreBg(s) {
        if (s >= 90) return 'rgba(51,154,240,0.12)';
        if (s >= 70) return 'rgba(81,207,102,0.12)';
        if (s >= 40) return 'rgba(240,140,0,0.12)';
        return 'rgba(224,49,49,0.12)';
    }

    const summaryCards = [
        { label: 'Слабых',        count: counts.weak,      color: '#e03131', bg: 'rgba(224,49,49,0.10)' },
        { label: 'Средних',       count: counts.medium,    color: '#f08c00', bg: 'rgba(240,140,0,0.10)' },
        { label: 'Сильных',       count: counts.strong,    color: '#51cf66', bg: 'rgba(81,207,102,0.10)' },
        { label: 'Очень сильных', count: counts.veryStrong,color: '#339af0', bg: 'rgba(51,154,240,0.10)' },
    ];

    const summaryHtml = summaryCards.map(c => `
        <div style="background:${c.bg};border:1px solid ${c.color}33;border-radius:12px;padding:16px 20px;text-align:center;flex:1;min-width:100px;">
            <div style="font-size:1.8em;font-weight:700;color:${c.color}">${c.count}</div>
            <div style="font-size:0.8em;color:#6c757d;margin-top:4px">${c.label}</div>
        </div>`).join('');

    const hibpSummary = isDetailed ? `
        <div style="background:rgba(174,62,201,0.10);border:1px solid #ae3ec933;border-radius:12px;padding:16px 20px;text-align:center;flex:1;min-width:100px;">
            <div style="font-size:1.8em;font-weight:700;color:#ae3ec9">${compromised}</div>
            <div style="font-size:0.8em;color:#6c757d;margin-top:4px">Скомпрометировано</div>
        </div>` : '';

    // Table rows
    const criteriaKeys = ['length','uppercase','lowercase','numbers','special','sequences','repeating','dates','leetspeak'];
    const criteriaLabels = {
        length:'≥12',uppercase:'A-Z',lowercase:'a-z',numbers:'0-9',special:'Спец',
        sequences:'Посл.',repeating:'Повт.',dates:'Даты',leetspeak:'Слова'
    };

    const detailedCols = isDetailed
        ? `<th>Время взлома</th><th>Энтропия</th><th>Утечки</th><th>${criteriaKeys.map(k => criteriaLabels[k]).join('</th><th>')}</th>`
        : '';

    const tableRows = results.map((r, i) => {
        const sc = scoreColor(r.score);
        const sb = scoreBg(r.score);
        const scoreBadge = `<span style="background:${sb};color:${sc};border:1px solid ${sc}33;padding:3px 10px;border-radius:20px;font-weight:700;font-size:0.85em;white-space:nowrap">${r.score}/100</span>`;
        const levelBadge = `<span style="color:${sc};font-weight:600;font-size:1em">${r.strengthLevel}</span>`;

        const detailedCells = isDetailed ? `
            <td style="white-space:nowrap">${r.crackTime}</td>
            <td>${r.entropy} бит</td>
            <td style="color:${r.pwnedCount > 0 ? '#e03131' : r.pwnedCount === -1 ? '#6c757d' : '#12b886'};font-weight:600">
                ${r.pwnedCount > 0 ? r.pwnedCount.toLocaleString() : r.pwnedCount === -1 ? 'Н/Д' : 'Чисто'}
            </td>
            ${criteriaKeys.map(k => `<td style="text-align:center;color:${r.criteria[k] ? '#12b886' : '#e03131'}">${r.criteria[k] ? '✓' : '✕'}</td>`).join('')}
        ` : '';

        return `<tr>
            <td style="text-align:center;color:#6c757d;font-size:0.85em">${i + 1}</td>
            <td style="font-family:monospace;font-size:0.8em;color:#6c757d">${r.maskedPassword.slice(0, 20)}</td>
            <td style="text-align:center">${r.length}</td>
            <td style="text-align:center">${scoreBadge}</td>
            <td>${levelBadge}</td>
            ${detailedCells}
        </tr>`;
    }).join('');

    return `<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Аудит паролей — KhodyrevGuard</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        *,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
        body{font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f0f1ff;background-image:radial-gradient(circle at 15% 85%,rgba(66,99,235,.12) 0%,transparent 50%),radial-gradient(circle at 85% 15%,rgba(121,80,242,.10) 0%,transparent 50%);min-height:100vh;padding:32px 20px 48px;color:#212529}
        .page{max-width:1100px;margin:0 auto;display:flex;flex-direction:column;gap:20px}
        .header{background:rgba(255,255,255,.65);backdrop-filter:blur(20px);border:1px solid rgba(255,255,255,.85);border-radius:20px;padding:20px 32px;display:flex;align-items:center;justify-content:space-between;box-shadow:0 4px 24px rgba(66,99,235,.08)}
        .logo{font-size:1.4em;font-weight:700;background:linear-gradient(135deg,#4263eb 0%,#7950f2 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
        .header-meta{font-size:0.82em;color:#6c757d;text-align:right;line-height:1.6}
        .header-meta strong{display:block;color:#495057}
        .card{background:#fff;border-radius:16px;box-shadow:0 2px 12px rgba(66,99,235,.07),0 1px 3px rgba(0,0,0,.04);border:1px solid rgba(66,99,235,.08);padding:24px}
        .summary{display:flex;gap:12px;flex-wrap:wrap}
        table{width:100%;border-collapse:collapse;font-size:1.05em}
        th{text-align:left;padding:12px 15px;background:#f8f9ff;color:#495057;font-weight:600;border-bottom:2px solid #e9ecef;white-space:nowrap}
        td{padding:11px 15px;border-bottom:1px solid #f1f3ff;vertical-align:middle}
        tr:hover td{background:#fafbff}
        .footer{text-align:center;color:#adb5bd;font-size:0.82em;padding:4px 0}
        @media(max-width:640px){.header{flex-direction:column;gap:12px;text-align:center}.header-meta{text-align:center}}
    </style>
</head>
<body>
<div class="page">
    <div class="header">
        <div class="logo">🛡️ KhodyrevGuard</div>
        <div class="header-meta">
            <strong>Пакетный аудит паролей${isDetailed ? ' · Подробный' : ' · Упрощённый'}</strong>
            ${date} · ${results.length} паролей
        </div>
    </div>

    <div class="card">
        <div style="font-size:0.85em;font-weight:600;color:#6c757d;margin-bottom:14px;text-transform:uppercase;letter-spacing:.05em">Сводка</div>
        <div class="summary">${summaryHtml}${hibpSummary}</div>
    </div>

    <div class="card" style="padding:0;overflow:hidden">
        <div style="overflow-x:auto">
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Пароль</th>
                        <th>Длина</th>
                        <th>Оценка</th>
                        <th>Уровень</th>
                        ${detailedCols}
                    </tr>
                </thead>
                <tbody>${tableRows}</tbody>
            </table>
        </div>
    </div>

    <div class="footer"><strong>KhodyrevGuard</strong> — Профессиональный анализатор надёжности паролей &nbsp;·&nbsp; ${date}</div>
</div>
</body>
</html>`;
}

// ----- Helpers -----

function summarizeCounts(results) {
    return {
        weak:      results.filter(r => r.score < 40).length,
        medium:    results.filter(r => r.score >= 40 && r.score < 70).length,
        strong:    results.filter(r => r.score >= 70 && r.score < 90).length,
        veryStrong:results.filter(r => r.score >= 90).length
    };
}

// ----- Event listeners -----

document.addEventListener('DOMContentLoaded', () => {
    // Trigger button (opens modal)
    const openBtn = document.getElementById('openAuditModalBtn');
    if (openBtn) openBtn.addEventListener('click', openAuditModal);

    // Close button
    const closeBtn = document.getElementById('auditCloseBtn');
    if (closeBtn) closeBtn.addEventListener('click', closeAuditModal);

    // Start button
    const startBtn = document.getElementById('auditStartBtn');
    if (startBtn) startBtn.addEventListener('click', runBatchAudit);

    // Restart button
    const restartBtn = document.getElementById('auditRestartBtn');
    if (restartBtn) restartBtn.addEventListener('click', resetAuditModal);

    // File input
    const fileInput = document.getElementById('auditFileInput');
    if (fileInput) {
        fileInput.addEventListener('change', e => {
            const file = e.target.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = ev => {
                const textarea = document.getElementById('auditTextarea');
                if (textarea) {
                    textarea.value = ev.target.result;
                    const raw = parsePasswordInput(ev.target.result);
                    updatePasswordCount(raw, ev.target.result.split(/[\s\n]+/).filter(p => p.length > 0).length);
                }
            };
            reader.readAsText(file);
            fileInput.value = '';
        });
    }

    // Dropzone drag-and-drop
    const dropzone = document.getElementById('auditDropzone');
    if (dropzone) {
        dropzone.addEventListener('dragover', e => {
            e.preventDefault();
            dropzone.classList.add('drag-over');
        });
        dropzone.addEventListener('dragleave', () => dropzone.classList.remove('drag-over'));
        dropzone.addEventListener('drop', e => {
            e.preventDefault();
            dropzone.classList.remove('drag-over');
            const file = e.dataTransfer.files[0];
            if (!file || !file.name.endsWith('.txt')) {
                showNotification('Поддерживаются только .txt файлы', 'warning');
                return;
            }
            const reader = new FileReader();
            reader.onload = ev => {
                const textarea = document.getElementById('auditTextarea');
                if (textarea) {
                    textarea.value = ev.target.result;
                    const raw = parsePasswordInput(ev.target.result);
                    updatePasswordCount(raw, ev.target.result.split(/[\s\n]+/).filter(p => p.length > 0).length);
                }
            };
            reader.readAsText(file);
        });
    }

    // Textarea input
    const textarea = document.getElementById('auditTextarea');
    if (textarea) {
        textarea.addEventListener('input', () => {
            const originalParts = textarea.value.split(/[\s\n]+/).filter(p => p.length > 0);
            const unique = parsePasswordInput(textarea.value);
            updatePasswordCount(unique, originalParts.length);
        });
    }

    // Mode radio → update AuditState.mode
    document.querySelectorAll('input[name="auditMode"]').forEach(radio => {
        radio.addEventListener('change', () => {
            AuditState.mode = radio.value;
            const step2 = document.getElementById('auditStep2');
            const step3 = document.getElementById('auditStep3');
            if ((step2 && !step2.hasAttribute('hidden')) || (step3 && !step3.hasAttribute('hidden'))) {
                softResetAudit();
            }
        });
    });

    // Close on overlay click
    const modal = document.getElementById('auditModal');
    if (modal) {
        modal.addEventListener('click', e => {
            if (e.target === modal) closeAuditModal();
        });
    }

    // Close on Escape
    document.addEventListener('keydown', e => {
        if (e.key === 'Escape') {
            const modal = document.getElementById('auditModal');
            if (modal && !modal.hasAttribute('hidden')) closeAuditModal();
        }
    });
});
