// Export functions
function generateExportFilename(format) {
    const now = new Date();
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const day = String(now.getDate()).padStart(2, '0');
    const hours = String(now.getHours()).padStart(2, '0');
    const minutes = String(now.getMinutes()).padStart(2, '0');
    const seconds = String(now.getSeconds()).padStart(2, '0');
    const dateStr = `${year}-${month}-${day}_${hours}-${minutes}-${seconds}`;
    return `password-analysis_${dateStr}.${format}`;
}

function downloadFile(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType + ';charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showNotification(`Файл ${filename} загружен!`);
}

function exportToTXT() {
    if (!AppState.lastAnalysisResults) {
        showNotification('Нет данных для экспорта. Сначала проанализируйте пароль.', 'warning');
        return;
    }

    const data = AppState.lastAnalysisResults;
    const date = new Date(data.timestamp).toLocaleString('ru-RU');

    let text = '╔════════════════════════════════════════════════════════════╗\n';
    text += '║     ОТЧЁТ АНАЛИЗА ПАРОЛЯ - KHODYREVGUARD                   ║\n';
    text += '╚════════════════════════════════════════════════════════════╝\n\n';

    text += `Дата анализа: ${date}\n`;
    text += '─'.repeat(60) + '\n\n';

    text += '📊 ОБЩАЯ ИНФОРМАЦИЯ:\n';
    text += `   Длина пароля: ${data.password.length} символов\n`;
    text += `   Оценка безопасности: ${data.score}/100\n`;
    text += `   Уровень надежности: ${data.strengthLevel}\n\n`;

    text += '🔐 ЭНТРОПИЯ И КРИПТОСТОЙКОСТЬ:\n';
    text += `   Энтропия: ${data.entropy} бит\n`;
    text += `   Размер алфавита: ${data.charsetSize} символов\n`;
    text += `   Возможных комбинаций: ${data.combinationsFormatted}\n`;
    text += `   Время взлома (brute-force): ${data.crackTime.formatted}\n`;
    text += `   Время взлома (zxcvbn): ${data.zxcvbnCrackTime ? data.zxcvbnCrackTime.formatted : 'Недоступно'}\n\n`;

    text += '✓ СООТВЕТСТВИЕ КРИТЕРИЯМ:\n';
    text += `   ${data.criteria.length ? '✓' : '✗'} Минимум 12 символов\n`;
    text += `   ${data.criteria.uppercase ? '✓' : '✗'} Заглавные буквы (A-Z)\n`;
    text += `   ${data.criteria.lowercase ? '✓' : '✗'} Строчные буквы (a-z)\n`;
    text += `   ${data.criteria.numbers ? '✓' : '✗'} Цифры (0-9)\n`;
    text += `   ${data.criteria.special ? '✓' : '✗'} Специальные символы (!@#$%...)\n`;
    text += `   ${data.criteria.sequences ? '✓' : '✗'} Без клавиатурных паттернов\n`;
    text += `   ${data.criteria.repeating ? '✓' : '✗'} Без повторений (aaa, 111...)\n`;
    text += `   ${data.criteria.dates ? '✓' : '✗'} Без дат рождения и годовщин\n`;
    text += `   ${data.criteria.leetspeak ? '✓' : '✗'} Без словарных слов и l33t-speak замен\n\n`;

    text += '🛡️ ПРОВЕРКА БЕЗОПАСНОСТИ:\n';
    text += `   Есть в утечках: ${data.pwnedCount > 0 ? 'Да' : 'Нет'}\n`;
    if (data.pwnedCount > 0) {
        text += `   ⚠️ ВНИМАНИЕ! Пароль найден в ${data.pwnedCount.toLocaleString()} утечках данных!\n`;
    }

    text += '\n' + '─'.repeat(60) + '\n';

    downloadFile(text, generateExportFilename('txt'), 'text/plain');
}

function exportToJSON() {
    if (!AppState.lastAnalysisResults) {
        showNotification('Нет данных для экспорта. Сначала проанализируйте пароль.', 'warning');
        return;
    }

    const json = JSON.stringify(AppState.lastAnalysisResults, null, 2);
    downloadFile(json, generateExportFilename('json'), 'application/json');
}

function exportToCSV() {
    if (!AppState.lastAnalysisResults) {
        showNotification('Нет данных для экспорта. Сначала проанализируйте пароль.', 'warning');
        return;
    }

    const data = AppState.lastAnalysisResults;
    const date = new Date(data.timestamp).toLocaleString('ru-RU');

    let csv = '\uFEFF'; // BOM для корректного отображения кириллицы в Excel
    csv += 'Параметр,Значение\n';
    csv += `Дата анализа,"${date}"\n`;
    csv += '\n';
    csv += 'ОБЩАЯ ИНФОРМАЦИЯ\n';
    csv += `Длина пароля,${data.password.length}\n`;
    csv += `Оценка безопасности,${data.score}\n`;
    csv += `Уровень надежности,"${data.strengthLevel}"\n`;
    csv += '\n';
    csv += 'ЭНТРОПИЯ\n';
    csv += `Энтропия (биты),${data.entropy}\n`;
    csv += `Размер алфавита,${data.charsetSize}\n`;
    csv += `Комбинаций,"${data.combinationsFormatted}"\n`;
    csv += `Время взлома (brute-force),"${data.crackTime.formatted}"\n`;
    csv += `Время взлома (zxcvbn),"${data.zxcvbnCrackTime ? data.zxcvbnCrackTime.formatted : 'Недоступно'}"\n`;
    csv += '\n';
    csv += 'КРИТЕРИИ\n';
    csv += `Минимум 12 символов,${data.criteria.length ? 'Да' : 'Нет'}\n`;
    csv += `Заглавные буквы,${data.criteria.uppercase ? 'Да' : 'Нет'}\n`;
    csv += `Строчные буквы,${data.criteria.lowercase ? 'Да' : 'Нет'}\n`;
    csv += `Цифры,${data.criteria.numbers ? 'Да' : 'Нет'}\n`;
    csv += `Специальные символы,${data.criteria.special ? 'Да' : 'Нет'}\n`;
    csv += `Без клавиатурных паттернов,${data.criteria.sequences ? 'Да' : 'Нет'}\n`;
    csv += `Без повторений,${data.criteria.repeating ? 'Да' : 'Нет'}\n`;
    csv += `Без дат рождения и годовщин,${data.criteria.dates ? 'Да' : 'Нет'}\n`;
    csv += `Без словарных слов и l33t-speak,${data.criteria.leetspeak ? 'Да' : 'Нет'}\n`;
    csv += '\n';
    csv += 'БЕЗОПАСНОСТЬ\n';
    csv += `Статус,"${data.pwnedStatus}"\n`;
    csv += `Найдено в утечках,${data.pwnedCount}\n`;

    downloadFile(csv, generateExportFilename('csv'), 'text/csv');
}

function exportToHTML() {
    if (!AppState.lastAnalysisResults) {
        showNotification('Нет данных для экспорта. Сначала проанализируйте пароль.', 'warning');
        return;
    }

    const data = AppState.lastAnalysisResults;
    const date = new Date(data.timestamp).toLocaleString('ru-RU');

    const scoreColor = data.score >= 70 ? '#12b886' : data.score >= 40 ? '#f08c00' : '#e03131';
    const scoreBg = data.score >= 70 ? 'rgba(18,184,134,0.12)' : data.score >= 40 ? 'rgba(240,140,0,0.12)' : 'rgba(224,49,49,0.12)';
    const scoreBorder = data.score >= 70 ? 'rgba(18,184,134,0.30)' : data.score >= 40 ? 'rgba(240,140,0,0.30)' : 'rgba(224,49,49,0.30)';

    let html = `<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Отчёт анализа пароля — KhodyrevGuard</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        *, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #f0f1ff;
            background-image:
                radial-gradient(circle at 15% 85%, rgba(66,99,235,0.12) 0%, transparent 50%),
                radial-gradient(circle at 85% 15%, rgba(121,80,242,0.10) 0%, transparent 50%);
            min-height: 100vh;
            padding: 32px 20px 48px;
            color: #212529;
        }
        .page { max-width: 860px; margin: 0 auto; display: flex; flex-direction: column; gap: 20px; }

        /* Header */
        .header {
            background: rgba(255,255,255,0.65);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid rgba(255,255,255,0.85);
            border-radius: 20px;
            padding: 24px 32px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            box-shadow: 0 4px 24px rgba(66,99,235,0.08);
        }
        .logo {
            font-size: 1.5em;
            font-weight: 700;
            background: linear-gradient(135deg, #4263eb 0%, #7950f2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .logo-icon { -webkit-text-fill-color: initial; }
        .header-date { font-size: 0.82em; color: #6c757d; text-align: right; line-height: 1.6; }
        .header-date strong { display: block; color: #495057; font-size: 1.05em; }

        /* Cards */
        .card {
            background: #ffffff;
            border-radius: 16px;
            box-shadow: 0 2px 12px rgba(66,99,235,0.07), 0 1px 3px rgba(0,0,0,0.04);
            border: 1px solid rgba(66,99,235,0.08);
            overflow: hidden;
        }
        .card-header {
            padding: 18px 24px 14px;
            border-bottom: 1px solid #f1f3ff;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .card-icon {
            width: 34px; height: 34px;
            background: linear-gradient(135deg, #4263eb 0%, #7950f2 100%);
            border-radius: 9px;
            display: flex; align-items: center; justify-content: center;
            font-size: 1em;
            flex-shrink: 0;
        }
        .card-title { font-size: 0.95em; font-weight: 600; color: #343a40; }
        .card-body { padding: 20px 24px; }

        /* Hero */
        .hero {
            display: flex;
            align-items: center;
            gap: 40px;
            padding: 28px 32px;
        }
        .ring {
            width: 156px; height: 156px;
            border-radius: 50%;
            background: conic-gradient(${scoreColor} ${data.score}%, #eef0ff ${data.score}%);
            display: flex; align-items: center; justify-content: center;
            flex-shrink: 0;
        }
        .ring-inner {
            width: 112px; height: 112px;
            background: white;
            border-radius: 50%;
            display: flex; flex-direction: column;
            align-items: center; justify-content: center;
        }
        .ring-score { font-size: 2.1em; font-weight: 700; color: ${scoreColor}; line-height: 1; }
        .ring-label { font-size: 0.67em; color: #6c757d; margin-top: 3px; }
        .hero-info { flex: 1; }
        .hero-title { font-size: 1.35em; font-weight: 700; color: #212529; margin-bottom: 6px; }
        .hero-subtitle { font-size: 0.88em; color: #6c757d; margin-bottom: 18px; }
        .strength-badge {
            display: inline-flex;
            padding: 8px 20px;
            border-radius: 999px;
            font-weight: 600;
            font-size: 0.92em;
            background: ${scoreBg};
            color: ${scoreColor};
            border: 1.5px solid ${scoreBorder};
        }

        /* 2x2 Grid */
        .grid-2x2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }

        /* Metric rows */
        .metric {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 0;
            border-bottom: 1px solid #f8f9fa;
            gap: 12px;
        }
        .metric:last-child { border-bottom: none; }
        .metric-label { font-size: 0.85em; color: #6c757d; font-weight: 500; }
        .metric-value { font-size: 0.85em; font-weight: 600; color: #212529; text-align: right; }
        .metric-value.mono { font-family: 'JetBrains Mono', 'Courier New', monospace; font-size: 0.80em; }

        /* Criteria badges */
        .badges { display: flex; flex-wrap: wrap; gap: 9px; }
        .badge {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 6px 13px;
            border-radius: 999px;
            font-size: 0.80em;
            font-weight: 500;
            line-height: 1;
        }
        .badge.valid { background: rgba(18,184,134,0.11); color: #0ca678; border: 1.5px solid rgba(18,184,134,0.24); }
        .badge.invalid { background: rgba(224,49,49,0.09); color: #c92a2a; border: 1.5px solid rgba(224,49,49,0.20); }

        /* HIBP card */
        .card-hibp {
            background: ${data.pwnedCount > 0
                ? 'linear-gradient(135deg, #e03131 0%, #c92a2a 100%)'
                : 'linear-gradient(135deg, #12b886 0%, #0ca678 100%)'};
            border: none;
        }
        .card-hibp .card-header { border-bottom-color: rgba(255,255,255,0.15); }
        .card-hibp .card-icon { background: rgba(255,255,255,0.22); }
        .card-hibp .card-title { color: rgba(255,255,255,0.92); }
        .hibp-body { color: white; text-align: center; padding: 10px 0 6px; }
        .hibp-icon { font-size: 2.4em; display: block; margin-bottom: 10px; }
        .hibp-text { font-size: 0.95em; font-weight: 600; margin-bottom: 4px; }
        .hibp-sub { font-size: 0.82em; opacity: 0.85; }
        .hibp-count {
            display: inline-block;
            background: rgba(255,255,255,0.2);
            border-radius: 10px;
            padding: 7px 16px;
            font-size: 1em;
            font-weight: 700;
            margin-top: 12px;
        }

        /* Lucide icons */
        .card-icon svg { width: 18px; height: 18px; color: white; stroke-width: 2; }
        .logo-svg svg { width: 26px; height: 26px; stroke-width: 2; color: #4263eb; }
        .hibp-icon-svg { display: block; margin: 0 auto 10px; }
        .hibp-icon-svg svg { width: 48px; height: 48px; color: white; stroke-width: 1.5; }

        /* Badge indicators via CSS */
        .badge.valid::before { content: '✓'; margin-right: 4px; font-weight: 700; }
        .badge.invalid::before { content: '✕'; margin-right: 4px; font-weight: 700; }

        /* Footer */
        .footer { text-align: center; color: #adb5bd; font-size: 0.82em; padding: 4px 0; }
        .footer strong { color: #6c757d; }

        /* Responsive */
        @media (max-width: 640px) {
            .hero { flex-direction: column; text-align: center; gap: 20px; }
            .grid-2x2 { grid-template-columns: 1fr; }
            .header { flex-direction: column; gap: 12px; text-align: center; }
            .header-date { text-align: center; }
        }
    </style>
</head>
<body>
    <div class="page">

        <div class="header">
            <div class="logo">
                <i data-lucide="shield" class="logo-svg"></i> KhodyrevGuard
            </div>
            <div class="header-date">
                <strong>Отчёт анализа пароля</strong>
                ${date}
            </div>
        </div>

        <div class="card">
            <div class="hero">
                <div class="ring">
                    <div class="ring-inner">
                        <span class="ring-score">${data.score}</span>
                        <span class="ring-label">из 100</span>
                    </div>
                </div>
                <div class="hero-info">
                    <div class="hero-title">Результат анализа</div>
                    <div class="hero-subtitle">Длина пароля: ${data.password.length} символов</div>
                    <span class="strength-badge">${data.strengthLevel}</span>
                </div>
            </div>
        </div>

        <div class="grid-2x2">

            <div class="card">
                <div class="card-header">
                    <div class="card-icon"><i data-lucide="bar-chart-2"></i></div>
                    <span class="card-title">Общая информация</span>
                </div>
                <div class="card-body">
                    <div class="metric">
                        <span class="metric-label">Длина пароля</span>
                        <span class="metric-value">${data.password.length} символов</span>
                    </div>
                    <div class="metric">
                        <span class="metric-label">Оценка безопасности</span>
                        <span class="metric-value">${data.score} / 100</span>
                    </div>
                    <div class="metric">
                        <span class="metric-label">Уровень надежности</span>
                        <span class="metric-value">${data.strengthLevel}</span>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <div class="card-icon"><i data-lucide="key-round"></i></div>
                    <span class="card-title">Криптостойкость</span>
                </div>
                <div class="card-body">
                    <div class="metric">
                        <span class="metric-label">Энтропия</span>
                        <span class="metric-value">${data.entropy} бит</span>
                    </div>
                    <div class="metric">
                        <span class="metric-label">Размер алфавита</span>
                        <span class="metric-value">${data.charsetSize} символов</span>
                    </div>
                    <div class="metric">
                        <span class="metric-label">Комбинаций</span>
                        <span class="metric-value">${data.combinationsFormatted}</span>
                    </div>
                    <div class="metric">
                        <span class="metric-label">Взлом (brute-force)</span>
                        <span class="metric-value">${data.crackTime.text}</span>
                    </div>
                    <div class="metric">
                        <span class="metric-label">Взлом (zxcvbn)</span>
                        <span class="metric-value">${data.zxcvbnCrackTime ? data.zxcvbnCrackTime.text : 'Недоступно'}</span>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <div class="card-icon"><i data-lucide="check-circle"></i></div>
                    <span class="card-title">Критерии безопасности</span>
                </div>
                <div class="card-body">
                    <div class="badges">
                        <span class="badge ${data.criteria.length ? 'valid' : 'invalid'}">Мин. 12 символов</span>
                        <span class="badge ${data.criteria.uppercase ? 'valid' : 'invalid'}">Заглавные</span>
                        <span class="badge ${data.criteria.lowercase ? 'valid' : 'invalid'}">Строчные</span>
                        <span class="badge ${data.criteria.numbers ? 'valid' : 'invalid'}">Цифры</span>
                        <span class="badge ${data.criteria.special ? 'valid' : 'invalid'}">Спец. символы</span>
                        <span class="badge ${data.criteria.sequences ? 'valid' : 'invalid'}">Без паттернов</span>
                        <span class="badge ${data.criteria.repeating ? 'valid' : 'invalid'}">Без повторений</span>
                        <span class="badge ${data.criteria.dates ? 'valid' : 'invalid'}">Без дат</span>
                        <span class="badge ${data.criteria.leetspeak ? 'valid' : 'invalid'}">Без словарных слов</span>
                    </div>
                </div>
            </div>

            <div class="card card-hibp">
                <div class="card-header">
                    <div class="card-icon"><i data-lucide="shield"></i></div>
                    <span class="card-title">Проверка утечек</span>
                </div>
                <div class="card-body">
                    <div class="hibp-body">
                        ${data.pwnedCount > 0 ? `
                            <i data-lucide="shield-alert" class="hibp-icon-svg"></i>
                            <div class="hibp-text">Пароль скомпрометирован!</div>
                            <div class="hibp-sub">Найден в базах данных утечек</div>
                            <div class="hibp-count">${data.pwnedCount.toLocaleString()} утечек</div>
                        ` : `
                            <i data-lucide="shield-check" class="hibp-icon-svg"></i>
                            <div class="hibp-text">Пароль не скомпрометирован</div>
                            <div class="hibp-sub">Не найден в известных утечках</div>
                        `}
                    </div>
                </div>
            </div>

        </div>

        <div class="footer">
            <strong>KhodyrevGuard</strong> — Профессиональный анализатор надежности паролей &nbsp;·&nbsp; ${date}
        </div>

    </div>
    <script src="https://unpkg.com/lucide@0.576.0/dist/umd/lucide.min.js"></script>
    <script>lucide.createIcons();</script>
</body>
</html>`;

    downloadFile(html, generateExportFilename('html'), 'text/html');
}

function toggleExportMenu() {
    const dropdown = document.getElementById('exportDropdown');
    if (dropdown) dropdown.classList.toggle('open');
}
