// =============================================
// MUTATOR — Мутатор паролей
// Зависимости: analyzePassword, calculateCrackTimeNew, calculateEntropy,
//              formatCrackTime (из analyzer.js)
//              checkPwnedCount (из hibp.js)
//              showNotification, AppState, updateStatusCounters (из app.js)
//              zxcvbn (глобальная библиотека)
// =============================================

// ── Таблица leet-замен ──
const LEET_MAP = {
    a: ['@', '4'],
    e: ['3'],
    i: ['1', '!'],
    o: ['0'],
    s: ['$'],
    t: ['+', '7'],
    l: ['1'],
    g: ['9'],
    b: ['8']
};

// ── Русские названия паттернов ──
const PATTERN_LABELS = {
    'word+number':  'Слово + число',
    'single-word':  'Словарное слово',
    'keyboard':     'Клавиатурный ряд',
    'repeat':       'Повторы',
    'phrase':       'Фраза',
    'generic':      'Произвольный'
};

// ── Определение типа пароля через zxcvbn.sequence ──
function detectPattern(password) {
    if (typeof zxcvbn !== 'function') return 'generic';
    const z = zxcvbn(password);
    const seq = z.sequence;
    const dictMatches = seq.filter(m => m.pattern === 'dictionary');
    const spatial = seq.find(m => m.pattern === 'spatial');
    const repeat  = seq.find(m => m.pattern === 'repeat');

    if (spatial && spatial.token.length / password.length >= 0.4) return 'keyboard';
    if (repeat  && repeat.token.length  / password.length >= 0.4) return 'repeat';
    if (dictMatches.length >= 2) return 'phrase';
    if (dictMatches.length === 1 && /\d/.test(password)) return 'word+number';
    if (dictMatches.length === 1) return 'single-word';
    return 'generic';
}

// ── Применение leet-замен к слову ──
// indices: массив позиций для замены (или null = все возможные позиции)
function applyLeet(word, indices) {
    const chars = word.toLowerCase().split('');
    const positions = indices !== null ? indices : chars.map((_, i) => i);
    positions.forEach(i => {
        const c = chars[i];
        if (LEET_MAP[c]) chars[i] = LEET_MAP[c][0];
    });
    return chars.join('');
}

// Применяет конкретную замену: applyLeetChar(word, 's', '$')
function applyLeetChar(word, from, to) {
    return word.toLowerCase().split('').map(c => c === from ? to : c).join('');
}

// ── Смешанный регистр (каждая вторая буква заглавная) ──
function mixedCase(str) {
    return str.split('').map((c, i) => i % 2 === 0 ? c.toLowerCase() : c.toUpperCase()).join('');
}

// ── Первая буква заглавная ──
function capitalizeFirst(str) {
    if (!str) return str;
    return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
}

// ── Обфускация года/числа ──
function obfuscateYear(numStr) {
    // 2023 → 2o23 (0 → o), 1990 → 1990 (замена 9→g или просто добавить символ)
    if (/^(19|20)\d{2}$/.test(numStr)) {
        return numStr.replace('0', 'o').replace('1', 'l');
    }
    // Не год — просто небольшая вставка
    return numStr.replace(/0/g, 'o').replace(/1/g, 'l') || numStr;
}

// ── Вставка символа в позицию ──
function injectAt(str, pos, sym) {
    const p = Math.max(0, Math.min(pos, str.length));
    return str.slice(0, p) + sym + str.slice(p);
}

// ── Извлечение числовой части из пароля ──
function extractParts(password, z) {
    if (typeof zxcvbn !== 'function') {
        // fallback: split at first digit run
        const m = password.match(/^([^\d]*)(\d+)(.*)$/);
        if (m) return { word: m[1] || password, num: m[2] + m[3] };
        return { word: password, num: '' };
    }
    const dictMatch = z.sequence.find(m => m.pattern === 'dictionary');
    if (dictMatch) {
        const token = dictMatch.token;
        const idx = password.toLowerCase().indexOf(token.toLowerCase());
        if (idx !== -1) {
            const word = password.slice(idx, idx + token.length);
            const prefix = password.slice(0, idx);
            const num = password.slice(idx + token.length);
            return { word, num: num || '', prefix };
        }
    }
    // fallback
    const m = password.match(/^([a-zA-Z]+)(\d+.*)$/);
    if (m) return { word: m[1], num: m[2], prefix: '' };
    return { word: password, num: '', prefix: '' };
}

// ── Рецепты для word+number (summer2023) ──
function getRecipes_wordNumber(password, z) {
    const { word, num } = extractParts(password, z);
    if (!word) return getRecipes_generic(password);

    return [
        // 1: leet(s) + original year + suffix !
        applyLeetChar(word, 's', '$') + num + '!',
        // 2: capitalize + @ between word and number
        capitalizeFirst(word) + '@' + num,
        // 3: leet(s+e) + # separator + year obfuscated
        applyLeet(word, null) + '#' + obfuscateYear(num),
        // 4: mixedCase + leet(e) + number + suffix
        mixedCase(applyLeetChar(word, 'e', '3')) + num + '!',
        // 5: leet(s) + capitalize first char + # + year obfuscated + suffix
        '$' + capitalizeFirst(applyLeet(word, null).slice(1)) + '#' + obfuscateYear(num).toUpperCase() + '!'
    ];
}

// ── Рецепты для single-word (password) ──
function getRecipes_singleWord(password) {
    const w = password.toLowerCase();
    return [
        // 1: leet all + suffix !7
        applyLeet(w, null) + '!7',
        // 2: capitalize + leet(o,s) + suffix #2
        capitalizeFirst(applyLeet(w, null)) + '#2',
        // 3: prefix $ + mixedCase + suffix !
        '$' + mixedCase(w) + '!',
        // 4: leet(e,a,i) + suffix @99
        applyLeet(w, null) + '@99',
        // 5: mixedCase + leet(s) + inject # in middle + suffix
        (function() {
            const base = mixedCase(applyLeetChar(w, 's', '$'));
            const mid = Math.floor(base.length / 2);
            return injectAt(base, mid, '#') + '!';
        })()
    ];
}

// ── Рецепты для keyboard pattern (qwerty123) ──
function getRecipes_keyboard(password) {
    const w = password;
    const mid = Math.floor(w.length / 2);
    return [
        // 1: inject ! at boundary between letters and digits
        (function() {
            const m = w.match(/^([a-zA-Z]+)(\d+.*)$/);
            return m ? m[1] + '!' + m[2] : w + '!';
        })(),
        // 2: capitalize first + @ between halves
        capitalizeFirst(w.slice(0, mid)) + '@' + w.slice(mid),
        // 3: prefix # + capitalizeFirst
        '#' + capitalizeFirst(w),
        // 4: wrap: ! prefix + suffix @2
        '!' + w + '@2',
        // 5: inject symbols at 2 positions
        injectAt(injectAt(w, Math.floor(w.length * 0.3), '!'), Math.floor(w.length * 0.7) + 1, '@')
    ];
}

// ── Рецепты для repeat pattern (aaaaabbb) ──
function getRecipes_repeat(password) {
    return [
        password + '!9',
        '#' + password + '!',
        password.charAt(0).toUpperCase() + password.slice(1) + '@3',
        '!' + password + '#',
        password + '$7' + password.charAt(0).toUpperCase()
    ];
}

// ── Рецепты для phrase (iloveyou) ──
function getRecipes_phrase(password, z) {
    // Treat similarly to single-word but inject symbols at word boundaries
    const w = password.toLowerCase();
    // Try to find word boundaries from zxcvbn
    let boundaries = [];
    if (z && z.sequence) {
        let pos = 0;
        z.sequence.forEach(m => {
            if (m.pattern === 'dictionary' && pos > 0) boundaries.push(pos);
            pos += m.token.length;
        });
    }
    const mid = boundaries[0] || Math.floor(w.length / 2);
    return [
        injectAt(w, mid, '!') + '@7',
        capitalizeFirst(w.slice(0, mid)) + '#' + w.slice(mid) + '!',
        applyLeet(w, null) + '!',
        '$' + mixedCase(w) + '2',
        injectAt(applyLeet(w, null), mid, '@') + '!'
    ];
}

// ── Рецепты для generic (Smdwk1d) — только аддитивные, ядро не трогать ──
function getRecipes_generic(password) {
    const mid = Math.floor(password.length / 2);
    return [
        // 1: suffix !
        password + '!',
        // 2: prefix # + suffix 2
        '#' + password + '2',
        // 3: suffix @99
        password + '@99',
        // 4: wrap _ ... _!
        '_' + password + '_!',
        // 5: inject ! in middle + suffix @2
        injectAt(password, mid, '!') + '@2'
    ];
}

// ── Главная функция генерации 5 мутаций ──
function generateMutations(password) {
    const z = typeof zxcvbn === 'function' ? zxcvbn(password) : null;
    const pattern = detectPattern(password);

    let candidates;
    switch (pattern) {
        case 'word+number':  candidates = getRecipes_wordNumber(password, z); break;
        case 'single-word':  candidates = getRecipes_singleWord(password); break;
        case 'keyboard':     candidates = getRecipes_keyboard(password); break;
        case 'repeat':       candidates = getRecipes_repeat(password); break;
        case 'phrase':       candidates = getRecipes_phrase(password, z); break;
        default:             candidates = getRecipes_generic(password);
    }

    // Дедупликация: убрать оригинал + пустые + дубли
    const seen = new Set([password.toLowerCase()]);
    const unique = [];
    for (const v of candidates) {
        if (!v || seen.has(v.toLowerCase())) continue;
        seen.add(v.toLowerCase());
        unique.push(v);
    }

    // Дополняем до 5 если меньше уникальных (не должно происходить, но подстраховка)
    const fallbacks = getRecipes_generic(password);
    for (const fb of fallbacks) {
        if (unique.length >= 5) break;
        if (!fb || seen.has(fb.toLowerCase())) continue;
        seen.add(fb.toLowerCase());
        unique.push(fb);
    }

    return unique.slice(0, 5);
}

// ── Синхронное вычисление score (без HIBP) ──
function scoreVariantSync(password) {
    const z = typeof zxcvbn === 'function' ? zxcvbn(password) : null;
    const analysis = analyzePassword(password, z);
    const crack = calculateCrackTimeNew(password);
    const entropyData = calculateEntropy(password);

    const posBonus = ['length', 'uppercase', 'lowercase', 'numbers', 'special']
        .filter(k => analysis.criteria[k]).length * 4;
    const negBonus = ['sequences', 'repeating', 'dates', 'leetspeak']
        .reduce((s, k) => s + (analysis.criteria[k] ? 4 : -4), 0);

    let base;
    if (z) {
        base = Math.min(64, Math.round((z.guesses_log10 / 20) * 64));
    } else {
        base = Math.min(64, Math.round(entropyData.entropy));
    }

    return {
        score: Math.min(100, Math.max(1, base + posBonus + negBonus)),
        entropy: Math.round(entropyData.entropy),
        crackSeconds: crack.seconds,
        crackSecondsZxcvbn: z ? z.crack_times_seconds.offline_slow_hashing_1e4_per_second : null,
        criteria: analysis.criteria
    };
}

// ── score → сегментов (0–4) ──
function scoreToSegments(score) {
    if (score <= 0) return 0;
    if (score < 40) return 1;
    if (score < 70) return 2;
    if (score < 90) return 3;
    return 4;
}

// ── score → CSS-класс и текст ──
function scoreToMeta(score) {
    if (score < 40) return { cls: 'weak',       label: 'Слабый',       color: 'var(--accent-red)'    };
    if (score < 70) return { cls: 'medium',     label: 'Средний',      color: 'var(--accent-yellow)' };
    if (score < 90) return { cls: 'strong',     label: 'Сильный',      color: 'var(--accent-green)'  };
    return              { cls: 'very-strong', label: 'Очень сильный', color: 'var(--accent-blue)'  };
}

// ── Обновление HIBP-полоски ──
function updateMutatorHIBP(elementId, count) {
    const el = document.getElementById(elementId);
    if (!el) return;

    if (count === 0) {
        el.className = 'mutator-hibp safe';
        el.innerHTML = '<i data-lucide="shield-check"></i><span>Не найден в утечках</span>';
    } else if (count > 0) {
        el.className = 'mutator-hibp compromised';
        el.innerHTML = `<i data-lucide="triangle-alert"></i><span>Найден в ${count.toLocaleString()} утечках</span>`;
    } else {
        el.className = 'mutator-hibp warning';
        el.innerHTML = '<i data-lucide="circle-alert"></i><span>Проверка недоступна</span>';
    }
    if (window.lucide) lucide.createIcons();
}

// ── Асинхронная проверка HIBP для исходного пароля ──
async function runMutatorOriginalHIBP(password) {
    try {
        const count = await checkPwnedCount(password);
        updateMutatorHIBP('mutatorOrigHIBP', count);
    } catch (e) {
        updateMutatorHIBP('mutatorOrigHIBP', -1);
    }
}

// ── Рендер строки "Исходный пароль" ──
function renderMutatorOriginalBar(password, stats) {
    const section = document.getElementById('mutatorOriginalSection');
    const pwdEl   = document.getElementById('mutatorOrigPassword');
    const scoreEl = document.getElementById('mutatorOrigScore');
    const entEl   = document.getElementById('mutatorOrigEntropy');
    const hibpEl  = document.getElementById('mutatorOrigHIBP');

    if (!section) return;

    // Показать пароль (маскировка не нужна — пользователь сам его ввёл)
    if (pwdEl) {
        pwdEl.textContent = password;
        pwdEl.title = password; // tooltip для длинных паролей
    }

    // Score
    if (scoreEl) {
        const meta = scoreToMeta(stats.score);
        scoreEl.textContent = `${stats.score}/100`;
        scoreEl.style.color = meta.color;
    }

    // Entropy
    if (entEl) entEl.textContent = `${stats.entropy} бит`;

    // Crack time — formatCrackTime обновит элемент #mutatorOrigCrackTime и вернёт данные
    formatCrackTime(stats.crackSeconds, 'mutatorOrigCrackTime');
    if (stats.crackSecondsZxcvbn != null)
        formatCrackTime(stats.crackSecondsZxcvbn, 'mutatorOrigCrackTimeZxcvbn');

    // HIBP — сброс в состояние "проверяем"
    if (hibpEl) {
        hibpEl.className = 'mutator-hibp checking';
        hibpEl.innerHTML = '<span class="mutator-hibp-spinner"></span><span>Проверяем...</span>';
    }

    // Pattern tag
    const pattern = detectPattern(password);
    const patternTag   = document.getElementById('mutatorPatternTag');
    const patternLabel = document.getElementById('mutatorPatternLabel');
    if (patternTag && patternLabel) {
        patternLabel.textContent = PATTERN_LABELS[pattern] || pattern;
        patternTag.style.display = 'inline-flex';
        if (window.lucide) lucide.createIcons();
    }

    section.style.display = 'block';
}

// ── Рендер одной карточки варианта ──
function renderVariantCard(index, variant, origStats, varStats) {
    const card = document.createElement('div');
    card.className = 'mutator-variant-card';
    card.dataset.index = index;

    const segments = scoreToSegments(varStats.score);
    const meta = scoreToMeta(varStats.score);

    const scoreDelta   = varStats.score - origStats.score;
    const entropyDelta = varStats.entropy - origStats.entropy;

    const scoreDeltaHtml = scoreDelta !== 0
        ? `<span class="mutator-stat-delta ${scoreDelta > 0 ? 'positive' : 'negative'}">${scoreDelta > 0 ? '+' : ''}${scoreDelta}</span>`
        : '';

    const entropyDeltaHtml = entropyDelta !== 0
        ? `<span class="mutator-stat-delta ${entropyDelta > 0 ? 'positive' : 'negative'}">${entropyDelta > 0 ? '+' : ''}${entropyDelta}</span>`
        : '';

    // Экранируем вариант для data-атрибута
    const variantEscaped = variant.replace(/"/g, '&quot;');

    card.innerHTML = `
        <div class="mutator-card-header">
            <span class="mutator-variant-label">Вариант ${index + 1}</span>
            <div class="mutator-actions">
                <button class="btn btn-secondary mutator-copy-btn"
                        data-variant="${variantEscaped}"
                        title="Копировать пароль">
                    <i data-lucide="clipboard"></i>
                </button>
                <button class="btn btn-analyze mutator-analyze-btn"
                        data-variant="${variantEscaped}"
                        title="Проанализировать в Анализаторе">
                    <i data-lucide="shield-check"></i>
                </button>
            </div>
        </div>

        <div class="mutator-password-display">${escapeHtml(variant)}</div>

        <div class="strength-segments" id="mutator-seg-${index}" data-active="${segments}">
            <div class="strength-segment" data-seg="1"></div>
            <div class="strength-segment" data-seg="2"></div>
            <div class="strength-segment" data-seg="3"></div>
            <div class="strength-segment" data-seg="4"></div>
        </div>

        <div class="mutator-stats-row">
            <div class="mutator-stat">
                <div class="mutator-stat-value" style="color:${meta.color}">
                    ${varStats.score}/100
                    ${scoreDeltaHtml}
                </div>
                <span class="mutator-stat-label">Оценка</span>
            </div>
            <div class="mutator-stat">
                <div class="mutator-stat-value" id="mutator-crack-${index}">—</div>
                <span class="mutator-stat-label">Взлом</span>
            </div>
            <div class="mutator-stat">
                <div class="mutator-stat-value" id="mutator-crack-zx-${index}">—</div>
                <span class="mutator-stat-label">Взлом zxcvbn</span>
            </div>
            <div class="mutator-stat">
                <div class="mutator-stat-value">
                    ${varStats.entropy} бит
                    ${entropyDeltaHtml}
                </div>
                <span class="mutator-stat-label">Энтропия</span>
            </div>
        </div>

        <div class="mutator-hibp checking" id="mutator-hibp-${index}">
            <span class="mutator-hibp-spinner"></span>
            <span>Проверяем утечки...</span>
        </div>
    `;

    return card;
}

// ── Вспомогательная: экранирование HTML ──
function escapeHtml(str) {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// ── Делегированный обработчик кликов на карточках ──
function handleMutatorResultsClick(e) {
    const pwDisplay = e.target.closest('.mutator-password-display');
    if (pwDisplay) {
        const card = pwDisplay.closest('.mutator-variant-card');
        const copyBtn = card ? card.querySelector('.mutator-copy-btn') : null;
        const text = copyBtn ? copyBtn.dataset.variant : pwDisplay.textContent.trim();
        navigator.clipboard.writeText(text)
            .then(() => showNotification('Пароль скопирован!'))
            .catch(() => showNotification('Не удалось скопировать', 'warning'));
        return;
    }

    const copyBtn = e.target.closest('.mutator-copy-btn');
    if (copyBtn) {
        const text = copyBtn.dataset.variant;
        navigator.clipboard.writeText(text)
            .then(() => showNotification('Пароль скопирован!'))
            .catch(() => showNotification('Не удалось скопировать', 'warning'));
        return;
    }

    const analyzeBtn = e.target.closest('.mutator-analyze-btn');
    if (analyzeBtn) {
        const text = analyzeBtn.dataset.variant;

        // Подставляем в поле анализатора
        const input = document.getElementById('passwordInput');
        if (input) input.value = text;

        // Активируем сайдбар-пункт анализатора
        document.querySelectorAll('.sidebar-item').forEach(item => {
            item.classList.remove('active');
            item.setAttribute('aria-selected', 'false');
        });
        const analyzerItem = document.querySelector('.sidebar-item[data-page="analyzer"]');
        if (analyzerItem) {
            analyzerItem.classList.add('active');
            analyzerItem.setAttribute('aria-selected', 'true');
        }

        // Статус-бар
        const titleEl = document.getElementById('statusPageTitle');
        if (titleEl) titleEl.textContent = 'Анализатор';

        // Inspector
        document.getElementById('contentArea')?.classList.add('has-inspector');

        // Анимация перехода (идентично analyzeGeneratedPassword в app.js)
        AppState.currentPage = 'analyzer';
        const curPage = document.querySelector('.page.active');
        if (curPage) {
            curPage.classList.add('page-exit');
            setTimeout(() => {
                document.querySelectorAll('.page').forEach(p => p.classList.remove('active', 'page-exit'));
                document.getElementById('analyzerPage').classList.add('active');
                if (input) input.dispatchEvent(new Event('input'));
            }, 180);
        }
    }
}

// ── Переключение видимости поля мутатора ──
function toggleMutatorVisibility() {
    const input = document.getElementById('mutatorInput');
    const btn   = document.getElementById('mutatorToggleBtn');
    if (!input || !btn) return;

    const isVisible = input.type === 'text';
    input.type = isVisible ? 'password' : 'text';
    btn.innerHTML = isVisible
        ? '<i data-lucide="eye"></i>'
        : '<i data-lucide="eye-off"></i>';
    btn.setAttribute('aria-label', isVisible ? 'Показать пароль' : 'Скрыть пароль');
    if (window.lucide) lucide.createIcons();
}

// ── Главная функция: запуск мутаций ──
async function runMutations() {
    const inputEl = document.getElementById('mutatorInput');
    if (!inputEl) return;

    const password = inputEl.value.trim();

    if (!password) {
        showNotification('Введите пароль для мутации', 'warning');
        return;
    }

    if (password.length < 2) {
        showNotification('Пароль слишком короткий', 'warning');
        return;
    }

    const resultsEl = document.getElementById('mutatorResults');
    if (!resultsEl) return;

    // Кнопка: состояние загрузки
    const mutateBtn = document.getElementById('mutatorMutateBtn');
    if (mutateBtn) {
        mutateBtn.disabled = true;
        mutateBtn.innerHTML = '<i data-lucide="loader-2"></i><span>Генерируем...</span>';
        if (window.lucide) lucide.createIcons();
    }

    try {
        // 1. Исходный пароль: stats + bar
        const origStats = scoreVariantSync(password);
        renderMutatorOriginalBar(password, origStats);

        // 2. Генерация 5 вариантов (синхронно)
        const variants = generateMutations(password);

        // 3. Рендер карточек
        resultsEl.innerHTML = '';
        resultsEl.style.display = 'grid';

        variants.forEach((variant, i) => {
            const varStats = scoreVariantSync(variant);
            const card = renderVariantCard(i, variant, origStats, varStats);
            resultsEl.appendChild(card);
            // formatCrackTime вызываем ПОСЛЕ вставки в DOM
            formatCrackTime(varStats.crackSeconds, 'mutator-crack-' + i);
            if (varStats.crackSecondsZxcvbn != null)
                formatCrackTime(varStats.crackSecondsZxcvbn, 'mutator-crack-zx-' + i);
        });

        // Обновляем Lucide иконки для всех карточек сразу
        if (window.lucide) lucide.createIcons();

        // 4. HIBP для исходного пароля (fire-and-forget)
        runMutatorOriginalHIBP(password);

        // 5. HIBP для вариантов с растяжкой 250мс (не бомбим API)
        variants.forEach((variant, i) => {
            setTimeout(() => {
                checkPwnedCount(variant)
                    .then(count => updateMutatorHIBP('mutator-hibp-' + i, count))
                    .catch(() => updateMutatorHIBP('mutator-hibp-' + i, -1));
            }, i * 250);
        });

        // 6. Счётчик (каждый запуск мутатора = 1 проверка)
        AppState.analyzedCount++;
        if (typeof updateStatusCounters === 'function') updateStatusCounters();

    } finally {
        // Восстанавливаем кнопку
        if (mutateBtn) {
            mutateBtn.disabled = false;
            mutateBtn.innerHTML = '<i data-lucide="wand-2"></i><span>Мутировать</span>';
            if (window.lucide) lucide.createIcons();
        }
    }
}
