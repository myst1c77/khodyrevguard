function calculateEntropy(password) {
    // Shannon Entropy: H = -Σ(p_i × log2(p_i))
    // Measures the actual information content based on character frequency

    if (password.length === 0) {
        return { entropy: 0, charsetSize: 0 };
    }

    // Count frequency of each character
    const charFrequency = {};
    for (let i = 0; i < password.length; i++) {
        const char = password[i];
        charFrequency[char] = (charFrequency[char] || 0) + 1;
    }

    // Calculate Shannon entropy
    let shannonEntropy = 0;
    const passwordLength = password.length;

    for (const char in charFrequency) {
        const probability = charFrequency[char] / passwordLength;
        // H = -Σ(p_i × log2(p_i))
        if (probability > 0) {
            shannonEntropy -= probability * Math.log2(probability);
        }
    }

    // Total entropy = entropy per character × number of characters
    let totalEntropy = shannonEntropy * passwordLength;

    // Apply minimum threshold: at least 1 bit per character
    // This accounts for the fact that an attacker must still try different combinations
    totalEntropy = Math.max(passwordLength, totalEntropy);

    // Calculate charset size for backward compatibility
    // This represents the theoretical character space, not the actual entropy
    let charsetSize = 0;
    if (/[a-z]/.test(password)) charsetSize += 26;
    if (/[A-Z]/.test(password)) charsetSize += 26;
    if (/[0-9]/.test(password)) charsetSize += 10;
    if (/[^a-zA-Z0-9]/.test(password)) {
        const specialChars = password.match(/[^a-zA-Z0-9]/g);
        const uniqueSpecialChars = new Set(specialChars);
        charsetSize += uniqueSpecialChars.size;
    }

    return {
        entropy: totalEntropy,
        charsetSize: charsetSize,
        shannonEntropyPerChar: shannonEntropy,
        uniqueChars: Object.keys(charFrequency).length
    };
}

/**
 * Форматирует время взлома пароля (НОВАЯ ВЕРСИЯ - passwordmonster-style)
 * Требования:
 * - Секунды: 2 десятичных знака (0.00, 0.01, 59.99)
 * - Минуты: десятичные знаки (3.72, 19.7)
 * - Часы и выше: целые числа
 * - После 1 миллиарда лет: "вечность"
 * @param {number} seconds - Время в секундах
 * @returns {object} Объект с text, emoji, color, seconds, formatted
 */
function updateCrackTimeDanger(seconds) {
    const card = document.getElementById('crackTimeDanger');
    const iconEl = document.getElementById('crackDangerIcon');
    const levelEl = document.getElementById('crackDangerLevel');
    const sublabelEl = document.getElementById('crackDangerSublabel');
    if (!card) return;

    let icon, level, sublabel, color, bgColor, iconBg;

    const isLight = document.documentElement.getAttribute('data-theme') === 'light';
    const a1 = isLight ? 0.22 : 0.08;   // фон шапки
    const a2 = isLight ? 0.38 : 0.15;   // фон иконки
    const a1s = isLight ? 0.18 : 0.06;  // фон шапки (слабый вариант)
    const a2s = isLight ? 0.30 : 0.12;  // фон иконки (слабый вариант)

    if (seconds < 60) {
        icon = 'shield-x'; level = 'Критически опасно'; sublabel = 'Взламывается за секунды';
        color = 'var(--accent-red)'; bgColor = `rgba(239,68,68,${a1})`; iconBg = `rgba(239,68,68,${a2})`;
    } else if (seconds < 3600) {
        icon = 'shield-alert'; level = 'Опасно'; sublabel = 'Взламывается за минуты';
        color = 'var(--accent-red)'; bgColor = `rgba(239,68,68,${a1s})`; iconBg = `rgba(239,68,68,${a2s})`;
    } else if (seconds < 86400) {
        icon = 'shield-minus'; level = 'Уязвимо'; sublabel = 'Взламывается за часы';
        color = '#ff6b6b'; bgColor = `rgba(255,107,107,${a1s})`; iconBg = `rgba(255,107,107,${a2s})`;
    } else if (seconds < 2592000) {
        icon = 'shield'; level = 'Умеренно'; sublabel = 'Взламывается за дни';
        color = '#ffa94d'; bgColor = `rgba(255,169,77,${a1s})`; iconBg = `rgba(255,169,77,${a2s})`;
    } else if (seconds < 31536000) {
        icon = 'shield-check'; level = 'Приемлемо'; sublabel = 'Взламывается за месяцы';
        color = 'var(--accent-yellow)'; bgColor = `rgba(245,158,11,${a1s})`; iconBg = `rgba(245,158,11,${a2s})`;
    } else if (seconds < 31536000000) {
        icon = 'shield-check'; level = 'Надёжно'; sublabel = 'Взломать займёт годы';
        color = '#51cf66'; bgColor = `rgba(81,207,102,${a1s})`; iconBg = `rgba(81,207,102,${a2s})`;
    } else if (seconds < 31536000000000000) {
        icon = 'shield-plus'; level = 'Крепко'; sublabel = 'Тысячелетия или дольше';
        color = '#339af0'; bgColor = `rgba(51,154,240,${a1s})`; iconBg = `rgba(51,154,240,${a2s})`;
    } else {
        icon = 'infinity'; level = 'Абсолютная защита'; sublabel = 'Практически невозможно взломать';
        color = '#845ef7'; bgColor = `rgba(132,94,247,${a1s})`; iconBg = `rgba(132,94,247,${a2s})`;
    }

    card.style.setProperty('--crack-danger-color', color);
    card.style.setProperty('--crack-danger-bg', bgColor);
    card.style.setProperty('--crack-danger-icon-bg', iconBg);
    iconEl.innerHTML = `<i data-lucide="${icon}"></i>`;
    levelEl.textContent = level;
    sublabelEl.textContent = sublabel;
    if (window.lucide) lucide.createIcons();
}

function formatCrackTime(seconds, elementId = 'crackTime') {
    let timeText = '';
    let emoji = '';
    let iconName = '';
    let color = '';

    // 1. СЕКУНДЫ (с 2 десятичными знаками)
    if (seconds < 60) {
        timeText = `${seconds.toFixed(2)} секунд`;
        emoji = seconds < 1 ? '⚡' : '⏱️';
        iconName = seconds < 1 ? 'zap' : 'timer';
        color = 'var(--accent-red)';
    }
    // 2. МИНУТЫ (с десятичными знаками - умное округление)
    else if (seconds < 3600) {
        const minutes = seconds / 60;
        // Для малых значений (< 10 минут): 2 десятичных знака
        if (minutes < 10) {
            const formatted = minutes.toFixed(2);
            // Убираем незначащие нули (3.70 -> 3.7)
            timeText = `${parseFloat(formatted)} минут`;
        } else {
            // Для больших значений (>= 10 минут): 1-2 десятичных знака
            const formatted = minutes.toFixed(2);
            timeText = `${parseFloat(formatted)} минут`;
        }
        emoji = '⏰';
        iconName = 'alarm-clock';
        color = 'var(--accent-red)';
    }
    // 3. ЧАСЫ (целые числа)
    else if (seconds < 86400) {
        timeText = `${Math.round(seconds / 3600)} часов`;
        emoji = '🕐';
        iconName = 'clock';
        color = '#ff6b6b';
    }
    // 4. ДНИ (целые числа)
    else if (seconds < 2592000) {  // < 30 дней
        timeText = `${Math.round(seconds / 86400)} дней`;
        emoji = '📅';
        iconName = 'calendar';
        color = '#ffa94d';
    }
    // 5. МЕСЯЦЫ (целые числа)
    else if (seconds < 31536000) {  // < 1 года
        timeText = `${Math.round(seconds / 2592000)} месяцев`;
        emoji = '📆';
        iconName = 'calendar-days';
        color = 'var(--accent-yellow)';
    }
    // 6. ГОДЫ (целые числа)
    else if (seconds < 31536000000) {  // < 1000 лет
        const years = Math.round(seconds / 31536000);
        timeText = `${years} лет`;
        emoji = years < 10 ? '🗓️' : '📊';
        iconName = years < 10 ? 'calendar-range' : 'bar-chart-2';
        color = '#51cf66';
    }
    // 7. ТЫСЯЧИ ЛЕТ (целые числа)
    else if (seconds < 31536000000000) {  // < 1 миллиона лет
        const thousands = Math.round(seconds / 31536000000);
        timeText = `${thousands} тыс. лет`;
        emoji = '🌍';
        iconName = 'globe';
        color = '#339af0';
    }
    // 8. МИЛЛИОНЫ ЛЕТ (целые числа)
    else if (seconds < 31536000000000000) {  // < 1 миллиарда лет
        const millions = Math.round(seconds / 31536000000000);
        timeText = `${millions} млн. лет`;
        emoji = '🦖';
        iconName = 'hourglass';
        color = '#845ef7';
    }
    // 9. МИЛЛИАРДЫ ЛЕТ И ВЫШЕ
    else {
        const years = seconds / 31536000;

        // КРИТИЧЕСКОЕ ТРЕБОВАНИЕ: После 1 миллиарда лет = "вечность"
        if (years >= 1e9) {
            timeText = 'вечность';
            emoji = '♾️';
            iconName = 'infinity';
            color = '#e64980';
        } else {
            // Миллиарды лет (но меньше 1 миллиарда)
            const billions = Math.round(years / 1e9);
            timeText = `${billions} млрд. лет`;
            emoji = '💫';
            iconName = 'infinity';
            color = '#e64980';
        }
    }

    // Update DOM element if exists
    const element = document.getElementById(elementId);
    if (element) {
        element.style.color = color;
        element.innerHTML = `<i data-lucide="${iconName}"></i>&nbsp;${timeText}`;
        if (window.lucide) lucide.createIcons();
    }

    // Return structured data for export
    return {
        text: timeText,
        emoji: emoji,
        color: color,
        seconds: seconds,
        formatted: `${emoji} ${timeText}`
    };
}

function hasSequence(password) {
    const sequences = [
        // Числовые паттерны
        '0123456789',

        // Алфавитные последовательности
        'abcdefghijklmnopqrstuvwxyz',
        'абвгдежзийклмнопрстуфхцчшщъыьэюя',

        // ЙЦУКЕН (русская) - горизонтальные ряды
        'йцукенгшщзхъ',
        'фывапролджэ',
        'ячсмитьбю',

        // ЙЦУКЕН - диагональные (слева-направо)
        'йфячсм',
        'цывап',
        'укеро',
        'кнгл',
        'емшо',
        'нищд',
        'гтж',
        'шьэ',
        'щбъ'
    ];

    const lower = password.toLowerCase();
    let totalMatchedChars = 0;

    for (let seq of sequences) {
        // Для числовых и длинных алфавитных последовательностей требуем минимум 4 символа
        // Это избегает ложных срабатываний на "123" в "User@Home123"
        const minLength = (seq === '0123456789' || seq.length > 20) ? 4 : 3;

        for (let i = 0; i <= seq.length - minLength; i++) {
            const subseq = seq.substring(i, i + minLength);
            const revSubseq = subseq.split('').reverse().join('');

            if (lower.includes(subseq) || lower.includes(revSubseq)) {
                totalMatchedChars = Math.max(totalMatchedChars, minLength);
            }
        }
    }

    // Только если паттерн покрывает 40%+ пароля, считаем его клавиатурным
    // qazwsxedc (9/9 = 100%) → TRUE
    // User@Home123 (4/12 = 33%) → FALSE
    // admin01012025 (4/13 = 31%) → FALSE
    const density = totalMatchedChars / password.length;
    return density >= 0.4;
}

function hasRepeating(password) {
    return /(.)\1{2,}/.test(password);
}

function hasLeetSpeak(password, zxcvbnResult) {
    // Русские l33t слова — своя проверка
    const russianLeetWords = [
        'пр0', 'х4к3р', 'к0д', 'п4р0ль', 'адм1н', 'л0л', 'п0льз0ват3ль'
    ];
    const lowerPass = password.toLowerCase();
    if (russianLeetWords.some(w => lowerPass.includes(w))) return true;

    // Словарные слова и l33t-замены — zxcvbn (включая слова внутри repeat-паттернов)
    if (!zxcvbnResult) return false;
    return zxcvbnResult.sequence.some(m => {
        if (m.pattern === 'dictionary') return true;
        // MartinMartin → repeat{base_token:'Martin'}, словарное слово внутри base_matches
        if (m.pattern === 'repeat' && m.base_matches) {
            return m.base_matches.some(bm => bm.pattern === 'dictionary');
        }
        return false;
    });
}

function analyzePassword(password, zxcvbnResult) {
    const criteria = {
        length: password.length >= 12,
        uppercase: /[A-Z]/.test(password),
        lowercase: /[a-z]/.test(password),
        numbers: /[0-9]/.test(password),
        special: /[^a-zA-Z0-9]/.test(password),
        // Своя проверка (рус. раскладка + числа + алфавит) + zxcvbn spatial (англ. клавиатура)
        sequences: !hasSequence(password) && !(zxcvbnResult?.sequence.some(m => m.pattern === 'spatial') ?? false),
        repeating: !hasRepeating(password),
        // zxcvbn ловит полные даты (01/01/2009, 01012009); своя regex ловит голые годы (2009, 1990)
        dates: !(zxcvbnResult?.sequence.some(m => m.pattern === 'date') ?? false) && !/(?:19|20)\d{2}/.test(password),
        leetspeak: !hasLeetSpeak(password, zxcvbnResult)
    };

    // Подсчет выполненных критериев
    let criteriaCount = 0;
    for (let key in criteria) {
        if (criteria[key]) {
            criteriaCount++;
        }
    }

    return {
        criteria,
        criteriaCount  // Возвращаем количество вместо score
    };
}

// ===========================
// NEW PASSWORD CRACKING TIME ALGORITHM (passwordmonster-style)
// ===========================
// Глобальные функции для доступа из test-passwords.html

/**
 * Главная функция расчёта времени взлома (упрощённый алгоритм - только чистый перебор)
 * @param {string} password - Пароль для анализа
 * @returns {object} Объект с seconds, method, description, rate, combinations, patterns
 */
function calculateCrackTimeNew(password) {
    const length = password.length;

    // Определяем размер набора символов
    let charsetSize = 0;
    if (/[a-z]/.test(password)) charsetSize += 26;      // нижний регистр
    if (/[A-Z]/.test(password)) charsetSize += 26;      // верхний регистр
    if (/[0-9]/.test(password)) charsetSize += 10;      // цифры
    if (/[^a-zA-Z0-9]/.test(password)) {
        // Считаем уникальные спецсимволы
        const specialChars = password.match(/[^a-zA-Z0-9]/g);
        const uniqueSpecialChars = new Set(specialChars);
        charsetSize += uniqueSpecialChars.size;
    }

    // Чистый перебор: charset^length комбинаций
    const combinations = Math.pow(charsetSize, length);

    // Скорость: 6.7 млрд хешей/сек
    const rate = 6.7e9;

    // Делим на 2 для среднего случая
    const secondsToCrack = combinations / rate / 2;

    // Расчёт энтропии (сохраняем для совместимости)
    const entropyData = calculateEntropy(password);

    return {
        seconds: secondsToCrack,
        method: 'brute-force',
        description: 'Чистый перебор',
        rate: rate,
        combinations: combinations,
        patterns: {
            length: length,
            charsetSize: charsetSize,
            entropy: entropyData.entropy
        }
    };
}

async function updatePasswordAnalysis() {
    const password = document.getElementById('passwordInput').value;

    if (!password) {
        resetAnalysis();
        return;
    }

    const zxcvbnAvailable = typeof zxcvbn === 'function';
    const zxcvbnResult = zxcvbnAvailable ? zxcvbn(password) : null;

    const analysis = analyzePassword(password, zxcvbnResult);

    // Update criteria
    for (let key in analysis.criteria) {
        const element = document.querySelector(`[data-criterion="${key}"]`);
        if (element) {
            if (analysis.criteria[key]) {
                element.classList.add('valid');
                element.classList.remove('invalid');
            } else {
                element.classList.add('invalid');
                element.classList.remove('valid');
            }
        }
    }

    // Calculate entropy and crack time (НОВЫЙ АЛГОРИТМ)
    const crackTimeResult = calculateCrackTimeNew(password);
    const secondsToCrack = crackTimeResult.seconds;
    const combinations = crackTimeResult.combinations;
    const { entropy, charsetSize } = crackTimeResult.patterns;

    // ГИБРИДНАЯ ФОРМУЛА: zxcvbn (реалистичная база) + критерии (бонус/штраф)
    const positiveKeys = ['length', 'uppercase', 'lowercase', 'numbers', 'special'];
    const negativeKeys = ['sequences', 'repeating', 'dates', 'leetspeak'];
    const positiveBonus = positiveKeys.filter(k => analysis.criteria[k]).length * 4;
    const negativeBonus = negativeKeys.reduce((sum, k) => sum + (analysis.criteria[k] ? 4 : -4), 0);

    let finalScore;
    if (zxcvbnAvailable) {
        const zxcvbnBase = Math.min(64, Math.round((zxcvbnResult.guesses_log10 / 20) * 64));
        finalScore = Math.max(1, zxcvbnBase + positiveBonus + negativeBonus);
    } else {
        // Fallback: старая формула
        finalScore = Math.max(1, Math.round(entropy) + (4 * analysis.criteriaCount));
    }

    // Update strength meter
    const strengthSegments = document.getElementById('strengthSegments');
    const strengthText = document.getElementById('strengthText');
    const strengthScore = document.getElementById('strengthScore');

    // Check in pwned database first
    const pwnedCount = await checkPwnedPassword(password);

    // Учёт утечек только для score (не для времени взлома)
    let pwnedSeverity = null;

    if (pwnedCount >= 1000000) {
        // >= 1M leaks: Critical - force score to 1
        pwnedSeverity = 'critical';
    } else if (pwnedCount >= 100000) {
        // 100k-999k leaks: Very dangerous
        pwnedSeverity = 'very-high';
    } else if (pwnedCount >= 10000) {
        // 10k-99k leaks: Dangerous
        pwnedSeverity = 'high';
    } else if (pwnedCount >= 1) {
        // 1-9999 leaks: Compromised
        pwnedSeverity = 'medium';
    }

    // Apply penalties to score based on severity
    let adjustedScore = finalScore;

    if (pwnedSeverity === 'critical') {
        adjustedScore = Math.round(finalScore * 0.2);  // >= 1,000,000
    } else if (pwnedSeverity === 'very-high') {
        adjustedScore = Math.round(finalScore * 0.4);  // 100,000-999,999
    } else if (pwnedSeverity === 'high') {
        adjustedScore = Math.round(finalScore * 0.6);  // 10,000-99,999
    } else if (pwnedSeverity === 'medium') {
        adjustedScore = Math.round(finalScore * 0.8);  // 1-9,999
    }

    // Ограничение отображаемого score до 100
    const displayScore = pwnedSeverity === 'critical' ? 1 : Math.min(100, adjustedScore);

    // Используем оригинальное время без корректировки
    const adjustedCrackTime = secondsToCrack;

    // Determine strength level, class and color based on display score
    let strengthLevel, strengthClass, color;

    if (displayScore < 40) {
        strengthLevel = 'Слабый пароль';
        strengthClass = 'weak';
        color = 'var(--accent-red)';
    } else if (displayScore < 70) {
        strengthLevel = 'Средний пароль';
        strengthClass = 'medium';
        color = 'var(--accent-yellow)';
    } else if (displayScore < 90) {
        strengthLevel = 'Сильный пароль';
        strengthClass = 'strong';
        color = 'var(--accent-green)';
    } else {
        strengthLevel = 'Очень сильный пароль';
        strengthClass = 'very-strong';
        color = 'var(--accent-blue)';
    }

    // Special message for critical compromise
    if (pwnedSeverity === 'critical') {
        strengthLevel = 'Скомпрометированный пароль';
    }

    // Update UI with display score (limited to 100)
    strengthScore.textContent = `${displayScore}/100`;
    strengthText.textContent = strengthLevel;

    // Update 4-segment strength bar
    if (pwnedSeverity === 'critical') {
        strengthSegments.dataset.active = '0';
    } else if (displayScore === 0) {
        strengthSegments.dataset.active = '0';
    } else if (displayScore < 40) {
        strengthSegments.dataset.active = '1';
    } else if (displayScore < 70) {
        strengthSegments.dataset.active = '2';
    } else if (displayScore < 90) {
        strengthSegments.dataset.active = '3';
    } else {
        strengthSegments.dataset.active = '4';
    }

    document.getElementById('crackTimeCard').style.display = 'flex';
    document.getElementById('entropyInfo').style.display = 'flex';

    // Calculate crack time based on adjusted time
    let crackTimeData;
    if (pwnedSeverity === 'critical') {
        // Only critically compromised passwords show instant crack time
        const element = document.getElementById('crackTime');
        if (element) {
            element.style.color = 'var(--accent-red)';
            element.innerHTML = '<i data-lucide="zap"></i> Мгновенно';
            if (window.lucide) lucide.createIcons();
        }
        crackTimeData = { text: 'Мгновенно', emoji: '⚡', color: 'var(--accent-red)', seconds: 0, formatted: '⚡ Мгновенно' };
    } else {
        // Use adjusted crack time for other cases (including compromised with multipliers)
        crackTimeData = formatCrackTime(adjustedCrackTime);
    }

    // Отображение zxcvbn crack time
    let zxcvbnCrackTimeData = null;
    if (zxcvbnAvailable) {
        const zxcvbnSeconds = zxcvbnResult.crack_times_seconds.offline_fast_hashing_1e10_per_second;
        zxcvbnCrackTimeData = formatCrackTime(zxcvbnSeconds, 'crackTimeZxcvbn');
    } else {
        const zxcvbnCrackEl = document.getElementById('crackTimeZxcvbn');
        if (zxcvbnCrackEl) {
            zxcvbnCrackEl.innerHTML = '<i data-lucide="wifi-off"></i> Библиотека не загружена';
            zxcvbnCrackEl.style.color = '';
            if (window.lucide) lucide.createIcons();
        }
    }

    // Обновить индикатор уровня угрозы по наихудшему из двух значений
    const worstSeconds = Math.min(
        crackTimeData.seconds,
        zxcvbnCrackTimeData ? zxcvbnCrackTimeData.seconds : Infinity
    );
    updateCrackTimeDanger(worstSeconds);

    document.getElementById('entropyBits').textContent = Math.round(entropy);
    document.getElementById('charsetSize').textContent = charsetSize;
    document.getElementById('combinations').textContent = combinations > 1e15 ?
        `${(combinations / 1e15).toExponential(1)}` :
        `${Math.round(combinations).toLocaleString()}`;

    // Save analysis results for export
    AppState.lastAnalysisResults = {
        timestamp: new Date().toISOString(),
        password: {
            length: password.length,
            maskedValue: '*'.repeat(password.length) // Не сохраняем сам пароль из соображений безопасности
        },
        score: displayScore,  // Отображаемый score (ограниченный 100)
        realScore: adjustedScore,  // Реальный score (может быть > 100)
        entropyBits: Math.round(entropy),
        criteriaFulfilled: analysis.criteriaCount,  // Количество выполненных критериев
        strengthLevel: strengthLevel,
        strengthClass: strengthClass,
        entropy: Math.round(entropy),
        charsetSize: charsetSize,
        combinations: combinations,
        combinationsFormatted: combinations > 1e15 ?
            `${(combinations / 1e15).toExponential(1)}` :
            `${Math.round(combinations).toLocaleString()}`,
        crackTime: crackTimeData,
        zxcvbnCrackTime: zxcvbnCrackTimeData,
        criteria: analysis.criteria,
        pwnedCount: pwnedCount,
        pwnedStatus: pwnedCount > 0 ? 'Скомпрометирован' : (pwnedCount === 0 ? 'Безопасен' : 'Проверка недоступна')
    };

    // Update status counter
    AppState.analyzedCount++;
    if (typeof updateStatusCounters === 'function') updateStatusCounters();

    // Show inspector panel (desktop only, controlled by CSS)
    document.getElementById('inspectorPanel')?.classList.add('visible');

    // Show export button
    const exportSection = document.getElementById('exportSection');
    if (exportSection) {
        exportSection.style.display = 'block';
    }
}

function resetAnalysis() {
    document.querySelectorAll('.criterion').forEach(el => {
        el.classList.remove('valid', 'invalid');
    });

    // Reset enhanced visualization
    document.getElementById('strengthSegments').dataset.active = '0';
    document.getElementById('strengthText').textContent = 'Введите пароль';
    document.getElementById('strengthScore').textContent = '0/100';
    document.getElementById('strengthIcon').innerHTML = '<i data-lucide="shield"></i>';
    document.getElementById('strengthIcon').className = 'strength-icon';
    if (window.lucide) lucide.createIcons();
    document.getElementById('strengthBadge').style.display = 'none';
    document.getElementById('strengthDetails').style.display = 'none';
    document.getElementById('strengthFeedback').style.display = 'none';

    document.getElementById('crackTimeCard').style.display = 'none';
    const zxcvbnCrackElReset = document.getElementById('crackTimeZxcvbn');
    if (zxcvbnCrackElReset) zxcvbnCrackElReset.innerHTML = '—';
    const crackElReset = document.getElementById('crackTime');
    if (crackElReset) crackElReset.innerHTML = '—';
    document.getElementById('entropyInfo').style.display = 'none';
    document.getElementById('pwnedStatus').className = 'pwned-status';

    // Hide export button and clear results
    const exportSection = document.getElementById('exportSection');
    if (exportSection) {
        exportSection.style.display = 'none';
    }
    const exportDropdown = document.getElementById('exportDropdown');
    if (exportDropdown) {
        exportDropdown.classList.remove('open');
    }
    AppState.lastAnalysisResults = null;

    // Hide inspector panel
    document.getElementById('inspectorPanel')?.classList.remove('visible');
}
