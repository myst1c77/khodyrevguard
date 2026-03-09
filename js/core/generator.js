// Generator functions
function getCharsets() {
    let charset = '';
    const similar = '0O1lI|nh6C5S';

    if (document.getElementById('lowercaseCheck').checked) {
        charset += 'abcdefghijklmnopqrstuvwxyz';
    }
    if (document.getElementById('uppercaseCheck').checked) {
        charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    }
    if (document.getElementById('numbersCheck').checked) {
        charset += '0123456789';
    }
    if (document.getElementById('symbolsCheck').checked) {
        charset += '!@#$%^&*';
    }
    if (document.getElementById('extendedCheck').checked) {
        charset += '{}[]|;:,.<>?/~`-_+=()\'\"\\$';
    }

    // Remove similar characters if needed
    if (document.getElementById('excludeSimilar').checked) {
        charset = charset.split('').filter(c => !similar.includes(c)).join('');
    }

    return charset;
}

// === Passphrase Generation Functions ===

/**
 * Generates a cryptographically secure random integer between 0 and max (exclusive)
 * Uses rejection sampling to eliminate modulo bias
 * @param {number} max - Maximum value (exclusive)
 * @returns {number} Random integer in range [0, max)
 */
function getSecureRandomInt(max) {
    const array = new Uint32Array(1);
    const maxUint32 = 0xFFFFFFFF;
    const range = maxUint32 - (maxUint32 % max);

    // Rejection sampling: reject values >= range to avoid bias
    let randomValue;
    do {
        crypto.getRandomValues(array);
        randomValue = array[0];
    } while (randomValue >= range);

    return randomValue % max;
}

function getRandomWord(language) {
    let wordList;
    if (language === 'english') {
        wordList = englishWords;
    } else if (language === 'russian') {
        wordList = russianWords;
    } else {
        return null;
    }

    const index = getSecureRandomInt(wordList.length);
    return wordList[index];
}

function capitalizeWord(word) {
    return word.charAt(0).toUpperCase() + word.slice(1).toLowerCase();
}

function generatePassphraseNumbers() {
    // Generate exactly 1 random digit using unbiased method
    return getSecureRandomInt(10).toString();
}

function _buildPassphrase() {
    const wordCount = parseInt(document.getElementById('wordCountSlider').value);
    const separator = AppState.currentPassphraseSeparator;
    const capitalize = document.getElementById('capitalizeCheck').checked;
    const addNumbers = document.getElementById('addNumbersCheck').checked;

    // Get language setting
    const languageRadios = document.getElementsByName('passphraseLanguage');
    let language = 'english';
    for (const radio of languageRadios) {
        if (radio.checked) {
            language = radio.value;
            break;
        }
    }

    let words = [];

    // Use single language (english or russian)
    for (let i = 0; i < wordCount; i++) {
        let word = getRandomWord(language);
        if (capitalize) {
            word = capitalizeWord(word);
        }
        words.push(word);
    }

    // Add digit to random word if enabled (using cryptographically secure randomness)
    if (addNumbers && words.length > 0) {
        const randomIndex = getSecureRandomInt(words.length);
        words[randomIndex] += generatePassphraseNumbers();
    }

    let passphrase = words.join(separator);
    return passphrase;
}

function generatePassphrase() {
    const count = AppState.batchCount;

    if (count === 1) {
        const passphrase = _buildPassphrase();
        AppState.generatedPassphraseText = passphrase;
        document.getElementById('generatedPassword').textContent = passphrase;
        document.getElementById('generatedPassword').style.display = '';
        document.getElementById('batchPasswordList').style.display = 'none';
        document.getElementById('batchPasswordList').innerHTML = '';
    } else {
        const phrases = [];
        for (let i = 0; i < count; i++) {
            phrases.push({ text: _buildPassphrase(), score: 0, color: 'var(--border-color)' });
        }
        AppState.batchPasswords = phrases;
        AppState.selectedBatchIndex = 0;
        AppState.generatedPassphraseText = phrases[0].text;

        document.getElementById('generatedPassword').style.display = 'none';
        renderBatchList(phrases);
        // Выделяем первый элемент без вызова _updateGenStats (панель статистики скрыта в режиме фраз)
        document.querySelectorAll('.batch-password-item').forEach((el, i) => {
            el.classList.toggle('active', i === 0);
        });
    }

    // Update status counter
    AppState.generatedCount++;
    if (typeof updateStatusCounters === 'function') updateStatusCounters();
}

// Строит один пароль по текущим настройкам (без DOM-эффектов)
function _buildPassword() {
    const length = parseInt(document.getElementById('lengthSlider').value);
    const charset = getCharsets();
    let password = '';
    for (let i = 0; i < length; i++) {
        password += charset[getSecureRandomInt(charset.length)];
    }
    return password;
}

// Быстрая оценка силы пароля для мини-полоски (без DOM-эффектов)
function _computeQuickScore(password) {
    const zxcvbnResult = typeof zxcvbn === 'function' ? zxcvbn(password) : null;
    const analysis = analyzePassword(password, zxcvbnResult);
    const { entropy } = calculateCrackTimeNew(password).patterns;

    const posBonus = ['length', 'uppercase', 'lowercase', 'numbers', 'special']
        .filter(k => analysis.criteria[k]).length * 4;
    const negBonus = ['sequences', 'repeating', 'dates', 'leetspeak']
        .reduce((sum, k) => sum + (analysis.criteria[k] ? 4 : -4), 0);

    let score;
    if (zxcvbnResult) {
        const base = Math.min(64, Math.round((zxcvbnResult.guesses_log10 / 20) * 64));
        score = Math.max(1, base + posBonus + negBonus);
    } else {
        score = Math.max(1, Math.round(entropy) + (4 * analysis.criteriaCount));
    }
    score = Math.min(100, score);

    let color;
    if (score < 40) color = '#ef4444';
    else if (score < 70) color = '#f59e0b';
    else if (score < 90) color = '#10b981';
    else color = '#3b82f6';

    return { score, color };
}

// Обновляет все статистические элементы генератора для данного пароля
function _updateGenStats(password) {
    const crackTimeResult = calculateCrackTimeNew(password);
    const secondsToCrack = crackTimeResult.seconds;
    const { entropy } = crackTimeResult.patterns;

    const genZxcvbnForScore = typeof zxcvbn === 'function' ? zxcvbn(password) : null;
    const analysis = analyzePassword(password, genZxcvbnForScore);

    const positiveBonusGen = ['length', 'uppercase', 'lowercase', 'numbers', 'special']
        .filter(k => analysis.criteria[k]).length * 4;
    const negativeBonusGen = ['sequences', 'repeating', 'dates', 'leetspeak']
        .reduce((sum, k) => sum + (analysis.criteria[k] ? 4 : -4), 0);

    let finalScore;
    if (genZxcvbnForScore) {
        const zxcvbnBase = Math.min(64, Math.round((genZxcvbnForScore.guesses_log10 / 20) * 64));
        finalScore = Math.max(1, zxcvbnBase + positiveBonusGen + negativeBonusGen);
    } else {
        finalScore = Math.max(1, Math.round(entropy) + (4 * analysis.criteriaCount));
    }
    const displayScore = Math.min(100, finalScore);

    let strengthColor;
    if (displayScore < 40) strengthColor = 'var(--accent-red)';
    else if (displayScore < 70) strengthColor = 'var(--accent-yellow)';
    else if (displayScore < 90) strengthColor = 'var(--accent-green)';
    else strengthColor = 'var(--accent-blue)';

    const strengthEl = document.getElementById('genStrength');
    strengthEl.textContent = displayScore + '/100';
    strengthEl.style.color = strengthColor;

    checkPwnedInGenerator(password);

    let timeText = '', iconName = '', timeColor = '';
    if (secondsToCrack < 1) {
        timeText = 'Мгновенно'; iconName = 'zap'; timeColor = 'var(--accent-red)';
    } else if (secondsToCrack < 60) {
        timeText = `${Math.round(secondsToCrack)} секунд`; iconName = 'timer'; timeColor = 'var(--accent-red)';
    } else if (secondsToCrack < 3600) {
        timeText = `${Math.round(secondsToCrack / 60)} минут`; iconName = 'alarm-clock'; timeColor = 'var(--accent-red)';
    } else if (secondsToCrack < 86400) {
        timeText = `${Math.round(secondsToCrack / 3600)} часов`; iconName = 'clock'; timeColor = '#ff6b6b';
    } else if (secondsToCrack < 2592000) {
        timeText = `${Math.round(secondsToCrack / 86400)} дней`; iconName = 'calendar'; timeColor = '#ffa94d';
    } else if (secondsToCrack < 31536000) {
        timeText = `${Math.round(secondsToCrack / 2592000)} месяцев`; iconName = 'calendar-days'; timeColor = 'var(--accent-yellow)';
    } else if (secondsToCrack < 315360000) {
        timeText = `${Math.round(secondsToCrack / 31536000)} лет`; iconName = 'calendar-range'; timeColor = '#51cf66';
    } else if (secondsToCrack < 31536000000) {
        const years = Math.round(secondsToCrack / 31536000);
        if (years < 100) { timeText = `${years} лет`; iconName = 'bar-chart-2'; }
        else if (years < 1000) { timeText = `${Math.round(years / 10) * 10} лет`; iconName = 'hourglass'; }
        else { timeText = `${Math.round(years / 100) / 10} тыс. лет`; iconName = 'landmark'; }
        timeColor = 'var(--accent-green)';
    } else if (secondsToCrack < 31536000000000) {
        timeText = `${Math.round(secondsToCrack / 31536000000)} тыс. лет`; iconName = 'globe'; timeColor = '#339af0';
    } else if (secondsToCrack < 31536000000000000) {
        timeText = `${Math.round(secondsToCrack / 31536000000000)} млн. лет`; iconName = 'infinity'; timeColor = '#845ef7';
    } else {
        timeText = 'Вечность'; iconName = 'infinity'; timeColor = '#e64980';
    }

    const crackTimeEl = document.getElementById('genCrackTime');
    crackTimeEl.innerHTML = `<i data-lucide="${iconName}"></i>&nbsp;${timeText}`;
    crackTimeEl.style.color = timeColor;

    if (genZxcvbnForScore) {
        const genZxcvbnSeconds = genZxcvbnForScore.crack_times_seconds.offline_fast_hashing_1e10_per_second;
        formatCrackTime(genZxcvbnSeconds, 'genZxcvbnCrackTime');
    } else {
        const genZxcvbnEl = document.getElementById('genZxcvbnCrackTime');
        if (genZxcvbnEl) { genZxcvbnEl.textContent = 'Недоступно'; genZxcvbnEl.style.color = 'var(--text-secondary)'; }
    }

    if (window.lucide) lucide.createIcons();
}

// Отрисовывает пакетный список паролей в DOM
function renderBatchList(passwords) {
    const container = document.getElementById('batchPasswordList');
    container.innerHTML = '';
    container.style.display = 'flex';

    passwords.forEach((item, i) => {
        const el = document.createElement('div');
        el.className = 'batch-password-item';
        el.dataset.index = i;

        const text = document.createElement('span');
        text.className = 'batch-password-text';
        text.textContent = item.text;

        el.appendChild(text);

        el.addEventListener('click', () => {
            if (AppState.selectedBatchIndex === i && el.classList.contains('active')) {
                // Повторный клик на выделенном — копировать
                navigator.clipboard.writeText(item.text).then(() => {
                    showNotification('Пароль скопирован в буфер обмена!');
                }).catch(() => showNotification('Не удалось скопировать', 'warning'));
            } else {
                selectBatchItem(i);
            }
        });

        container.appendChild(el);
    });

    if (window.lucide) lucide.createIcons();
}

// Выбирает элемент из пакета по индексу и обновляет статистику
function selectBatchItem(index) {
    AppState.selectedBatchIndex = index;
    const item = AppState.batchPasswords[index];

    document.querySelectorAll('.batch-password-item').forEach((el, i) => {
        el.classList.toggle('active', i === index);
    });

    if (AppState.currentGeneratorMode === 'passphrase') {
        AppState.generatedPassphraseText = item.text;
    } else {
        AppState.generatedPasswordText = item.text;
        _updateGenStats(item.text);
    }
}

function generateCustomPassword() {
    const charset = getCharsets();
    if (charset.length === 0) {
        showNotification('Выберите хотя бы один набор символов!', 'warning');
        return;
    }

    const count = AppState.batchCount;

    if (count === 1) {
        const password = _buildPassword();
        AppState.generatedPasswordText = password;
        document.getElementById('generatedPassword').textContent = password;
        document.getElementById('generatedPassword').style.display = '';
        document.getElementById('batchPasswordList').style.display = 'none';
        document.getElementById('batchPasswordList').innerHTML = '';
        _updateGenStats(password);
    } else {
        const passwords = [];
        for (let i = 0; i < count; i++) {
            const pwd = _buildPassword();
            const { score, color } = _computeQuickScore(pwd);
            passwords.push({ text: pwd, score, color });
        }
        AppState.batchPasswords = passwords;
        AppState.selectedBatchIndex = 0;
        AppState.generatedPasswordText = passwords[0].text;

        document.getElementById('generatedPassword').style.display = 'none';
        renderBatchList(passwords);
        selectBatchItem(0);
    }

    // Update status counter
    AppState.generatedCount++;
    if (typeof updateStatusCounters === 'function') updateStatusCounters();
}

// === Generator Mode Switching ===

function switchGeneratorMode(mode) {
    AppState.currentGeneratorMode = mode;

    // Update tabs
    document.querySelectorAll('.generator-mode-tab').forEach(tab => {
        tab.classList.remove('active');
    });
    document.querySelector(`.generator-mode-tab[data-mode="${mode}"]`).classList.add('active');

    // Show/hide appropriate controls
    if (mode === 'password') {
        document.getElementById('passwordControls').style.display = 'grid';
        document.getElementById('passphraseControls').style.display = 'none';
        document.getElementById('passwordEntropyInfo').style.display = 'flex';
        document.getElementById('passphraseMemorabilityInfo').style.display = 'none';

        // Update button to call password generation
        const generateBtn = document.querySelector('.btn-primary');
        generateBtn.onclick = generateCustomPassword;
    } else {
        document.getElementById('passwordControls').style.display = 'none';
        document.getElementById('passphraseControls').style.display = 'grid';
        document.getElementById('passwordEntropyInfo').style.display = 'none';
        document.getElementById('passphraseMemorabilityInfo').style.display = 'block';

        // Update button to call passphrase generation
        const generateBtn = document.querySelector('.btn-primary');
        generateBtn.onclick = generatePassphrase;
    }

    // Сбросить batch-список при переключении режима
    AppState.batchPasswords = [];
    AppState.selectedBatchIndex = 0;
    document.getElementById('batchPasswordList').innerHTML = '';
    document.getElementById('batchPasswordList').style.display = 'none';
    document.getElementById('generatedPassword').style.display = '';

    // Восстановить текст для выбранного режима или показать placeholder
    const storedText = mode === 'password' ? AppState.generatedPasswordText : AppState.generatedPassphraseText;
    if (storedText) {
        document.getElementById('generatedPassword').textContent = storedText;
    } else {
        document.getElementById('generatedPassword').textContent = 'Нажмите "Сгенерировать" для создания ' + (mode === 'password' ? 'пароля' : 'парольной фразы');
        // Сброс статистики — она относится к другому режиму
        ['genStrength', 'genHibpResult', 'genCrackTime', 'genZxcvbnCrackTime'].forEach(id => {
            const el = document.getElementById(id);
            el.textContent = '—';
            el.style.color = '';
        });
    }
}

function selectSeparator(separator) {
    AppState.currentPassphraseSeparator = separator;

    // Update active button
    document.querySelectorAll('.separator-option').forEach(btn => {
        btn.classList.remove('active');
    });
    document.querySelector(`.separator-option[data-separator="${separator}"]`).classList.add('active');
}
