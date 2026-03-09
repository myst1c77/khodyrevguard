// =============================================
// COMPARATOR — Сравнитель паролей
// Зависимости: analyzePassword, calculateCrackTimeNew, formatCrackTime (из analyzer.js)
//              zxcvbn (глобальная библиотека)
// =============================================

(function () {
    // Дебаунс-таймеры
    let debounceA = null;
    let debounceB = null;

    // Пороги оценки (совпадают с analyzer.js)
    function getStrengthMeta(score) {
        if (score < 40) return { level: 'Слабый пароль',        cls: 'weak',        color: 'var(--accent-red)',    icon: 'shield-x' };
        if (score < 70) return { level: 'Средний пароль',       cls: 'medium',      color: 'var(--accent-yellow)', icon: 'shield' };
        if (score < 90) return { level: 'Сильный пароль',       cls: 'strong',      color: 'var(--accent-green)',  icon: 'shield-check' };
        return             { level: 'Очень сильный пароль', cls: 'very-strong', color: 'var(--accent-blue)',  icon: 'shield-plus' };
    }

    // Вычисление оценки — зеркало логики из updatePasswordAnalysis (analyzer.js), включая HIBP-штраф
    async function scorePassword(password) {
        if (!password) return null;

        const zxcvbnAvailable = typeof zxcvbn === 'function';
        const zxcvbnResult = zxcvbnAvailable ? zxcvbn(password) : null;
        const analysis = analyzePassword(password, zxcvbnResult);
        const crackData = calculateCrackTimeNew(password);

        const positiveKeys = ['length', 'uppercase', 'lowercase', 'numbers', 'special'];
        const negativeKeys = ['sequences', 'repeating', 'dates', 'leetspeak'];
        const positiveBonus = positiveKeys.filter(k => analysis.criteria[k]).length * 2;
        const negativeBonus = negativeKeys.reduce((s, k) => s + (analysis.criteria[k] ? 4 : -4), 0);

        let finalScore;
        if (zxcvbnAvailable) {
            const zxcvbnSec = zxcvbnResult.crack_times_seconds.offline_fast_hashing_1e10_per_second;
            const base = Math.min(100, Math.max(0, Math.round((Math.log10(Math.max(0.001, zxcvbnSec)) + 3) / 20 * 100)));
            finalScore = Math.max(1, base + positiveBonus + negativeBonus);
        } else {
            finalScore = Math.max(1, Math.round(crackData.patterns.entropy) + 4 * analysis.criteriaCount);
        }

        // HIBP-штраф — идентично analyzer.js (строки 441-468)
        // checkPwnedCount разделяет кэш с анализатором → повторная проверка мгновенна
        const pwnedCount = typeof checkPwnedCount === 'function'
            ? await checkPwnedCount(password)
            : -1;
        let adjustedScore = finalScore;
        if      (pwnedCount >= 1000000) adjustedScore = Math.round(finalScore * 0.2);
        else if (pwnedCount >= 100000)  adjustedScore = Math.round(finalScore * 0.4);
        else if (pwnedCount >= 10000)   adjustedScore = Math.round(finalScore * 0.6);
        else if (pwnedCount >= 1)       adjustedScore = Math.round(finalScore * 0.8);

        return {
            score: pwnedCount >= 1000000 ? 1 : Math.min(100, adjustedScore),
            criteria: analysis.criteria,
            crackSeconds: crackData.seconds,
            zxcvbnSeconds: zxcvbnAvailable
                ? zxcvbnResult.crack_times_seconds.offline_fast_hashing_1e10_per_second
                : null,
            entropy: Math.round(crackData.patterns.entropy),
            pwnedCount,
        };
    }

    // Обновление одной карточки
    function updateCompCard(side, data) {
        const s = side; // 'A' или 'B'
        const meta = getStrengthMeta(data.score);

        // Иконка + текст + оценка
        const iconEl = document.getElementById('compIcon' + s);
        const textEl = document.getElementById('compText' + s);
        const scoreEl = document.getElementById('compScore' + s);

        if (iconEl) {
            iconEl.className = 'strength-icon ' + meta.cls;
            iconEl.innerHTML = `<i data-lucide="${meta.icon}"></i>`;
        }
        if (textEl) textEl.textContent = meta.level;
        if (scoreEl) scoreEl.textContent = data.score + '/100';

        // Сегменты силы
        const segsEl = document.getElementById('compSegments' + s);
        if (segsEl) {
            let active;
            if (data.score === 0) active = 0;
            else if (data.score < 40) active = 1;
            else if (data.score < 70) active = 2;
            else if (data.score < 90) active = 3;
            else active = 4;
            segsEl.dataset.active = String(active);
        }

        // Скомпрометированный пароль — перезаписываем отображение (как в анализаторе)
        if (data.pwnedCount >= 1000000) {
            if (iconEl) {
                iconEl.className = 'strength-icon weak';
                iconEl.innerHTML = '<i data-lucide="shield-off"></i>';
            }
            if (textEl) textEl.textContent = 'Скомпрометированный пароль';
            if (segsEl) segsEl.dataset.active = '0';
        }

        // Критерии
        const attr = 'data-comp-criterion-' + s.toLowerCase();
        document.querySelectorAll('[' + attr + ']').forEach(el => {
            const key = el.getAttribute(attr);
            el.classList.toggle('valid', !!data.criteria[key]);
            el.classList.toggle('invalid', !data.criteria[key]);
        });

        // Время взлома: formatCrackTime обновляет #compCrackA / #compCrackB
        formatCrackTime(data.crackSeconds, 'compCrack' + s);

        if (data.zxcvbnSeconds !== null) {
            formatCrackTime(data.zxcvbnSeconds, 'compZxcvbn' + s);
        } else {
            const zEl = document.getElementById('compZxcvbn' + s);
            if (zEl) { zEl.textContent = 'N/A'; zEl.style.color = ''; }
        }

        // Энтропия
        const entEl = document.getElementById('compEntropy' + s);
        if (entEl) entEl.textContent = data.entropy + ' бит';

        // HIBP-индикатор
        updatePwnedIndicator(s, data.pwnedCount);

        if (window.lucide) lucide.createIcons();
    }

    // Обновление HIBP-индикатора в карточке
    function updatePwnedIndicator(side, pwnedCount) {
        const el = document.getElementById('compPwned' + side);
        if (!el) return;
        if (pwnedCount === -1) { el.hidden = true; return; }
        el.hidden = false;
        if (pwnedCount === 0) {
            el.className = 'comp-pwned safe';
            el.innerHTML = '<i data-lucide="shield-check"></i> Не найден в базах утечек';
        } else {
            el.className = 'comp-pwned compromised';
            el.innerHTML = `<i data-lucide="triangle-alert"></i> Найден в ${pwnedCount.toLocaleString()} утечках`;
        }
        if (window.lucide) lucide.createIcons();
    }

    // Сброс карточки в пустое состояние
    function resetCompCard(side) {
        const s = side;
        const iconEl = document.getElementById('compIcon' + s);
        const textEl = document.getElementById('compText' + s);
        const scoreEl = document.getElementById('compScore' + s);
        const segsEl = document.getElementById('compSegments' + s);

        if (iconEl) { iconEl.className = 'strength-icon'; iconEl.innerHTML = '<i data-lucide="shield"></i>'; }
        if (textEl) textEl.textContent = 'Введите пароль';
        if (scoreEl) scoreEl.textContent = '0/100';
        if (segsEl) segsEl.dataset.active = '0';

        const attr = 'data-comp-criterion-' + s.toLowerCase();
        document.querySelectorAll('[' + attr + ']').forEach(el => {
            el.classList.remove('valid', 'invalid');
        });

        ['compCrack', 'compZxcvbn', 'compEntropy'].forEach(prefix => {
            const el = document.getElementById(prefix + s);
            if (el) { el.innerHTML = '—'; el.style.color = ''; }
        });

        const pwnedEl = document.getElementById('compPwned' + s);
        if (pwnedEl) pwnedEl.hidden = true;

        if (window.lucide) lucide.createIcons();
    }

    // Склонение "балл/балла/баллов"
    function pluralPoints(n) {
        if (n % 10 === 1 && n % 100 !== 11) return 'балл';
        if ([2, 3, 4].includes(n % 10) && ![12, 13, 14].includes(n % 100)) return 'балла';
        return 'баллов';
    }

    // Обновление вердикта
    function updateCompVerdict(dataA, dataB, identical = false) {
        const cardA = document.getElementById('compCardA');
        const cardB = document.getElementById('compCardB');
        const badgeA = document.getElementById('compWinnerA');
        const badgeB = document.getElementById('compWinnerB');
        const verdict = document.getElementById('comparatorVerdict');
        const verdictIcon = document.getElementById('comparatorVerdictIcon');
        const verdictText = document.getElementById('comparatorVerdictText');
        const verdictSub = document.getElementById('comparatorVerdictSub');

        if (!verdict) return;

        // Сброс классов
        cardA.classList.remove('winner', 'loser');
        cardB.classList.remove('winner', 'loser');
        verdict.classList.remove('verdict-a', 'verdict-b', 'verdict-tie');

        const diff = dataA.score - dataB.score;

        if (diff === 0) {
            // Одинаковый балл — тайбрейк 1: время взлома
            const worstA = dataA.zxcvbnSeconds !== null ? Math.min(dataA.crackSeconds, dataA.zxcvbnSeconds) : dataA.crackSeconds;
            const worstB = dataB.zxcvbnSeconds !== null ? Math.min(dataB.crackSeconds, dataB.zxcvbnSeconds) : dataB.crackSeconds;

            if (worstA > worstB * 1.5) {
                cardA.classList.add('winner');
                cardB.classList.add('loser');
                badgeA.hidden = false;
                badgeB.hidden = true;
                verdict.classList.add('verdict-a');
                verdictIcon.innerHTML = '<i data-lucide="trophy" style="color:var(--accent-green)"></i>';
                verdictText.textContent = 'Вариант A надёжнее';
                verdictSub.textContent = 'Одинаковый балл — A сложнее взломать';
            } else if (worstB > worstA * 1.5) {
                cardB.classList.add('winner');
                cardA.classList.add('loser');
                badgeB.hidden = false;
                badgeA.hidden = true;
                verdict.classList.add('verdict-b');
                verdictIcon.innerHTML = '<i data-lucide="trophy" style="color:var(--accent-green)"></i>';
                verdictText.textContent = 'Вариант B надёжнее';
                verdictSub.textContent = 'Одинаковый балл — B сложнее взломать';
            } else {
                // Тайбрейк 2: энтропия
                const entropyDiff = dataA.entropy - dataB.entropy;
                if (entropyDiff > 5) {
                    cardA.classList.add('winner');
                    cardB.classList.add('loser');
                    badgeA.hidden = false;
                    badgeB.hidden = true;
                    verdict.classList.add('verdict-a');
                    verdictIcon.innerHTML = '<i data-lucide="trophy" style="color:var(--accent-green)"></i>';
                    verdictText.textContent = 'Вариант A надёжнее';
                    verdictSub.textContent = `Одинаковый балл — выше энтропия (${dataA.entropy} vs ${dataB.entropy} бит)`;
                } else if (entropyDiff < -5) {
                    cardB.classList.add('winner');
                    cardA.classList.add('loser');
                    badgeB.hidden = false;
                    badgeA.hidden = true;
                    verdict.classList.add('verdict-b');
                    verdictIcon.innerHTML = '<i data-lucide="trophy" style="color:var(--accent-green)"></i>';
                    verdictText.textContent = 'Вариант B надёжнее';
                    verdictSub.textContent = `Одинаковый балл — выше энтропия (${dataB.entropy} vs ${dataA.entropy} бит)`;
                } else {
                    // Полная ничья
                    badgeA.hidden = true;
                    badgeB.hidden = true;
                    verdict.classList.add('verdict-tie');
                    verdictIcon.innerHTML = '<i data-lucide="equal" style="color:var(--accent-blue)"></i>';
                    verdictText.textContent = 'Варианты равнозначны';
                    verdictSub.textContent = identical
                        ? 'Пароли одинаковы'
                        : 'Пароли практически одинаковы по надёжности';
                }
            }
        } else if (diff > 0) {
            // A победил по счёту
            cardA.classList.add('winner');
            cardB.classList.add('loser');
            badgeA.hidden = false;
            badgeB.hidden = true;
            verdict.classList.add('verdict-a');
            verdictIcon.innerHTML = '<i data-lucide="trophy" style="color:var(--accent-green)"></i>';
            verdictText.textContent = `Вариант A надёжнее на ${diff} ${pluralPoints(diff)}`;
            verdictSub.textContent = buildVerdictSub(dataA, dataB, 'B');
        } else {
            // B победил по счёту
            cardB.classList.add('winner');
            cardA.classList.add('loser');
            badgeB.hidden = false;
            badgeA.hidden = true;
            verdict.classList.add('verdict-b');
            verdictIcon.innerHTML = '<i data-lucide="trophy" style="color:var(--accent-green)"></i>';
            const absDiff = Math.abs(diff);
            verdictText.textContent = `Вариант B надёжнее на ${absDiff} ${pluralPoints(absDiff)}`;
            verdictSub.textContent = buildVerdictSub(dataB, dataA, 'A');
        }

        verdict.hidden = false;
        if (window.lucide) lucide.createIcons();
    }

    // Вспомогательный текст для вердикта — только HIBP-объяснение при победе по счёту
    function buildVerdictSub(winner, loser, loserLabel) {
        if (loser.pwnedCount > 0 && winner.pwnedCount === 0) {
            return `Вариант ${loserLabel} найден в базах утечек данных`;
        }
        return '';
    }

    // Скрыть вердикт и снять классы с карточек
    function hideVerdict() {
        const cardA = document.getElementById('compCardA');
        const cardB = document.getElementById('compCardB');
        const badgeA = document.getElementById('compWinnerA');
        const badgeB = document.getElementById('compWinnerB');
        const verdict = document.getElementById('comparatorVerdict');
        if (cardA) cardA.classList.remove('winner', 'loser');
        if (cardB) cardB.classList.remove('winner', 'loser');
        if (badgeA) badgeA.hidden = true;
        if (badgeB) badgeB.hidden = true;
        if (verdict) verdict.hidden = true;
    }

    // Главная функция сравнения (async: scorePassword делает HIBP-запрос)
    async function runComparison() {
        const pwA = document.getElementById('compInputA').value;
        const pwB = document.getElementById('compInputB').value;

        const dataA = pwA ? await scorePassword(pwA) : null;
        const dataB = pwB ? await scorePassword(pwB) : null;

        if (dataA) updateCompCard('A', dataA); else resetCompCard('A');
        if (dataB) updateCompCard('B', dataB); else resetCompCard('B');

        if (dataA && dataB) {
            updateCompVerdict(dataA, dataB, pwA === pwB);
        } else {
            hideVerdict();
        }
    }

    // Инициализация — вешаем слушатели после загрузки DOM
    document.addEventListener('DOMContentLoaded', function () {
        const inputA = document.getElementById('compInputA');
        const inputB = document.getElementById('compInputB');
        const toggleA = document.getElementById('compToggleA');
        const toggleB = document.getElementById('compToggleB');

        if (!inputA || !inputB) return;

        function makeDebounced(timer, setter) {
            return function () {
                clearTimeout(timer);
                const t = setTimeout(runComparison, 300);
                setter(t);
            };
        }

        inputA.addEventListener('input', makeDebounced(debounceA, t => { debounceA = t; }));
        inputB.addEventListener('input', makeDebounced(debounceB, t => { debounceB = t; }));

        // Paste — вставляем только текст
        [inputA, inputB].forEach(inp => {
            inp.addEventListener('paste', function (e) {
                e.preventDefault();
                const text = (e.clipboardData || window.clipboardData).getData('text').trim();
                document.execCommand('insertText', false, text);
            });
        });

        // Visibility toggles
        function makeToggle(input, btn) {
            let visible = false;
            btn.addEventListener('click', function () {
                visible = !visible;
                input.type = visible ? 'text' : 'password';
                btn.innerHTML = visible
                    ? '<i data-lucide="eye-off"></i>'
                    : '<i data-lucide="eye"></i>';
                btn.setAttribute('aria-label', visible ? 'Скрыть пароль' : 'Показать пароль');
                if (window.lucide) lucide.createIcons();
            });
        }

        if (toggleA) makeToggle(inputA, toggleA);
        if (toggleB) makeToggle(inputB, toggleB);
    });
})();
