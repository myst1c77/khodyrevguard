// Конфигурация HIBP проверки с fallback endpoints
const HIBP_CONFIG = {
    endpoints: [
        { name: 'deno', url: (p) => `https://noisy-dodo-86-3070w9wty3ry.myst1c77.deno.net?prefix=${p}`, timeout: 4000 },
        { name: 'direct', url: (p) => `https://api.pwnedpasswords.com/range/${p}`, timeout: 3000 }
    ],
    lastSuccessfulMethod: null
};

// Fetch с таймаутом через AbortController
async function fetchWithTimeout(url, options = {}, timeoutMs = 4000) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
        const response = await fetch(url, { ...options, signal: controller.signal });
        clearTimeout(timeoutId);
        return response;
    } catch (error) {
        clearTimeout(timeoutId);
        if (error.name === 'AbortError') {
            throw new Error(`Таймаут запроса (${timeoutMs}ms)`);
        }
        throw error;
    }
}

// Парсинг ответа HIBP API
function parseHIBPResponse(text, suffix) {
    for (const line of text.split('\n')) {
        const [hashSuffix, count] = line.split(':');
        if (hashSuffix && hashSuffix.trim() === suffix) {
            return parseInt(count.trim(), 10);
        }
    }
    return 0;
}

// Отображение результата проверки HIBP
function displayPwnedResult(statusEl, textEl, count) {
    if (count > 0) {
        statusEl.className = 'pwned-status compromised show';
        textEl.innerHTML = `<span class="criterion-icon"><i data-lucide="triangle-alert"></i></span><span>Пароль найден в ${count.toLocaleString()} утечках данных! Срочно смените его!</span>`;
    } else if (count === 0) {
        statusEl.className = 'pwned-status safe show';
        textEl.innerHTML = '<span class="criterion-icon"><i data-lucide="shield-check"></i></span><span>Пароль не найден в базах утечек</span>';
    } else {
        statusEl.className = 'pwned-status warning show';
        textEl.innerHTML = '<span class="criterion-icon"><i data-lucide="circle-alert"></i></span><span>Не удалось проверить пароль в базе утечек</span>';
    }
    if (window.lucide) lucide.createIcons();
}

// Check password in Have I Been Pwned database
async function checkPwnedPassword(password) {
    const statusEl = document.getElementById('pwnedStatus');
    const textEl = document.getElementById('pwnedText');

    // Show checking status
    statusEl.className = 'pwned-status checking show';
    textEl.textContent = 'Проверяем пароль в базе утечек...';

    try {
        // SHA-1 hash
        const encoder = new TextEncoder();
        const data = encoder.encode(password);
        const hashBuffer = await crypto.subtle.digest('SHA-1', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

        // Check cache first
        if (AppState.pwnedCache.has(hashHex)) {
            const cachedCount = AppState.pwnedCache.get(hashHex);
            displayPwnedResult(statusEl, textEl, cachedCount);
            return cachedCount;
        }

        const prefix = hashHex.substring(0, 5).toUpperCase();
        const suffix = hashHex.substring(5).toUpperCase();

        // Оптимизация: начать с последнего успешного метода
        let endpoints = [...HIBP_CONFIG.endpoints];
        if (HIBP_CONFIG.lastSuccessfulMethod) {
            const idx = endpoints.findIndex(e => e.name === HIBP_CONFIG.lastSuccessfulMethod);
            if (idx > 0) {
                const [last] = endpoints.splice(idx, 1);
                endpoints.unshift(last);
            }
        }

        // Перебор endpoints с таймаутами
        for (let i = 0; i < endpoints.length; i++) {
            const endpoint = endpoints[i];
            try {
                const response = await fetchWithTimeout(endpoint.url(prefix), {
                    mode: 'cors',
                    headers: { 'User-Agent': 'KhodyrevGuard-Password-Analyzer' }
                }, endpoint.timeout);

                if (response.ok) {
                    const text = await response.text();
                    const breachCount = parseHIBPResponse(text, suffix);

                    // Кэшируем результат
                    AppState.pwnedCache.set(hashHex, breachCount);
                    try { sessionStorage.setItem('hibpCache', JSON.stringify(Object.fromEntries(AppState.pwnedCache))); } catch(e) {}
                    // Запоминаем успешный метод
                    HIBP_CONFIG.lastSuccessfulMethod = endpoint.name;

                    displayPwnedResult(statusEl, textEl, breachCount);
                    return breachCount;
                }
            } catch (error) {
                // Если это последний метод, выбрасываем ошибку
                if (i === endpoints.length - 1) throw error;
            }
        }

        // Если все методы не сработали
        throw new Error('Все методы подключения к HIBP API не удались');

    } catch (error) {
        console.error('HIBP ошибка:', error);
        // Graceful degradation - показываем предупреждение и продолжаем
        statusEl.className = 'pwned-status warning show';
        textEl.innerHTML = '<i data-lucide="circle-alert"></i> Проверка утечек недоступна. Анализ выполнен без этой проверки.';
        if (window.lucide) lucide.createIcons();
        return -1;
    }
}

// HIBP проверка для компактного блока статистики генератора
async function checkPwnedInGenerator(password) {
    const el = document.getElementById('genHibpResult');
    if (!el) return;
    el.textContent = '…';
    el.style.color = 'var(--text-secondary)';

    try {
        const encoder = new TextEncoder();
        const data = encoder.encode(password);
        const hashBuffer = await crypto.subtle.digest('SHA-1', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

        // Проверяем кэш
        if (AppState.pwnedCache.has(hashHex)) {
            displayGenHibpResult(el, AppState.pwnedCache.get(hashHex));
            return;
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
                    try { sessionStorage.setItem('hibpCache', JSON.stringify(Object.fromEntries(AppState.pwnedCache))); } catch(e) {}
                    HIBP_CONFIG.lastSuccessfulMethod = endpoint.name;
                    displayGenHibpResult(el, count);
                    return;
                }
            } catch (err) {
                if (i === endpoints.length - 1) throw err;
            }
        }
        throw new Error('HIBP недоступен');
    } catch (e) {
        el.textContent = 'N/A';
        el.style.color = 'var(--text-secondary)';
    }
}

// Чистая HIBP-проверка без DOM — возвращает count (или -1 при ошибке).
// Используется компаратором для одинакового scoring с анализатором.
// Разделяет кэш (AppState.pwnedCache) с checkPwnedPassword.
async function checkPwnedCount(password) {
    try {
        const encoder = new TextEncoder();
        const data = encoder.encode(password);
        const hashBuffer = await crypto.subtle.digest('SHA-1', data);
        const hashHex = Array.from(new Uint8Array(hashBuffer))
            .map(b => b.toString(16).padStart(2, '0')).join('');

        if (AppState.pwnedCache.has(hashHex)) return AppState.pwnedCache.get(hashHex);

        const prefix = hashHex.substring(0, 5).toUpperCase();
        const suffix  = hashHex.substring(5).toUpperCase();

        let endpoints = [...HIBP_CONFIG.endpoints];
        if (HIBP_CONFIG.lastSuccessfulMethod) {
            const idx = endpoints.findIndex(e => e.name === HIBP_CONFIG.lastSuccessfulMethod);
            if (idx > 0) { const [ep] = endpoints.splice(idx, 1); endpoints.unshift(ep); }
        }

        for (let i = 0; i < endpoints.length; i++) {
            const ep = endpoints[i];
            try {
                const res = await fetchWithTimeout(ep.url(prefix),
                    { mode: 'cors', headers: { 'User-Agent': 'KhodyrevGuard-Password-Analyzer' } },
                    ep.timeout);
                if (res.ok) {
                    const count = parseHIBPResponse(await res.text(), suffix);
                    AppState.pwnedCache.set(hashHex, count);
                    try { sessionStorage.setItem('hibpCache', JSON.stringify(Object.fromEntries(AppState.pwnedCache))); } catch (_) {}
                    HIBP_CONFIG.lastSuccessfulMethod = ep.name;
                    return count;
                }
            } catch (err) { if (i === endpoints.length - 1) throw err; }
        }
        return -1;
    } catch (_) { return -1; }
}

function displayGenHibpResult(el, count) {
    if (count === 0) {
        el.textContent = 'Чист';
        el.style.color = 'var(--accent-green)';
    } else if (count > 0) {
        let label;
        if (count >= 1000000) label = '>' + Math.floor(count / 1000000) + 'М ут.';
        else if (count >= 1000) label = Math.floor(count / 1000) + 'тыс. ут.';
        else label = count + ' ут.';
        el.textContent = label;
        el.style.color = 'var(--accent-red)';
    } else {
        el.textContent = 'N/A';
        el.style.color = 'var(--text-secondary)';
    }
}
