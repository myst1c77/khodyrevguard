        // Theme switcher
        let currentTheme = localStorage.getItem('theme') || 'original';
        document.documentElement.setAttribute('data-theme', currentTheme);
        document.querySelector(`.theme-btn[data-theme="${currentTheme}"]`).classList.add('active');

        function switchTheme(theme) {
            document.documentElement.setAttribute('data-theme', theme);
            localStorage.setItem('theme', theme);
            
            // Update active button
            document.querySelectorAll('.theme-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            document.querySelector(`.theme-btn[data-theme="${theme}"]`).classList.add('active');
        }


        const AppState = {
            debounceTimer: null,
            hasherDebounceTimer: null,
            isPasswordVisible: false,
            currentPage: 'analyzer',
            generatedPasswordText: '',
            currentGeneratorMode: 'password',
            currentPassphraseSeparator: '-',
            currentHashFormat: 'hex',
            currentHashAlgorithm: null,
            currentHashValue: '',
            lastAnalysisResults: null, // Хранилище результатов последнего анализа для экспорта
            pwnedAbortController: null, // AbortController для отмены HIBP запросов
            pwnedCache: new Map() // Кэш для HIBP проверок (SHA-1 hash -> breach count)
        };

        // Page switching
        function switchPage(page, event) {
            AppState.currentPage = page;

            // Update tabs
            document.querySelectorAll('.nav-tab').forEach(tab => tab.classList.remove('active'));
            if (event && event.target) {
                event.target.closest('.nav-tab').classList.add('active');
            }

            // Update pages
            document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
            document.getElementById(page + 'Page').classList.add('active');
        }

        // Password visibility toggle
        function togglePasswordVisibility() {
            const input = document.getElementById('passwordInput');
            const btn = document.getElementById('toggleBtn');
            
            if (AppState.isPasswordVisible) {
                input.type = 'password';
                btn.textContent = '👁️';
            } else {
                input.type = 'text';
                btn.textContent = '👁️‍🗨️';
            }
            AppState.isPasswordVisible = !AppState.isPasswordVisible;
        }

        // MD5 implementation (RFC 1321 compliant)
        function md5(string) {
            // Convert string to UTF-8 bytes
            const utf8Bytes = unescape(encodeURIComponent(string));
            const msgLength = utf8Bytes.length;
            const blockCount = ((msgLength + 8) >>> 6) + 1;
            const blocks = new Array(blockCount * 16);

            // Convert message to 32-bit words
            let i;
            for (i = 0; i < msgLength; i++) {
                blocks[i >>> 2] |= utf8Bytes.charCodeAt(i) << ((i % 4) << 3);
            }

            // Append padding
            blocks[i >>> 2] |= 0x80 << ((i % 4) << 3);
            blocks[blockCount * 16 - 2] = msgLength << 3;
            blocks[blockCount * 16 - 1] = msgLength >>> 29;

            // MD5 constants
            const K = [
                0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
                0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
                0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
                0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
            ];

            const S = [
                7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
                5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
                4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
                6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
            ];

            // Helper function for left rotation
            const rotateLeft = (x, n) => (x << n) | (x >>> (32 - n));

            // Initialize hash values
            let a = 0x67452301;
            let b = 0xefcdab89;
            let c = 0x98badcfe;
            let d = 0x10325476;

            // Process each 512-bit block
            for (let i = 0; i < blockCount * 16; i += 16) {
                const aa = a, bb = b, cc = c, dd = d;

                // 64 operations in 4 rounds
                for (let j = 0; j < 64; j++) {
                    let f, g;

                    if (j < 16) {
                        f = (b & c) | (~b & d);
                        g = j;
                    } else if (j < 32) {
                        f = (d & b) | (~d & c);
                        g = (5 * j + 1) % 16;
                    } else if (j < 48) {
                        f = b ^ c ^ d;
                        g = (3 * j + 5) % 16;
                    } else {
                        f = c ^ (b | ~d);
                        g = (7 * j) % 16;
                    }

                    const temp = d;
                    d = c;
                    c = b;
                    b = (b + rotateLeft((a + f + K[j] + blocks[i + g]) | 0, S[j])) | 0;
                    a = temp;
                }

                a = (a + aa) | 0;
                b = (b + bb) | 0;
                c = (c + cc) | 0;
                d = (d + dd) | 0;
            }

            // Convert to hex string (little-endian)
            const toHex = n => {
                let hex = '';
                for (let i = 0; i < 4; i++) {
                    hex += ((n >>> (i * 8)) & 0xff).toString(16).padStart(2, '0');
                }
                return hex;
            };

            return toHex(a) + toHex(b) + toHex(c) + toHex(d);
        }

        // Format hash output based on current format setting
        function formatHash(hashHex, format = AppState.currentHashFormat) {
            if (format === 'base64') {
                // Convert hex string to bytes, then to base64
                const bytes = new Uint8Array(hashHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
                return btoa(String.fromCharCode(...bytes));
            } else if (format === 'uppercase') {
                return hashHex.toUpperCase();
            }
            // Default: lowercase hex
            return hashHex;
        }

        // Hash functions
        async function hashData(text, algorithm) {
            const encoder = new TextEncoder();
            const data = encoder.encode(text);

            let hashHex;

            if (algorithm === 'MD5') {
                // MD5 returns hex string directly (RFC 1321 compliant)
                hashHex = md5(text);
            } else {
                // Use Web Crypto API for SHA algorithms
                const hashBuffer = await crypto.subtle.digest(algorithm, data);
                const hashArray = Array.from(new Uint8Array(hashBuffer));
                hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            }

            // Apply formatting (hex, base64, or uppercase)
            return formatHash(hashHex);
        }

        async function setHashFormat(format) {
            AppState.currentHashFormat = format;
            document.querySelectorAll('.format-option').forEach(btn => {
                btn.classList.remove('active');
            });
            document.querySelector(`.format-option[data-format="${format}"]`).classList.add('active');
            
            // Re-hash if there's a current result
            if (AppState.currentHashAlgorithm && document.getElementById('hasherInput').value) {
                const input = document.getElementById('hasherInput').value;
                const hash = await hashData(input, AppState.currentHashAlgorithm);
                AppState.currentHashValue = hash;
                document.getElementById('hashValue').textContent = hash;
            }
        }

        async function hashSingleAlgorithm(algorithm, isUserClick = true) {
            const input = document.getElementById('hasherInput').value;
            if (!input) {
                alert('Пожалуйста, введите текст для хеширования');
                return;
            }
            
            // Update active button only if it's a user click
            if (isUserClick) {
                document.querySelectorAll('.algorithm-btn').forEach(btn => {
                    btn.classList.remove('active');
                });
                
                // Find and activate the clicked button
                const clickedBtn = event?.target?.closest('.algorithm-btn');
                if (clickedBtn) {
                    clickedBtn.classList.add('active');
                } else {
                    // If called programmatically, find button by algorithm name
                    document.querySelectorAll('.algorithm-btn').forEach(btn => {
                        if (btn.textContent.includes(algorithm)) {
                            btn.classList.add('active');
                        }
                    });
                }
            }
            
            const hash = await hashData(input, algorithm);
            AppState.currentHashAlgorithm = algorithm;
            AppState.currentHashValue = hash;
            displayHashResult(algorithm, hash);
        }

        function displayHashResult(algorithm, hash) {
            const container = document.getElementById('hashResultContainer');
            const algorithmIcon = document.getElementById('algorithmIcon');
            const algorithmName = document.getElementById('algorithmName');
            const hashValue = document.getElementById('hashValue');
            
            // Update algorithm info
            algorithmIcon.textContent = getAlgorithmIcon(algorithm);
            algorithmName.textContent = algorithm;
            hashValue.textContent = hash;
            
            // Show container
            container.style.display = 'block';
        }

        function getAlgorithmIcon(algorithm) {
            const icons = {
                'MD5': '📝',
                'SHA-1': '🔒',
                'SHA-256': '🔐',
                'SHA-512': '⚡'
            };
            return icons[algorithm] || '🔑';
        }

        function copyHashValue() {
            if (!AppState.currentHashValue) return;

            navigator.clipboard.writeText(AppState.currentHashValue).then(() => {
                showNotification('✅ Хеш скопирован в буфер обмена!');
            }).catch(err => {
                alert('Не удалось скопировать хеш');
            });
        }

        function clearHasher() {
            document.getElementById('hasherInput').value = '';
            document.getElementById('hashResultContainer').style.display = 'none';
            document.querySelectorAll('.algorithm-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            AppState.currentHashAlgorithm = null;
            AppState.currentHashValue = '';

            // Reset format to default
            AppState.currentHashFormat = 'hex';
            document.querySelectorAll('.format-option').forEach(btn => {
                btn.classList.remove('active');
            });
            document.querySelector('.format-option[data-format="hex"]').classList.add('active');
        }

        function showNotification(message) {
            const notification = document.getElementById('copyNotification');
            notification.textContent = message;
            notification.classList.add('show');
            
            setTimeout(() => {
                notification.classList.remove('show');
            }, 3000);
        }

        // Check password in Have I Been Pwned database
        async function checkPwnedPassword(password) {
            const statusEl = document.getElementById('pwnedStatus');
            const textEl = document.getElementById('pwnedText');

            // Cancel any pending request
            if (AppState.pwnedAbortController) {
                AppState.pwnedAbortController.abort();
            }

            // Show checking status
            statusEl.className = 'pwned-status checking show';
            textEl.textContent = '🔍 Проверяем пароль в базе утечек...';

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
                    if (cachedCount > 0) {
                        statusEl.className = 'pwned-status compromised show';
                        textEl.textContent = `Этот пароль был найден в ${cachedCount.toLocaleString()} утечках данных! Срочно смените его!`;
                    } else {
                        statusEl.className = 'pwned-status safe show';
                        textEl.textContent = '✅ Пароль не найден в базах утечек';
                    }
                    return cachedCount;
                }

                const prefix = hashHex.substring(0, 5).toUpperCase();
                const suffix = hashHex.substring(5).toUpperCase();

                // Create new AbortController for this request
                AppState.pwnedAbortController = new AbortController();

                // Try to fetch from API
                try {
                    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
                        mode: 'cors',
                        headers: {
                            'User-Agent': 'KhodyrevGuard-Password-Analyzer'
                        },
                        signal: AppState.pwnedAbortController.signal
                    });

                    if (response.ok) {
                        const text = await response.text();
                        const lines = text.split('\n');

                        for (const line of lines) {
                            const [hashSuffix, count] = line.split(':');
                            if (hashSuffix === suffix) {
                                const breachCount = parseInt(count);
                                // Cache the result
                                AppState.pwnedCache.set(hashHex, breachCount);
                                statusEl.className = 'pwned-status compromised show';
                                textEl.textContent = `Этот пароль был найден в ${breachCount.toLocaleString()} утечках данных! Срочно смените его!`;
                                return breachCount;
                            }
                        }

                        // Password not found - cache result
                        AppState.pwnedCache.set(hashHex, 0);
                        statusEl.className = 'pwned-status safe show';
                        textEl.textContent = '✅ Пароль не найден в базах утечек';
                        return 0;
                    }
                } catch (networkError) {
                    // Check if request was aborted (user is typing)
                    if (networkError.name === 'AbortError') {
                        console.log('HIBP запрос отменён (пользователь продолжает ввод)');
                        return -1;
                    }

                    // CORS or network error - use fallback method
                    console.log('HIBP API недоступен:', networkError);

                    statusEl.className = 'pwned-status show';
                    textEl.textContent = '⚠️ Проверка недоступна (требуется подключение к интернету)';
                    return 0;
                }
            } catch (error) {
                console.error('Ошибка при проверке пароля:', error);
                statusEl.className = 'pwned-status';
                return -1;
            }
        }

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

        function formatCrackTime(seconds) {
            let timeText = '';
            let emoji = '';
            let color = '';

            if (seconds < 1) {
                timeText = 'Мгновенно';
                emoji = '⚡';
                color = 'var(--accent-red)';
            } else if (seconds < 60) {
                timeText = `${Math.round(seconds)} секунд`;
                emoji = '⏱️';
                color = 'var(--accent-red)';
            } else if (seconds < 3600) {
                timeText = `${Math.round(seconds / 60)} минут`;
                emoji = '⏰';
                color = 'var(--accent-red)';
            } else if (seconds < 86400) {
                timeText = `${Math.round(seconds / 3600)} часов`;
                emoji = '🕐';
                color = '#ff6b6b';
            } else if (seconds < 2592000) {
                timeText = `${Math.round(seconds / 86400)} дней`;
                emoji = '📅';
                color = '#ffa94d';
            } else if (seconds < 31536000) {
                timeText = `${Math.round(seconds / 2592000)} месяцев`;
                emoji = '📆';
                color = 'var(--accent-yellow)';
            } else if (seconds < 315360000) {
                timeText = `${Math.round(seconds / 31536000)} лет`;
                emoji = '🗓️';
                color = '#51cf66';
            } else if (seconds < 31536000000) {
                const years = Math.round(seconds / 31536000);
                if (years < 100) {
                    timeText = `${years} лет`;
                    emoji = '📊';
                } else if (years < 1000) {
                    timeText = `${Math.round(years / 10) * 10} лет`;
                    emoji = '⌛';
                } else {
                    timeText = `${Math.round(years / 100) / 10} тыс. лет`;
                    emoji = '🏛️';
                }
                color = 'var(--accent-green)';
            } else if (seconds < 31536000000000) {
                timeText = `${Math.round(seconds / 31536000000)} тыс. лет`;
                emoji = '🌍';
                color = '#339af0';
            } else if (seconds < 31536000000000000) {
                timeText = `${Math.round(seconds / 31536000000000)} млн. лет`;
                emoji = '🦖';
                color = '#845ef7';
            } else {
                timeText = 'Вечность';
                emoji = '♾️';
                color = '#e64980';
            }

            // Update DOM element if exists
            const element = document.getElementById('crackTime');
            if (element) {
                element.style.color = color;
                element.innerHTML = `${emoji} ${timeText}`;
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
                '0123456789',
                'abcdefghijklmnopqrstuvwxyz',
                'qwertyuiop',
                'asdfghjkl',
                'zxcvbnm',
                'йцукенгшщзхъ',
                'фывапролджэ',
                'ячсмитьбю'
            ];
            
            const lower = password.toLowerCase();
            
            for (let seq of sequences) {
                for (let i = 0; i <= seq.length - 3; i++) {
                    const subseq = seq.substring(i, i + 3);
                    const revSubseq = subseq.split('').reverse().join('');
                    if (lower.includes(subseq) || lower.includes(revSubseq)) {
                        return true;
                    }
                }
            }
            return false;
        }

        function hasRepeating(password) {
            return /(.)\1{2,}/.test(password);
        }
        // ============================================
        // ИСПРАВЛЕННАЯ ПРОВЕРКА ДАТ В ПАРОЛЕ v7 - ФИНАЛ
        // ============================================

        function hasDatePatterns(password) {
            let match;

            // ===== 1. ФОРМАТЫ С РАЗДЕЛИТЕЛЯМИ: NN.NN.NNNN =====
            const dateWithSepLongRegex = /(\d{1,2})[.\-\/](\d{1,2})[.\-\/](\d{4})/g;
            while ((match = dateWithSepLongRegex.exec(password)) !== null) {
                const n1 = parseInt(match[1]);
                const n2 = parseInt(match[2]);
                const year = parseInt(match[3]);

                if (isValidDate(n1, n2, year) || isValidDate(n2, n1, year)) {
                    return true;
                }
            }

            // ===== 2. ФОРМАТЫ С РАЗДЕЛИТЕЛЯМИ: NNNN.NN.NN =====
            const isoLongRegex = /(\d{4})[.\-\/](\d{1,2})[.\-\/](\d{1,2})/g;
            while ((match = isoLongRegex.exec(password)) !== null) {
                const year = parseInt(match[1]);
                const month = parseInt(match[2]);
                const day = parseInt(match[3]);

                if (isValidDate(day, month, year)) {
                    return true;
                }
            }

            // ===== 3. ФОРМАТЫ С РАЗДЕЛИТЕЛЯМИ: NN.NN.NN =====
            const dateWithSepShortRegex = /(\d{1,2})[.\-\/](\d{1,2})[.\-\/](\d{2})(?!\d)/g;
            while ((match = dateWithSepShortRegex.exec(password)) !== null) {
                const n1 = parseInt(match[1]);
                const n2 = parseInt(match[2]);
                const n3 = parseInt(match[3]);

                const yearFromN3 = n3 + (n3 >= 50 ? 1900 : 2000);
                const yearFromN1 = n1 + (n1 >= 50 ? 1900 : 2000);

                if (isValidDate(n1, n2, yearFromN3) ||
                    isValidDate(n2, n1, yearFromN3) ||
                    isValidDate(n3, n2, yearFromN1)) {
                    return true;
                }
            }

            // ===== 6. ТОЛЬКО ГОД (1900-2099) =====
            const yearRegex = /(19\d{2}|20\d{2})/g;
            while ((match = yearRegex.exec(password)) !== null) {
                const yearStr = match[1];
                const year = parseInt(yearStr);
                const startIndex = match.index;
                const endIndex = startIndex + yearStr.length;

                const charBefore = startIndex > 0 ? password[startIndex - 1] : '';
                const charAfter = endIndex < password.length ? password[endIndex] : '';

                // Проверка на часть полной даты
                if (['.', '-', '/'].includes(charBefore)) {
                    if (startIndex >= 5) {
                        const fiveCharsBefore = password.substring(startIndex - 5, startIndex);
                        const dateSepPattern = /\d{1,2}[.\-\/]\d{1,2}[.\-\/]$/;
                        if (dateSepPattern.test(fiveCharsBefore)) {
                            continue;
                        }
                    }
                    if (startIndex >= 3) {
                        const threeCharsBefore = password.substring(startIndex - 3, startIndex);
                        const shortDatePattern = /^\d{1,2}[.\-\/]$/;
                        if (shortDatePattern.test(threeCharsBefore)) {
                            continue;
                        }
                    }
                }

                // Проверка на IP-адрес
                if (charBefore && /[\d.]/.test(charBefore) && charAfter === '.' && endIndex + 1 < password.length && /\d/.test(password[endIndex + 1])) {
                    continue;
                }

                // Проверка на часть большего числа
                if (/\d/.test(charBefore) || /\d/.test(charAfter)) {
                    continue;
                }

                if (year >= 1900 && year <= 2099) {
                    return true;
                }
            }

            // ===== 7. ТОЛЬКО ДЕНЬ И МЕСЯЦ - ИСПРАВЛЕНО! =====
            // ВАЖНО: Этот паттерн должен находить ИЗОЛИРОВАННЫЕ даты день/месяц
            // Не должен срабатывать, если это часть более длинной даты
            
            // Сначала проверяем все потенциальные совпадения
            const dayMonthCandidates = [];
            const dayMonthRegex = /(\d{1,2})[.\-\/](\d{1,2})/g;
            
            while ((match = dayMonthRegex.exec(password)) !== null) {
                const startPos = match.index;
                const endPos = startPos + match[0].length;
                
                // Проверяем, что после этого паттерна НЕТ разделителя с годом
                const afterPattern = password.substring(endPos, endPos + 6); // Проверяем до 6 символов вперед
                const hasYearAfter = /^[.\-\/]\d{2,4}/.test(afterPattern);
                
                // Проверяем, что перед паттерном нет цифры (чтобы это не было частью большего числа)
                const charBefore = startPos > 0 ? password[startPos - 1] : '';
                const hasDigitBefore = /\d/.test(charBefore);

                // Принимаем этот паттерн только если:
                // 1. После него НЕТ года (не часть полной даты)
                // 2. Перед ним НЕТ цифры (не часть большего числа)
                if (!hasYearAfter && !hasDigitBefore) {
                    const n1 = parseInt(match[1]);
                    const n2 = parseInt(match[2]);
                    
                    const currentYear = 2024;
                    if (isValidDate(n1, n2, currentYear) || isValidDate(n2, n1, currentYear)) {
                        return true;
                    }
                }
            }

            // ===== 11. СПЕЦИАЛЬНЫЕ ПАТТЕРНЫ =====
            if (/birth\d+|bd\d+|bday\d+|\d+birth|\d+bd|\d+bday/i.test(password)) {
                return true;
            }

            if (/anniversary\d+|\d+anniversary/i.test(password)) {
                return true;
            }

            return false;
        }

        // Функция валидации даты
        function isValidDate(day, month, year) {
            if (!Number.isInteger(day) || !Number.isInteger(month) || !Number.isInteger(year)) {
                return false;
            }
            
            if (year < 1900 || year > 2099) return false;
            if (month < 1 || month > 12) return false;
            if (day < 1) return false;
            
            const daysInMonth = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
            
            if (month === 2) {
                const isLeapYear = (year % 4 === 0 && year % 100 !== 0) || (year % 400 === 0);
                const maxDays = isLeapYear ? 29 : 28;
                return day <= maxDays;
            }
            
            const maxDays = daysInMonth[month - 1];
            return day <= maxDays;
        }

        function analyzePassword(password) {
            const criteria = {
                length: password.length >= 12,
                uppercase: /[A-Z]/.test(password),
                lowercase: /[a-z]/.test(password),
                numbers: /[0-9]/.test(password),
                special: /[^a-zA-Z0-9]/.test(password),
                sequences: !hasSequence(password),
                repeating: !hasRepeating(password),
                dates: !hasDatePatterns(password)  // Новая проверка на даты
            };

            // Calculate score
            let score = 0;
            const weights = {
                length: password.length >= 16 ? 20 : (password.length >= 12 ? 10 : 0),
                uppercase: 12,
                lowercase: 12,
                numbers: 12,
                special: 14,
                sequences: 10,
                repeating: 10,
                dates: 10  // Вес для критерия дат
            };
            
            for (let key in criteria) {
                if (criteria[key]) {
                    score += weights[key];
                }
            }
            
            // Length bonuses
            if (password.length > 16) score += 10;
            if (password.length > 20) score += 10;
            
            return {
                criteria,
                score: Math.min(100, score)
            };
        }

        async function updatePasswordAnalysis() {
            const password = document.getElementById('passwordInput').value;
            
            if (!password) {
                resetAnalysis();
                return;
            }
            
            const analysis = analyzePassword(password);
            
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
            
            // Calculate entropy and crack time
            const { entropy, charsetSize } = calculateEntropy(password);
            const combinations = Math.pow(charsetSize, password.length);
            const secondsToCrack = combinations / 1e12 / 2;
            
            // Calculate score based on entropy and criteria
            let baseScore = 0;

            // Entropy-based scoring (main factor)
            if (entropy < 30) {
                baseScore = Math.round(entropy / 30 * 20);
            } else if (entropy < 60) {
                baseScore = 20 + Math.round((entropy - 30) / 30 * 30);
            } else if (entropy < 90) {
                baseScore = 50 + Math.round((entropy - 60) / 30 * 30);
            } else {
                baseScore = 80 + Math.min(20, Math.round((entropy - 90) / 30 * 20));
            }

            // Criteria bonuses/penalties
            let criteriaBonus = 0;
            if (!analysis.criteria.sequences) criteriaBonus -= 5;
            if (!analysis.criteria.repeating) criteriaBonus -= 5;
            if (!analysis.criteria.common) criteriaBonus -= 10;
            if (!analysis.criteria.dates) criteriaBonus -= 10;  // Штраф за наличие дат
            if (password.length >= 12) criteriaBonus += 5;
            if (password.length >= 16) criteriaBonus += 5;

            const finalScore = Math.max(0, Math.min(100, baseScore + criteriaBonus));

            // Update strength meter
            const strengthMeter = document.getElementById('strengthMeter');
            const strengthText = document.getElementById('strengthText');
            const strengthScore = document.getElementById('strengthScore');

            // Check in pwned database first
            const pwnedCount = await checkPwnedPassword(password);

            // Calculate pwned multiplier based on leak severity
            let pwnedMultiplier = 1.0;
            let pwnedSeverity = null;

            if (pwnedCount >= 1000000) {
                // >= 1M leaks: Critical - force score to 1
                pwnedMultiplier = 0.0;
                pwnedSeverity = 'critical';
            } else if (pwnedCount >= 100000) {
                // 100k-999k leaks: Very dangerous - 50% penalty
                pwnedMultiplier = 0.5;
                pwnedSeverity = 'very-high';
            } else if (pwnedCount >= 10000) {
                // 10k-99k leaks: Dangerous - 25% penalty
                pwnedMultiplier = 0.75;
                pwnedSeverity = 'high';
            } else if (pwnedCount >= 1) {
                // 1-9999 leaks: Compromised - 10% penalty
                pwnedMultiplier = 0.9;
                pwnedSeverity = 'medium';
            }

            // Apply multiplier to score and crack time
            let adjustedScore = finalScore;
            let adjustedCrackTime = secondsToCrack;

            if (pwnedSeverity === 'critical') {
                adjustedScore = 1;
                adjustedCrackTime = 0;
            } else if (pwnedSeverity) {
                adjustedScore = Math.max(1, Math.round(finalScore * pwnedMultiplier));
                adjustedCrackTime = secondsToCrack * pwnedMultiplier;
            }

            // Determine strength level, class and color based on adjusted score
            let strengthLevel, strengthClass, color;

            if (adjustedScore < 30) {
                strengthLevel = '⚠️ Слабый пароль';
                strengthClass = 'weak';
                color = 'var(--accent-red)';
            } else if (adjustedScore < 60) {
                strengthLevel = '⚡ Средний пароль';
                strengthClass = 'medium';
                color = 'var(--accent-yellow)';
            } else if (adjustedScore < 80) {
                strengthLevel = '✅ Сильный пароль';
                strengthClass = 'strong';
                color = 'var(--accent-green)';
            } else {
                strengthLevel = '🛡️ Очень сильный пароль';
                strengthClass = 'very-strong';
                color = 'var(--accent-blue)';
            }

            // Special message for critical compromise
            if (pwnedSeverity === 'critical') {
                strengthLevel = '⚠️ Скомпрометированный пароль';
            }

            // Update UI with adjusted values
            strengthMeter.style.width = `${adjustedScore}%`;
            strengthScore.textContent = `${adjustedScore}/100`;
            strengthText.textContent = strengthLevel;
            strengthMeter.className = 'strength-meter-fill ' + strengthClass;
            strengthMeter.style.background = color;

            // Independent condition counting - each condition is checked separately
            // Condition 1: Minimum 8 characters
            // Condition 2: Both uppercase AND lowercase letters
            // Condition 3: Contains numbers
            // Condition 4: Contains special characters
            // Condition 5: No sequences/repeating patterns

            // Count how many conditions are fulfilled
            let fulfilledCount = 0;

            if (analysis.criteria.length) fulfilledCount++;
            if (analysis.criteria.uppercase && analysis.criteria.lowercase) fulfilledCount++;
            if (analysis.criteria.numbers) fulfilledCount++;
            if (analysis.criteria.special) fulfilledCount++;
            // Condition 5 only counts if password has 8+ characters
            if (analysis.criteria.length && analysis.criteria.sequences && analysis.criteria.repeating) fulfilledCount++;

            // Update indicators based on count
            const indicators = document.querySelectorAll('.strength-indicator');
            indicators.forEach((indicator, index) => {
                // Remove all classes
                indicator.classList.remove('active', 'weak', 'medium', 'strong', 'very-strong');

                // If password is critically compromised (>= 1M leaks), all indicators stay inactive
                if (pwnedSeverity === 'critical') {
                    // Do nothing - all indicators remain inactive
                } else {
                    // Light up indicator if its index is less than fulfilled count
                    if (index < fulfilledCount) {
                        indicator.classList.add('active', strengthClass);
                    }
                }
            });

            document.getElementById('timeToCrack').style.display = 'block';
            document.getElementById('entropyInfo').style.display = 'flex';

            // Calculate crack time based on adjusted time
            let crackTimeData;
            if (pwnedSeverity === 'critical') {
                // Only critically compromised passwords show instant crack time
                const element = document.getElementById('crackTime');
                if (element) {
                    element.style.color = 'var(--accent-red)';
                    element.innerHTML = '⚡ Мгновенно';
                }
                crackTimeData = { text: 'Мгновенно', emoji: '⚡', color: 'var(--accent-red)', seconds: 0, formatted: '⚡ Мгновенно' };
            } else {
                // Use adjusted crack time for other cases (including compromised with multipliers)
                crackTimeData = formatCrackTime(adjustedCrackTime);
            }

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
                score: finalScore,
                strengthLevel: strengthLevel,
                strengthClass: strengthClass,
                entropy: Math.round(entropy),
                charsetSize: charsetSize,
                combinations: combinations,
                combinationsFormatted: combinations > 1e15 ?
                    `${(combinations / 1e15).toExponential(1)}` :
                    `${Math.round(combinations).toLocaleString()}`,
                crackTime: crackTimeData,
                criteria: analysis.criteria,
                pwnedCount: pwnedCount,
                pwnedStatus: pwnedCount > 0 ? 'Скомпрометирован' : (pwnedCount === 0 ? 'Безопасен' : 'Проверка недоступна')
            };

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
            document.getElementById('strengthMeter').style.width = '0%';
            document.getElementById('strengthMeter').className = 'strength-meter-fill';
            document.getElementById('strengthText').textContent = 'Введите пароль';
            document.getElementById('strengthScore').textContent = '0/100';
            document.getElementById('strengthIcon').textContent = '🔒';
            document.getElementById('strengthIcon').className = 'strength-icon';
            document.getElementById('strengthBadge').style.display = 'none';
            document.getElementById('strengthDetails').style.display = 'none';
            document.getElementById('strengthFeedback').style.display = 'none';

            // Reset indicators
            document.querySelectorAll('.strength-indicator').forEach(indicator => {
                indicator.classList.remove('active', 'weak', 'medium', 'strong', 'very-strong');
            });

            document.getElementById('timeToCrack').style.display = 'none';
            document.getElementById('entropyInfo').style.display = 'none';
            document.getElementById('pwnedStatus').className = 'pwned-status';

            // Hide export button and clear results
            const exportSection = document.getElementById('exportSection');
            if (exportSection) {
                exportSection.style.display = 'none';
            }
            const exportDropdown = document.getElementById('exportDropdown');
            if (exportDropdown) {
                exportDropdown.style.display = 'none';
            }
            AppState.lastAnalysisResults = null;
        }

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

        function generatePassphrase() {
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

            if (language === 'mixed') {
                // Mix English and Russian words using cryptographically secure randomness
                for (let i = 0; i < wordCount; i++) {
                    const usedLanguage = getSecureRandomInt(2) === 0 ? 'english' : 'russian';
                    let word = getRandomWord(usedLanguage);
                    if (capitalize) {
                        word = capitalizeWord(word);
                    }
                    words.push(word);
                }
            } else {
                // Use single language
                for (let i = 0; i < wordCount; i++) {
                    let word = getRandomWord(language);
                    if (capitalize) {
                        word = capitalizeWord(word);
                    }
                    words.push(word);
                }
            }

            // Add digit to random word if enabled (using cryptographically secure randomness)
            if (addNumbers && words.length > 0) {
                const randomIndex = getSecureRandomInt(words.length);
                words[randomIndex] += generatePassphraseNumbers();
            }

            let passphrase = words.join(separator);

            AppState.generatedPasswordText = passphrase;
            document.getElementById('generatedPassword').textContent = passphrase;
        }

        function generateCustomPassword() {
            const length = parseInt(document.getElementById('lengthSlider').value);
            const charset = getCharsets();

            if (charset.length === 0) {
                alert('Выберите хотя бы один набор символов!');
                return;
            }

            // Use rejection sampling to eliminate modulo bias
            let password = '';
            for (let i = 0; i < length; i++) {
                password += charset[getSecureRandomInt(charset.length)];
            }
            
            AppState.generatedPasswordText = password;
            document.getElementById('generatedPassword').textContent = password;

            // Update entropy display using Shannon entropy
            const { entropy, charsetSize } = calculateEntropy(password);
            const combinations = Math.pow(charsetSize, password.length);
            const secondsToCrack = combinations / 1e12 / 2;

            document.getElementById('genEntropyBits').textContent = Math.round(entropy);
            
            let strength;
            let strengthColor;
            if (entropy < 60) {
                strength = '⚠️ Слабый';
                strengthColor = 'var(--accent-red)';
            } else if (entropy < 90) {
                strength = '⚡ Средний';
                strengthColor = 'var(--accent-yellow)';
            } else {
                strength = '✅ Сильный';
                strengthColor = 'var(--accent-green)';
            }
            
            const strengthEl = document.getElementById('genStrength');
            strengthEl.textContent = strength;
            strengthEl.style.color = strengthColor;
            
            // Format crack time with visual variety (matching analyzer page)
            let timeText = '';
            let emoji = '';
            let timeColor = '';
            
            if (secondsToCrack < 1) {
                timeText = 'Мгновенно';
                emoji = '⚡';
                timeColor = 'var(--accent-red)';
            } else if (secondsToCrack < 60) {
                timeText = `${Math.round(secondsToCrack)} секунд`;
                emoji = '⏱️';
                timeColor = 'var(--accent-red)';
            } else if (secondsToCrack < 3600) {
                timeText = `${Math.round(secondsToCrack / 60)} минут`;
                emoji = '⏰';
                timeColor = 'var(--accent-red)';
            } else if (secondsToCrack < 86400) {
                timeText = `${Math.round(secondsToCrack / 3600)} часов`;
                emoji = '🕐';
                timeColor = '#ff6b6b';
            } else if (secondsToCrack < 2592000) {
                timeText = `${Math.round(secondsToCrack / 86400)} дней`;
                emoji = '📅';
                timeColor = '#ffa94d';
            } else if (secondsToCrack < 31536000) {
                timeText = `${Math.round(secondsToCrack / 2592000)} месяцев`;
                emoji = '📆';
                timeColor = 'var(--accent-yellow)';
            } else if (secondsToCrack < 315360000) {
                timeText = `${Math.round(secondsToCrack / 31536000)} лет`;
                emoji = '🗓️';
                timeColor = '#51cf66';
            } else if (secondsToCrack < 31536000000) {
                const years = Math.round(secondsToCrack / 31536000);
                if (years < 100) {
                    timeText = `${years} лет`;
                    emoji = '📊';
                } else if (years < 1000) {
                    timeText = `${Math.round(years / 10) * 10} лет`;
                    emoji = '⌛';
                } else {
                    timeText = `${Math.round(years / 100) / 10} тыс. лет`;
                    emoji = '🏛️';
                }
                timeColor = 'var(--accent-green)';
            } else if (secondsToCrack < 31536000000000) {
                timeText = `${Math.round(secondsToCrack / 31536000000)} тыс. лет`;
                emoji = '🌍';
                timeColor = '#339af0';
            } else if (secondsToCrack < 31536000000000000) {
                timeText = `${Math.round(secondsToCrack / 31536000000000)} млн. лет`;
                emoji = '🦖';
                timeColor = '#845ef7';
            } else {
                timeText = 'Вечность';
                emoji = '♾️';
                timeColor = '#e64980';
            }
            
            const crackTimeEl = document.getElementById('genCrackTime');
            crackTimeEl.innerHTML = `${emoji} ${timeText}`;
            crackTimeEl.style.color = timeColor;
        }

        function copyPassword() {
            if (!AppState.generatedPasswordText) {
                alert('Сначала сгенерируйте пароль!');
                return;
            }

            navigator.clipboard.writeText(AppState.generatedPasswordText).then(() => {
                showNotification('✅ Пароль скопирован в буфер обмена!');
            }).catch(err => {
                alert('Не удалось скопировать пароль');
            });
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

            // Reset generated password display
            document.getElementById('generatedPassword').textContent = 'Нажмите "Сгенерировать" для создания ' + (mode === 'password' ? 'пароля' : 'парольной фразы');
            AppState.generatedPasswordText = '';
        }

        function selectSeparator(separator) {
            AppState.currentPassphraseSeparator = separator;

            // Update active button
            document.querySelectorAll('.separator-option').forEach(btn => {
                btn.classList.remove('active');
            });
            document.querySelector(`.separator-option[data-separator="${separator}"]`).classList.add('active');
        }

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
            showNotification(`✅ Файл ${filename} загружен!`);
        }

        function exportToTXT() {
            if (!AppState.lastAnalysisResults) {
                alert('Нет данных для экспорта. Сначала проанализируйте пароль.');
                return;
            }

            const data = AppState.lastAnalysisResults;
            const date = new Date(data.timestamp).toLocaleString('ru-RU');

            let text = '╔════════════════════════════════════════════════════════════╗\n';
            text += '║     ОТЧЁТ АНАЛИЗА ПАРОЛЯ - KHODYREVGUARD                  ║\n';
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
            text += `   Время взлома (brute-force): ${data.crackTime.formatted}\n\n`;

            text += '✓ СООТВЕТСТВИЕ КРИТЕРИЯМ:\n';
            text += `   ${data.criteria.length ? '✓' : '✗'} Минимум 8 символов\n`;
            text += `   ${data.criteria.uppercase ? '✓' : '✗'} Заглавные буквы (A-Z)\n`;
            text += `   ${data.criteria.lowercase ? '✓' : '✗'} Строчные буквы (a-z)\n`;
            text += `   ${data.criteria.numbers ? '✓' : '✗'} Цифры (0-9)\n`;
            text += `   ${data.criteria.special ? '✓' : '✗'} Специальные символы (!@#$%...)\n`;
            text += `   ${data.criteria.sequences ? '✓' : '✗'} Без последовательностей (123, abc...)\n`;
            text += `   ${data.criteria.repeating ? '✓' : '✗'} Без повторений (aaa, 111...)\n`;
            text += `   ${data.criteria.common ? '✓' : '✗'} Не входит в список распространенных\n\n`;

            text += '🛡️ ПРОВЕРКА БЕЗОПАСНОСТИ:\n';
            text += `   Статус: ${data.pwnedStatus}\n`;
            if (data.pwnedCount > 0) {
                text += `   ⚠️ ВНИМАНИЕ! Пароль найден в ${data.pwnedCount.toLocaleString()} утечках данных!\n`;
            }

            text += '\n' + '─'.repeat(60) + '\n';

            downloadFile(text, generateExportFilename('txt'), 'text/plain');
        }

        function exportToJSON() {
            if (!AppState.lastAnalysisResults) {
                alert('Нет данных для экспорта. Сначала проанализируйте пароль.');
                return;
            }

            const json = JSON.stringify(AppState.lastAnalysisResults, null, 2);
            downloadFile(json, generateExportFilename('json'), 'application/json');
        }

        function exportToCSV() {
            if (!AppState.lastAnalysisResults) {
                alert('Нет данных для экспорта. Сначала проанализируйте пароль.');
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
            csv += `Время взлома,"${data.crackTime.formatted}"\n`;
            csv += '\n';
            csv += 'КРИТЕРИИ\n';
            csv += `Минимум 8 символов,${data.criteria.length ? 'Да' : 'Нет'}\n`;
            csv += `Заглавные буквы,${data.criteria.uppercase ? 'Да' : 'Нет'}\n`;
            csv += `Строчные буквы,${data.criteria.lowercase ? 'Да' : 'Нет'}\n`;
            csv += `Цифры,${data.criteria.numbers ? 'Да' : 'Нет'}\n`;
            csv += `Специальные символы,${data.criteria.special ? 'Да' : 'Нет'}\n`;
            csv += `Без последовательностей,${data.criteria.sequences ? 'Да' : 'Нет'}\n`;
            csv += `Без повторений,${data.criteria.repeating ? 'Да' : 'Нет'}\n`;
            csv += `Не распространенный,${data.criteria.common ? 'Да' : 'Нет'}\n`;
            csv += '\n';
            csv += 'БЕЗОПАСНОСТЬ\n';
            csv += `Статус,"${data.pwnedStatus}"\n`;
            csv += `Найдено в утечках,${data.pwnedCount}\n`;

            downloadFile(csv, generateExportFilename('csv'), 'text/csv');
        }

        function exportToHTML() {
            if (!AppState.lastAnalysisResults) {
                alert('Нет данных для экспорта. Сначала проанализируйте пароль.');
                return;
            }

            const data = AppState.lastAnalysisResults;
            const date = new Date(data.timestamp).toLocaleString('ru-RU');

            let html = `<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Отчёт анализа пароля - KhodyrevGuard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 40px 20px;
            min-height: 100vh;
        }
        .container {
            max-width: 900px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header p { opacity: 0.9; font-size: 1.1em; }
        .content { padding: 40px; }
        .section { margin-bottom: 35px; }
        .section-title {
            font-size: 1.5em;
            color: #667eea;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .metric {
            display: flex;
            justify-content: space-between;
            padding: 15px 20px;
            margin: 10px 0;
            background: #f8f9fa;
            border-radius: 10px;
            border-left: 4px solid #667eea;
        }
        .metric-label { font-weight: 600; color: #495057; }
        .metric-value { font-weight: 700; color: #212529; }
        .score-big {
            text-align: center;
            font-size: 4em;
            font-weight: bold;
            color: ${data.score >= 70 ? '#28a745' : data.score >= 40 ? '#ffc107' : '#dc3545'};
            margin: 20px 0;
        }
        .criteria-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }
        .criterion {
            padding: 15px;
            background: #f8f9fa;
            border-radius: 10px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .criterion.valid { border-left: 4px solid #28a745; }
        .criterion.invalid { border-left: 4px solid #dc3545; }
        .criterion-icon { font-size: 1.5em; }
        .alert {
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
            font-weight: 500;
        }
        .alert-danger {
            background: #f8d7da;
            border-left: 4px solid #dc3545;
            color: #721c24;
        }
        .alert-success {
            background: #d4edda;
            border-left: 4px solid #28a745;
            color: #155724;
        }
        .footer {
            text-align: center;
            padding: 30px;
            background: #f8f9fa;
            color: #6c757d;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 KhodyrevGuard</h1>
            <p>Отчёт анализа надежности пароля</p>
            <p style="font-size: 0.9em; margin-top: 10px;">Дата: ${date}</p>
        </div>

        <div class="content">
            <div class="section">
                <div class="section-title">📊 Общая оценка</div>
                <div class="score-big">${data.score}/100</div>
                <div class="metric">
                    <span class="metric-label">Уровень надежности</span>
                    <span class="metric-value">${data.strengthLevel}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Длина пароля</span>
                    <span class="metric-value">${data.password.length} символов</span>
                </div>
            </div>

            <div class="section">
                <div class="section-title">🔐 Криптостойкость</div>
                <div class="metric">
                    <span class="metric-label">Энтропия</span>
                    <span class="metric-value">${data.entropy} бит</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Размер алфавита</span>
                    <span class="metric-value">${data.charsetSize} символов</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Возможных комбинаций</span>
                    <span class="metric-value">${data.combinationsFormatted}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Время взлома (brute-force)</span>
                    <span class="metric-value">${data.crackTime.formatted}</span>
                </div>
            </div>

            <div class="section">
                <div class="section-title">✓ Соответствие критериям</div>
                <div class="criteria-grid">
                    <div class="criterion ${data.criteria.length ? 'valid' : 'invalid'}">
                        <span class="criterion-icon">${data.criteria.length ? '✅' : '❌'}</span>
                        <span>Минимум 8 символов</span>
                    </div>
                    <div class="criterion ${data.criteria.uppercase ? 'valid' : 'invalid'}">
                        <span class="criterion-icon">${data.criteria.uppercase ? '✅' : '❌'}</span>
                        <span>Заглавные буквы</span>
                    </div>
                    <div class="criterion ${data.criteria.lowercase ? 'valid' : 'invalid'}">
                        <span class="criterion-icon">${data.criteria.lowercase ? '✅' : '❌'}</span>
                        <span>Строчные буквы</span>
                    </div>
                    <div class="criterion ${data.criteria.numbers ? 'valid' : 'invalid'}">
                        <span class="criterion-icon">${data.criteria.numbers ? '✅' : '❌'}</span>
                        <span>Цифры</span>
                    </div>
                    <div class="criterion ${data.criteria.special ? 'valid' : 'invalid'}">
                        <span class="criterion-icon">${data.criteria.special ? '✅' : '❌'}</span>
                        <span>Специальные символы</span>
                    </div>
                    <div class="criterion ${data.criteria.sequences ? 'valid' : 'invalid'}">
                        <span class="criterion-icon">${data.criteria.sequences ? '✅' : '❌'}</span>
                        <span>Без последовательностей</span>
                    </div>
                    <div class="criterion ${data.criteria.repeating ? 'valid' : 'invalid'}">
                        <span class="criterion-icon">${data.criteria.repeating ? '✅' : '❌'}</span>
                        <span>Без повторений</span>
                    </div>
                </div>
            </div>

            <div class="section">
                <div class="section-title">🛡️ Проверка безопасности</div>
                ${data.pwnedCount > 0 ?
                    `<div class="alert alert-danger">
                        <strong>⚠️ ВНИМАНИЕ!</strong> Пароль был найден в <strong>${data.pwnedCount.toLocaleString()}</strong> утечках данных.
                        Немедленно смените этот пароль!
                    </div>` :
                    `<div class="alert alert-success">
                        <strong>✅ Отлично!</strong> Пароль не найден в известных базах данных утечек.
                    </div>`
                }
            </div>
        </div>

        <div class="footer">
            <p><strong>KhodyrevGuard</strong> - Профессиональный анализатор надежности паролей</p>
            <p style="margin-top: 10px;">Отчёт сгенерирован: ${date}</p>
        </div>
    </div>
</body>
</html>`;

            downloadFile(html, generateExportFilename('html'), 'text/html');
        }

        function toggleExportMenu() {
            const dropdown = document.getElementById('exportDropdown');
            if (dropdown) {
                const isVisible = dropdown.style.display === 'block';
                dropdown.style.display = isVisible ? 'none' : 'block';
            }
        }

        // Close export menu when clicking outside
        document.addEventListener('click', function(e) {
            const exportSection = document.getElementById('exportSection');
            const exportDropdown = document.getElementById('exportDropdown');
            if (exportSection && exportDropdown && !exportSection.contains(e.target)) {
                exportDropdown.style.display = 'none';
            }
        });

        // Event listeners
        document.getElementById('passwordInput').addEventListener('input', (e) => {
            clearTimeout(AppState.debounceTimer);
            AppState.debounceTimer = setTimeout(() => {
                updatePasswordAnalysis();
            }, 300);
        });

        document.getElementById('passwordInput').addEventListener('paste', (e) => {
            e.preventDefault();
            const text = (e.clipboardData || window.clipboardData).getData('text').trim();
            document.execCommand('insertText', false, text);
        });

        // Generator controls
        document.getElementById('lengthSlider').addEventListener('input', (e) => {
            document.getElementById('lengthValue').textContent = e.target.value;
        });

        document.getElementById('wordCountSlider').addEventListener('input', (e) => {
            document.getElementById('wordCountValue').textContent = e.target.value;
        });

        // Initialize generator on first load
        document.addEventListener('DOMContentLoaded', () => {
            generateCustomPassword();
            
            // Initialize hasher event listeners
            const hasherInput = document.getElementById('hasherInput');
            if (hasherInput) {
                hasherInput.addEventListener('input', async (e) => {
                    if (AppState.currentHashAlgorithm && e.target.value) {
                        // Auto-update hash when text changes if algorithm is selected
                        clearTimeout(AppState.hasherDebounceTimer);
                        AppState.hasherDebounceTimer = setTimeout(async () => {
                            const hash = await hashData(e.target.value, AppState.currentHashAlgorithm);
                            AppState.currentHashValue = hash;
                            const hashValueEl = document.getElementById('hashValue');
                            if (hashValueEl) {
                                hashValueEl.textContent = hash;
                            }
                        }, 300);
                    } else if (!e.target.value && AppState.currentHashAlgorithm) {
                        // Hide result if input is cleared
                        const container = document.getElementById('hashResultContainer');
                        if (container) {
                            container.style.display = 'none';
                        }
                        AppState.currentHashAlgorithm = null;
                        AppState.currentHashValue = '';
                        document.querySelectorAll('.algorithm-btn').forEach(btn => {
                            btn.classList.remove('active');
                        });
                    }
                });
            }
        });
