        const AppState = {
            debounceTimer: null,
            hasherDebounceTimer: null,
            isPasswordVisible: false,
            currentPage: 'analyzer',
            generatedPasswordText: '',
            generatedPassphraseText: '',
            currentGeneratorMode: 'password',
            currentPassphraseSeparator: '-',
            currentHashFormat: 'hex',
            currentHashAlgorithm: null,
            currentHashValue: '',
            lastAnalysisResults: null, // Хранилище результатов последнего анализа для экспорта
            pwnedCache: new Map(), // Кэш для HIBP проверок (SHA-1 hash -> breach count)
            batchCount: 1,         // Количество паролей для пакетной генерации (1–8)
            batchPasswords: [],    // Массив { text, score, color } для пакетного режима
            selectedBatchIndex: 0  // Индекс выбранного пароля в пакете
        };

        // Восстанавливаем HIBP-кэш из sessionStorage (живёт до закрытия вкладки)
        (function() {
            try {
                const stored = sessionStorage.getItem('hibpCache');
                if (stored) AppState.pwnedCache = new Map(Object.entries(JSON.parse(stored)));
            } catch(e) {}
        })();

        function showNotification(message, type = 'success') {
            const notification = document.getElementById('copyNotification');
            const icon = type === 'warning' ? 'alert-triangle' : 'check-circle';
            notification.innerHTML = `<i data-lucide="${icon}"></i><span>${message}</span>`;
            notification.className = `copy-notification show copy-notification--${type}`;
            if (window.lucide) lucide.createIcons();

            setTimeout(() => {
                notification.classList.remove('show');
            }, 3000);
        }

        // Page switching
        function switchPage(page, event) {
            const currentPageEl = document.querySelector('.page.active');
            if (currentPageEl && currentPageEl.id === page + 'Page') return;

            AppState.currentPage = page;

            // Update tabs immediately
            document.querySelectorAll('.nav-tab').forEach(tab => {
                tab.classList.remove('active');
                tab.setAttribute('aria-selected', 'false');
            });
            if (event && event.target) {
                const activeTab = event.target.closest('.nav-tab');
                activeTab.classList.add('active');
                activeTab.setAttribute('aria-selected', 'true');
            }

            // Fade out current page, then switch
            if (currentPageEl) {
                currentPageEl.classList.add('page-exit');
                setTimeout(() => {
                    document.querySelectorAll('.page').forEach(p => p.classList.remove('active', 'page-exit'));
                    document.getElementById(page + 'Page').classList.add('active');
                }, 50);
            } else {
                document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
                document.getElementById(page + 'Page').classList.add('active');
            }
        }

        // Password visibility toggle
        function togglePasswordVisibility() {
            const input = document.getElementById('passwordInput');
            const btn = document.getElementById('toggleBtn');

            if (AppState.isPasswordVisible) {
                input.type = 'password';
                btn.innerHTML = '<i data-lucide="eye"></i>';
                btn.setAttribute('aria-label', 'Показать пароль');
            } else {
                input.type = 'text';
                btn.innerHTML = '<i data-lucide="eye-off"></i>';
                btn.setAttribute('aria-label', 'Скрыть пароль');
            }
            AppState.isPasswordVisible = !AppState.isPasswordVisible;
            if (window.lucide) lucide.createIcons();
        }

        function copyPassword() {
            const textToCopy = AppState.currentGeneratorMode === 'passphrase'
                ? AppState.generatedPassphraseText
                : AppState.generatedPasswordText;
            if (!textToCopy) {
                showNotification('Сначала сгенерируйте пароль!', 'warning');
                return;
            }

            navigator.clipboard.writeText(textToCopy).then(() => {
                showNotification('Пароль скопирован в буфер обмена!');
                const btn = document.getElementById('copyBtn');
                if (btn && !btn.disabled) {
                    const orig = btn.innerHTML;
                    btn.innerHTML = '<i data-lucide="check"></i><span>Скопировано!</span>';
                    if (window.lucide) lucide.createIcons();
                    btn.disabled = true;
                    setTimeout(() => { btn.innerHTML = orig; btn.disabled = false; }, 2000);
                }
            }).catch(err => {
                showNotification('Не удалось скопировать пароль', 'warning');
            });
        }

        // Отправить сгенерированный пароль в анализатор
        function analyzeGeneratedPassword() {
            const textToAnalyze = AppState.currentGeneratorMode === 'passphrase'
                ? AppState.generatedPassphraseText
                : AppState.generatedPasswordText;
            if (!textToAnalyze) {
                showNotification('Сначала сгенерируйте пароль!', 'warning');
                return;
            }
            document.getElementById('passwordInput').value = textToAnalyze;

            // Переключить активную nav-вкладку
            document.querySelectorAll('.nav-tab').forEach(t => {
                t.classList.remove('active');
                t.setAttribute('aria-selected', 'false');
            });
            const analyzerTab = document.querySelector('.nav-tab[aria-controls="analyzerPage"]');
            analyzerTab.classList.add('active');
            analyzerTab.setAttribute('aria-selected', 'true');

            // Переключить страницу с анимацией
            AppState.currentPage = 'analyzer';
            const currentPageEl = document.querySelector('.page.active');
            if (currentPageEl) {
                currentPageEl.classList.add('page-exit');
                setTimeout(() => {
                    document.querySelectorAll('.page').forEach(p => p.classList.remove('active', 'page-exit'));
                    document.getElementById('analyzerPage').classList.add('active');
                    document.getElementById('passwordInput').dispatchEvent(new Event('input'));
                }, 180);
            }
        }

        // Запрет копирования и контекстного меню на всём сайте, кроме поля ввода пароля
        document.addEventListener('DOMContentLoaded', function() {
            // Запрет копирования
            document.addEventListener('copy', function(e) {
                const target = e.target;
                if (!['passwordInput', 'generatedPassword', 'compInputA', 'compInputB'].includes(target.id)) {
                    e.preventDefault();
                    return false;
                }
            });

            // Запрет вырезания
            document.addEventListener('cut', function(e) {
                const target = e.target;
                if (!['passwordInput', 'generatedPassword', 'compInputA', 'compInputB'].includes(target.id)) {
                    e.preventDefault();
                    return false;
                }
            });

            // Запрет контекстного меню (правой кнопки мыши)
            document.addEventListener('contextmenu', function(e) {
                const target = e.target;
                if (!['passwordInput', 'generatedPassword', 'compInputA', 'compInputB'].includes(target.id)) {
                    e.preventDefault();
                    return false;
                }
            });
        });

        // Close export menu when clicking outside
        document.addEventListener('click', function(e) {
            const exportSection = document.getElementById('exportSection');
            const exportDropdown = document.getElementById('exportDropdown');
            if (exportSection && exportDropdown && !exportSection.contains(e.target)) {
                exportDropdown.classList.remove('open');
            }
        });

        // Event listeners
        document.getElementById('passwordInput').addEventListener('input', (e) => {
            const len = e.target.value.length;
            const counterEl = document.getElementById('charCounter');
            if (len > 0) {
                counterEl.innerHTML = `<span class="char-counter-pill"><i data-lucide="type"></i>${len} симв.</span>`;
                if (window.lucide) lucide.createIcons();
            } else {
                counterEl.innerHTML = '';
            }
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
            // generateCustomPassword(); // Убрана автогенерация при загрузке страницы

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

            // --- Bind all event listeners (replaces inline onclick= attributes) ---

            // Theme buttons
            document.querySelectorAll('.theme-btn').forEach(btn => {
                btn.addEventListener('click', () => switchTheme(btn.dataset.theme));
            });

            // Nav tabs
            document.querySelectorAll('.nav-tab').forEach(tab => {
                tab.addEventListener('click', (e) => {
                    const page = tab.getAttribute('aria-controls').replace('Page', '');
                    switchPage(page, e);
                });
            });

            // Analyzer: visibility toggle
            const toggleBtn = document.getElementById('toggleBtn');
            if (toggleBtn) toggleBtn.addEventListener('click', togglePasswordVisibility);

            // Analyzer: info icon tooltips
            const crackTimeInfoIcon = document.getElementById('crackTimeInfoIcon');
            if (crackTimeInfoIcon) crackTimeInfoIcon.addEventListener('click', toggleCrackTimeTooltip);
            const zxcvbnCrackTimeInfoIcon = document.getElementById('zxcvbnCrackTimeInfoIcon');
            if (zxcvbnCrackTimeInfoIcon) zxcvbnCrackTimeInfoIcon.addEventListener('click', toggleZxcvbnCrackTimeTooltip);
            const entropyInfoIcon = document.getElementById('entropyInfoIcon');
            if (entropyInfoIcon) entropyInfoIcon.addEventListener('click', toggleEntropyTooltip);

            // Export
            const exportBtn = document.getElementById('exportBtn');
            if (exportBtn) exportBtn.addEventListener('click', toggleExportMenu);
            const exportFns = [exportToTXT, exportToJSON, exportToCSV, exportToHTML];
            document.querySelectorAll('.export-option').forEach((opt, i) => {
                opt.addEventListener('click', exportFns[i]);
            });

            // Generator mode tabs
            document.querySelectorAll('.generator-mode-tab').forEach(tab => {
                tab.addEventListener('click', () => switchGeneratorMode(tab.dataset.mode));
            });

            // Generator buttons
            const generateBtn = document.getElementById('generateBtn');
            if (generateBtn) generateBtn.addEventListener('click', generateCustomPassword);
            const copyBtn = document.getElementById('copyBtn');
            if (copyBtn) copyBtn.addEventListener('click', copyPassword);
            const analyzeBtn = document.getElementById('analyzeBtn');
            if (analyzeBtn) analyzeBtn.addEventListener('click', analyzeGeneratedPassword);

            // Batch count selector
            document.querySelectorAll('.batch-count-btn').forEach(btn => {
                btn.addEventListener('click', () => {
                    AppState.batchCount = parseInt(btn.dataset.count);
                    document.querySelectorAll('.batch-count-btn').forEach(b => b.classList.remove('active'));
                    btn.classList.add('active');

                    // Авто-генерировать с новым количеством
                    if (AppState.currentGeneratorMode === 'passphrase') {
                        generatePassphrase();
                    } else {
                        generateCustomPassword();
                    }
                });
            });

            // Separator buttons
            document.querySelectorAll('.separator-option').forEach(btn => {
                btn.addEventListener('click', () => selectSeparator(btn.dataset.separator));
            });

            // Hasher: algorithm buttons
            document.querySelectorAll('.algorithm-btn').forEach(btn => {
                btn.addEventListener('click', (e) => hashSingleAlgorithm(btn.dataset.algorithm, true, e));
            });

            // Hasher: format buttons
            document.querySelectorAll('.format-option').forEach(btn => {
                btn.addEventListener('click', () => setHashFormat(btn.dataset.format));
            });

            // Hasher: copy hash
            const hashOutput = document.getElementById('hashOutput');
            if (hashOutput) hashOutput.addEventListener('click', copyHashValue);
            const hashCopyBtn = document.querySelector('.hash-copy-btn-single');
            if (hashCopyBtn) hashCopyBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                copyHashValue();
            });

            // Hasher: clear
            const clearHasherBtn = document.getElementById('clearHasherBtn');
            if (clearHasherBtn) clearHasherBtn.addEventListener('click', clearHasher);

            // Initial Lucide icon render
            if (window.lucide) lucide.createIcons();
        });
