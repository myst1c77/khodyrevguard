// MD5 implementation (RFC 1321 compliant)
function md5(string) {
    // Convert string to UTF-8 bytes
    const utf8Array = new TextEncoder().encode(string);
    const msgLength = utf8Array.length;
    const blockCount = ((msgLength + 8) >>> 6) + 1;
    const blocks = new Array(blockCount * 16);

    // Convert message to 32-bit words
    let i;
    for (i = 0; i < msgLength; i++) {
        blocks[i >>> 2] |= utf8Array[i] << ((i % 4) << 3);
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

async function hashSingleAlgorithm(algorithm, isUserClick = true, ev = null) {
    const input = document.getElementById('hasherInput').value;
    if (!input) {
        showNotification('Введите текст для хеширования', 'warning');
        return;
    }

    // Update active button only if it's a user click
    if (isUserClick) {
        document.querySelectorAll('.algorithm-btn').forEach(btn => {
            btn.classList.remove('active');
        });

        // Find and activate the clicked button
        const clickedBtn = ev?.target?.closest('.algorithm-btn');
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
    algorithmIcon.innerHTML = getAlgorithmIcon(algorithm);
    if (window.lucide) lucide.createIcons();
    algorithmName.textContent = algorithm;
    hashValue.textContent = hash;

    // Show container
    container.style.display = 'block';
}

function getAlgorithmIcon(algorithm) {
    const icons = {
        'MD5': 'code-2',
        'SHA-1': 'lock',
        'SHA-256': 'shield-check',
        'SHA-512': 'zap'
    };
    return `<i data-lucide="${icons[algorithm] || 'key-round'}"></i>`;
}

function copyHashValue() {
    if (!AppState.currentHashValue) return;

    navigator.clipboard.writeText(AppState.currentHashValue).then(() => {
        showNotification('Хеш скопирован в буфер обмена!');
    }).catch(err => {
        showNotification('Не удалось скопировать хеш', 'warning');
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
