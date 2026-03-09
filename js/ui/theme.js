// Theme switcher
const THEME_COLORS = { light: '#f8f9fa', dark: '#0d0d0d', original: '#0a0e27', blue: '#0a1929' };

let currentTheme = localStorage.getItem('theme') || 'light';
document.documentElement.setAttribute('data-theme', currentTheme);
document.querySelectorAll(`.theme-btn[data-theme="${currentTheme}"]`).forEach(btn => btn.classList.add('active'));
document.getElementById('themeColorMeta').setAttribute('content', THEME_COLORS[currentTheme] || '#f8f9fa');

function switchTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
    document.getElementById('themeColorMeta').setAttribute('content', THEME_COLORS[theme] || '#f8f9fa');

    // Update active button
    document.querySelectorAll('.theme-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    document.querySelectorAll(`.theme-btn[data-theme="${theme}"]`).forEach(btn => btn.classList.add('active'));
}
