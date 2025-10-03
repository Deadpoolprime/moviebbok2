
const STORAGE_KEY = 'themePreference';

function applyTheme(theme) {
    if (theme === 'dark') {
        document.body.classList.add('dark-mode');
        // Update button text if needed, though simple 'Toggle' works fine
    } else {
        document.body.classList.remove('dark-mode');
    }
}

function loadThemePreference() {
    // Check if user has a preference, otherwise default to light
    const storedTheme = localStorage.getItem(STORAGE_KEY);
    applyTheme(storedTheme || 'light'); 
}

function toggleTheme() {
    const currentTheme = document.body.classList.contains('dark-mode') ? 'dark' : 'light';
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';

    localStorage.setItem(STORAGE_KEY, newTheme);
    applyTheme(newTheme);
}

// Apply theme immediately on page load
loadThemePreference();