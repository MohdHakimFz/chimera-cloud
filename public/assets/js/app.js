const toggle = document.querySelector('.nav-toggle');
const menu = document.querySelector('#primary-menu');
const themeToggle = document.querySelector('[data-theme-toggle]');

if (themeToggle) {
    const root = document.documentElement;
    const themeLabel = themeToggle.querySelector('[data-theme-label]');
    const themeMeta = document.querySelector('meta[name="theme-color"]');

    const renderTheme = (theme) => {
        const dark = theme === 'dark';
        root.dataset.theme = theme;
        themeToggle.setAttribute('aria-label', `Switch to ${dark ? 'light' : 'dark'} theme`);
        themeToggle.setAttribute('aria-pressed', String(dark));
        if (themeLabel) themeLabel.textContent = dark ? 'Dark' : 'Light';
        if (themeMeta) themeMeta.setAttribute('content', dark ? '#070b12' : '#f2f5f3');
    };

    renderTheme(root.dataset.theme === 'light' ? 'light' : 'dark');
    themeToggle.addEventListener('click', () => {
        const nextTheme = root.dataset.theme === 'dark' ? 'light' : 'dark';
        renderTheme(nextTheme);
        try { localStorage.setItem('chimera-theme', nextTheme); } catch (_) {}
    });
}

if (toggle && menu) {
    const closeMenu = () => {
        toggle.setAttribute('aria-expanded', 'false');
        toggle.setAttribute('aria-label', 'Open navigation');
        menu.classList.remove('mobile-open');
        document.body.style.overflow = '';
    };

    toggle.addEventListener('click', () => {
        const opening = toggle.getAttribute('aria-expanded') !== 'true';
        toggle.setAttribute('aria-expanded', String(opening));
        toggle.setAttribute('aria-label', opening ? 'Close navigation' : 'Open navigation');
        menu.classList.toggle('mobile-open', opening);
        document.body.style.overflow = opening ? 'hidden' : '';
    });

    menu.querySelectorAll('a').forEach((link) => link.addEventListener('click', closeMenu));
    window.addEventListener('resize', () => { if (window.innerWidth > 1100) closeMenu(); });
    document.addEventListener('keydown', (event) => { if (event.key === 'Escape') closeMenu(); });
}

const confirmForms = document.querySelectorAll('form[data-confirm]');
if (confirmForms.length > 0) {
    const dialog = document.createElement('dialog');
    dialog.className = 'confirm-dialog';
    dialog.innerHTML = `
        <div class="confirm-dialog-inner">
            <p class="section-label">Confirm action</p>
            <h2>Are you sure?</h2>
            <p data-confirm-message></p>
            <div class="confirm-actions">
                <button class="button button-secondary" type="button" data-confirm-cancel>Cancel</button>
                <button class="button button-danger" type="button" data-confirm-accept>Continue</button>
            </div>
        </div>`;
    document.body.append(dialog);
    let pendingForm = null;

    confirmForms.forEach((form) => {
        form.addEventListener('submit', (event) => {
            if (form.dataset.confirmed === 'true') return;
            event.preventDefault();
            pendingForm = form;
            const message = form.getAttribute('data-confirm') || 'Continue with this action?';
            dialog.querySelector('[data-confirm-message]').textContent = message;
            if (typeof dialog.showModal === 'function') dialog.showModal();
            else if (window.confirm(message)) {
                form.dataset.confirmed = 'true';
                form.requestSubmit();
            }
        });
    });

    dialog.querySelector('[data-confirm-cancel]').addEventListener('click', () => { pendingForm = null; dialog.close(); });
    dialog.querySelector('[data-confirm-accept]').addEventListener('click', () => {
        if (!pendingForm) return;
        const form = pendingForm;
        pendingForm = null;
        form.dataset.confirmed = 'true';
        dialog.close();
        form.requestSubmit();
    });
    dialog.addEventListener('cancel', () => { pendingForm = null; });
}
