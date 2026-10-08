<section class="auth-shell">
    <div class="auth-panel">
        <p class="section-label">Welcome back</p>
        <h1 class="page-title text-4xl">Sign in to your workspace.</h1>
        <p class="mt-3 text-slate-600 dark:text-slate-300">Use your CHIMERA CLOUD account credentials.</p>
        <?php $formErrors = errors(); ?>
        <form action="<?= e(url('/login')) ?>" method="post" class="mt-8 space-y-5" novalidate>
            <?= csrf_field() ?>
            <div class="field">
                <label for="email">Email address</label>
                <input id="email" name="email" type="email" autocomplete="email" value="<?= old('email') ?>" required aria-describedby="email-error">
                <?php if (isset($formErrors['email'])): ?><p id="email-error" class="field-error"><?= e($formErrors['email']) ?></p><?php endif; ?>
            </div>
            <div class="field">
                <label for="password">Password</label>
                <input id="password" name="password" type="password" autocomplete="current-password" required>
            </div>
            <button class="button button-primary w-full" type="submit">Sign in</button>
        </form>
        <p class="mt-6 text-sm text-slate-600 dark:text-slate-400">New here? <a class="text-link" href="<?= e(url('/register')) ?>">Create an account</a>.</p>
    </div>
</section>

