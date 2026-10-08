<section class="auth-shell">
    <div class="auth-panel">
        <p class="section-label">Create your workspace</p>
        <h1 class="page-title text-4xl">Start with a protected account.</h1>
        <p class="mt-3 text-slate-600 dark:text-slate-300">Registration always creates a standard User role.</p>
        <?php $formErrors = errors(); ?>
        <form action="<?= e(url('/register')) ?>" method="post" class="mt-8 space-y-5" novalidate>
            <?= csrf_field() ?>
            <div class="field">
                <label for="name">Full name</label>
                <input id="name" name="name" type="text" maxlength="100" autocomplete="name" value="<?= old('name') ?>" required>
                <?php if (isset($formErrors['name'])): ?><p class="field-error"><?= e($formErrors['name']) ?></p><?php endif; ?>
            </div>
            <div class="field">
                <label for="email">Email address</label>
                <input id="email" name="email" type="email" maxlength="190" autocomplete="email" value="<?= old('email') ?>" required>
                <?php if (isset($formErrors['email'])): ?><p class="field-error"><?= e($formErrors['email']) ?></p><?php endif; ?>
            </div>
            <div class="field">
                <label for="password">Password</label>
                <input id="password" name="password" type="password" minlength="12" autocomplete="new-password" required>
                <p class="field-help">At least 12 characters with letters and numbers.</p>
                <?php if (isset($formErrors['password'])): ?><p class="field-error"><?= e($formErrors['password']) ?></p><?php endif; ?>
            </div>
            <div class="field">
                <label for="password_confirmation">Confirm password</label>
                <input id="password_confirmation" name="password_confirmation" type="password" autocomplete="new-password" required>
                <?php if (isset($formErrors['password_confirmation'])): ?><p class="field-error"><?= e($formErrors['password_confirmation']) ?></p><?php endif; ?>
            </div>
            <button class="button button-primary w-full" type="submit">Create account</button>
        </form>
    </div>
</section>

