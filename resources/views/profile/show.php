<?php $formErrors = errors(); ?>
<section class="page-section">
    <div><p class="section-label">Account settings</p><h1 class="page-title">Profile</h1><p class="page-lead">Manage the display information attached to your own account.</p></div>
    <div class="mt-10 grid gap-6 lg:grid-cols-[1fr_.8fr]">
        <section class="surface">
            <h2>Profile information</h2>
            <form action="<?= e(url('/profile')) ?>" method="post" class="mt-6 space-y-5" novalidate>
                <?= csrf_field() ?>
                <div class="field"><label for="name">Full name</label><input id="name" name="name" type="text" maxlength="100" autocomplete="name" value="<?= old('name', $account['name']) ?>" required><?php if (isset($formErrors['name'])): ?><p class="field-error"><?= e($formErrors['name']) ?></p><?php endif; ?></div>
                <div class="field"><label for="email">Email address</label><input id="email" type="email" value="<?= e($account['email']) ?>" disabled><p class="field-help">Email changes are disabled in this phase to protect account identity.</p></div>
                <button class="button button-primary" type="submit">Save profile</button>
            </form>
        </section>
        <aside class="surface">
            <h2>Account metadata</h2>
            <dl class="detail-list"><div><dt>Account role</dt><dd><?= e(str_replace('_', ' ', $account['role'])) ?></dd></div><div><dt>Created</dt><dd><?= e(format_datetime($account['created_at'])) ?></dd></div><div><dt>Last sign in</dt><dd><?= e(format_datetime($account['last_login_at'] ?? null)) ?></dd></div><div><dt>Status</dt><dd><?= $account['is_active'] ? 'Active' : 'Disabled' ?></dd></div></dl>
        </aside>
    </div>
</section>
