<?php $currentUser = user(); ?>
<section class="page-section">
    <div class="dashboard-heading">
        <div><p class="section-label">Workspace</p><h1 class="page-title">Good to see you, <?= e($currentUser['name']) ?>.</h1></div>
        <span class="role-badge"><?= e(str_replace('_', ' ', $currentUser['role'])) ?></span>
    </div>
    <div class="mt-8 grid gap-4 sm:grid-cols-2">
        <div class="metric"><span>Your documents</span><strong><?= e($summary['document_count']) ?></strong></div>
        <div class="metric"><span>Storage used</span><strong><?= e(format_bytes($summary['storage_bytes'])) ?></strong></div>
    </div>
    <div class="mt-10 grid gap-5 md:grid-cols-[1.3fr_.7fr]">
        <section class="surface min-h-64">
            <div class="flex items-center justify-between gap-4"><h2>Recent documents</h2><a class="text-link text-sm" href="<?= e(url('/documents')) ?>">Manage documents</a></div>
            <?php if ($recentDocuments === []): ?>
                <div class="empty-state"><strong>No documents yet</strong><p>Upload an approved dummy document to begin.</p><a class="button button-primary mt-4" href="<?= e(url('/documents')) ?>">Upload document</a></div>
            <?php else: ?>
                <div class="compact-list mt-5">
                    <?php foreach ($recentDocuments as $document): ?>
                        <a href="<?= e(url('/documents/' . $document['id'])) ?>"><span><strong><?= e($document['original_name']) ?></strong><small><?= e(format_datetime($document['created_at'])) ?></small></span><span><?= e(format_bytes((int) $document['size_bytes'])) ?></span></a>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </section>
        <aside class="surface">
            <h2>Account</h2>
            <dl class="detail-list"><div><dt>Email</dt><dd><?= e($currentUser['email']) ?></dd></div><div><dt>Access</dt><dd><?= e(str_replace('_', ' ', $currentUser['role'])) ?></dd></div></dl>
            <a class="button button-secondary mt-6 w-full" href="<?= e(url('/profile')) ?>">View profile</a>
            <?php if ($currentUser['role'] === 'admin'): ?><a class="button button-secondary mt-6 w-full" href="<?= e(url('/admin')) ?>">Open administration</a><?php endif; ?>
            <?php if ($currentUser['role'] === 'security_admin'): ?><a class="button button-secondary mt-6 w-full" href="<?= e(url('/security')) ?>">Open security operations</a><?php endif; ?>
        </aside>
    </div>
    <section class="surface mt-5">
        <div class="flex items-center justify-between gap-4"><h2>Recent activity</h2><a class="text-link text-sm" href="<?= e(url('/activity')) ?>">View history</a></div>
        <?php if ($recentActivity === []): ?><div class="empty-state"><strong>No activity recorded</strong><p>Account actions will appear here.</p></div><?php else: ?>
            <div class="activity-list mt-5"><?php foreach ($recentActivity as $activity): ?><div><span><strong><?= e($activity['description']) ?></strong><small><?= e(str_replace('_', ' ', strtolower($activity['activity_type']))) ?></small></span><time datetime="<?= e($activity['created_at']) ?>"><?= e(format_datetime($activity['created_at'])) ?></time></div><?php endforeach; ?></div>
        <?php endif; ?>
    </section>
</section>
