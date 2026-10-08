<section class="page-section">
    <div><p class="section-label">Application administration</p><h1 class="page-title">Administration</h1><p class="page-lead">Manage laboratory accounts and application operations.</p></div>
    <div class="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div class="metric"><span>Users</span><strong><?= e($counts['user']) ?></strong></div>
        <div class="metric"><span>Administrators</span><strong><?= e($counts['admin']) ?></strong></div>
        <div class="metric"><span>Security admins</span><strong><?= e($counts['security_admin']) ?></strong></div>
        <div class="metric"><span>Documents</span><strong><?= e($documentSummary['document_count']) ?></strong><small><?= e(format_bytes($documentSummary['storage_bytes'])) ?> stored</small></div>
    </div>
    <section class="surface mt-8 overflow-x-auto">
        <h2>Recent accounts</h2>
        <table class="data-table mt-5"><thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th></tr></thead><tbody>
        <?php foreach ($recentUsers as $account): ?><tr><td><?= e($account['name']) ?></td><td><?= e($account['email']) ?></td><td><?= e(str_replace('_', ' ', $account['role'])) ?></td><td><?= $account['is_active'] ? 'Active' : 'Disabled' ?></td></tr><?php endforeach; ?>
        </tbody></table>
    </section>
    <div class="mt-8 grid gap-6 lg:grid-cols-2">
        <section class="surface overflow-x-auto">
            <h2>Recent document metadata</h2>
            <?php if ($recentDocuments === []): ?><div class="empty-state"><strong>No documents</strong><p>Uploaded document metadata will appear here.</p></div><?php else: ?>
            <table class="data-table mt-5"><thead><tr><th>Document</th><th>Owner</th><th>Size</th></tr></thead><tbody>
            <?php foreach ($recentDocuments as $document): ?><tr><td><?= e($document['original_name']) ?><small class="block text-slate-500"><?= e($document['mime_type']) ?></small></td><td><?= e($document['owner_name']) ?><small class="block text-slate-500"><?= e($document['owner_email']) ?></small></td><td><?= e(format_bytes((int) $document['size_bytes'])) ?></td></tr><?php endforeach; ?>
            </tbody></table><?php endif; ?>
        </section>
        <section class="surface">
            <h2>Recent application activity</h2>
            <?php if ($recentActivity === []): ?><div class="empty-state"><strong>No activity</strong><p>Legitimate user actions will appear here.</p></div><?php else: ?>
            <div class="activity-list mt-5"><?php foreach ($recentActivity as $activity): ?><div><span><strong><?= e($activity['description']) ?></strong><small><?= e($activity['user_name'] ?? 'Deleted account') ?>, <?= e($activity['user_email'] ?? 'unavailable') ?></small></span><time datetime="<?= e($activity['created_at']) ?>"><?= e(format_datetime($activity['created_at'])) ?></time></div><?php endforeach; ?></div><?php endif; ?>
        </section>
    </div>
</section>
