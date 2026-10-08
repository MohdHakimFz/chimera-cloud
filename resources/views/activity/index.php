<section class="page-section">
    <div><p class="section-label">Account history</p><h1 class="page-title">Your activity</h1><p class="page-lead">Legitimate account actions are private to your account and separate from security monitoring.</p></div>
    <section class="surface mt-10">
        <?php if ($activities === []): ?><div class="empty-state"><strong>No activity recorded</strong><p>Your account actions will appear here.</p></div><?php else: ?>
        <div class="activity-list"><?php foreach ($activities as $activity): ?><div><span><strong><?= e($activity['description']) ?></strong><small><?= e(str_replace('_', ' ', strtolower($activity['activity_type']))) ?></small></span><time datetime="<?= e($activity['created_at']) ?>"><?= e(format_datetime($activity['created_at'])) ?></time></div><?php endforeach; ?></div><?php endif; ?>
    </section>
</section>
