<section class="page-section">
    <a class="text-link text-sm" href="<?= e(url('/documents')) ?>">Back to documents</a>
    <div class="mt-6"><p class="section-label">Document metadata</p><h1 class="page-title break-words"><?= e($document['original_name']) ?></h1></div>
    <div class="mt-10 grid gap-6 lg:grid-cols-[1fr_.65fr]">
        <section class="surface"><h2>File details</h2><dl class="detail-list"><div><dt>Type</dt><dd class="normal-case"><?= e($document['mime_type']) ?></dd></div><div><dt>Size</dt><dd><?= e(format_bytes((int) $document['size_bytes'])) ?></dd></div><div><dt>Uploaded</dt><dd><?= e(format_datetime($document['created_at'])) ?></dd></div><div><dt>SHA-256 checksum</dt><dd class="checksum"><?= e($document['checksum_sha256']) ?></dd></div></dl><a class="button button-primary mt-6" href="<?= e(url('/documents/' . $document['id'] . '/download')) ?>">Download document</a></section>
        <aside class="surface danger-surface"><h2>Delete document</h2><p>Deletion removes this document record and its stored file. This action cannot be undone.</p><form action="<?= e(url('/documents/' . $document['id'] . '/delete')) ?>" method="post" class="mt-6" data-confirm="Delete this document permanently?"><?= csrf_field() ?><button class="button button-danger" type="submit">Delete document</button></form></aside>
    </div>
</section>
