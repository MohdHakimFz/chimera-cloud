<?php $formErrors = errors(); ?>
<section class="page-section">
    <div class="dashboard-heading"><div><p class="section-label">Secure file storage</p><h1 class="page-title">Documents</h1><p class="page-lead">Only documents owned by your account are shown and accessible.</p></div><div class="text-right"><strong class="block text-2xl"><?= e($summary['document_count']) ?></strong><span class="text-sm text-slate-500"><?= e(format_bytes($summary['storage_bytes'])) ?> stored</span></div></div>
    <div class="mt-10 grid gap-6 lg:grid-cols-[.72fr_1.28fr]">
        <section class="surface">
            <h2>Upload a document</h2>
            <form action="<?= e(url('/documents')) ?>" method="post" enctype="multipart/form-data" class="mt-6 space-y-5">
                <?= csrf_field() ?>
                <input type="hidden" name="MAX_FILE_SIZE" value="<?= e($maxBytes) ?>">
                <div class="field"><label for="document">Document file</label><input id="document" name="document" type="file" accept=".pdf,.txt,.csv,.md" required><?php if (isset($formErrors['document'])): ?><p class="field-error"><?= e($formErrors['document']) ?></p><?php endif; ?><p class="field-help">Allowed: <?= e(strtoupper(implode(', ', $allowedExtensions))) ?>. Maximum <?= e(format_bytes($maxBytes)) ?>.</p></div>
                <button class="button button-primary" type="submit">Upload document</button>
            </form>
        </section>
        <section class="surface overflow-x-auto">
            <h2>Your documents</h2>
            <?php if ($documents === []): ?><div class="empty-state"><strong>No documents yet</strong><p>Choose an approved dummy document using the upload form.</p></div><?php else: ?>
            <table class="data-table mt-5"><thead><tr><th>Name</th><th>Type</th><th>Size</th><th>Uploaded</th><th><span class="sr-only">Action</span></th></tr></thead><tbody>
                <?php foreach ($documents as $document): ?><tr><td class="font-semibold"><?= e($document['original_name']) ?></td><td><?= e($document['mime_type']) ?></td><td><?= e(format_bytes((int) $document['size_bytes'])) ?></td><td><?= e(format_datetime($document['created_at'])) ?></td><td><a class="text-link" href="<?= e(url('/documents/' . $document['id'])) ?>">Details</a></td></tr><?php endforeach; ?>
            </tbody></table><?php endif; ?>
        </section>
    </div>
</section>
