<section class="soc-shell min-h-screen">
    <div class="mx-auto max-w-7xl px-4 py-10 sm:px-6 lg:px-8">
        <div class="dashboard-heading">
            <div><p class="section-label">Security operations</p><h1>Telemetry overview</h1><p class="mt-3 max-w-3xl text-slate-400">Normalized security events are evaluated through deterministic threat scoring. No automated blocking or account action is performed.</p></div>
            <span class="role-badge">Security Admin only</span>
        </div>
        <div class="mt-10 grid gap-px overflow-hidden rounded-2xl border border-slate-800 bg-slate-800 sm:grid-cols-2 lg:grid-cols-4">
            <?php foreach ([['All events', $summary['total']], ['Authentication failures', $summary['type']['LOGIN_FAILURE']], ['Authorization denials', $summary['type']['ACCESS_DENIED'] + $summary['type']['ROLE_ACCESS_DENIED'] + $summary['type']['OWNERSHIP_ACCESS_DENIED']], ['High / critical', $summary['severity']['HIGH'] + $summary['severity']['CRITICAL']]] as [$label, $value]): ?>
                <div class="bg-slate-900 p-6"><span class="text-sm text-slate-400"><?= e($label) ?></span><strong class="mt-3 block text-3xl text-slate-100"><?= e((string) $value) ?></strong></div>
            <?php endforeach; ?>
        </div>
        <div class="mt-6 flex flex-wrap gap-2" aria-label="Events by category">
            <?php foreach ($summary['by_category'] as $category): ?>
                <span class="rounded-full border border-slate-700 bg-slate-900 px-3 py-1 text-xs text-slate-300"><?= e($category['category'] ?? 'UNKNOWN') ?> <strong class="ml-1 text-slate-100"><?= e((string) $category['total']) ?></strong></span>
            <?php endforeach; ?>
        </div>
        <section class="mt-8 rounded-2xl border border-slate-800 bg-slate-900 p-6" aria-labelledby="telemetry-filters">
            <h2 id="telemetry-filters" class="text-lg font-semibold text-slate-100">Filter events</h2>
            <form method="get" action="<?= e(url('/security')) ?>" class="mt-5 grid gap-4 md:grid-cols-4">
                <label class="text-sm text-slate-300">Event type<select name="type" class="field mt-2"><option value="">All types</option><?php foreach ($eventTypes as $type): ?><option value="<?= e($type) ?>" <?= $filters['type'] === $type ? 'selected' : '' ?>><?= e($type) ?></option><?php endforeach; ?></select></label>
                <label class="text-sm text-slate-300">Severity<select name="severity" class="field mt-2"><option value="">All severities</option><?php foreach ($severities as $severity): ?><option value="<?= e($severity) ?>" <?= $filters['severity'] === $severity ? 'selected' : '' ?>><?= e($severity) ?></option><?php endforeach; ?></select></label>
                <label class="text-sm text-slate-300">Outcome<select name="outcome" class="field mt-2"><option value="">All outcomes</option><?php foreach (['SUCCESS','FAILURE','DENIED','REJECTED','ERROR'] as $outcome): ?><option value="<?= e($outcome) ?>" <?= $filters['outcome'] === $outcome ? 'selected' : '' ?>><?= e($outcome) ?></option><?php endforeach; ?></select></label>
                <label class="text-sm text-slate-300">From date<input class="field mt-2" type="date" name="date_from" value="<?= e($filters['date_from']) ?>"></label>
                <div class="flex gap-3 md:col-span-4"><button class="button button-primary" type="submit">Apply filters</button><a class="button button-secondary" href="<?= e(url('/security')) ?>">Clear</a></div>
            </form>
        </section>
        <section class="mt-8 overflow-hidden rounded-2xl border border-slate-800 bg-slate-900" aria-labelledby="recent-events">
            <div class="border-b border-slate-800 px-6 py-5"><h2 id="recent-events" class="text-lg font-semibold text-slate-100">Recent security events</h2><p class="mt-1 text-sm text-slate-400">Newest 50 matching events.</p></div>
            <?php if ($events === []): ?><div class="empty-state border-slate-800 text-slate-400"><strong class="text-slate-200">No matching events</strong><p>Telemetry appears here after a classified security-relevant action.</p></div>
            <?php else: ?><div class="overflow-x-auto"><table class="w-full text-left text-sm"><thead class="bg-slate-950 text-slate-400"><tr><th class="px-5 py-3">Time</th><th class="px-5 py-3">Event</th><th class="px-5 py-3">Severity</th><th class="px-5 py-3">Outcome</th><th class="px-5 py-3">Endpoint</th></tr></thead><tbody class="divide-y divide-slate-800">
            <?php foreach ($events as $event): ?><tr class="text-slate-300"><td class="whitespace-nowrap px-5 py-4"><?= e($event['created_at']) ?></td><td class="px-5 py-4"><a class="font-medium text-emerald-400 hover:text-emerald-300" href="<?= e(url('/security/events/' . $event['id'])) ?>"><?= e($event['event_type']) ?></a><span class="mt-1 block text-xs text-slate-500"><?= e($event['category']) ?></span></td><td class="px-5 py-4"><?= e($event['severity']) ?></td><td class="px-5 py-4"><?= e($event['outcome']) ?></td><td class="max-w-xs truncate px-5 py-4 font-mono text-xs"><?= e($event['http_method'] . ' ' . $event['endpoint']) ?></td></tr><?php endforeach; ?>
            </tbody></table></div><?php endif; ?>
        </section>
    </div>
</section>
