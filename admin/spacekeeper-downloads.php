<?php

declare(strict_types=1);

// Included only after the main admin has authenticated the request.
if (!isset($backendRoot)) {
    http_response_code(404);
    exit;
}
require_once $backendRoot . '/src/SpaceKeeperDownloads.php';
$spaceKeeper = \INoon\Licensing\SpaceKeeperDownloads::load($backendRoot . '/cache');
$spaceKeeperStats = $spaceKeeper['stats'];
?>
<div class="metric-heading">
    <h3>SpaceKeeper downloads</h3>
    <p><a href="https://github.com/cosmicnoon-app/spacekeeper-updates/releases" target="_blank" rel="noopener noreferrer">GitHub releases ↗</a> · Refreshes every 15 minutes</p>
</div>
<?php if ($spaceKeeperStats === null): ?>
    <section class="panel" aria-label="SpaceKeeper download statistics">
        <p>Download statistics are temporarily unavailable. Try again shortly.</p>
    </section>
<?php else: ?>
    <section class="cards" aria-label="SpaceKeeper download statistics">
        <div class="stat highlight"><strong><?= number_format($spaceKeeperStats['total']) ?></strong><span>Total Mac installer downloads</span></div>
        <div class="stat"><strong><?= isset($spaceKeeperStats['latest']) ? number_format($spaceKeeperStats['latest']['downloads']) : '—' ?></strong><span>Latest release downloads</span></div>
        <div class="stat"><strong><?= escapeHtml($spaceKeeperStats['latest']['tag'] ?? '—') ?></strong><span>Latest release</span></div>
    </section>
    <p class="subtle">
        DMG downloads across published releases, including repeat downloads and app updates. Not unique users.
        <?= $spaceKeeper['stale'] ? 'GitHub is temporarily unavailable. Last successful update:' : 'Last updated:' ?>
        <?= escapeHtml(gmdate('Y-m-d H:i', $spaceKeeper['updated_at'])) ?> UTC.
    </p>
<?php endif; ?>
