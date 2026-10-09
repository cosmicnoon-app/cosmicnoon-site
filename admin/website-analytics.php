<?php

declare(strict_types=1);

if (($_SESSION['admin_authenticated'] ?? false) !== true || !isset($backendRoot)) {
    http_response_code(404);
    exit;
}
require_once dirname(__DIR__, 2) . '/private/MatomoReports.php';
$periodLabels = ['today' => 'Today', 'month' => 'This month', 'last-month' => 'Last month'];
$analyticsPeriod = is_string($_GET['period'] ?? null) && isset($periodLabels[$_GET['period']])
    ? $_GET['period'] : 'month';
$analytics = \CosmicNoon\Analytics\MatomoReports::load(
    $adminRuntime['matomo_root'],
    dirname(__DIR__, 2) . '/private/analytics-cache',
    $analyticsPeriod
);
?>
<section class="hero">
    <div>
        <h2>Website overview</h2>
        <p><?= escapeHtml($periodLabels[$analyticsPeriod]) ?> · Perth time</p>
    </div>
    <div class="analytics-periods" aria-label="Analytics period">
        <?php foreach ($periodLabels as $key => $label): ?>
            <a href="?tab=dashboard&amp;period=<?= escapeHtml($key) ?>" class="<?= $analyticsPeriod === $key ? 'active' : '' ?>" <?= $analyticsPeriod === $key ? 'aria-current="true"' : '' ?>><?= escapeHtml($label) ?></a>
        <?php endforeach; ?>
    </div>
</section>
<div class="website-grid">
    <?php foreach ([1 => ['iNoon', 'inoon.app', 'inoon'], 2 => ['Gelato Maestro', 'gelato-maestro.com', 'gelato']] as $id => [$name, $host, $class]):
        $metrics = $analytics['sites'][$id] ?? null;
    ?>
        <section class="panel website-panel <?= escapeHtml($class) ?>" aria-label="<?= escapeHtml($name) ?> website statistics">
            <h3><?= escapeHtml($name) ?></h3>
            <a class="site-url" href="https://<?= escapeHtml($host) ?>/" target="_blank" rel="noopener noreferrer"><?= escapeHtml($host) ?> ↗</a>
            <div class="website-metrics">
                <div><strong><?= $metrics === null ? '—' : number_format($metrics['visitors']) ?></strong><span>Unique visitors</span></div>
                <div><strong><?= $metrics === null ? '—' : number_format($metrics['pageviews']) ?></strong><span>Page views</span></div>
            </div>
            <?php if ($metrics === null): ?><p class="subtle">Analytics temporarily unavailable.</p><?php endif; ?>
        </section>
    <?php endforeach; ?>
</div>
<p class="subtle">Matomo · <?= $analytics['stale'] ? 'Showing the last available report.' : 'Reports refresh hourly.' ?></p>
