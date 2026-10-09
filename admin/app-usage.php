<?php

declare(strict_types=1);

if (($_SESSION['admin_authenticated'] ?? false) !== true || !isset($backendRoot)) {
    http_response_code(404);
    exit;
}

$usageEnvironment = ($_GET['usage_environment'] ?? '') === 'test' ? 'test' : 'production';
$usagePeriod = in_array($_GET['usage_period'] ?? '', ['today', '7d', '30d'], true)
    ? $_GET['usage_period'] : '7d';
$usageNow = new DateTimeImmutable('now', new DateTimeZone('UTC'));
$usageStart = $usageNow->modify(match ($usagePeriod) { 'today' => '0 days', '30d' => '-29 days', default => '-6 days' })->format('Y-m-d');
$usageEnd = $usageNow->format('Y-m-d');
$usageError = false;
$usageSettings = [];
$usageReport = ['totals' => [], 'issues' => [], 'versions' => [], 'operations' => []];
try {
    require_once ADMIN_PRIVATE_ROOT . '/usage-backend/src/UsageStatistics.php';
    $usageSettings = require ADMIN_PRIVATE_ROOT . '/usage-backend/config.php';
    $usageReport = (new \INoon\Usage\UsageStore($database))->report($usageEnvironment, $usageStart, $usageEnd);
} catch (Throwable) {
    // Do not disclose database configuration or request/error text in the dashboard or logs.
    $usageError = true;
}

function usageLabel(string $value): string
{
    return ucwords(str_replace('_', ' ', $value));
}

function usageNumber(int $value, string $environment): string
{
    // Small non-zero production counts are not exposed as exact values.
    return $environment === 'production' && $value > 0 && $value < 5 ? '<5' : number_format($value);
}

$usageMetrics = [
    'first_launch' => 'First launches', 'repeat_launch' => 'Subsequent launches',
    'app_ready' => 'App ready', 'startup_failed' => 'Startup failures',
    'device_detected' => 'Device detections', 'connection_started' => 'Connection attempts',
    'connection_succeeded' => 'Successful connections', 'connection_failed' => 'Connection failures',
    'connection_action_required' => 'Unlock / trust / pairing required',
    'device_disconnected' => 'Disconnections', 'feature_opened' => 'Features opened',
    'data_load_succeeded' => 'Data loads completed', 'data_load_failed' => 'Data loads failed',
    'operation_requested' => 'Operations requested', 'operation_blocked' => 'Operations blocked',
    'operation_started' => 'Operations started', 'operation_succeeded' => 'Operations succeeded',
    'operation_failed' => 'Operations failed', 'operation_cancelled' => 'Operations cancelled',
    'free_backup_completed' => 'First free backups completed',
    'license_gate_shown' => 'Licence gates shown', 'license_gate_dismissed' => 'Licence gates dismissed',
    'purchase_clicked' => 'Purchase clicks', 'purchase_link_opened' => 'Purchase links opened',
    'purchase_link_failed' => 'Purchase links failed', 'license_activation_started' => 'Activation attempts',
    'license_activation_succeeded' => 'Activations succeeded', 'license_activation_failed' => 'Activations failed',
];
?>
<style>
    .usage-sections { display: grid; gap: 20px; }
    .usage-sections .filters { grid-template-columns: minmax(0, 1fr) minmax(0, 1fr) auto; }
    @media (max-width: 650px) { .usage-sections .filters { grid-template-columns: 1fr; } }
</style>
<section class="hero">
    <div><h2>iNoon App Usage</h2><p>Aggregate statistics · <?= escapeHtml($usageStart) ?> to <?= escapeHtml($usageEnd) ?> · UTC</p></div>
</section>
<div class="usage-sections">
<section class="panel">
    <form method="get" class="filters">
        <input type="hidden" name="tab" value="usage">
        <label>Period <select name="usage_period">
            <?php foreach (['today' => 'Today', '7d' => 'Last 7 days', '30d' => 'Last 30 days'] as $key => $label): ?>
                <option value="<?= escapeHtml($key) ?>" <?= $usagePeriod === $key ? 'selected' : '' ?>><?= escapeHtml($label) ?></option>
            <?php endforeach; ?>
        </select></label>
        <label>Traffic <select name="usage_environment">
            <option value="production" <?= $usageEnvironment === 'production' ? 'selected' : '' ?>>Production</option>
            <option value="test" <?= $usageEnvironment === 'test' ? 'selected' : '' ?>>Synthetic tests only</option>
        </select></label>
        <button class="button" type="submit">Show statistics</button>
    </form>
    <?php if ($usageEnvironment === 'test'): ?><p class="message">Synthetic test data — not customer activity. Excluded from production statistics.</p><?php endif; ?>
    <?php if ($usageError): ?>
        <p role="alert">App usage storage is unavailable. No statistics are shown; this does not mean zero activity.</p>
    <?php elseif (($usageSettings['production_enabled'] ?? false) !== true): ?>
        <p class="subtle">Production collection is not enabled. The receiver is available for authorised synthetic tests. The desktop apps have not been instrumented yet.</p>
    <?php endif; ?>
    <p class="subtle">Counts are actions, not unique people. No user, device, installation or session identifiers are stored. Production counts below five are grouped as &lt;5.</p>
</section>
<?php if (!$usageError): ?>
    <?php if ($usageReport['totals'] === []): ?><section class="panel"><p>No app statistics received for this period. Downloads alone do not populate this view.</p></section><?php endif; ?>
    <section class="panel">
        <h3>Launch → connection → operation → purchase</h3>
        <div class="table-wrap"><table>
            <thead><tr><th>Action</th><th>Mac</th><th>Windows</th><th>Total</th></tr></thead><tbody>
            <?php foreach ($usageMetrics as $metric => $label):
                $mac = $usageReport['totals'][$metric]['macos'] ?? 0;
                $windows = $usageReport['totals'][$metric]['windows'] ?? 0;
            ?>
                <tr><td><?= escapeHtml($label) ?></td><td><?= escapeHtml(usageNumber($mac, $usageEnvironment)) ?></td><td><?= escapeHtml(usageNumber($windows, $usageEnvironment)) ?></td><td><?= escapeHtml(usageNumber($mac + $windows, $usageEnvironment)) ?></td></tr>
            <?php endforeach; ?>
            </tbody></table></div>
        <p class="subtle">These action totals are not a person-level conversion funnel. Repeated attempts count separately; purchase clicks are not confirmed sales.</p>
    </section>
    <section class="panel">
        <h3>Operations, including backups</h3>
        <div class="table-wrap"><table><thead><tr><th>Operation</th><th>Requested</th><th>Blocked</th><th>Started</th><th>Succeeded</th><th>Failed</th><th>Cancelled</th></tr></thead><tbody>
            <?php foreach ($usageReport['operations'] as $operation => $counts): ?>
                <tr><td><?= escapeHtml(usageLabel($operation)) ?></td>
                    <?php foreach (['requested', 'blocked', 'started', 'succeeded', 'failed', 'cancelled'] as $outcome): ?>
                        <td><?= escapeHtml(usageNumber($counts['operation_' . $outcome] ?? 0, $usageEnvironment)) ?></td>
                    <?php endforeach; ?>
                </tr>
            <?php endforeach; ?>
            <?php if ($usageReport['operations'] === []): ?><tr><td colspan="7">No operation counters received.</td></tr><?php endif; ?>
        </tbody></table></div>
    </section>
    <section class="panel">
        <h3>Session milestones</h3>
        <div class="table-wrap"><table><thead><tr><th>Milestone</th><th>Sessions reporting it</th></tr></thead><tbody>
            <?php foreach (['session_ready', 'session_connected', 'session_feature_used', 'session_operation_attempted', 'session_operation_succeeded', 'session_gate_shown', 'session_purchase_clicked'] as $metric): ?>
                <tr><td><?= escapeHtml(usageLabel($metric)) ?></td><td><?= escapeHtml(usageNumber(array_sum($usageReport['totals'][$metric] ?? []), $usageEnvironment)) ?></td></tr>
            <?php endforeach; ?>
        </tbody></table></div>
        <p class="subtle">Clients count each milestone once per session. Milestones are not necessarily an ordered sequence and cannot link different sessions.</p>
    </section>
    <section class="panel">
        <h3>Failures, prerequisites and licence gates</h3>
        <div class="table-wrap"><table><thead><tr><th>Action</th><th>Operation</th><th>Reason / restriction</th><th>Count</th></tr></thead><tbody>
            <?php foreach ($usageReport['issues'] as $row): ?>
                <tr><td><?= escapeHtml(usageLabel($row['metric'])) ?></td><td><?= escapeHtml(usageLabel($row['operation'])) ?></td><td><?= escapeHtml(usageLabel($row['reason'] ?: $row['gate_kind'])) ?></td><td><?= escapeHtml(usageNumber((int)$row['total'], $usageEnvironment)) ?></td></tr>
            <?php endforeach; ?>
            <?php if ($usageReport['issues'] === []): ?><tr><td colspan="4">No failure or gate counters received.</td></tr><?php endif; ?>
        </tbody></table></div>
    </section>
    <section class="panel">
        <h3>Launches by platform and version</h3>
        <div class="table-wrap"><table><thead><tr><th>Platform</th><th>App version</th><th>OS major version</th><th>Launches</th></tr></thead><tbody>
            <?php foreach ($usageReport['versions'] as $row):
                if ($usageEnvironment === 'production' && (int)$row['total'] < 5) continue;
            ?>
                <tr><td><?= $row['platform'] === 'macos' ? 'Mac' : 'Windows' ?></td><td><?= escapeHtml($row['app_version']) ?></td><td><?= escapeHtml($row['os_major']) ?></td><td><?= escapeHtml(number_format((int)$row['total'])) ?></td></tr>
            <?php endforeach; ?>
        </tbody></table></div>
        <p class="subtle">Small production version groups are omitted. No hardware, location or customer breakdowns are available.</p>
    </section>
<?php endif; ?>
</div>
