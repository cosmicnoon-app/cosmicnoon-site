<?php
declare(strict_types=1);
if (($_SESSION['admin_authenticated'] ?? false) !== true || !isset($backendRoot)) {
    http_response_code(404); exit;
}
$usageEnvironment = ($_GET['usage_environment'] ?? '') === 'test' ? 'test' : 'production';
$usagePeriod = in_array($_GET['usage_period'] ?? '', ['today', '7d', '30d'], true) ? $_GET['usage_period'] : '7d';
$usageCohort = ($_GET['usage_cohort'] ?? '') === 'active' ? 'active' : 'new';
$usagePage = max(1, min(10000, (int)($_GET['usage_page'] ?? 1)));
$journeyPage = max(1, min(10000, (int)($_GET['journey_page'] ?? 1)));
$usageInstallation = is_string($_GET['installation'] ?? null) ? $_GET['installation'] : '';
$usageNow = new DateTimeImmutable('now', new DateTimeZone('UTC'));
$usageStart = $usageNow->modify(match ($usagePeriod) { 'today' => '0 days', '30d' => '-29 days', default => '-6 days' })->format('Y-m-d');
$usageEnd = $usageNow->format('Y-m-d');
$usageError = false; $usageSettings = []; $usageReport = []; $usageJourney = [];
try {
    require_once ADMIN_PRIVATE_ROOT . '/usage-backend/src/UsageStatistics.php';
    $usageSettings = require ADMIN_PRIVATE_ROOT . '/usage-backend/config.php';
    $usageStore = new \INoon\Usage\UsageStore($database);
    $usageReport = $usageStore->report($usageEnvironment, $usageStart, $usageEnd, $usageCohort, $usagePage);
    if ($usageInstallation !== '') $usageJourney = $usageStore->journey($usageEnvironment, $usageInstallation, $journeyPage);
} catch (Throwable) { $usageError = true; }
function usageLabel(string $value): string { return ucwords(str_replace('_', ' ', $value)); }
function usageLink(array $changes): string {
    global $usageEnvironment, $usagePeriod, $usageCohort;
    return '?' . http_build_query(array_merge(['tab' => 'usage', 'usage_environment' => $usageEnvironment,
        'usage_period' => $usagePeriod, 'usage_cohort' => $usageCohort], $changes));
}
function usageTime(int $timestamp): string { return gmdate('d M Y H:i:s', $timestamp); }
?>
<style>.usage-sections{display:grid;gap:20px}.usage-sections .filters{grid-template-columns:repeat(3,minmax(0,1fr)) auto}@media(max-width:650px){.usage-sections .filters{grid-template-columns:1fr}}</style>
<section class="hero"><div><h2>iNoon App Usage</h2><p>Installation journeys · <?= escapeHtml($usageStart) ?> to <?= escapeHtml($usageEnd) ?> · UTC</p></div></section>
<div class="usage-sections">
<section class="panel">
<form method="get" class="filters">
<input type="hidden" name="tab" value="usage">
<label>Period<select name="usage_period"><?php foreach (['today'=>'Today','7d'=>'Last 7 days','30d'=>'Last 30 days'] as $key=>$label): ?>
<option value="<?= escapeHtml($key) ?>" <?= $usagePeriod===$key?'selected':'' ?>><?= escapeHtml($label) ?></option><?php endforeach; ?></select></label>
<label>Traffic<select name="usage_environment"><option value="production" <?= $usageEnvironment==='production'?'selected':'' ?>>Production</option><option value="test" <?= $usageEnvironment==='test'?'selected':'' ?>>Development tests</option></select></label>
<label>Population<select name="usage_cohort"><option value="new" <?= $usageCohort==='new'?'selected':'' ?>>First observed in period</option><option value="active" <?= $usageCohort==='active'?'selected':'' ?>>All active installations</option></select></label>
<button class="button" type="submit">Show statistics</button></form>
<?php if ($usageEnvironment==='test'): ?><p class="message">Development test activity only. Never included in production.</p><?php endif; ?>
<?php if ($usageError): ?><p role="alert">Usage storage is unavailable. This does not mean zero activity.</p>
<?php elseif (($usageSettings['production_enabled']??false)!==true): ?><p role="alert">Production collection is disabled.</p><?php endif; ?>
<p class="subtle">Each installation counts once per milestone, regardless of repeat activity. Random installation IDs link launches, not people or accounts. First observed is not necessarily a new download; upgrades and reinstalls can start a new journey. No device identifiers or personal content are collected. Events are retained for 90 days.</p>
<p class="subtle">Journeys require the updated desktop collector. Previous aggregate statistics were reset and cannot be reconstructed into journeys.</p>
</section>
<?php if (!$usageError): $denominator=(int)$usageReport['summary']['installations']; ?>
<section class="panel"><h3><?= number_format($denominator) ?> <?= $denominator===1?'installation':'installations' ?> · <?= number_format((int)$usageReport['summary']['sessions']) ?> <?= (int)$usageReport['summary']['sessions']===1?'session':'sessions' ?></h3>
<p><?= $usageCohort==='new'?'Only installations first observed within the selected period.':'All installations with activity in the selected period, including returning installations.' ?> <?= number_format((int)$usageReport['summary']['actions']) ?> events received. Downloads alone do not populate this view.</p></section>
<?php if ($usageInstallation!==''): ?>
<section class="panel"><h3>Installation journey · <?= escapeHtml(substr($usageInstallation,0,8)) ?></h3>
<a class="button" href="<?= escapeHtml(usageLink([])) ?>">Back to installations</a>
<?php if (!$usageJourney['header']): ?><p>No retained journey for this installation.</p><?php else: ?>
<p>First observed <?= escapeHtml(usageTime((int)$usageJourney['header']['started_at'])) ?> UTC · <?= $usageJourney['header']['platform']==='macos'?'Mac':'Windows' ?> · <?= number_format($usageJourney['total']) ?> retained events across launches.</p>
<div class="table-wrap"><table><thead><tr><th>Sequence</th><th>Session</th><th>Occurred (UTC)</th><th>Event</th><th>Details</th><th>App / OS / licence</th></tr></thead><tbody>
<?php $previous=null; foreach ($usageJourney['events'] as $row):
    $sequence=(int)$row['event_sequence']; $dimensions=json_decode($row['dimensions_json'],true);
    if (($previous===null && $journeyPage===1 && $sequence>1) || ($previous!==null && $sequence>$previous+1)): ?>
<tr><td colspan="6">Some events are missing (offline expiry, queue limits or retention). Do not infer actions from this gap.</td></tr>
<?php endif; $previous=$sequence; ?>
<tr><td><?= $sequence ?></td><td><?= escapeHtml(substr($row['session_id'],0,8)) ?></td><td><?= escapeHtml(usageTime((int)$row['occurred_at'])) ?></td>
<td><?= escapeHtml(usageLabel($row['metric'])) ?></td><td><?php foreach ($dimensions as $key=>$value): ?><?= escapeHtml(usageLabel($key).': '.usageLabel($value)) ?><br><?php endforeach; ?></td>
<td><?= escapeHtml($row['app_version'].' / '.$row['os_major'].' / '.$row['license_state']) ?></td></tr>
<?php endforeach; ?></tbody></table></div>
<p class="subtle">Sequence is authoritative when offline batches arrive out of order. Timestamps come from the app clock. A session is a launch, not a person. No identity lookup is available.</p>
<?php if ($journeyPage>1): ?><a class="button" href="<?= escapeHtml(usageLink(['installation'=>$usageInstallation,'journey_page'=>$journeyPage-1])) ?>">Previous events</a><?php endif; ?>
<?php if ($journeyPage*100<$usageJourney['total']): ?><a class="button" href="<?= escapeHtml(usageLink(['installation'=>$usageInstallation,'journey_page'=>$journeyPage+1])) ?>">Next events</a><?php endif; ?>
<?php endif; ?></section><?php endif; ?>
<section class="panel"><h3>Ordered conversion path</h3>
<p class="subtle">Each step requires the preceding steps in this order, within the selected period, across any sessions. Paths that skip steps are still visible in independent milestone reach below. This reports licence activation, not confirmed sales.</p>
<div class="table-wrap"><table><thead><tr><th>Step</th><th>Mac</th><th>Windows</th><th>Installations</th><th>% of population</th><th>% of prior step</th></tr></thead><tbody>
<?php $prior=$denominator; foreach ($usageReport['funnel'] as $metric=>$platforms): $total=array_sum($platforms); ?>
<tr><td><?= escapeHtml(usageLabel($metric)) ?></td><td><?= $platforms['macos'] ?></td><td><?= $platforms['windows'] ?></td><td><?= $total ?></td><td><?= $denominator?round($total*100/$denominator,1).'%':'—' ?></td><td><?= $prior?round($total*100/$prior,1).'%':'—' ?></td></tr>
<?php $prior=$total; endforeach; ?></tbody></table></div></section>
<section class="panel"><h3>Independent milestone reach</h3><p class="subtle">Distinct installations reaching each event. Not a forced linear funnel. A heavy installation contributes only one here.</p>
<div class="table-wrap"><table><thead><tr><th>Milestone</th><th>Mac</th><th>Windows</th><th>Installations</th><th>% of population</th></tr></thead><tbody>
<?php foreach ($usageReport['reach'] as $metric=>$platforms): if (str_starts_with($metric,'session_')) continue; $total=array_sum($platforms); ?>
<tr><td><?= escapeHtml(usageLabel($metric)) ?></td><td><?= $platforms['macos']??0 ?></td><td><?= $platforms['windows']??0 ?></td><td><?= $total ?></td><td><?= $denominator?round($total*100/$denominator,1).'%':'—' ?></td></tr>
<?php endforeach; ?></tbody></table></div></section>
<section class="panel"><h3>Installations — open a journey</h3><div class="table-wrap"><table><thead><tr><th>Installation</th><th>Platform</th><th>First observed (UTC)</th><th>Last activity (UTC)</th><th>Sessions in period</th><th>Events in period</th></tr></thead><tbody>
<?php foreach ($usageReport['installations'] as $row): ?><tr><td><a href="<?= escapeHtml(usageLink(['installation'=>$row['installation_id']])) ?>"><?= escapeHtml(substr($row['installation_id'],0,8)) ?></a></td><td><?= $row['platform']==='macos'?'Mac':'Windows' ?></td><td><?= escapeHtml(usageTime((int)$row['started_at'])) ?></td><td><?= escapeHtml(usageTime((int)$row['last_active'])) ?></td><td><?= $row['sessions'] ?></td><td><?= $row['actions'] ?></td></tr><?php endforeach; ?>
<?php if (!$denominator): ?><tr><td colspan="6">No installation journeys received for this population.</td></tr><?php endif; ?></tbody></table></div>
<?php if ($usagePage>1): ?><a class="button" href="<?= escapeHtml(usageLink(['usage_page'=>$usagePage-1])) ?>">Previous installations</a><?php endif; ?>
<?php if ($usagePage*50<$denominator): ?><a class="button" href="<?= escapeHtml(usageLink(['usage_page'=>$usagePage+1])) ?>">Next installations</a><?php endif; ?></section>
<section class="panel"><h3>Failures, prerequisites and licence gates</h3><div class="table-wrap"><table><thead><tr><th>Event</th><th>Details</th><th>Affected installations</th><th>Total events</th></tr></thead><tbody>
<?php foreach ($usageReport['issues'] as $row): ?><tr><td><?= escapeHtml(usageLabel($row['metric'])) ?></td><td><?php foreach (json_decode($row['dimensions_json'],true) as $key=>$value): ?><?= escapeHtml(usageLabel($key).': '.usageLabel($value)) ?><br><?php endforeach; ?></td><td><?= $row['installations'] ?></td><td><?= $row['actions'] ?></td></tr><?php endforeach; ?></tbody></table></div></section>
<section class="panel"><h3>Platform and version reach</h3><div class="table-wrap"><table><thead><tr><th>Platform</th><th>App</th><th>OS major</th><th>Installations</th></tr></thead><tbody>
<?php foreach ($usageReport['versions'] as $row): ?><tr><td><?= $row['platform']==='macos'?'Mac':'Windows' ?></td><td><?= escapeHtml($row['app_version']) ?></td><td><?= $row['os_major'] ?></td><td><?= $row['installations'] ?></td></tr><?php endforeach; ?></tbody></table></div><p class="subtle">An installation can appear in multiple version groups after an update.</p></section>
<section class="panel"><h3>Repeat activity — event volume, not conversion</h3><div class="table-wrap"><table><thead><tr><th>Event</th><th>Mac events</th><th>Windows events</th></tr></thead><tbody>
<?php foreach ($usageReport['volume'] as $metric=>$platforms): ?><tr><td><?= escapeHtml(usageLabel($metric)) ?></td><td><?= $platforms['macos']??0 ?></td><td><?= $platforms['windows']??0 ?></td></tr><?php endforeach; ?></tbody></table></div></section>
<?php endif; ?></div>
