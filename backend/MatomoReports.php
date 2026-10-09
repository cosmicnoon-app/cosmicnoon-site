<?php

declare(strict_types=1);

namespace CosmicNoon\Analytics;

final class MatomoReports
{
    public static function load(string $root, string $cacheDirectory, string $selection): array
    {
        $perth = new \DateTimeImmutable('now', new \DateTimeZone('Australia/Perth'));
        $periods = [
            'today' => ['day', 'today'],
            'month' => ['month', 'today'],
            'last-month' => ['month', $perth->modify('first day of last month')->format('Y-m-d')],
        ];
        $selection = isset($periods[$selection]) ? $selection : 'month';
        [$period, $date] = $periods[$selection];
        $cacheFile = $cacheDirectory . '/websites-' . $selection . '-' . $perth->format('Y-m-d') . '.json';
        $cached = is_file($cacheFile) ? json_decode((string)file_get_contents($cacheFile), true) : null;
        if (is_array($cached) && ($cached['updated_at'] ?? 0) > time() - 60) {
            return $cached;
        }

        $timezone = date_default_timezone_get();
        $initialized = false;
        $access = null;
        try {
            if (!defined('PIWIK_DOCUMENT_ROOT')) {
                define('PIWIK_DOCUMENT_ROOT', $root);
                define('PIWIK_INCLUDE_PATH', $root);
                define('PIWIK_ENABLE_ERROR_HANDLER', false);
                define('PIWIK_ENABLE_DISPATCH', false);
                define('PIWIK_ENABLE_SESSION_START', false);
                require_once $root . '/core/bootstrap.php';
            }
            $environment = new \Piwik\Application\Environment('cli');
            $environment->init();
            $initialized = true;
            \Piwik\Plugin\Manager::getInstance()->loadActivatedPlugins();
            // This helper runs only after the Cosmic Noon admin has authenticated.
            // No HTTP API token or caller-supplied API method is accepted.
            $access = \Piwik\Access::getInstance();
            $access->setSuperUserAccess(true);
            $sites = [];
            foreach ([1, 2] as $id) {
                $encoded = \Piwik\API\Request::processRequest('API.get', [
                    'idSite' => $id,
                    'period' => $period,
                    'date' => $date,
                    'columns' => 'nb_uniq_visitors,nb_pageviews',
                    'format' => 'json',
                ], []);
                $report = json_decode($encoded, true, 32, JSON_THROW_ON_ERROR);
                if (!is_array($report) || !isset($report['nb_uniq_visitors'], $report['nb_pageviews'])) {
                    throw new \RuntimeException('Matomo report unavailable.');
                }
                $sites[$id] = [
                    'visitors' => max(0, (int)$report['nb_uniq_visitors']),
                    'pageviews' => max(0, (int)$report['nb_pageviews']),
                ];
            }
            $result = ['sites' => $sites, 'updated_at' => time(), 'stale' => false];
            if (!is_dir($cacheDirectory)) {
                mkdir($cacheDirectory, 0700, true);
            }
            $temporary = tempnam($cacheDirectory, 'reports-');
            if ($temporary !== false) {
                chmod($temporary, 0600);
                file_put_contents($temporary, json_encode($result, JSON_THROW_ON_ERROR), LOCK_EX);
                rename($temporary, $cacheFile);
            }
            return $result;
        } catch (\Throwable $error) {
            error_log('Cosmic Noon website analytics unavailable: ' . get_class($error));
            if (is_array($cached) && ($cached['updated_at'] ?? 0) > time() - 1800) {
                $cached['stale'] = true;
                return $cached;
            }
            return ['sites' => [], 'updated_at' => null, 'stale' => false];
        } finally {
            if ($access !== null) {
                $access->setSuperUserAccess(false);
            }
            if ($initialized) {
                $environment->destroy();
            }
            date_default_timezone_set($timezone);
        }
    }
}
