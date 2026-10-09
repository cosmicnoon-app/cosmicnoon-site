<?php

declare(strict_types=1);

use INoon\Licensing\Config;
use INoon\Licensing\CustomerDeletion;
use INoon\Licensing\LicenseKey;
use INoon\Licensing\LicenseMailer;
use INoon\Licensing\Logger;
use INoon\Licensing\PromoCodes;
use INoon\Diagnostics\CrashReportStore;

// Keep credentials and operational data in their existing private location.
$adminRuntimeFile = dirname(__DIR__, 2) . '/private/admin-config.php';
$adminRuntime = is_file($adminRuntimeFile) ? require $adminRuntimeFile : [];
define('ADMIN_PRIVATE_ROOT', $adminRuntime['inoon_private_root'] ?? dirname(__DIR__, 2) . '/private');

const ADMIN_IP_ATTEMPTS_PER_WINDOW = 5;
const ADMIN_ACCOUNT_ATTEMPTS_PER_WINDOW = 20;
const ADMIN_LOGIN_WINDOW_SECONDS = 900;
const ADMIN_LOGIN_BLOCK_SECONDS = 900;
const ADMIN_IDLE_TIMEOUT_SECONDS = 1800;
const ADMIN_ABSOLUTE_TIMEOUT_SECONDS = 28800;
const ADMIN_SESSION_ROTATION_SECONDS = 900;

function adminAuthDirectory(): string
{
    return ADMIN_PRIVATE_ROOT . '/admin-auth';
}

function ensureAdminAuthDirectory(string $directory): void
{
    if (!is_dir($directory)
        && !mkdir($directory, 0700, true)
        && !is_dir($directory)
    ) {
        throw new RuntimeException('Could not create admin authentication storage.');
    }
    @chmod($directory, 0700);
}

function adminWritePrivateFile(string $path, string $contents): void
{
    $temporaryPath = $path . '.tmp-' . bin2hex(random_bytes(8));
    if (@file_put_contents($temporaryPath, $contents, LOCK_EX) === false) {
        throw new RuntimeException('Could not write admin authentication state.');
    }
    @chmod($temporaryPath, 0600);
    if (!@rename($temporaryPath, $path)) {
        @unlink($temporaryPath);
        throw new RuntimeException('Could not replace admin authentication state.');
    }
    @chmod($path, 0600);
}

function adminRateLimitKey(string $directory): string
{
    $path = $directory . '/rate-limit.key';
    $encoded = @file_get_contents($path);
    if (is_string($encoded)) {
        $key = base64_decode(trim($encoded), true);
        if (is_string($key) && strlen($key) === 32) {
            return $key;
        }
    }

    $key = random_bytes(32);
    adminWritePrivateFile($path, base64_encode($key) . PHP_EOL);
    return $key;
}

/**
 * @return array{window_started_at: int, attempts: int, blocked_until: int}
 */
function adminReadAttemptState(string $path, int $now): array
{
    $default = [
        'window_started_at' => $now,
        'attempts' => 0,
        'blocked_until' => 0,
    ];
    $encoded = @file_get_contents($path);
    if (!is_string($encoded) || $encoded === '') {
        return $default;
    }

    try {
        $state = json_decode($encoded, true, 8, JSON_THROW_ON_ERROR);
    } catch (JsonException) {
        return $default;
    }
    if (!is_array($state)) {
        return $default;
    }

    $windowStartedAt = filter_var(
        $state['window_started_at'] ?? null,
        FILTER_VALIDATE_INT
    );
    $attempts = filter_var(
        $state['attempts'] ?? null,
        FILTER_VALIDATE_INT
    );
    $blockedUntil = filter_var(
        $state['blocked_until'] ?? null,
        FILTER_VALIDATE_INT
    );
    if (!is_int($windowStartedAt)
        || !is_int($attempts)
        || !is_int($blockedUntil)
        || $windowStartedAt < 0
        || $attempts < 0
        || $blockedUntil < 0
    ) {
        return $default;
    }

    if ($now - $windowStartedAt >= ADMIN_LOGIN_WINDOW_SECONDS
        && $blockedUntil <= $now
    ) {
        return $default;
    }

    return [
        'window_started_at' => $windowStartedAt,
        'attempts' => $attempts,
        'blocked_until' => $blockedUntil,
    ];
}

/**
 * Atomically reserves one authentication attempt.
 *
 * @return int Number of seconds before another attempt is allowed, or zero.
 */
function adminConsumeLoginAttempt(string $username, string $ipAddress): int
{
    $directory = adminAuthDirectory();
    ensureAdminAuthDirectory($directory);
    $lockPath = $directory . '/attempts.lock';
    $lock = @fopen($lockPath, 'c+b');
    if ($lock === false) {
        throw new RuntimeException('Could not open admin authentication lock.');
    }
    @chmod($lockPath, 0600);

    try {
        if (!flock($lock, LOCK_EX)) {
            throw new RuntimeException('Could not lock admin authentication state.');
        }

        $now = time();
        $key = adminRateLimitKey($directory);
        if (random_int(1, 100) === 1) {
            $expiredBefore = $now - (ADMIN_LOGIN_WINDOW_SECONDS * 8);
            foreach (glob($directory . '/attempt-*.json') ?: [] as $path) {
                $modifiedAt = @filemtime($path);
                if (is_int($modifiedAt) && $modifiedAt < $expiredBefore) {
                    @unlink($path);
                }
            }
        }
        $identities = [
            [
                'value' => 'ip:' . $ipAddress,
                'maximum' => ADMIN_IP_ATTEMPTS_PER_WINDOW,
            ],
            [
                'value' => 'account:' . strtolower($username),
                'maximum' => ADMIN_ACCOUNT_ATTEMPTS_PER_WINDOW,
            ],
        ];
        $states = [];
        $retryAfter = 0;
        foreach ($identities as $identity) {
            $hash = hash_hmac('sha256', $identity['value'], $key);
            $path = $directory . '/attempt-' . $hash . '.json';
            $state = adminReadAttemptState($path, $now);
            $states[] = [
                'path' => $path,
                'maximum' => $identity['maximum'],
                'state' => $state,
            ];
            if ($state['blocked_until'] > $now) {
                $retryAfter = max(
                    $retryAfter,
                    $state['blocked_until'] - $now
                );
            }
        }

        if ($retryAfter > 0) {
            return $retryAfter;
        }

        foreach ($states as $entry) {
            $state = $entry['state'];
            $state['attempts']++;
            if ($state['attempts'] >= $entry['maximum']) {
                $state['blocked_until'] = $now + ADMIN_LOGIN_BLOCK_SECONDS;
            }
            adminWritePrivateFile(
                $entry['path'],
                json_encode(
                    $state,
                    JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
                ) . PHP_EOL
            );
        }

        return 0;
    } finally {
        flock($lock, LOCK_UN);
        fclose($lock);
    }
}

function adminClearLoginAttempts(string $username, string $ipAddress): void
{
    $directory = adminAuthDirectory();
    ensureAdminAuthDirectory($directory);
    $lockPath = $directory . '/attempts.lock';
    $lock = @fopen($lockPath, 'c+b');
    if ($lock === false) {
        throw new RuntimeException('Could not open admin authentication lock.');
    }
    @chmod($lockPath, 0600);

    try {
        if (!flock($lock, LOCK_EX)) {
            throw new RuntimeException('Could not lock admin authentication state.');
        }
        $key = adminRateLimitKey($directory);
        foreach ([
            'ip:' . $ipAddress,
            'account:' . strtolower($username),
        ] as $identity) {
            $hash = hash_hmac('sha256', $identity, $key);
            $path = $directory . '/attempt-' . $hash . '.json';
            if (is_file($path) && !@unlink($path)) {
                throw new RuntimeException(
                    'Could not clear admin authentication state.'
                );
            }
        }
    } finally {
        flock($lock, LOCK_UN);
        fclose($lock);
    }
}

function adminUpgradePasswordHash(
    string $passwordFile,
    string $username,
    string $password,
    string $storedHash
): void {
    $argonAvailable = in_array('argon2id', password_algos(), true);
    $algorithm = $argonAvailable ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT;
    $options = $argonAvailable
        ? [
            'memory_cost' => 65536,
            'time_cost' => 4,
            'threads' => 2,
        ]
        : ['cost' => 12];
    if (!password_needs_rehash($storedHash, $algorithm, $options)) {
        return;
    }

    $newHash = password_hash($password, $algorithm, $options);
    if (!is_string($newHash)) {
        throw new RuntimeException('Could not upgrade admin password hash.');
    }
    adminWritePrivateFile(
        $passwordFile,
        $username . ':' . $newHash . PHP_EOL
    );
}

function adminEndSession(): void
{
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $parameters = session_get_cookie_params();
        setcookie(session_name(), '', [
            'expires' => time() - 42000,
            'path' => $parameters['path'],
            'domain' => $parameters['domain'],
            'secure' => $parameters['secure'],
            'httponly' => $parameters['httponly'],
            'samesite' => $parameters['samesite'] ?? 'Strict',
        ]);
    }
    session_destroy();
}

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('X-Robots-Tag: noindex, nofollow, noarchive');

session_name('cosmicnoon_admin');
ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/admin/',
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Strict',
]);
session_start();

$adminPasswordFile = ADMIN_PRIVATE_ROOT . '/admin.htpasswd';
$loginError = null;
$loginStatus = 200;
$now = time();
if (($_SESSION['admin_authenticated'] ?? false) === true) {
    $authenticatedAt = is_int($_SESSION['admin_authenticated_at'] ?? null)
        ? $_SESSION['admin_authenticated_at']
        : 0;
    $lastActivityAt = is_int($_SESSION['admin_last_activity_at'] ?? null)
        ? $_SESSION['admin_last_activity_at']
        : 0;
    if ($authenticatedAt <= 0
        || $lastActivityAt <= 0
        || $now - $lastActivityAt > ADMIN_IDLE_TIMEOUT_SECONDS
        || $now - $authenticatedAt > ADMIN_ABSOLUTE_TIMEOUT_SECONDS
    ) {
        unset(
            $_SESSION['admin_authenticated'],
            $_SESSION['admin_authenticated_at'],
            $_SESSION['admin_last_activity_at'],
            $_SESSION['admin_last_regenerated_at'],
            $_SESSION['csrf_token']
        );
        session_regenerate_id(true);
    } else {
        $lastRegeneratedAt = is_int(
            $_SESSION['admin_last_regenerated_at'] ?? null
        ) ? $_SESSION['admin_last_regenerated_at'] : 0;
        if ($now - $lastRegeneratedAt >= ADMIN_SESSION_ROTATION_SECONDS) {
            session_regenerate_id(true);
            $_SESSION['admin_last_regenerated_at'] = $now;
        }
        $_SESSION['admin_last_activity_at'] = $now;
    }
}
if (!is_string($_SESSION['admin_login_token'] ?? null)) {
    $_SESSION['admin_login_token'] = bin2hex(random_bytes(32));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST'
    && ($_POST['admin_action'] ?? '') === 'login'
) {
    $postedLoginToken = is_string($_POST['login_token'] ?? null)
        ? $_POST['login_token']
        : '';
    $username = trim(
        is_string($_POST['username'] ?? null) ? $_POST['username'] : ''
    );
    $password = is_string($_POST['password'] ?? null)
        ? $_POST['password']
        : '';
    $credentials = is_readable($adminPasswordFile)
        ? trim((string)file_get_contents($adminPasswordFile))
        : '';
    [$storedUsername, $storedHash] = array_pad(
        explode(':', $credentials, 2),
        2,
        ''
    );

    $validToken = hash_equals(
        (string)$_SESSION['admin_login_token'],
        $postedLoginToken
    );
    $validUsername = $storedUsername !== ''
        && hash_equals($storedUsername, $username);
    $validPassword = false;
    $remoteAddress = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    if (!is_string($remoteAddress)
        || filter_var($remoteAddress, FILTER_VALIDATE_IP) === false
    ) {
        $remoteAddress = 'unknown';
    }
    $retryAfter = 0;
    if ($validToken) {
        try {
            $retryAfter = adminConsumeLoginAttempt(
                $storedUsername !== '' ? $storedUsername : 'admin',
                $remoteAddress
            );
        } catch (Throwable) {
            error_log('iNoon admin authentication throttling is unavailable.');
            $loginStatus = 503;
            $loginError = 'Secure sign-in is temporarily unavailable. Please try again shortly.';
        }
    }
    if ($loginStatus === 200 && $retryAfter === 0 && $storedHash !== '') {
        $validPassword = password_verify($password, $storedHash);
    }

    if ($loginStatus === 200
        && $retryAfter === 0
        && $validToken
        && $validUsername
        && $validPassword
    ) {
        try {
            adminClearLoginAttempts($storedUsername, $remoteAddress);
            adminUpgradePasswordHash(
                $adminPasswordFile,
                $storedUsername,
                $password,
                $storedHash
            );
        } catch (Throwable) {
            error_log('iNoon admin could not finalize authentication security state.');
            $loginStatus = 503;
            $loginError = 'Secure sign-in is temporarily unavailable. Please try again shortly.';
        }
    }

    if ($loginStatus === 200
        && $retryAfter === 0
        && $validToken
        && $validUsername
        && $validPassword
    ) {
        session_regenerate_id(true);
        $_SESSION['admin_authenticated'] = true;
        $_SESSION['admin_authenticated_at'] = $now;
        $_SESSION['admin_last_activity_at'] = $now;
        $_SESSION['admin_last_regenerated_at'] = $now;
        $_SESSION['admin_login_token'] = bin2hex(random_bytes(32));
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        header('Location: /admin/', true, 303);
        exit;
    }

    usleep(350000);
    if ($retryAfter > 0) {
        $loginStatus = 429;
        header('Retry-After: ' . $retryAfter);
        $minutes = max(1, (int)ceil($retryAfter / 60));
        $loginError = "Too many sign-in attempts. Please wait {$minutes} minute"
            . ($minutes === 1 ? '' : 's')
            . ' and try again.';
    } elseif ($loginError === null) {
        $loginError = 'Those details did not match. Please try again.';
    }
}

if (($_SESSION['admin_authenticated'] ?? false) !== true) {
    http_response_code($loginStatus);
    $loginToken = htmlspecialchars(
        (string)$_SESSION['admin_login_token'],
        ENT_QUOTES | ENT_SUBSTITUTE,
        'UTF-8'
    );
    $errorMarkup = $loginError === null
        ? ''
        : '<div class="error" role="alert">'
            . htmlspecialchars(
                $loginError,
                ENT_QUOTES | ENT_SUBSTITUTE,
                'UTF-8'
            )
            . '</div>';
    $loginPage = <<<'HTML'
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex,nofollow,noarchive">
    <title>Sign in · Cosmic Noon Admin</title>
    <style>
        :root {
            color-scheme: light dark;
            --login-ink: #172033;
            --login-muted: #68748a;
            --login-page: #f5f8ff;
            --login-card: rgba(255, 255, 255, .9);
            --login-line: rgba(198, 213, 238, .86);
            --login-field: #fff;
            --login-error-ink: #9f2338;
            --login-error-line: #f0bac3;
            --login-error-surface: #fff1f3;
        }
        * { box-sizing: border-box; }
        body {
            margin: 0;
            min-height: 100vh;
            display: grid;
            place-items: center;
            padding: 24px;
            color: var(--login-ink);
            background:
                radial-gradient(circle at 12% 4%, rgba(42, 122, 255, .22), transparent 31rem),
                radial-gradient(circle at 88% 22%, rgba(203, 72, 226, .2), transparent 29rem),
                var(--login-page);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        }
        .card {
            width: min(440px, 100%);
            padding: 36px;
            border: 1px solid var(--login-line);
            border-radius: 26px;
            background: var(--login-card);
            box-shadow: 0 28px 80px rgba(39, 65, 110, .17);
            backdrop-filter: blur(24px);
        }
        .mark {
            display: grid;
            place-items: center;
            width: 58px;
            height: 58px;
            margin-bottom: 22px;
            color: #fff;
            font-size: 23px;
            font-weight: 850;
            letter-spacing: -.06em;
            border-radius: 18px;
            background: linear-gradient(135deg, #2173f5, #a04fe8);
            box-shadow: 0 14px 32px rgba(73, 91, 224, .28);
        }
        h1 { margin: 0; font-size: 30px; letter-spacing: -.045em; }
        p { margin: 8px 0 25px; color: var(--login-muted); }
        label {
            display: block;
            margin: 15px 0 7px;
            font-size: 13px;
            font-weight: 800;
        }
        input {
            width: 100%;
            padding: 13px 14px;
            border: 1px solid var(--login-line);
            border-radius: 12px;
            background: var(--login-field);
            color: var(--login-ink);
            font: inherit;
            outline: none;
        }
        input:focus {
            border-color: #4387f5;
            box-shadow: 0 0 0 4px rgba(33, 115, 245, .12);
        }
        button {
            width: 100%;
            margin-top: 22px;
            padding: 13px 16px;
            border: 0;
            border-radius: 13px;
            color: #fff;
            background: linear-gradient(135deg, #2173f5, #8b50e9);
            box-shadow: 0 13px 28px rgba(54, 90, 221, .24);
            font: inherit;
            font-weight: 820;
            cursor: pointer;
        }
        .error {
            margin-bottom: 17px;
            padding: 11px 13px;
            border: 1px solid var(--login-error-line);
            border-radius: 11px;
            color: var(--login-error-ink);
            background: var(--login-error-surface);
            font-size: 13px;
            font-weight: 700;
        }
        .privacy {
            margin: 18px 0 0;
            font-size: 12px;
            text-align: center;
        }
        @media (prefers-color-scheme: dark) {
            :root {
                --login-ink: #f4f7ff;
                --login-muted: #aab6ca;
                --login-page: #0c1220;
                --login-card: rgba(24, 31, 46, .92);
                --login-line: rgba(128, 151, 190, .3);
                --login-field: rgba(10, 16, 29, .82);
                --login-error-ink: #ffb4c0;
                --login-error-line: rgba(255, 117, 139, .48);
                --login-error-surface: rgba(111, 27, 43, .36);
            }
            body {
                background:
                    radial-gradient(circle at 12% 4%, rgba(42, 122, 255, .24), transparent 31rem),
                    radial-gradient(circle at 88% 22%, rgba(203, 72, 226, .2), transparent 29rem),
                    var(--login-page);
            }
            .card { box-shadow: 0 30px 90px rgba(0, 0, 0, .42); }
            input:focus { box-shadow: 0 0 0 4px rgba(72, 143, 255, .2); }
        }
    </style>
</head>
<body>
    <main class="card">
        <div class="mark">CN</div>
        <h1>Cosmic Noon Admin</h1>
        <p>Sign in to view website activity and manage iNoon.</p>
        {{ERROR}}
        <form method="post" action="/admin/" autocomplete="on">
            <input type="hidden" name="admin_action" value="login">
            <input type="hidden" name="login_token" value="{{TOKEN}}">
            <label for="username">Username</label>
            <input id="username" name="username" type="text" autocomplete="username" required autofocus>
            <label for="password">Password</label>
            <input id="password" name="password" type="password" autocomplete="current-password" required>
            <button type="submit">Sign in securely</button>
        </form>
        <p class="privacy">Private access · Cosmic Noon</p>
    </main>
</body>
</html>
HTML;
    echo str_replace(
        ['{{ERROR}}', '{{TOKEN}}'],
        [$errorMarkup, $loginToken],
        $loginPage
    );
    exit;
}

if (!is_string($_SESSION['csrf_token'] ?? null)) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrfToken = (string)$_SESSION['csrf_token'];

if ($_SERVER['REQUEST_METHOD'] === 'POST'
    && ($_POST['admin_action'] ?? '') === 'logout'
) {
    $postedToken = is_string($_POST['csrf_token'] ?? null)
        ? $_POST['csrf_token']
        : '';
    if (!hash_equals($csrfToken, $postedToken)) {
        http_response_code(400);
        exit('Invalid request.');
    }
    adminEndSession();
    header('Location: /admin/', true, 303);
    exit;
}

$backendRoot = ADMIN_PRIVATE_ROOT . '/license-backend';
require_once $backendRoot . '/src/LicenseBackend.php';
require_once $backendRoot . '/src/CrashReportStore.php';
require_once $backendRoot . '/vendor/autoload.php';
require_once $backendRoot . '/src/LicenseEmail.php';
require_once $backendRoot . '/src/PromoCodes.php';
require_once $backendRoot . '/src/CustomerDeletion.php';

$config = Config::load($backendRoot . '/config.php');
$logger = new Logger($config->string('logging.path'));
$database = new PDO(
    $config->string('database.dsn'),
    $config->string('database.username'),
    $config->string('database.password'),
    [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]
);
$database->exec("SET time_zone = '+00:00'");
$promoCodes = new PromoCodes($database, $logger);
$customerDeletion = new CustomerDeletion($database, $logger);
$database->exec('SET NAMES utf8mb4');
$crashReportStore = new CrashReportStore($database);

$flash = is_array($_SESSION['flash'] ?? null) ? $_SESSION['flash'] : null;
unset($_SESSION['flash']);

$allowedTabs = ['dashboard', 'usage', 'licenses', 'crashes', 'promos', 'add'];
$tab = is_string($_GET['tab'] ?? null) ? $_GET['tab'] : 'dashboard';
if (!in_array($tab, $allowedTabs, true)) {
    $tab = 'dashboard';
}

function escapeHtml(mixed $value): string
{
    return htmlspecialchars(
        is_scalar($value) ? (string)$value : '',
        ENT_QUOTES | ENT_SUBSTITUTE,
        'UTF-8'
    );
}

function redirectTo(string $location): never
{
    header('Location: ' . $location, true, 303);
    exit;
}

function manualIdentifier(string $kind): string
{
    return 'manual_' . $kind . '_' . bin2hex(random_bytes(12));
}

function issueManualLicense(
    PDO $database,
    Config $config,
    Logger $logger,
    string $name,
    string $email,
    int $seatCount,
    bool $sendEmail
): array {
    $licenseKey = LicenseKey::generate($config->string('license.prefix'));
    $customerIdentifier = manualIdentifier('ctm');
    $transactionIdentifier = manualIdentifier('txn');
    $licenseId = 0;

    try {
        $database->beginTransaction();

        $customer = $database->prepare(
            'INSERT INTO customers
                (paddle_customer_id, email, name, marketing_consent,
                 created_at, updated_at)
             VALUES
                (:customer_id, :email, :name, 1,
                 UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))'
        );
        $customer->execute([
            ':customer_id' => $customerIdentifier,
            ':email' => $email,
            ':name' => $name,
        ]);
        $customerId = (int)$database->lastInsertId();

        $purchase = $database->prepare(
            'INSERT INTO purchases
                (customer_id, paddle_transaction_id, paddle_price_id,
                 paddle_product_id, eligible_item_ids, seat_count,
                 status, source_type, purchased_at, created_at, updated_at)
             VALUES
                (:customer_id, :transaction_id, :price_id,
                 :product_id, :eligible_items, :seat_count,
                 :status, :source_type, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))'
        );
        $purchase->execute([
            ':customer_id' => $customerId,
            ':transaction_id' => $transactionIdentifier,
            ':price_id' => 'manual_admin',
            ':product_id' => 'manual_admin',
            ':eligible_items' => '["manual_admin"]',
            ':seat_count' => $seatCount,
            ':status' => 'completed',
            ':source_type' => 'manual',
        ]);
        $purchaseId = (int)$database->lastInsertId();

        $license = $database->prepare(
            'INSERT INTO licenses
                (purchase_id, license_key_hash, license_key_ciphertext,
                 license_key_hint, status, delivery_status, issued_at,
                 created_at, updated_at)
             VALUES
                (:purchase_id, :license_key_hash, :license_key_ciphertext,
                 :license_key_hint, :status, :delivery_status, UTC_TIMESTAMP(6),
                 UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))'
        );
        $license->bindValue(':purchase_id', $purchaseId, PDO::PARAM_INT);
        $license->bindValue(
            ':license_key_hash',
            LicenseKey::hash($licenseKey),
            PDO::PARAM_LOB
        );
        $license->bindValue(
            ':license_key_ciphertext',
            LicenseKey::encrypt(
                $licenseKey,
                $config->string('license.encryption_key')
            )
        );
        $license->bindValue(
            ':license_key_hint',
            LicenseKey::hint($licenseKey)
        );
        $license->bindValue(':status', 'active');
        $license->bindValue(
            ':delivery_status',
            $sendEmail ? 'pending' : 'manual'
        );
        $license->execute();
        $licenseId = (int)$database->lastInsertId();

        $database->commit();
    } catch (Throwable $error) {
        if ($database->inTransaction()) {
            $database->rollBack();
        }
        $logger->write('Manual license creation failed.', [
            'error_type' => $error::class,
        ]);
        throw $error;
    }

    require_once ADMIN_PRIVATE_ROOT . '/license-backend/src/ZohoCampaigns.php';
    \INoon\Licensing\scheduleZohoCampaignsSync(ADMIN_PRIVATE_ROOT . '/license-backend/config.php');

    $deliveryStatus = 'manual';
    $deliveryMessage = 'The licence was created and is ready to copy.';
    if ($sendEmail) {
        $attempt = $database->prepare(
            'UPDATE licenses
             SET email_attempt_count = email_attempt_count + 1,
                 last_email_attempt_at = UTC_TIMESTAMP(6),
                 last_email_error_code = NULL
             WHERE id = :license_id'
        );
        $attempt->execute([':license_id' => $licenseId]);

        try {
            $mailer = new LicenseMailer($config, $logger);
            $mailer->send($email, $name, [$licenseKey], false);
            $sent = $database->prepare(
                "UPDATE licenses
                 SET delivery_status = 'sent',
                     email_sent_at = UTC_TIMESTAMP(6),
                     last_email_error_code = NULL
                 WHERE id = :license_id"
            );
            $sent->execute([':license_id' => $licenseId]);
            $deliveryStatus = 'sent';
            $deliveryMessage = 'The licence was created and emailed to the customer.';
        } catch (Throwable $error) {
            $failed = $database->prepare(
                "UPDATE licenses
                 SET delivery_status = 'failed',
                     last_email_error_code = :error_code
                 WHERE id = :license_id"
            );
            $failed->execute([
                ':error_code' => substr($error::class, 0, 64),
                ':license_id' => $licenseId,
            ]);
            $deliveryStatus = 'failed';
            $deliveryMessage = 'The licence was created, but email delivery failed. Copy the key below and send it manually.';
            $logger->write('Manual license email delivery failed.', [
                'license_id' => $licenseId,
                'error_type' => $error::class,
            ]);
        }
    }

    $logger->write('Manual license created.', [
        'license_id' => $licenseId,
        'delivery_status' => $deliveryStatus,
        'seat_count' => $seatCount,
    ]);

    return [
        'license_key' => $licenseKey,
        'delivery_status' => $deliveryStatus,
        'message' => $deliveryMessage,
    ];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $postedToken = is_string($_POST['csrf_token'] ?? null)
        ? $_POST['csrf_token']
        : '';
    if (!hash_equals($csrfToken, $postedToken)) {
        http_response_code(400);
        $_SESSION['flash'] = [
            'type' => 'error',
            'title' => 'Request expired',
            'message' => 'Refresh the page and try again.',
        ];
        $failedAction = is_string($_POST['action'] ?? null) ? $_POST['action'] : '';
        redirectTo(str_starts_with($failedAction, 'promo_')
            ? '/admin/?tab=promos'
            : ($failedAction === 'delete_customer'
                ? '/admin/?tab=licenses'
                : '/admin/?tab=add'));
    }

    $action = is_string($_POST['action'] ?? null) ? $_POST['action'] : '';
    if (in_array($action, ['promo_create', 'promo_update', 'promo_remove'], true)) {
        try {
            $_SESSION['flash'] = $promoCodes->handleAdminAction($action, $_POST);
        } catch (InvalidArgumentException $error) {
            $_SESSION['flash'] = [
                'type' => 'error',
                'title' => 'Check the promo code',
                'message' => $error->getMessage(),
            ];
        } catch (Throwable) {
            $_SESSION['flash'] = [
                'type' => 'error',
                'title' => 'Promo code not saved',
                'message' => 'The server could not save the promo code. Please try again.',
            ];
        }
        redirectTo('/admin/?tab=promos');
    }
    if ($action === 'delete_customer') {
        $customerId = filter_var(
            $_POST['customer_id'] ?? null,
            FILTER_VALIDATE_INT,
            ['options' => ['min_range' => 1]]
        );
        try {
            if (!is_int($customerId)) {
                throw new InvalidArgumentException('Select a valid customer.');
            }
            $deleted = $customerDeletion->delete($customerId);
            $_SESSION['flash'] = [
                'type' => 'success',
                'title' => 'Customer deleted',
                'message' => sprintf(
                    'Deleted the customer, %d licence%s, %d purchase%s, and %d giveaway claim%s.',
                    $deleted['licenses'],
                    $deleted['licenses'] === 1 ? '' : 's',
                    $deleted['purchases'],
                    $deleted['purchases'] === 1 ? '' : 's',
                    $deleted['claims'],
                    $deleted['claims'] === 1 ? '' : 's'
                ),
            ];
        } catch (InvalidArgumentException $error) {
            $_SESSION['flash'] = [
                'type' => 'error',
                'title' => 'Customer not deleted',
                'message' => $error->getMessage(),
            ];
        } catch (Throwable) {
            $_SESSION['flash'] = [
                'type' => 'error',
                'title' => 'Customer not deleted',
                'message' => 'The server could not delete this customer. No records were changed.',
            ];
        }
        redirectTo('/admin/?tab=licenses');
    }
    if ($action === 'create_license') {
        $name = trim(is_string($_POST['name'] ?? null) ? $_POST['name'] : '');
        $email = strtolower(trim(
            is_string($_POST['email'] ?? null) ? $_POST['email'] : ''
        ));
        $seatCount = filter_var(
            $_POST['seat_count'] ?? null,
            FILTER_VALIDATE_INT,
            ['options' => ['min_range' => 1, 'max_range' => 100]]
        );
        $sendEmail = ($_POST['send_email'] ?? '') === '1';

        $validationError = null;
        $nameLength = function_exists('mb_strlen')
            ? mb_strlen($name)
            : strlen($name);
        if ($name === '' || $nameLength > 200) {
            $validationError = 'Enter a customer name of 200 characters or fewer.';
        } elseif (filter_var($email, FILTER_VALIDATE_EMAIL) === false
            || strlen($email) > 320
        ) {
            $validationError = 'Enter a valid customer email address.';
        } elseif (!is_int($seatCount)) {
            $validationError = 'Seats must be between 1 and 100.';
        }

        if ($validationError !== null) {
            $_SESSION['flash'] = [
                'type' => 'error',
                'title' => 'Check the licence details',
                'message' => $validationError,
            ];
        } else {
            try {
                $result = issueManualLicense(
                    $database,
                    $config,
                    $logger,
                    $name,
                    $email,
                    $seatCount,
                    $sendEmail
                );
                $_SESSION['flash'] = [
                    'type' => $result['delivery_status'] === 'failed'
                        ? 'warning'
                        : 'success',
                    'title' => 'Licence issued',
                    'message' => $result['message'],
                    'license_key' => $result['license_key'],
                ];
            } catch (Throwable) {
                $_SESSION['flash'] = [
                    'type' => 'error',
                    'title' => 'Licence not created',
                    'message' => 'The server could not create this licence. No partial record was kept.',
                ];
            }
        }

        redirectTo('/admin/?tab=add');
    }

    http_response_code(400);
    exit('Unknown admin action.');
}

function dashboardStats(PDO $database, CrashReportStore $crashReportStore): array
{
    $licenseCounts = $database->query(
        "SELECT
            SUM(status = 'active') AS active,
            SUM(status <> 'active') AS inactive,
            SUM(delivery_status = 'failed') AS delivery_failed
         FROM licenses"
    )->fetch();
    $paidCustomers = (int)$database->query(
        "SELECT COUNT(DISTINCT customer_id)
         FROM purchases
         WHERE source_type = 'paddle' AND status = 'completed'"
    )->fetchColumn();
    $manual = (int)$database->query(
        "SELECT COUNT(*)
         FROM purchases
         WHERE source_type = 'manual'"
    )->fetchColumn();
    $retrievalToday = (int)$database->query(
        'SELECT COUNT(*)
         FROM license_retrieval_requests
         WHERE requested_at >= UTC_DATE()'
    )->fetchColumn();
    $visitorCounts = $database->query(
        'SELECT
            COUNT(*) AS total,
            SUM(last_seen_at >= UTC_DATE()) AS today
         FROM site_visitors'
    )->fetch();
    $downloadCounts = $database->query(
        "SELECT
            COUNT(*) AS total,
            SUM(downloaded_at >= UTC_DATE()) AS today,
            SUM(platform = 'mac') AS mac,
            SUM(platform = 'pc') AS pc
         FROM download_events"
    )->fetch();
    $crashCounts = $crashReportStore->statistics();

    return [
        'paid_customers' => $paidCustomers,
        'active' => (int)($licenseCounts['active'] ?? 0),
        'inactive' => (int)($licenseCounts['inactive'] ?? 0),
        'delivery_failed' => (int)($licenseCounts['delivery_failed'] ?? 0),
        'manual' => $manual,
        'retrieval_today' => $retrievalToday,
        'crashes' => $crashCounts['total'],
        'crashes_today' => $crashCounts['today'],
        'visitors' => (int)($visitorCounts['total'] ?? 0),
        'visitors_today' => (int)($visitorCounts['today'] ?? 0),
        'downloads' => (int)($downloadCounts['total'] ?? 0),
        'downloads_today' => (int)($downloadCounts['today'] ?? 0),
        'downloads_mac' => (int)($downloadCounts['mac'] ?? 0),
        'downloads_pc' => (int)($downloadCounts['pc'] ?? 0),
    ];
}

function recentLicenses(PDO $database, int $limit = 8): array
{
    $statement = $database->prepare(
        'SELECT
            licenses.id,
            licenses.status,
            licenses.delivery_status,
            licenses.license_key_ciphertext,
            licenses.license_key_hint,
            licenses.issued_at,
            purchases.paddle_transaction_id,
            purchases.source_type,
            purchases.source_code,
            purchases.seat_count,
            customers.name,
            customers.email
         FROM licenses
         INNER JOIN purchases ON purchases.id = licenses.purchase_id
         INNER JOIN customers ON customers.id = purchases.customer_id
         ORDER BY licenses.issued_at DESC
         LIMIT :limit'
    );
    $statement->bindValue(':limit', $limit, PDO::PARAM_INT);
    $statement->execute();
    return $statement->fetchAll();
}

function findLicenses(
    PDO $database,
    Config $config,
    string $query,
    string $status,
    int $page,
    int $perPage = 20
): array {
    $where = [];
    $bindings = [];
    $binaryHash = null;

    if ($status !== 'all') {
        $where[] = 'licenses.status = :status';
        $bindings[':status'] = $status;
    }

    if ($query !== '') {
        $normalizedKey = LicenseKey::normalize(
            $query,
            $config->string('license.prefix')
        );
        if ($normalizedKey !== null) {
            $where[] = 'licenses.license_key_hash = :license_key_hash';
            $binaryHash = LicenseKey::hash($normalizedKey);
        } else {
            $where[] = '(customers.email LIKE :query_email
                OR customers.name LIKE :query_name
                OR customers.paddle_customer_id LIKE :query_customer
                OR purchases.paddle_transaction_id LIKE :query_transaction
                OR purchases.source_code LIKE :query_source_code
                OR licenses.license_key_hint LIKE :query_hint)';
            $likeQuery = '%' . $query . '%';
            $bindings[':query_email'] = $likeQuery;
            $bindings[':query_name'] = $likeQuery;
            $bindings[':query_customer'] = $likeQuery;
            $bindings[':query_transaction'] = $likeQuery;
            $bindings[':query_source_code'] = $likeQuery;
            $bindings[':query_hint'] = $likeQuery;
        }
    }

    $whereSql = $where === [] ? '' : ' WHERE ' . implode(' AND ', $where);
    $count = $database->prepare(
        'SELECT COUNT(*)
         FROM licenses
         INNER JOIN purchases ON purchases.id = licenses.purchase_id
         INNER JOIN customers ON customers.id = purchases.customer_id'
        . $whereSql
    );
    foreach ($bindings as $name => $value) {
        $count->bindValue($name, $value);
    }
    if ($binaryHash !== null) {
        $count->bindValue(':license_key_hash', $binaryHash, PDO::PARAM_LOB);
    }
    $count->execute();
    $total = (int)$count->fetchColumn();
    $pages = max(1, (int)ceil($total / $perPage));
    $page = max(1, min($page, $pages));
    $offset = ($page - 1) * $perPage;

    $statement = $database->prepare(
        'SELECT
            licenses.id,
            licenses.status,
            licenses.delivery_status,
            licenses.license_key_ciphertext,
            licenses.license_key_hint,
            licenses.email_sent_at,
            licenses.email_attempt_count,
            licenses.last_email_error_code,
            licenses.issued_at,
            licenses.revoked_at,
            licenses.created_at,
            licenses.updated_at,
            purchases.paddle_transaction_id,
            purchases.source_type,
            purchases.source_code,
            purchases.paddle_price_id,
            purchases.paddle_product_id,
            purchases.seat_count,
            purchases.currency_code,
            purchases.total_amount,
            purchases.status AS purchase_status,
            purchases.purchased_at,
            customers.id AS customer_id,
            customers.paddle_customer_id,
            customers.name,
            customers.email
         FROM licenses
         INNER JOIN purchases ON purchases.id = licenses.purchase_id
         INNER JOIN customers ON customers.id = purchases.customer_id'
        . $whereSql
        . ' ORDER BY licenses.issued_at DESC
            LIMIT :limit OFFSET :offset'
    );
    foreach ($bindings as $name => $value) {
        $statement->bindValue($name, $value);
    }
    if ($binaryHash !== null) {
        $statement->bindValue(
            ':license_key_hash',
            $binaryHash,
            PDO::PARAM_LOB
        );
    }
    $statement->bindValue(':limit', $perPage, PDO::PARAM_INT);
    $statement->bindValue(':offset', $offset, PDO::PARAM_INT);
    $statement->execute();

    return [
        'rows' => $statement->fetchAll(),
        'total' => $total,
        'page' => $page,
        'pages' => $pages,
    ];
}

function decryptedKey(array $row, Config $config): string
{
    try {
        return LicenseKey::decrypt(
            (string)$row['license_key_ciphertext'],
            $config->string('license.encryption_key')
        );
    } catch (Throwable) {
        return 'Unavailable';
    }
}

function sourceLabel(array $row): string
{
    return match ((string)($row['source_type'] ?? 'paddle')) {
        'giveaway' => 'Giveaway · ' . (string)($row['source_code'] ?: 'Unknown code'),
        'manual' => 'Manual',
        default => 'Paddle',
    };
}

function statusClass(string $status): string
{
    $normalized = preg_replace('/[^a-z0-9_-]/i', '', strtolower($status));
    return is_string($normalized) && $normalized !== ''
        ? 'status-' . $normalized
        : 'status-unknown';
}

$environment = $config->string('environment');
$isSandbox = strtolower($environment) === 'sandbox';
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex,nofollow,noarchive">
    <title>Cosmic Noon Admin</title>
    <style>
        :root {
            color-scheme: light dark;
            --ink: #172033;
            --muted: #68748a;
            --line: #dce6f5;
            --surface: rgba(255, 255, 255, .9);
            --page: #f5f8ff;
            --nav-surface: rgba(255, 255, 255, .68);
            --solid-surface: #fff;
            --subtle-surface: #f8faff;
            --hover-surface: #fafcff;
            --blue-surface: #eef5ff;
            --highlight-surface: linear-gradient(145deg, #f4f8ff, #eef4ff);
            --blue: #2173f5;
            --blue-dark: #1559c7;
            --purple: #9f4fe8;
            --pink: #d848d7;
            --green: #178753;
            --amber: #a85c00;
            --red: #b82f43;
            --shadow: 0 24px 70px rgba(39, 65, 110, .12);
        }
        * { box-sizing: border-box; }
        body {
            margin: 0;
            min-height: 100vh;
            color: var(--ink);
            background:
                radial-gradient(circle at 8% 0%, rgba(62, 129, 255, .18), transparent 32rem),
                radial-gradient(circle at 92% 16%, rgba(205, 74, 226, .15), transparent 30rem),
                var(--page);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            line-height: 1.5;
        }
        button, input, select, textarea { font: inherit; }
        a { color: inherit; }
        .shell { width: min(1180px, calc(100% - 32px)); margin: 0 auto; padding: 30px 0 54px; }
        .topbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 20px;
            margin-bottom: 22px;
        }
        .brand { display: flex; align-items: center; gap: 12px; }
        .brand-mark {
            display: grid;
            place-items: center;
            width: 44px;
            height: 44px;
            color: #fff;
            font-weight: 850;
            letter-spacing: -.05em;
            border-radius: 14px;
            background: linear-gradient(135deg, var(--blue), var(--purple));
            box-shadow: 0 12px 28px rgba(72, 88, 224, .24);
        }
        .brand h1 { margin: 0; font-size: 22px; letter-spacing: -.035em; }
        .brand p { margin: 1px 0 0; color: var(--muted); font-size: 13px; }
        .environment {
            display: inline-flex;
            align-items: center;
            gap: 7px;
            padding: 7px 11px;
            border: 1px solid #e6c873;
            border-radius: 999px;
            background: #fff9df;
            color: #815d00;
            font-size: 12px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: .08em;
        }
        .environment::before {
            content: "";
            width: 7px;
            height: 7px;
            border-radius: 50%;
            background: #e6a915;
            box-shadow: 0 0 0 4px rgba(230, 169, 21, .15);
        }
        nav {
            display: flex;
            gap: 7px;
            padding: 7px;
            margin-bottom: 22px;
            overflow-x: auto;
            border: 1px solid var(--line);
            border-radius: 16px;
            background: var(--nav-surface);
            backdrop-filter: blur(18px);
        }
        nav a {
            padding: 9px 14px;
            color: var(--muted);
            border-radius: 11px;
            text-decoration: none;
            white-space: nowrap;
            font-size: 14px;
            font-weight: 750;
        }
        nav a:hover { color: var(--blue-dark); background: var(--blue-surface); }
        nav a.active {
            color: #fff;
            background: linear-gradient(135deg, var(--blue), #4c7bf1 58%, var(--purple));
            box-shadow: 0 8px 20px rgba(54, 103, 223, .2);
        }
        .logout-form {
            display: flex;
            margin: 0 0 0 auto;
        }
        .logout-button {
            padding: 9px 14px;
            border: 0;
            border-radius: 11px;
            color: var(--muted);
            background: transparent;
            white-space: nowrap;
            font-size: 14px;
            font-weight: 750;
            cursor: pointer;
        }
        .logout-button:hover {
            color: var(--red);
            background: var(--subtle-surface);
        }
        .hero {
            display: flex;
            align-items: flex-end;
            justify-content: space-between;
            gap: 20px;
            margin: 6px 0 18px;
        }
        .hero h2 { margin: 0; font-size: clamp(28px, 5vw, 42px); letter-spacing: -.055em; line-height: 1.03; }
        .hero p { max-width: 650px; margin: 9px 0 0; color: var(--muted); }
        .panel {
            padding: 20px;
            border: 1px solid var(--line);
            border-radius: 22px;
            background: var(--surface);
            box-shadow: var(--shadow);
            backdrop-filter: blur(22px);
        }
        .cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 11px;
            margin: 18px 0 22px;
        }
        .metric-heading {
            display: flex;
            align-items: baseline;
            justify-content: space-between;
            gap: 18px;
            margin: 24px 0 -7px;
        }
        .metric-heading h3 { margin: 0; font-size: 18px; letter-spacing: -.025em; }
        .metric-heading p { margin: 0; color: var(--muted); font-size: 12px; }
        .stat {
            min-height: 112px;
            padding: 16px;
            border: 1px solid var(--line);
            border-radius: 18px;
            background: var(--surface);
        }
        .stat strong { display: block; font-size: 29px; letter-spacing: -.04em; }
        .stat span { display: block; margin-top: 5px; color: var(--muted); font-size: 12px; font-weight: 800; text-transform: uppercase; letter-spacing: .065em; }
        .stat.highlight { border-color: #a8c8ff; background: var(--highlight-surface); }
        .section-head {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 14px;
            margin-bottom: 14px;
        }
        .section-head h3 { margin: 0; font-size: 17px; letter-spacing: -.02em; }
        .section-head a { color: var(--blue-dark); font-size: 13px; font-weight: 750; text-decoration: none; }
        .table-wrap { width: 100%; overflow-x: auto; border: 1px solid var(--line); border-radius: 16px; }
        table { width: 100%; border-collapse: collapse; background: var(--solid-surface); }
        th, td { padding: 12px 13px; text-align: left; border-bottom: 1px solid #edf1f8; font-size: 13px; vertical-align: middle; }
        th { color: var(--muted); background: var(--subtle-surface); font-size: 11px; font-weight: 850; text-transform: uppercase; letter-spacing: .065em; }
        tbody tr:last-child td { border-bottom: 0; }
        tbody tr:hover { background: var(--hover-surface); }
        .name { font-weight: 760; }
        .subtle { color: var(--muted); font-size: 12px; }
        .mono { font-family: "SFMono-Regular", Consolas, monospace; font-size: 12px; letter-spacing: .025em; }
        .key-line { display: flex; align-items: center; gap: 7px; white-space: nowrap; }
        .status {
            display: inline-flex;
            align-items: center;
            padding: 4px 9px;
            border-radius: 999px;
            background: #edf2fa;
            color: #53627a;
            font-size: 11px;
            font-weight: 850;
            text-transform: capitalize;
        }
        .status-active, .status-sent { background: #e8f8ef; color: var(--green); }
        .status-refunded, .status-revoked, .status-failed, .status-canceled { background: #fdebee; color: var(--red); }
        .status-pending { background: #fff4df; color: var(--amber); }
        .status-manual { background: #f2ebff; color: #7041a8; }
        .copy-button, .button {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 7px;
            min-height: 36px;
            padding: 8px 13px;
            border: 0;
            border-radius: 11px;
            color: #fff;
            background: linear-gradient(135deg, var(--blue), #4d7ef2 58%, var(--purple));
            box-shadow: 0 8px 20px rgba(45, 97, 220, .18);
            cursor: pointer;
            text-decoration: none;
            font-size: 13px;
            font-weight: 800;
        }
        .copy-button { min-height: 28px; padding: 5px 9px; font-size: 11px; box-shadow: none; }
        .copy-button:hover, .button:hover { filter: brightness(1.04); transform: translateY(-1px); }
        .button.secondary { color: var(--blue-dark); background: var(--blue-surface); box-shadow: none; }
        .button.danger { background: #c9354f; box-shadow: none; }
        .filters {
            display: grid;
            grid-template-columns: minmax(240px, 1fr) 170px auto;
            gap: 10px;
            margin-bottom: 15px;
        }
        .filters.crash-filters {
            grid-template-columns: minmax(240px, 1fr) auto;
        }
        input[type="text"], input[type="email"], input[type="number"], input[type="datetime-local"], select, textarea {
            width: 100%;
            min-height: 44px;
            padding: 10px 12px;
            color: var(--ink);
            border: 1px solid #cfd9e9;
            border-radius: 12px;
            outline: none;
            background: var(--solid-surface);
        }
        textarea { min-height: 96px; resize: vertical; }
        input:focus, select:focus, textarea:focus { border-color: var(--blue); box-shadow: 0 0 0 4px rgba(33, 115, 245, .12); }
        .form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }
        .field { display: flex; flex-direction: column; gap: 6px; }
        .field.full { grid-column: 1 / -1; }
        .field label { font-size: 13px; font-weight: 800; }
        .field small { color: var(--muted); }
        .check {
            display: flex;
            align-items: flex-start;
            gap: 10px;
            padding: 14px;
            border: 1px solid var(--line);
            border-radius: 14px;
            background: var(--subtle-surface);
        }
        .check input { width: 18px; height: 18px; accent-color: var(--blue); }
        .check strong { display: block; font-size: 14px; }
        .check span { display: block; margin-top: 2px; color: var(--muted); font-size: 12px; }
        .actions { display: flex; align-items: center; gap: 10px; margin-top: 18px; }
        .message {
            margin-bottom: 18px;
            padding: 15px 17px;
            border: 1px solid;
            border-radius: 16px;
        }
        .message strong { display: block; margin-bottom: 3px; }
        .message-success { color: #12663f; border-color: #a6dec0; background: #eaf9f1; }
        .message-warning { color: #825109; border-color: #eac886; background: #fff6e3; }
        .message-error { color: #9c2639; border-color: #efb9c2; background: #fff0f2; }
        .issued-key {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            margin-top: 12px;
            padding: 13px 14px;
            color: var(--ink);
            border: 1px solid rgba(33, 115, 245, .24);
            border-radius: 13px;
            background: var(--solid-surface);
        }
        details { min-width: 220px; }
        summary { color: var(--blue-dark); cursor: pointer; font-weight: 760; }
        .details-grid {
            display: grid;
            grid-template-columns: max-content minmax(180px, 1fr);
            gap: 7px 14px;
            min-width: 480px;
            margin-top: 11px;
            padding: 13px;
            border: 1px solid var(--line);
            border-radius: 13px;
            background: var(--subtle-surface);
        }
        .details-grid dt { color: var(--muted); font-size: 12px; font-weight: 780; }
        .details-grid dd { margin: 0; overflow-wrap: anywhere; font-size: 12px; }
        .danger-zone {
            margin-top: 10px;
            padding: 12px 13px;
            border: 1px solid #efb9c2;
            border-radius: 13px;
            background: #fff0f2;
        }
        .danger-zone p { margin: 0 0 9px; color: #8c2437; font-size: 12px; line-height: 1.45; }
        .pager { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 16px; }
        .pager a, .pager span { padding: 6px 10px; border: 1px solid var(--line); border-radius: 9px; color: var(--muted); background: var(--solid-surface); text-decoration: none; font-size: 12px; }
        .pager .current { color: #fff; border-color: transparent; background: var(--blue); }
        .crash-description {
            max-width: 430px;
            overflow: hidden;
            color: var(--muted);
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .crash-report {
            display: grid;
            gap: 18px;
        }
        .crash-meta {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 10px;
        }
        .crash-meta div {
            padding: 13px 14px;
            border: 1px solid var(--line);
            border-radius: 13px;
            background: var(--subtle-surface);
        }
        .crash-meta dt {
            margin-bottom: 4px;
            color: var(--muted);
            font-size: 11px;
            font-weight: 850;
            text-transform: uppercase;
            letter-spacing: .06em;
        }
        .crash-meta dd {
            margin: 0;
            overflow-wrap: anywhere;
            font-size: 13px;
        }
        .crash-notes {
            padding: 15px;
            border: 1px solid #d9c9f4;
            border-radius: 14px;
            background: #faf6ff;
            white-space: pre-wrap;
        }
        .crash-log {
            max-height: 620px;
            margin: 0;
            overflow: auto;
            padding: 16px;
            color: #dce7ff;
            border-radius: 15px;
            background: #111827;
            font: 11px/1.55 "SFMono-Regular", Consolas, monospace;
            white-space: pre-wrap;
            overflow-wrap: anywhere;
        }
        .empty { padding: 28px; color: var(--muted); text-align: center; }
        .footer { margin-top: 20px; color: var(--muted); font-size: 12px; text-align: center; }
        @media (prefers-color-scheme: dark) {
            :root {
                --ink: #f2f6ff;
                --muted: #a9b5ca;
                --line: rgba(130, 153, 190, .26);
                --surface: rgba(25, 32, 48, .9);
                --page: #0c1220;
                --nav-surface: rgba(23, 30, 45, .78);
                --solid-surface: #151c2b;
                --subtle-surface: #1b2435;
                --hover-surface: #202b3e;
                --blue-surface: #192c4a;
                --highlight-surface: linear-gradient(145deg, #172943, #20283e);
                --blue: #4c91ff;
                --blue-dark: #8ebaff;
                --purple: #b46cf3;
                --pink: #f06ae7;
                --green: #65d59c;
                --amber: #f0bd65;
                --red: #ff8495;
                --shadow: 0 26px 76px rgba(0, 0, 0, .32);
            }
            body {
                background:
                    radial-gradient(circle at 8% 0%, rgba(62, 129, 255, .22), transparent 32rem),
                    radial-gradient(circle at 92% 16%, rgba(205, 74, 226, .18), transparent 30rem),
                    var(--page);
            }
            .environment {
                border-color: rgba(235, 187, 72, .48);
                background: rgba(111, 78, 8, .3);
                color: #ffd879;
            }
            .logout-button:hover {
                color: #ff9aaa;
                background: rgba(134, 35, 53, .28);
            }
            th, td { border-bottom-color: rgba(130, 153, 190, .16); }
            .status { background: #253147; color: #c0cbe0; }
            .status-active, .status-sent { background: rgba(31, 126, 80, .3); color: #79e3ad; }
            .status-refunded, .status-revoked, .status-failed, .status-canceled { background: rgba(151, 43, 63, .3); color: #ff9aaa; }
            .status-pending { background: rgba(143, 94, 17, .3); color: #ffd078; }
            .status-manual { background: rgba(112, 65, 168, .32); color: #d1a8ff; }
            .message-success { color: #9ae4bc; border-color: rgba(84, 195, 136, .45); background: rgba(28, 111, 67, .25); }
            .message-warning { color: #ffd08a; border-color: rgba(223, 167, 73, .45); background: rgba(121, 79, 14, .27); }
            .message-error { color: #ffadba; border-color: rgba(231, 98, 120, .46); background: rgba(126, 32, 50, .27); }
            .crash-notes { border-color: rgba(180, 121, 238, .36); background: rgba(90, 49, 126, .22); }
            input:focus, select:focus { box-shadow: 0 0 0 4px rgba(76, 145, 255, .2); }
        }
        @media (max-width: 900px) {
            .cards { grid-template-columns: repeat(3, minmax(0, 1fr)); }
        }
        @media (max-width: 650px) {
            .shell { width: min(100% - 20px, 1180px); padding-top: 18px; }
            .topbar, .hero { align-items: flex-start; flex-direction: column; }
            .cards { grid-template-columns: repeat(2, minmax(0, 1fr)); }
            .filters, .form-grid { grid-template-columns: 1fr; }
            .field.full { grid-column: auto; }
            .panel { padding: 15px; border-radius: 18px; }
        }

        .website-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 20px; margin-bottom: 12px; }
        .website-panel { border-top: 4px solid #2173f5; padding: 24px; }
        .website-panel.gelato { border-top-color: #71995b; }
        .website-panel h3 { font-size: 25px; margin: 0 0 4px; letter-spacing: -.035em; }
        .website-panel .site-url { color: var(--muted); font-size: 14px; }
        .website-metrics { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; margin-top: 30px; }
        .website-metrics strong { display: block; font-size: clamp(30px, 4vw, 44px); letter-spacing: -.05em; line-height: 1.1; }
        .website-metrics span { display: block; margin-top: 7px; color: var(--muted); font-size: 14px; }
        .analytics-periods { display: flex; gap: 7px; flex-wrap: wrap; }
        .analytics-periods a { border: 1px solid var(--line); padding: 8px 13px; border-radius: 10px; color: var(--muted); text-decoration: none; font-size: 14px; white-space: nowrap; }
        .analytics-periods a.active { color: #fff; background: var(--blue); border-color: var(--blue); }
        .operations-heading { margin-top: 40px; padding-top: 28px; border-top: 1px solid var(--line); }
        .operations-heading h2 { font-size: 28px; }
        @media (max-width: 680px) { .website-grid { grid-template-columns: 1fr; } .website-panel { padding: 20px; } .hero { align-items: flex-start; flex-direction: column; } }
    </style>
</head>
<body>
<main class="shell">
    <header class="topbar">
        <div class="brand">
            <div class="brand-mark" aria-hidden="true">CN</div>
            <div>
                <h1>Cosmic Noon Admin</h1>
                <p>iNoon &amp; Gelato Maestro · Website activity and operations</p>
            </div>
        </div>
        <span class="environment"><?= escapeHtml($environment) ?></span>
    </header>

    <nav aria-label="Admin sections">
        <a href="?tab=dashboard" class="<?= $tab === 'dashboard' ? 'active' : '' ?>">Overview</a>
        <a href="?tab=usage" class="<?= $tab === 'usage' ? 'active' : '' ?>">iNoon App Usage</a>
        <a href="?tab=licenses" class="<?= $tab === 'licenses' ? 'active' : '' ?>">iNoon Licences</a>
        <a href="?tab=promos" class="<?= $tab === 'promos' ? 'active' : '' ?>">iNoon Promo Codes</a>
        <a href="?tab=crashes" class="<?= $tab === 'crashes' ? 'active' : '' ?>">iNoon Crash Reports</a>
        <a href="?tab=add" class="<?= $tab === 'add' ? 'active' : '' ?>">Issue Licence</a>
        <a href="https://inoon.app/stats/" target="_blank" rel="noreferrer">Matomo ↗</a>
        <a href="https://inoon.app/" target="_blank" rel="noreferrer">Open iNoon ↗</a>
        <form class="logout-form" method="post" action="/admin/">
            <input type="hidden" name="admin_action" value="logout">
            <input type="hidden" name="csrf_token" value="<?= escapeHtml($csrfToken) ?>">
            <button class="logout-button" type="submit">Sign out</button>
        </form>
    </nav>

    <?php if (is_array($flash)): ?>
        <section class="message message-<?= escapeHtml($flash['type'] ?? 'success') ?>" role="status">
            <strong><?= escapeHtml($flash['title'] ?? '') ?></strong>
            <span><?= escapeHtml($flash['message'] ?? '') ?></span>
            <?php if (is_string($flash['license_key'] ?? null)): ?>
                <div class="issued-key">
                    <span class="mono"><?= escapeHtml($flash['license_key']) ?></span>
                    <button class="copy-button" type="button" data-copy="<?= escapeHtml($flash['license_key']) ?>">Copy key</button>
                </div>
            <?php endif; ?>
        </section>
    <?php endif; ?>

    <?php if ($tab === 'dashboard'):
        $stats = dashboardStats($database, $crashReportStore);
        $recent = recentLicenses($database);
    ?>
        <?php require __DIR__ . '/website-analytics.php'; ?>

        <section class="hero operations-heading">
            <div>
                <h2>iNoon operations</h2>
                <p>Downloads, customer access and licence delivery.</p>
            </div>
            <a class="button" href="?tab=add">＋ Issue a licence</a>
        </section>
        <div class="metric-heading"><h3>iNoon downloads</h3></div>
        <section class="cards" aria-label="iNoon download statistics">
            <div class="stat highlight"><strong><?= $stats['downloads'] ?></strong><span>Total downloads</span></div>
            <div class="stat"><strong><?= $stats['downloads_today'] ?></strong><span>Downloads today</span></div>
            <div class="stat"><strong><?= $stats['downloads_mac'] ?></strong><span>Mac downloads</span></div>
            <div class="stat"><strong><?= $stats['downloads_pc'] ?></strong><span>PC downloads</span></div>
        </section>

        <?php require __DIR__ . '/spacekeeper-downloads.php'; ?>

        <div class="metric-heading">
            <h3>iNoon licence activity</h3>
            <p>Purchases, fulfilment, retrievals, and support</p>
        </div>
        <section class="cards" aria-label="Licence statistics">
            <div class="stat highlight"><strong><?= $stats['paid_customers'] ?></strong><span>Paid customers</span></div>
            <div class="stat"><strong><?= $stats['active'] ?></strong><span>Active</span></div>
            <div class="stat"><strong><?= $stats['inactive'] ?></strong><span>Inactive</span></div>
            <div class="stat"><strong><?= $stats['manual'] ?></strong><span>Manual</span></div>
            <div class="stat"><strong><?= $stats['delivery_failed'] ?></strong><span>Email issues</span></div>
            <div class="stat"><strong><?= $stats['retrieval_today'] ?></strong><span>Retrievals today</span></div>
            <div class="stat"><strong><?= $stats['crashes'] ?></strong><span>Crash reports</span></div>
            <div class="stat"><strong><?= $stats['crashes_today'] ?></strong><span>Crashes today</span></div>
        </section>

        <section class="panel">
            <div class="section-head">
                <h3>Recently issued</h3>
                <a href="?tab=licenses">View all licences →</a>
            </div>
            <div class="table-wrap">
                <table>
                    <thead><tr><th>Customer</th><th>Licence</th><th>Status</th><th>Delivery</th><th>Source</th><th>Issued</th></tr></thead>
                    <tbody>
                    <?php foreach ($recent as $row):
                        $key = decryptedKey($row, $config);
                    ?>
                        <tr>
                            <td><span class="name"><?= escapeHtml($row['name'] ?: 'Unnamed customer') ?></span><br><span class="subtle"><?= escapeHtml($row['email'] ?: 'No email') ?></span></td>
                            <td><div class="key-line"><span class="mono"><?= escapeHtml($key) ?></span><button class="copy-button" type="button" data-copy="<?= escapeHtml($key) ?>">Copy</button></div></td>
                            <td><span class="status <?= statusClass((string)$row['status']) ?>"><?= escapeHtml($row['status']) ?></span></td>
                            <td><span class="status <?= statusClass((string)$row['delivery_status']) ?>"><?= escapeHtml($row['delivery_status']) ?></span></td>
                            <td><?= escapeHtml(sourceLabel($row)) ?></td>
                            <td><?= escapeHtml($row['issued_at']) ?> UTC</td>
                        </tr>
                    <?php endforeach; ?>
                    <?php if ($recent === []): ?><tr><td class="empty" colspan="6">No licences have been issued yet.</td></tr><?php endif; ?>
                    </tbody>
                </table>
            </div>
        </section>

    <?php elseif ($tab === 'usage'): ?>
        <?php require __DIR__ . '/app-usage.php'; ?>
    <?php elseif ($tab === 'licenses'):
        $query = trim(is_string($_GET['q'] ?? null) ? $_GET['q'] : '');
        if (strlen($query) > 320) {
            $query = substr($query, 0, 320);
        }
        $status = is_string($_GET['status'] ?? null) ? $_GET['status'] : 'all';
        $allowedStatuses = ['all', 'active', 'refunded', 'revoked', 'invalid'];
        if (!in_array($status, $allowedStatuses, true)) {
            $status = 'all';
        }
        $page = max(1, (int)($_GET['p'] ?? 1));
        $results = findLicenses($database, $config, $query, $status, $page);
    ?>
        <section class="hero">
            <div>
                <h2>Licences</h2>
                <p>Search by customer, transaction, promo code, key hint, or a complete licence key.</p>
            </div>
        </section>

        <section class="panel">
            <form class="filters" method="get">
                <input type="hidden" name="tab" value="licenses">
                <input type="text" name="q" value="<?= escapeHtml($query) ?>" placeholder="Email, name, Paddle ID, transaction, or key">
                <select name="status" aria-label="Licence status">
                    <?php foreach ($allowedStatuses as $statusOption): ?>
                        <option value="<?= escapeHtml($statusOption) ?>" <?= $status === $statusOption ? 'selected' : '' ?>><?= escapeHtml(ucfirst($statusOption)) ?></option>
                    <?php endforeach; ?>
                </select>
                <button class="button" type="submit">Search</button>
            </form>

            <div class="section-head">
                <h3><?= $results['total'] ?> licence<?= $results['total'] === 1 ? '' : 's' ?></h3>
                <?php if ($query !== '' || $status !== 'all'): ?><a href="?tab=licenses">Clear filters</a><?php endif; ?>
            </div>

            <div class="table-wrap">
                <table>
                    <thead><tr><th>Customer</th><th>Licence</th><th>Status</th><th>Delivery</th><th>Source</th><th>Details</th></tr></thead>
                    <tbody>
                    <?php foreach ($results['rows'] as $row):
                        $key = decryptedKey($row, $config);
                    ?>
                        <tr>
                            <td><span class="name"><?= escapeHtml($row['name'] ?: 'Unnamed customer') ?></span><br><span class="subtle"><?= escapeHtml($row['email'] ?: 'No email') ?></span></td>
                            <td><div class="key-line"><span class="mono"><?= escapeHtml($key) ?></span><button class="copy-button" type="button" data-copy="<?= escapeHtml($key) ?>">Copy</button></div></td>
                            <td><span class="status <?= statusClass((string)$row['status']) ?>"><?= escapeHtml($row['status']) ?></span></td>
                            <td><span class="status <?= statusClass((string)$row['delivery_status']) ?>"><?= escapeHtml($row['delivery_status']) ?></span></td>
                            <td><?= escapeHtml(sourceLabel($row)) ?></td>
                            <td>
                                <details>
                                    <summary>View</summary>
                                    <dl class="details-grid">
                                        <dt>Licence ID</dt><dd><?= (int)$row['id'] ?></dd>
                                        <dt>Key hint</dt><dd class="mono"><?= escapeHtml($row['license_key_hint']) ?></dd>
                                        <dt>Paddle customer</dt><dd class="mono"><?= escapeHtml($row['paddle_customer_id']) ?></dd>
                                        <dt>Transaction</dt><dd class="mono"><?= escapeHtml($row['paddle_transaction_id']) ?></dd>
                                        <dt>Product</dt><dd class="mono"><?= escapeHtml($row['paddle_product_id'] ?: '—') ?></dd>
                                        <dt>Price</dt><dd class="mono"><?= escapeHtml($row['paddle_price_id']) ?></dd>
                                        <dt>Seats</dt><dd><?= (int)$row['seat_count'] ?></dd>
                                        <dt>Purchase status</dt><dd><?= escapeHtml($row['purchase_status']) ?></dd>
                                        <dt>Purchased</dt><dd><?= escapeHtml($row['purchased_at']) ?> UTC</dd>
                                        <dt>Issued</dt><dd><?= escapeHtml($row['issued_at']) ?> UTC</dd>
                                        <dt>Email sent</dt><dd><?= escapeHtml($row['email_sent_at'] ?: '—') ?></dd>
                                        <dt>Email attempts</dt><dd><?= (int)$row['email_attempt_count'] ?></dd>
                                        <dt>Last email error</dt><dd><?= escapeHtml($row['last_email_error_code'] ?: '—') ?></dd>
                                        <dt>Revoked</dt><dd><?= escapeHtml($row['revoked_at'] ?: '—') ?></dd>
                                    </dl>
                                    <form class="danger-zone" method="post" action="/admin/?tab=licenses" onsubmit="return confirm('Permanently delete this customer and all associated licences and purchases? This cannot be undone.');">
                                        <input type="hidden" name="csrf_token" value="<?= escapeHtml($csrfToken) ?>">
                                        <input type="hidden" name="action" value="delete_customer">
                                        <input type="hidden" name="customer_id" value="<?= (int)$row['customer_id'] ?>">
                                        <p>This permanently removes the customer and every associated licence, purchase, and giveaway claim.</p>
                                        <button class="button danger" type="submit">Delete customer</button>
                                    </form>
                                </details>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                    <?php if ($results['rows'] === []): ?><tr><td class="empty" colspan="6">No licences match this search.</td></tr><?php endif; ?>
                    </tbody>
                </table>
            </div>

            <?php if ($results['pages'] > 1): ?>
                <div class="pager" aria-label="Licence pages">
                    <?php for ($pageNumber = 1; $pageNumber <= $results['pages']; $pageNumber++):
                        $pageUrl = '?tab=licenses&p=' . $pageNumber
                            . '&status=' . rawurlencode($status)
                            . '&q=' . rawurlencode($query);
                    ?>
                        <?php if ($pageNumber === $results['page']): ?>
                            <span class="current"><?= $pageNumber ?></span>
                        <?php else: ?>
                            <a href="<?= escapeHtml($pageUrl) ?>"><?= $pageNumber ?></a>
                        <?php endif; ?>
                    <?php endfor; ?>
                </div>
            <?php endif; ?>
        </section>

    <?php elseif ($tab === 'crashes'):
        $query = trim(is_string($_GET['q'] ?? null) ? $_GET['q'] : '');
        if (strlen($query) > 200) {
            $query = substr($query, 0, 200);
        }
        $reportIdentifier = strtolower(trim(
            is_string($_GET['report'] ?? null) ? $_GET['report'] : ''
        ));
        $selectedReport = $reportIdentifier !== ''
            ? $crashReportStore->find($reportIdentifier)
            : null;
        $page = max(1, (int)($_GET['p'] ?? 1));
        $results = is_array($selectedReport)
            ? null
            : $crashReportStore->search($query, $page);
    ?>
        <?php if (is_array($selectedReport)): ?>
            <section class="hero">
                <div>
                    <h2>Crash report</h2>
                    <p>Review the user-approved diagnostic report stored in iNoon’s private backend.</p>
                </div>
                <a class="button secondary" href="?tab=crashes">← All crash reports</a>
            </section>

            <section class="panel crash-report">
                <?php if (!$selectedReport['_valid']): ?>
                    <div class="message message-error">
                        <strong>Report could not be decoded</strong>
                        <span>The stored file is present, but it does not contain valid crash-report JSON.</span>
                    </div>
                <?php endif; ?>

                <dl class="crash-meta">
                    <div><dt>Received</dt><dd><?= escapeHtml($selectedReport['receivedAt'] ?: 'Unknown') ?></dd></div>
                    <div><dt>Crash date</dt><dd><?= escapeHtml($selectedReport['crashDate'] ?: 'Unknown') ?></dd></div>
                    <div><dt>App version</dt><dd><?= escapeHtml($selectedReport['appVersion'] ?: 'Unknown') ?></dd></div>
                    <div><dt>Build</dt><dd><?= escapeHtml($selectedReport['buildNumber'] ?: 'Unknown') ?></dd></div>
                    <div><dt>Operating system</dt><dd><?= escapeHtml($selectedReport['osVersion'] ?: 'Unknown') ?></dd></div>
                    <div><dt>Report ID</dt><dd class="mono"><?= escapeHtml($selectedReport['_identifier'] ?: 'Unknown') ?></dd></div>
                    <div><dt>Stored size</dt><dd><?= number_format(((int)$selectedReport['_size']) / 1024, 1) ?> KB</dd></div>
                </dl>

                <div>
                    <div class="section-head"><h3>What the user was doing</h3></div>
                    <div class="crash-notes"><?= escapeHtml($selectedReport['userDescription'] ?: 'No description was supplied.') ?></div>
                </div>

                <div>
                    <div class="section-head">
                        <h3>Crash log</h3>
                        <button
                            class="copy-button"
                            type="button"
                            data-copy-target="crash-log"
                        >Copy log</button>
                    </div>
                    <pre id="crash-log" class="crash-log"><?= escapeHtml($selectedReport['log'] ?: 'No crash log was stored.') ?></pre>
                </div>
            </section>
        <?php else: ?>
            <section class="hero">
                <div>
                    <h2>Crash reports</h2>
                    <p>Reports appear here only after a user reviews one in iNoon and chooses Send Report.</p>
                </div>
            </section>

            <?php if ($reportIdentifier !== ''): ?>
                <section class="message message-error">
                    <strong>Crash report not found</strong>
                    <span>The requested report does not exist or is no longer available.</span>
                </section>
            <?php endif; ?>

            <section class="panel">
                <form class="filters crash-filters" method="get">
                    <input type="hidden" name="tab" value="crashes">
                    <input
                        type="text"
                        name="q"
                        value="<?= escapeHtml($query) ?>"
                        placeholder="Search version, build, operating system, notes, report ID, or crash log"
                    >
                    <button class="button" type="submit">Search</button>
                </form>

                <div class="section-head">
                    <h3><?= (int)$results['total'] ?> report<?= $results['total'] === 1 ? '' : 's' ?></h3>
                    <?php if ($query !== ''): ?><a href="?tab=crashes">Clear search</a><?php endif; ?>
                </div>

                <div class="table-wrap">
                    <table>
                        <thead><tr><th>Received</th><th>Version</th><th>Operating system</th><th>User notes</th><th>Report</th></tr></thead>
                        <tbody>
                        <?php foreach ($results['rows'] as $report): ?>
                            <tr>
                                <td><?= escapeHtml($report['receivedAt'] ?: 'Unknown') ?></td>
                                <td>
                                    <span class="name"><?= escapeHtml($report['appVersion'] ?: 'Unknown') ?></span>
                                    <br><span class="subtle">Build <?= escapeHtml($report['buildNumber'] ?: 'Unknown') ?></span>
                                </td>
                                <td><?= escapeHtml($report['osVersion'] ?: 'Unknown') ?></td>
                                <td>
                                    <div class="crash-description">
                                        <?= escapeHtml($report['userDescription'] ?: 'No description supplied') ?>
                                    </div>
                                </td>
                                <td>
                                    <?php if ($report['_identifier'] !== ''): ?>
                                        <a class="button secondary" href="?tab=crashes&amp;report=<?= escapeHtml($report['_identifier']) ?>">View report</a>
                                    <?php else: ?>
                                        <span class="status status-failed">Invalid file</span>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        <?php if ($results['rows'] === []): ?><tr><td class="empty" colspan="5">No crash reports match this search.</td></tr><?php endif; ?>
                        </tbody>
                    </table>
                </div>

                <?php if ($results['pages'] > 1): ?>
                    <div class="pager" aria-label="Crash report pages">
                        <?php for ($pageNumber = 1; $pageNumber <= $results['pages']; $pageNumber++):
                            $pageUrl = '?tab=crashes&p=' . $pageNumber
                                . '&q=' . rawurlencode($query);
                        ?>
                            <?php if ($pageNumber === $results['page']): ?>
                                <span class="current"><?= $pageNumber ?></span>
                            <?php else: ?>
                                <a href="<?= escapeHtml($pageUrl) ?>"><?= $pageNumber ?></a>
                            <?php endif; ?>
                        <?php endfor; ?>
                    </div>
                <?php endif; ?>
            </section>
        <?php endif; ?>

    <?php elseif ($tab === 'promos'): ?>
        <?php require __DIR__ . '/promo-codes.php'; ?>
    <?php elseif ($tab === 'add'): ?>
        <section class="hero">
            <div>
                <h2>Issue a licence</h2>
                <p>Create an active perpetual licence without a Paddle transaction. It will work with app validation and licence retrieval immediately.</p>
            </div>
        </section>

        <section class="panel">
            <form method="post" action="/admin/?tab=add" autocomplete="off">
                <input type="hidden" name="csrf_token" value="<?= escapeHtml($csrfToken) ?>">
                <input type="hidden" name="action" value="create_license">
                <div class="form-grid">
                    <div class="field">
                        <label for="name">Customer name</label>
                        <input id="name" name="name" type="text" maxlength="200" required autocomplete="name" placeholder="Customer name">
                    </div>
                    <div class="field">
                        <label for="email">Customer email</label>
                        <input id="email" name="email" type="email" maxlength="320" required autocomplete="email" placeholder="customer@example.com">
                    </div>
                    <div class="field">
                        <label for="seat_count">Seats</label>
                        <input id="seat_count" name="seat_count" type="number" min="1" max="100" value="1" required>
                        <small>One seat is the normal perpetual licence.</small>
                    </div>
                    <label class="check">
                        <input type="checkbox" name="send_email" value="1" checked>
                        <span>
                            <strong>Email the licence now</strong>
                            <span>Send the standard iNoon licence email from info@inoon.app.</span>
                        </span>
                    </label>
                </div>
                <div class="actions">
                    <button class="button" type="submit">Issue perpetual licence</button>
                    <a class="button secondary" href="?tab=licenses">Cancel</a>
                </div>
            </form>
        </section>
    <?php endif; ?>

    <p class="footer">Protected iNoon operations · Times shown in UTC · <?= $isSandbox ? 'Sandbox data only' : 'Live account' ?></p>
</main>

<script>
document.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-copy], [data-copy-target]");
    if (!button) return;
    const original = button.textContent;
    const target = button.dataset.copyTarget
        ? document.getElementById(button.dataset.copyTarget)
        : null;
    const text = target ? target.textContent : (button.dataset.copy || "");
    try {
        await navigator.clipboard.writeText(text || "");
        button.textContent = "Copied";
    } catch {
        button.textContent = "Copy failed";
    }
    window.setTimeout(() => { button.textContent = original; }, 1400);
});
</script>
</body>
</html>
