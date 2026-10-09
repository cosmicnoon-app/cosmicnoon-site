<?php

// Install outside public_html as private/admin-config.php.
$domains = dirname(__DIR__, 2);
return [
    'inoon_private_root' => $domains . '/inoon.app/private',
    'matomo_root' => $domains . '/inoon.app/public_html/stats',
];
