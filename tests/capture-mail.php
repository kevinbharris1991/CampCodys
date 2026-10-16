<?php
declare(strict_types=1);

// Native mail() invokes this CLI transport only through the integration server's PHP INI.
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}
$path = getenv('TEST_MAIL_CAPTURE');
if (!$path || dirname($path) !== dirname(__DIR__) . '/.local') {
    exit(1);
}
file_put_contents($path, stream_get_contents(STDIN), FILE_APPEND | LOCK_EX);
