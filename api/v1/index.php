<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/App.php';

ini_set('display_errors', '0');
// Exception messages can contain record contents or connection credentials.
ini_set('log_errors', '0');
try {
    $config = \Camp\config();
    (new \Camp\App(\Camp\database($config), $config))->run();
} catch (\Throwable) {
    http_response_code(503);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo '{"error":"Service unavailable"}';
}
