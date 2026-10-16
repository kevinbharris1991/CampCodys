<?php
declare(strict_types=1);

// Test-only router: never use the test directory as a production document root.
if (str_starts_with(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), '/api/v1/')) {
    require dirname(__DIR__) . '/api/v1/index.php';
    return true;
}
http_response_code(404);
