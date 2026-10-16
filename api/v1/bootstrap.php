<?php
declare(strict_types=1);

namespace Camp;

require_once __DIR__ . '/catalog.php';
require_once __DIR__ . '/Auth.php';

final class ApiError extends \RuntimeException
{
    public function __construct(public readonly int $status, string $message)
    {
        parent::__construct($message);
    }
}

function config(?string $root = null): array
{
    $file = ($root ?? dirname(__DIR__, 2)) . '/.env';
    $values = [];
    if (is_file($file)) {
        foreach (file($file, FILE_IGNORE_NEW_LINES) as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }
            if (!preg_match('/^([A-Z][A-Z0-9_]*)=(.*)$/D', $line, $match)) {
                throw new \RuntimeException('Invalid configuration');
            }
            $values[$match[1]] = trim($match[2], " \t\"'");
        }
    }
    foreach (['APP_ENV', 'APP_REQUIRE_TLS', 'DB_DSN', 'DB_USER', 'DB_PASSWORD', 'APP_ENCRYPTION_KEY'] as $key) {
        $value = getenv($key);
        if ($value !== false) {
            $values[$key] = $value;
        }
        $sslCa = getenv('DB_SSL_CA');
        if ($sslCa !== false) {
            $values['DB_SSL_CA'] = $sslCa;
        }
        if (!isset($values[$key]) || $values[$key] === '' || str_contains($values[$key], 'REPLACE_WITH')) {
            throw new \RuntimeException('Missing configuration');
        }
    }
    foreach (['APP_PUBLIC_URL', 'APP_MAIL_FROM'] as $name) {
        $value = getenv($name);
        if ($value !== false) {
            $values[$name] = $value;
        }
        $values[$name] ??= '';
    }
    $key = base64_decode($values['APP_ENCRYPTION_KEY'], true);
    if ($key === false || strlen($key) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES
        || count(array_unique(str_split($key))) < 8
        || !in_array($values['APP_ENV'], ['production', 'development', 'test'], true)
        || !in_array($values['APP_REQUIRE_TLS'], ['true', 'false'], true)
        || ($values['APP_ENV'] === 'production' && $values['APP_REQUIRE_TLS'] !== 'true')
        || !str_starts_with($values['DB_DSN'], 'mysql:')
        || !str_contains($values['DB_DSN'], 'charset=utf8mb4')) {
        throw new \RuntimeException('Unsafe configuration');
    }
    preg_match_all('/(?:^|;)host=([^;]+)/', substr($values['DB_DSN'], 6), $hosts);
    $remote = (bool) array_diff($hosts[1], ['localhost', '127.0.0.1', '::1']);
    if (($values['APP_ENV'] === 'production' && $remote && empty($values['DB_SSL_CA']))
        || (!empty($values['DB_SSL_CA']) && !is_readable($values['DB_SSL_CA']))) {
        throw new \RuntimeException('Verified database TLS required');
    }
    $values['key'] = $key;
    if ($values['APP_PUBLIC_URL'] !== '' || $values['APP_MAIL_FROM'] !== '') {
        $url = parse_url($values['APP_PUBLIC_URL']);
        if (!$url || !filter_var($values['APP_PUBLIC_URL'], FILTER_VALIDATE_URL)
            || !isset($url['host'], $url['scheme']) || isset($url['user']) || isset($url['pass'])
            || isset($url['query']) || isset($url['fragment']) || ($url['path'] ?? '') !== '/public/'
            || preg_match('/[\x00-\x20\x7f]/', $values['APP_PUBLIC_URL'])
            || !in_array($url['scheme'], ['https', 'http'], true)
            || ($values['APP_ENV'] === 'production' && $url['scheme'] !== 'https')
            || !filter_var($values['APP_MAIL_FROM'], FILTER_VALIDATE_EMAIL)
            || preg_match('/[\r\n]/', $values['APP_MAIL_FROM'])) {
            throw new \RuntimeException('Unsafe registration configuration');
        }
    }
    return $values;
}

function database(array $config): \PDO
{
    $options = [
        \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
        \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
        \PDO::ATTR_EMULATE_PREPARES => false,
        \PDO::MYSQL_ATTR_MULTI_STATEMENTS => false,
    ];
    if (!empty($config['DB_SSL_CA'])) {
        $options[\PDO::MYSQL_ATTR_SSL_CA] = $config['DB_SSL_CA'];
        $options[\PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT] = true;
    }
    $pdo = new \PDO($config['DB_DSN'], $config['DB_USER'], $config['DB_PASSWORD'], $options);
    if (!empty($config['DB_SSL_CA'])) {
        $cipher = $pdo->query("SHOW STATUS LIKE 'Ssl_cipher'")->fetch();
        if (!$cipher || ($cipher['Value'] ?? '') === '') {
            throw new \RuntimeException('Database TLS was not established');
        }
    }
    $pdo->exec("SET time_zone = '+00:00'");
    return $pdo;
}

function encryptPayload(array $payload, string $key): string
{
    $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    return base64_encode($nonce . sodium_crypto_secretbox(json_encode($payload, JSON_THROW_ON_ERROR), $nonce, $key));
}

function decryptPayload(string $encrypted, string $key): array
{
    $raw = base64_decode($encrypted, true);
    if ($raw === false || strlen($raw) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
        throw new \RuntimeException('Invalid encrypted record');
    }
    $plain = sodium_crypto_secretbox_open(substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES), substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES), $key);
    if ($plain === false) {
        throw new \RuntimeException('Invalid encrypted record');
    }
    return json_decode($plain, true, 32, JSON_THROW_ON_ERROR);
}

function projectPayload(string $encrypted, array $definition, string $key): array
{
    $payload = array_intersect_key(decryptPayload($encrypted, $key), $definition['fields']);
    try {
        return validateFields($payload, $definition);
    } catch (ApiError) {
        throw new \RuntimeException('Invalid stored record');
    }
}

function validateFields(array $body, array $definition, bool $partial = false): array
{
    foreach ($body as $name => $value) {
        if (!isset($definition['fields'][$name])) {
            throw new ApiError(422, 'Unknown field');
        }
        $field = $definition['fields'][$name];
        $valid = match ($field['type']) {
            'text' => is_string($value) && mb_check_encoding($value, 'UTF-8')
                && mb_strlen(trim($value)) > 0 && mb_strlen($value) <= $field['max']
                && !preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F]/', $value),
            'date' => is_string($value) && preg_match('/^\d{4}-\d{2}-\d{2}$/D', $value)
                && ($d = \DateTimeImmutable::createFromFormat('!Y-m-d', $value)) && $d->format('Y-m-d') === $value,
            'datetime' => is_string($value) && preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/D', $value)
                && ($d = \DateTimeImmutable::createFromFormat('!Y-m-d\TH:i:s\Z', $value, new \DateTimeZone('UTC')))
                && $d->format('Y-m-d\TH:i:s\Z') === $value,
            'boolean' => is_bool($value),
            'integer' => is_int($value) && $value >= $field['min'] && $value <= $field['max'],
            'reference' => is_int($value) && $value > 0,
            'enum' => is_string($value) && in_array($value, $field['values'], true),
            'list' => is_array($value) && array_is_list($value) && count($value) <= $field['max']
                && array_all_strings($value),
            default => false,
        };
        if (!$valid) {
            throw new ApiError(422, 'Invalid field value');
        }
    }
    if (!$partial) {
        foreach ($definition['required'] as $name) {
            if (!array_key_exists($name, $body)) {
                throw new ApiError(422, 'Missing required field');
            }
        }
    }
    return $body;
}

function array_all_strings(array $values): bool
{
    foreach ($values as $value) {
        if (!is_string($value) || trim($value) === '' || mb_strlen($value) > 160
            || !mb_check_encoding($value, 'UTF-8') || preg_match('/[\x00-\x1F]/', $value)) {
            return false;
        }
    }
    return true;
}
