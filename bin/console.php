<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}
require_once dirname(__DIR__) . '/api/v1/bootstrap.php';

function usage(): never
{
    echo <<<'HELP'
Trusted local operator commands (run from the repository; .env is required except key/help):
  php bin/console.php key
  php bin/console.php setup
  php bin/console.php roles
  php bin/console.php user EMAIL DISPLAY_NAME           (password on stdin)
  php bin/console.php password USER_ID                 (new password on stdin)
  php bin/console.php membership USER_ID ROLE_ID [remove]
  php bin/console.php assign COUNSELOR_USER_ID CAMPER_ID [remove]
  php bin/console.php seed-task RESOURCE                (flat JSON object on stdin)
  php bin/console.php client NAME RESOURCE_CSV_OR_all    (credentials displayed ONCE; expires in 90 days)
  php bin/console.php revoke-client CLIENT_ID
  php bin/console.php disable-user USER_ID
  php bin/console.php revoke-sessions USER_ID
  php bin/console.php cleanup
Passwords must be 12-1024 bytes. Never pass passwords on the command line.
Client scopes are explicit resource names, or the deliberately privileged literal "all".
Setup requires a pre-created MySQL database and DDL privileges. Runtime should use a
separate account with SELECT/INSERT/UPDATE/DELETE only; deny UPDATE/DELETE on audit_events.
Use a restricted local account for operations; no HTTP role or user provisioning exists.
Keep stdout credentials private, not in shell logs, browser source, or version control.
All record payloads are encrypted. Back up the encryption key separately from the database.
CLI cleanup removes only expired rate buckets and sessions expired/revoked over 30 days ago.
seed-task preloads only sanitation, sensory_setup, safety_notices, emergency_plans,
or emergency_alerts for teams with read/update access. It cannot provision camper data.

HELP;
    exit;
}

function positive(?string $value): int
{
    if ($value === null || !preg_match('/^[1-9][0-9]{0,17}$/D', $value)) {
        throw new \RuntimeException('Positive numeric ID required');
    }
    return (int) $value;
}

function passwordInput(): string
{
    $value = stream_get_contents(STDIN, 1026);
    if ($value === false) {
        throw new \RuntimeException('Password required on stdin');
    }
    $value = rtrim($value, "\r\n");
    if (strlen($value) < 12 || strlen($value) > 1024 || str_contains($value, "\0")) {
        throw new \RuntimeException('Password must be 12-1024 bytes');
    }
    return password_hash($value, PASSWORD_ARGON2ID);
}

$command = $argv[1] ?? 'help';
if ($command === 'help') {
    usage();
}
if ($command === 'key') {
    echo base64_encode(random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES)) . PHP_EOL;
    exit;
}
ini_set('display_errors', '0');
ini_set('log_errors', '0');
try {
    $config = \Camp\config();
    $db = \Camp\database($config);
    $query = static function (string $sql, array $params = []) use ($db): \PDOStatement {
        $stmt = $db->prepare($sql);
        $stmt->execute($params);
        return $stmt;
    };
    $audit = static function (string $event, ?string $resource = null, ?int $id = null) use ($query, $config): void {
        $query('INSERT INTO audit_events (event, resource, record_id, outcome, request_id, address_hash) VALUES (?, ?, ?, ?, ?, ?)', [
            'cli.' . $event, $resource, $id, 'success', bin2hex(random_bytes(16)),
            hash_hmac('sha256', 'trusted-local-cli', $config['key']),
        ]);
    };
    if ($command === 'setup') {
        $sql = file_get_contents(dirname(__DIR__) . '/api/v1/schema.sql');
        foreach (explode(';', $sql) as $statement) {
            if (trim($statement) !== '') {
                $db->exec($statement);
            }
        }
        $audit('setup');
        echo "Schema ready; all 12 roles seeded. No users or client credentials were created.\n";
        exit;
    }
    $db->beginTransaction();
    switch ($command) {
        case 'roles':
            $result = $query('SELECT id, name FROM roles ORDER BY id')->fetchAll();
            break;
        case 'user':
            $email = strtolower(trim($argv[2] ?? ''));
            $name = trim($argv[3] ?? '');
            if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 254 || $name === '' || mb_strlen($name) > 120 || !mb_check_encoding($name, 'UTF-8')) {
                throw new \RuntimeException('Valid email and display name required');
            }
            $query('INSERT INTO users (email, display_name, password_hash) VALUES (?, ?, ?)', [$email, $name, passwordInput()]);
            $result = ['id' => (int) $db->lastInsertId()];
            $audit('user.create', 'users', $result['id']);
            break;
        case 'password':
            $id = positive($argv[2] ?? null);
            if (!$query('SELECT id FROM users WHERE id = ? FOR UPDATE', [$id])->fetchColumn()) {
                throw new \RuntimeException('User not found');
            }
            $query('UPDATE users SET password_hash = ? WHERE id = ?', [passwordInput(), $id]);
            $query('UPDATE sessions SET revoked_at = UTC_TIMESTAMP() WHERE user_id = ?', [$id]);
            $audit('password.change', 'users', $id);
            $result = ['updated' => true];
            break;
        case 'membership':
            $user = positive($argv[2] ?? null);
            $role = positive($argv[3] ?? null);
            if (($argv[4] ?? '') === 'remove') {
                $query('DELETE FROM memberships WHERE user_id = ? AND role_id = ?', [$user, $role]);
                if ($role === 7) {
                    $query('DELETE FROM counselor_assignments WHERE user_id = ?', [$user]);
                }
            } elseif (isset($argv[4])) {
                throw new \RuntimeException('Use remove or omit the final argument');
            } else {
                $query('INSERT IGNORE INTO memberships (user_id, role_id) VALUES (?, ?)', [$user, $role]);
            }
            $query('UPDATE sessions SET revoked_at = UTC_TIMESTAMP() WHERE user_id = ?', [$user]);
            $audit('membership.change', 'users', $user);
            $result = ['updated' => true];
            break;
        case 'assign':
            $user = positive($argv[2] ?? null);
            $camper = positive($argv[3] ?? null);
            if (!$query("SELECT id FROM records WHERE id = ? AND resource = 'campers' FOR UPDATE", [$camper])->fetchColumn()
                || !$query('SELECT 1 FROM memberships WHERE user_id = ? AND role_id = 7', [$user])->fetchColumn()) {
                throw new \RuntimeException('A camper and counselor membership are required');
            }
            if (($argv[4] ?? '') === 'remove') {
                $query('DELETE FROM counselor_assignments WHERE user_id = ? AND camper_id = ?', [$user, $camper]);
            } elseif (isset($argv[4])) {
                throw new \RuntimeException('Use remove or omit the final argument');
            } else {
                $query('INSERT IGNORE INTO counselor_assignments (user_id, camper_id) VALUES (?, ?)', [$user, $camper]);
            }
            $audit('assignment.change', 'campers', $camper);
            $result = ['updated' => true];
            break;
        case 'seed-task':
            $resource = $argv[2] ?? '';
            if (!in_array($resource, ['sanitation', 'sensory_setup', 'safety_notices', 'emergency_plans', 'emergency_alerts'], true)) {
                throw new \RuntimeException('Only non-camper operational tasks may be seeded');
            }
            $raw = stream_get_contents(STDIN, 65537);
            if ($raw === false || strlen($raw) > 65536 || !json_decode($raw, false, 16, JSON_THROW_ON_ERROR) instanceof \stdClass) {
                throw new \RuntimeException('A bounded JSON object is required');
            }
            $payload = \Camp\validateFields(json_decode($raw, true, 16, JSON_THROW_ON_ERROR), \Camp\catalog()[$resource]);
            $query('INSERT INTO records (resource, payload) VALUES (?, ?)', [$resource, \Camp\encryptPayload($payload, $config['key'])]);
            $id = (int) $db->lastInsertId();
            $audit('task.seed', $resource, $id);
            $result = ['id' => $id];
            break;
        case 'client':
            $name = trim($argv[2] ?? '');
            $requested = $argv[3] ?? '';
            if ($name === '' || mb_strlen($name) > 120 || $requested === '') {
                throw new \RuntimeException('Name and explicit resource scopes required');
            }
            $resources = $requested === 'all' ? array_keys(\Camp\catalog()) : explode(',', $requested);
            $scopes = [];
            foreach ($resources as $resource) {
                if (!isset(\Camp\catalog()[$resource])) {
                    throw new \RuntimeException('Unknown resource scope');
                }
                $scopes[$resource] = ['read', 'create', 'update', 'delete'];
            }
            $token = bin2hex(random_bytes(24));
            $secret = bin2hex(random_bytes(32));
            $expires = gmdate('Y-m-d H:i:s', time() + 90 * 86400);
            $query('INSERT INTO api_clients (name, token, secret_hash, scopes, expires_at) VALUES (?, ?, ?, ?, ?)', [
                $name, $token, hash('sha256', $secret), json_encode($scopes, JSON_THROW_ON_ERROR), $expires,
            ]);
            $id = (int) $db->lastInsertId();
            $audit('client.create', 'api_clients', $id);
            $result = ['id' => $id, 'api_token' => $token, 'api_secret' => $secret, 'expires_at' => $expires];
            break;
        case 'revoke-client':
            $id = positive($argv[2] ?? null);
            $query('UPDATE api_clients SET active = 0 WHERE id = ?', [$id]);
            $query('UPDATE sessions SET revoked_at = UTC_TIMESTAMP() WHERE client_id = ?', [$id]);
            $audit('client.revoke', 'api_clients', $id);
            $result = ['revoked' => true];
            break;
        case 'disable-user':
        case 'revoke-sessions':
            $id = positive($argv[2] ?? null);
            if ($command === 'disable-user') {
                $query('UPDATE users SET active = 0 WHERE id = ?', [$id]);
            }
            $query('UPDATE sessions SET revoked_at = UTC_TIMESTAMP() WHERE user_id = ?', [$id]);
            $audit($command, 'users', $id);
            $result = ['revoked' => true];
            break;
        case 'cleanup':
            $query('DELETE FROM rate_limits WHERE expires_at < UTC_TIMESTAMP()');
            $query('DELETE FROM sessions WHERE expires_at < UTC_TIMESTAMP() - INTERVAL 30 DAY OR revoked_at < UTC_TIMESTAMP() - INTERVAL 30 DAY');
            $audit('cleanup');
            $result = ['cleaned' => true];
            break;
        default:
            throw new \RuntimeException('Unknown command; run php bin/console.php help');
    }
    $db->commit();
    echo json_encode($result, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR) . PHP_EOL;
} catch (\Throwable $e) {
    if (isset($db) && $db->inTransaction()) {
        $db->rollBack();
    }
    // Do not print SQL, credentials, submitted values or internal exception messages.
    fwrite(STDERR, "Operation failed. Check command arguments, configuration and database availability.\n");
    exit(1);
}
