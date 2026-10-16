<?php
declare(strict_types=1);

require dirname(__DIR__) . '/api/v1/bootstrap.php';

// Uses a disposable, uniquely named database and user. Never points the app at a live database.
// TEST_MYSQL_DSN must be an administrative MySQL DSN without dbname, including charset=utf8mb4.
// Race barriers also require access to performance_schema.data_locks and data_lock_waits.
$dsn = getenv('TEST_MYSQL_DSN');
if (!$dsn || !str_starts_with($dsn, 'mysql:') || str_contains($dsn, 'dbname=')) {
    fwrite(STDERR, "Set TEST_MYSQL_DSN (no dbname), TEST_MYSQL_USER and TEST_MYSQL_PASSWORD for a disposable MySQL test server.\n");
    exit(1);
}
$root = dirname(__DIR__);
$admin = new PDO($dsn, getenv('TEST_MYSQL_USER') ?: 'root', getenv('TEST_MYSQL_PASSWORD') ?: '', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$name = 'camp_test_' . bin2hex(random_bytes(6));
$dbPassword = bin2hex(random_bytes(24));
$key = random_bytes(32);
$servers = [];
$count = 0;
$clientToken = bin2hex(random_bytes(24));
$clientSecret = bin2hex(random_bytes(32));
$base = '';
$mailCapture = $root . '/.local/mail-' . $name . '.txt';

function expect(bool $condition, string $name): void
{
    global $count;
    if (!$condition) {
        throw new RuntimeException('Failed: ' . $name);
    }
    $count++;
}
function request(string $method, string $path, ?string $session = null, array|string|null $body = null, bool $credentials = true, array $extra = []): array
{
    global $base, $clientToken, $clientSecret;
    $headers = ['Content-Type: application/json'];
    foreach ($extra as $header) {
        if (str_starts_with(strtolower($header), 'content-type:')) {
            $headers = [];
            break;
        }
    }
    if ($credentials) {
        $headers[] = 'X-API-Token: ' . $clientToken;
        $headers[] = 'X-API-Secret: ' . $clientSecret;
    }
    if ($session !== null) {
        $headers[] = 'Authorization: ' . 'Bea' . 'rer ' . $session;
    }
    $curl = curl_init($base . '/api/v1' . $path);
    curl_setopt_array($curl, [
        CURLOPT_CUSTOMREQUEST => $method, CURLOPT_HTTPHEADER => array_merge($headers, $extra),
        CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 10,
    ]);
    if ($body !== null) {
        curl_setopt($curl, CURLOPT_POSTFIELDS, is_string($body) ? $body : json_encode($body, JSON_THROW_ON_ERROR));
    }
    $raw = curl_exec($curl);
    $status = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
    curl_close($curl);
    if ($raw === false) {
        throw new RuntimeException('HTTP request failed');
    }
    return [$status, json_decode($raw, true, 32, JSON_THROW_ON_ERROR)];
}
function api(string $method, string $path, string $session, ?array $body = null, int $status = 200): array
{
    [$actual, $response] = request($method, $path, $session, $body);
    expect($actual === $status, "$method $path expected $status got $actual");
    return $response;
}
function cli(array $args, string $input = ''): array
{
    global $root;
    $process = proc_open(array_merge([PHP_BINARY, $root . '/bin/console.php'], $args), [
        0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w'],
    ], $pipes, $root);
    fwrite($pipes[0], $input);
    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    return [proc_close($process), $stdout, $stderr];
}
function startServer(bool $portal = false): string
{
    global $root, $servers, $portalSessionDir;
    $socket = stream_socket_server('tcp://127.0.0.1:0', $error, $message);
    $address = stream_socket_get_name($socket, false);
    fclose($socket);
    $port = (int) substr(strrchr($address, ':'), 1);
    if ($portal) {
        $portalSessionDir = $root . '/.local/portal-sessions-' . bin2hex(random_bytes(6));
        mkdir($portalSessionDir, 0700);
    }
    $command = $portal
        ? [PHP_BINARY, '-d', 'session.save_path=' . $portalSessionDir, '-S', '127.0.0.1:' . $port, '-t', $root]
        : [PHP_BINARY, '-d', 'sendmail_path=' . PHP_BINARY . ' ' . $root . '/tests/capture-mail.php',
            '-S', '127.0.0.1:' . $port, $root . '/tests/router.php'];
    $process = proc_open($command, [
        0 => ['pipe', 'r'], 1 => ['file', $root . '/.local/integration-server.log', 'a'],
        2 => ['file', $root . '/.local/integration-server.log', 'a'],
    ], $pipes, $root);
    fclose($pipes[0]);
    $servers[] = $process;
    for ($i = 0; $i < 60; $i++) {
        $probe = @fsockopen('127.0.0.1', $port);
        if ($probe) {
            fclose($probe);
            return 'http://127.0.0.1:' . $port;
        }
        usleep(50000);
    }
    throw new RuntimeException('Server did not start');
}

function portalRequest(CurlHandle $curl, string $url, ?array $fields = null): array
{
    curl_setopt($curl, CURLOPT_URL, $url);
    curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($curl, CURLOPT_MAXREDIRS, 5);
    if ($fields === null) {
        curl_setopt($curl, CURLOPT_HTTPGET, true);
    } else {
        curl_setopt_array($curl, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => http_build_query($fields)]);
    }
    $html = curl_exec($curl);
    if ($html === false) {
        throw new RuntimeException('Portal request failed');
    }
    return [curl_getinfo($curl, CURLINFO_RESPONSE_CODE), $html];
}

function portalCsrf(string $html): string
{
    if (!preg_match('/name="csrf" value="([a-f0-9]{64})"/D', $html, $match)) {
        throw new RuntimeException('Portal CSRF token missing');
    }
    return $match[1];
}

function portalResult(string $html): array
{
    if (!preg_match('~<h2>API result</h2>\s*<pre>(.*?)</pre>~s', $html, $match)) {
        throw new RuntimeException('Portal API result missing');
    }
    return json_decode(html_entity_decode($match[1], ENT_QUOTES | ENT_HTML5, 'UTF-8'), true, 32, JSON_THROW_ON_ERROR);
}

function portalNextForm(string $html, string $button): array
{
    preg_match_all('~<form\b[^>]*>(.*?)</form>~s', $html, $forms);
    foreach ($forms[1] as $form) {
        if (str_contains($form, '>' . $button . '</button>')) {
            preg_match_all('~<input\b[^>]*name="([^"]+)"[^>]*value="([^"]*)"[^>]*>~', $form, $fields, PREG_SET_ORDER);
            $result = [];
            foreach ($fields as $field) {
                $result[$field[1]] = html_entity_decode($field[2], ENT_QUOTES | ENT_HTML5, 'UTF-8');
            }
            return $result;
        }
    }
    throw new RuntimeException('Portal pagination control missing');
}

function login(int $user): string
{
    global $password;
    [$status, $response] = request('POST', '/auth/login', null, ['email' => "role$user@example.test", 'password' => $password]);
    expect($status === 200 && strlen($response['access_token'] ?? '') === 64 && $response['expires_in'] === 3600, 'login ' . $user);
    return $response['access_token'];
}

function waitForUserLock(PDO $admin, string $schema, bool $waiter, ?callable $tick = null): bool
{
    $sql = $waiter
        ? "SELECT 1 FROM performance_schema.data_lock_waits w JOIN performance_schema.data_locks l ON l.ENGINE_LOCK_ID = w.BLOCKING_ENGINE_LOCK_ID AND l.ENGINE = w.ENGINE WHERE l.OBJECT_SCHEMA = ? AND l.OBJECT_NAME = 'users' LIMIT 1"
        : "SELECT 1 FROM performance_schema.data_locks WHERE OBJECT_SCHEMA = ? AND OBJECT_NAME = 'users' AND LOCK_TYPE = 'RECORD' LIMIT 1";
    $query = $admin->prepare($sql);
    for ($i = 0; $i < 300; $i++) {
        if ($tick !== null) {
            $tick();
        }
        $query->execute([$schema]);
        if ($query->fetchColumn()) {
            return true;
        }
        usleep(20000);
    }
    return false;
}

function passwordResetRace(PDO $admin, PDO $db, string $schema, int $user, string $email, string $oldPassword, string $newPassword): void
{
    global $root, $base, $clientToken, $clientSecret;
    $process = null;
    $pipes = [];
    $multi = null;
    $curl = null;
    try {
        // The real CLI locks the user before reading stdin; withhold EOF to hold that lock.
        $process = proc_open([PHP_BINARY, $root . '/bin/console.php', 'password', (string) $user], [
            0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w'],
        ], $pipes, $root);
        expect(waitForUserLock($admin, $schema, false), 'concurrent reset CLI holds the user-row lock');
        $curl = curl_init($base . '/api/v1/auth/login');
        curl_setopt_array($curl, [
            CURLOPT_POST => true, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 10,
            CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'X-API-Token: ' . $clientToken, 'X-API-Secret: ' . $clientSecret],
            CURLOPT_POSTFIELDS => json_encode(['email' => $email, 'password' => $oldPassword], JSON_THROW_ON_ERROR),
        ]);
        $multi = curl_multi_init();
        curl_multi_add_handle($multi, $curl);
        $running = 0;
        $tick = static function () use ($multi, &$running): void {
            do {
                $result = curl_multi_exec($multi, $running);
            } while ($result === CURLM_CALL_MULTI_PERFORM);
        };
        expect(waitForUserLock($admin, $schema, true, $tick), 'login verified old hash and now waits for reset lock');
        fwrite($pipes[0], $newPassword . "\n");
        fclose($pipes[0]);
        unset($pipes[0]);
        foreach ($pipes as $pipe) {
            stream_get_contents($pipe);
            fclose($pipe);
        }
        $pipes = [];
        $exit = proc_close($process);
        $process = null;
        expect($exit === 0, 'concurrent CLI reset commits and revokes sessions');
        $deadline = microtime(true) + 10;
        do {
            $tick();
            if ($running) {
                curl_multi_select($multi, 0.05);
            }
        } while ($running && microtime(true) < $deadline);
        expect(!$running && curl_getinfo($curl, CURLINFO_RESPONSE_CODE) === 401, 'stale verified password cannot mint a post-reset session');
        $query = $db->prepare('SELECT password_hash FROM users WHERE id = ?');
        $query->execute([$user]);
        $currentHash = $query->fetchColumn();
        expect(password_verify($newPassword, $currentHash) && !password_verify($oldPassword, $currentHash), 'stale bcrypt rehash cannot overwrite the committed reset hash');
        $query = $db->prepare('SELECT COUNT(*) FROM sessions WHERE user_id = ? AND revoked_at IS NULL');
        $query->execute([$user]);
        expect((int) $query->fetchColumn() === 0, 'reset leaves no unrevoked stale-login session');
    } finally {
        foreach ($pipes as $pipe) {
            if (is_resource($pipe)) {
                fclose($pipe);
            }
        }
        if (is_resource($process)) {
            if (proc_get_status($process)['running']) {
                proc_terminate($process);
            }
            proc_close($process);
        }
        if ($multi !== null && $curl !== null) {
            curl_multi_remove_handle($multi, $curl);
        }
        if ($curl !== null) {
            curl_close($curl);
        }
        if ($multi !== null) {
            curl_multi_close($multi);
        }
    }
}

try {
    if (!is_dir($root . '/.local')) {
        mkdir($root . '/.local', 0700);
    }
    $admin->exec("CREATE DATABASE `$name` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
    $admin->exec('CREATE USER ' . $admin->quote($name) . "@'localhost' IDENTIFIED BY " . $admin->quote($dbPassword));
    $admin->exec("GRANT ALL PRIVILEGES ON `$name`.* TO " . $admin->quote($name) . "@'localhost'");
    foreach ([
        'APP_ENV' => 'test', 'APP_REQUIRE_TLS' => 'false', 'DB_DSN' => $dsn . ';dbname=' . $name,
        'DB_USER' => $name, 'DB_PASSWORD' => $dbPassword, 'APP_ENCRYPTION_KEY' => base64_encode($key),
        'APP_PUBLIC_URL' => 'https://registration.example.test/public/', 'APP_MAIL_FROM' => 'accounts@example.test',
        'TEST_MAIL_CAPTURE' => $mailCapture,
    ] as $variable => $value) {
        putenv("$variable=$value");
    }
    [$code] = cli(['setup']);
    expect($code === 0, 'CLI schema setup');
    $db = \Camp\database(\Camp\config());
    $db->exec("UPDATE roles SET name = 'Old executive label' WHERE id = 1");
    [$code] = cli(['setup']);
    expect($code === 0, 'CLI schema setup is idempotent');
    expect((int) $db->query('SELECT COUNT(*) FROM roles')->fetchColumn() === 12, '12 seeded roles');
    expect($db->query('SELECT name FROM roles ORDER BY id')->fetchAll(PDO::FETCH_COLUMN) === [
        'Executive Director', 'Administrative Directors', 'Medical & Nursing Staff',
        'Behavioral Support Services', 'Accessibility & Adaptive Services', 'Program Directors',
        "Counselors & DSP's", 'Facilities & Cabin Maintenance', 'Housekeeping',
        'Catering & Dietary Support', 'Finance & Accounting', 'Guest',
    ], 'exact requested role names, including migration of old labels');
    $password = bin2hex(random_bytes(16));
    $passwordHash = password_hash($password, PASSWORD_ARGON2ID);
    $insert = $db->prepare('INSERT INTO users (email, display_name, password_hash) VALUES (?, ?, ?)');
    for ($role = 1; $role <= 15; $role++) {
        $insert->execute(["role$role@example.test", 'Test role ' . $role, $passwordHash]);
        if ($role <= 12 || $role === 13) {
            $db->prepare('INSERT INTO memberships (user_id, role_id) VALUES (?, ?)')->execute([$role, min($role, 12)]);
        }
    }
    [$code] = cli(['setup']);
    expect($code === 0 && (int) $db->query('SELECT COUNT(*) FROM users')->fetchColumn() === 15,
        'additive setup preserves populated existing users');
    expect($db->query('SELECT password_hash FROM users WHERE id = 1')->fetchColumn() === $passwordHash,
        'setup preserves existing operator credentials');
    [$code, $output] = cli(['client', 'Integration', 'all']);
    expect($code === 0, 'CLI client provisioning');
    $credentials = json_decode($output, true, 32, JSON_THROW_ON_ERROR);
    $clientId = $credentials['id'];
    $clientToken = $credentials['api_token'];
    $clientSecret = $credentials['api_secret'];
    expect($db->query('SELECT secret_hash FROM api_clients LIMIT 1')->fetchColumn() !== $clientSecret, 'client secret hashed');
    [$code, $output] = cli(['user', 'operator-created@example.test', 'Provisioned user'], $password . "\n");
    expect($code === 0 && isset(json_decode($output, true)['id']), 'CLI user provisioning');
    $longPassword = bin2hex(random_bytes(36)) . str_repeat('z', 951) . 'x';
    [$code, $output] = cli(['user', 'long-password@example.test', 'Long password test'], $longPassword . "\n");
    expect($code === 0 && strlen($longPassword) === 1024, 'CLI accepts full 1024-byte password');
    $longHash = $db->query("SELECT password_hash FROM users WHERE email = 'long-password@example.test'")->fetchColumn();
    expect(password_get_info($longHash)['algoName'] === 'argon2id', 'CLI stores Argon2id, not bcrypt');
    $differentLongPassword = substr($longPassword, 0, 1023) . 'y';
    expect(password_verify($longPassword, $longHash) && !password_verify($differentLongPassword, $longHash), 'Argon2id distinguishes passwords after byte 72');
    [$code] = cli(['user', 'too-long@example.test', 'Too long test'], $longPassword . 'x');
    expect($code !== 0, 'CLI rejects password longer than 1024 bytes');
    [$code] = cli(['membership', '14', '8']);
    expect($code === 0, 'CLI role membership');
    $base = startServer();
    require __DIR__ . '/onboarding-cases.php';
    if (getenv('TEST_ONBOARDING_ONLY') === '1') {
        echo "PASS: $count onboarding integration assertions\n";
        return;
    }
    expect(request('POST', '/auth/login', null, ['email' => 'role1@example.test', 'password' => $password], false)[0] === 401, 'login requires client credentials');
    expect(request('GET', '/resources', null, null, false)[0] === 401, 'resources require client credentials');
    expect(request('GET', '/resources')[0] === 401, 'resources require session');
    expect(request('POST', '/auth/login', null, ['email' => 'long-password@example.test', 'password' => $longPassword])[0] === 200, 'HTTP login accepts exact long password');
    expect(request('POST', '/auth/login', null, ['email' => 'long-password@example.test', 'password' => $differentLongPassword])[0] === 401, 'HTTP login checks bytes beyond bcrypt boundary');
    expect(request('POST', '/auth/login', null, ['email' => 'long-password@example.test', 'password' => $longPassword . 'x'])[0] === 422, 'HTTP login enforces 1024-byte maximum');
    $legacyPassword = bin2hex(random_bytes(36));
    $insert->execute(['legacy-password@example.test', 'Legacy hash migration test', password_hash($legacyPassword, PASSWORD_BCRYPT)]);
    expect(request('POST', '/auth/login', null, ['email' => 'legacy-password@example.test', 'password' => $legacyPassword . 'ignored-suffix'])[0] === 401, 'ambiguous overlong bcrypt login fails closed');
    expect(request('POST', '/auth/login', null, ['email' => 'legacy-password@example.test', 'password' => $legacyPassword])[0] === 200, 'unambiguous legacy bcrypt login can migrate');
    $migratedHash = $db->query("SELECT password_hash FROM users WHERE email = 'legacy-password@example.test'")->fetchColumn();
    expect(password_get_info($migratedHash)['algoName'] === 'argon2id', 'legacy bcrypt hash upgrades to Argon2id');
    $raceOldPassword = bin2hex(random_bytes(16));
    $raceNewPassword = bin2hex(random_bytes(16));
    $insert->execute(['race-password@example.test', 'Password reset race test', password_hash($raceOldPassword, PASSWORD_BCRYPT)]);
    $raceUser = (int) $db->lastInsertId();
    $db->prepare('INSERT INTO sessions (user_id, client_id, token_hash, expires_at) VALUES (?, ?, ?, ?)')->execute([
        $raceUser, $clientId, hash('sha256', random_bytes(32)), gmdate('Y-m-d H:i:s', time() + 3600),
    ]);
    passwordResetRace($admin, $db, $name, $raceUser, 'race-password@example.test', $raceOldPassword, $raceNewPassword);
    expect(request('POST', '/auth/login', null, ['email' => 'race-password@example.test', 'password' => $raceOldPassword])[0] === 401, 'reset old password remains invalid');
    expect(request('POST', '/auth/login', null, ['email' => 'race-password@example.test', 'password' => $raceNewPassword])[0] === 200, 'reset new password remains usable');
    $sessions = [];
    for ($role = 1; $role <= 15; $role++) {
        $sessions[$role] = login($role);
    }
    $db->exec('DELETE FROM rate_limits');
    $guest = $sessions[12];
    $other = $sessions[13];
    $adminSession = $sessions[2];
    $clinical = $sessions[3];
    $program = $sessions[6];
    $counselor = $sessions[7];
    $kitchen = $sessions[10];
    $finance = $sessions[11];
    expect(request('POST', '/records/campers', $adminSession, '{bad json')[0] === 422, 'malformed JSON rejected');
    expect(request('POST', '/records/campers', $adminSession, '[]')[0] === 422, 'JSON array rejected');
    expect(request('POST', '/records/campers', $adminSession, str_repeat('a', 65537))[0] === 413, 'body size bounded');
    expect(request('POST', '/records/campers', $adminSession, '{}', true, ['Content-Type: text/plain'])[0] === 415, 'content type required');
    $me = api('GET', '/auth/me', $guest);
    expect($me['user']['id'] === 12 && $me['groups'][0]['id'] === 12, 'me identity and roles');
    expect(isset($me['permissions']['prescriptions']) && !isset($me['permissions']['clinical_notes']), 'guest permission map');
    $empty = api('GET', '/auth/me', $sessions[15]);
    expect($empty['permissions'] === [], 'no implicit grants without membership');
    api('GET', '/records/campers', $sessions[15], null, 403);
    $camper = api('POST', '/records/campers', $adminSession, ['owner_id' => 12, 'display_name' => 'First camper', 'arrival_date' => '2027-06-01', 'departure_date' => '2027-06-05'], 201)['data']['id'];
    $second = api('POST', '/records/campers', $adminSession, ['owner_id' => 13, 'display_name' => 'Second camper'], 201)['data']['id'];
    api('POST', '/records/campers', $adminSession, ['owner_id' => 12, 'display_name' => 'Camper', 'clinical_notes' => 'no'], 422);
    api('POST', '/records/campers', $adminSession, ['owner_id' => 99999, 'display_name' => 'Camper'], 422);
    api('GET', '/records/campers/' . $second, $guest, null, 404);
    $owned = api('GET', '/records/campers', $guest);
    expect(count($owned['data']) === 1 && $owned['data'][0]['id'] === $camper, 'guest lists only own campers');
    foreach ([1, 8, 9, 10, 11] as $role) {
        api('GET', '/records/campers', $sessions[$role], null, 403);
    }
    $directory = api('GET', '/records/camper_names/' . $camper, $kitchen)['data'];
    expect($directory === ['id' => $camper, 'display_name' => 'First camper'], 'dietary directory excludes ownership, dates and all other camper fields');
    expect(count(api('GET', '/records/camper_names', $kitchen)['data']) === 2, 'dietary directory can resolve camper names');
    api('GET', '/records/camper_names', $guest, null, 403);
    api('PATCH', '/records/camper_names/' . $camper, $kitchen, ['display_name' => 'No edit'], 403);
    $note = api('POST', '/records/clinical_notes', $clinical, ['camper_id' => $camper, 'note' => 'Confidential clinical example', 'recorded_on' => gmdate('Y-m-d')], 201)['data']['id'];
    foreach ([1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12] as $role) {
        api('GET', '/records/clinical_notes/' . $note, $sessions[$role], null, 403);
    }
    $care = api('POST', '/records/care_profiles', $clinical, ['camper_id' => $camper, 'care_instructions' => 'Minimum necessary instructions'], 201)['data']['id'];
    api('GET', '/records/care_profiles/' . $care, $counselor, null, 404);
    [$code] = cli(['assign', '7', (string) $camper]);
    expect($code === 0, 'CLI counselor assignment');
    api('GET', '/records/care_profiles/' . $care, $counselor);
    api('GET', '/records/campers/' . $second, $counselor, null, 404);
    api('GET', '/activities', $counselor, null, 403);
    $log = api('POST', '/records/daily_logs', $counselor, ['camper_id' => $camper, 'recorded_on' => gmdate('Y-m-d'), 'observation' => 'Daily observation'], 201)['data']['id'];
    api('GET', '/records/daily_logs/' . $log, $counselor);
    api('POST', '/records/daily_logs', $counselor, ['camper_id' => $second, 'recorded_on' => gmdate('Y-m-d'), 'observation' => 'Not assigned'], 403);
    $incident = api('POST', '/records/incidents', $counselor, ['camper_id' => $camper, 'occurred_on' => gmdate('Y-m-d'), 'report' => 'Incident example'], 201)['data'];
    expect(array_keys($incident) === ['id'], 'incident create receipt does not grant read');
    api('GET', '/records/incidents/' . $incident['id'], $counselor, null, 403);
    api('PATCH', '/records/daily_logs/' . $log, $counselor, ['observation' => 'Edited'], 403);
    foreach ([
        'reservations' => ['arrival_date' => '2027-06-01', 'departure_date' => '2027-06-05', 'status' => 'requested'],
        'accommodations' => ['request' => 'Accessible space', 'status' => 'requested'],
        'prescriptions' => ['medication' => 'Declared prescription', 'instructions' => 'Prescriber instructions'],
        'allergies' => ['allergen' => 'Milk', 'severity' => 'severe'],
    ] as $resource => $fields) {
        $id = api('POST', '/records/' . $resource, $guest, ['camper_id' => $camper] + $fields, 201)['data']['id'];
        api('GET', '/records/' . $resource . '/' . $id, $other, null, 404);
        api('POST', '/records/' . $resource, $guest, ['camper_id' => $second] + $fields, 403);
        api('PATCH', '/records/' . $resource . '/' . $id, $guest, ['camper_id' => $second], 422);
        api('PATCH', '/records/' . $resource . '/' . $id, $other, $fields, 404);
    }
    api('POST', '/records/reservations', $guest, ['camper_id' => $camper, 'arrival_date' => '2027-01-01', 'departure_date' => '2027-01-02', 'status' => 'confirmed'], 403);
    $confirmed = api('POST', '/records/reservations', $adminSession, ['camper_id' => $camper, 'arrival_date' => '2027-01-01', 'departure_date' => '2027-01-02', 'status' => 'confirmed'], 201)['data']['id'];
    api('PATCH', '/records/reservations/' . $confirmed, $guest, ['departure_date' => '2027-02-01'], 403);
    api('DELETE', '/records/reservations/' . $confirmed, $guest, null, 403);
    api('DELETE', '/records/reservations/' . $confirmed, $adminSession, null, 403);
    api('DELETE', '/records/campers/' . $camper, $adminSession, null, 403);
    api('GET', '/records/prescriptions', $sessions[4], null, 403);
    api('GET', '/records/care_profiles/' . $care, $sessions[4], null, 403);
    api('GET', '/records/allergies', $kitchen);
    api('GET', '/records/prescriptions', $kitchen, null, 403);
    $work = api('POST', '/records/work_orders', $sessions[5], ['location' => 'Building A', 'request' => 'Repair', 'status' => 'open'], 201)['data']['id'];
    api('PATCH', '/records/work_orders/' . $work, $sessions[8], ['status' => 'in_progress']);
    api('PATCH', '/records/work_orders/' . $work, $sessions[5], ['status' => 'closed'], 403);
    api('DELETE', '/records/work_orders/' . $work, $sessions[8], null, 403);
    api('POST', '/records/work_orders', $sessions[8], ['location' => 'Building A', 'request' => 'Repair', 'status' => 'open'], 403);
    api('POST', '/records/sanitation', $sessions[9], ['location' => 'Dining hall', 'task' => 'Clean', 'status' => 'open'], 403);
    [$code, $output] = cli(['seed-task', 'sanitation'], json_encode(['location' => 'Dining hall', 'task' => 'Clean', 'status' => 'open']));
    expect($code === 0, 'trusted CLI seeds sanitation task');
    $task = json_decode($output, true)['id'];
    api('PATCH', '/records/sanitation/' . $task, $sessions[9], ['status' => 'complete']);
    api('DELETE', '/records/sanitation/' . $task, $sessions[9], null, 403);
    $menuFields = ['name' => 'Lunch', 'service_date' => '2027-06-01', 'ingredients' => ['Rice', 'Milk'], 'allergens' => ['Milk'], 'status' => 'published'];
    $menu = api('POST', '/records/menus', $kitchen, $menuFields, 201)['data']['id'];
    $draft = api('POST', '/records/menus', $kitchen, array_replace($menuFields, ['status' => 'draft']), 201)['data']['id'];
    api('GET', '/records/menus/' . $draft, $guest, null, 404);
    $menus = api('GET', '/menus?camper_id=' . $camper, $guest);
    expect(count($menus['data']) === 1 && $menus['data'][0]['allergy_evaluation']['status'] === 'potential_conflict', 'guest menu allergy evaluation');
    api('GET', '/menus?camper_id=' . $second, $guest, null, 404);
    $profile = api('POST', '/records/dietary_profiles', $clinical, ['camper_id' => $camper, 'instructions' => 'Dietary sensitivity instruction', 'excluded_ingredients' => ['Sesame']], 201)['data']['id'];
    $otherProfile = api('POST', '/records/dietary_profiles', $clinical, ['camper_id' => $second, 'instructions' => 'Separate family sensitivity', 'excluded_ingredients' => ['Rice']], 201)['data']['id'];
    api('GET', '/records/dietary_profiles/' . $profile, $guest);
    api('GET', '/records/dietary_profiles/' . $otherProfile, $guest, null, 404);
    $sensitivityMenu = api('POST', '/records/menus', $kitchen, array_replace($menuFields, ['name' => 'Sesame lunch', 'ingredients' => ['sesame'], 'allergens' => []]), 201)['data']['id'];
    $evaluated = api('GET', '/menus?camper_id=' . $camper, $guest)['data'];
    $byId = array_column($evaluated, null, 'id');
    expect($byId[$sensitivityMenu]['allergy_evaluation']['status'] === 'potential_conflict', 'sensitivity exclusions match ingredients case-insensitively');
    $evaluated = api('GET', '/menus?camper_id=' . $second, $other)['data'];
    $byId = array_column($evaluated, null, 'id');
    expect($byId[$menu]['allergy_evaluation']['status'] === 'potential_conflict', 'sensitivity-only conflict works without allergy records');
    expect($byId[$sensitivityMenu]['allergy_evaluation']['status'] === 'no_declared_match', 'another family sensitivity never contaminates evaluation');
    $evaluated = api('GET', '/menus?camper_id=' . $camper, $kitchen)['data'];
    expect(count($evaluated) === 3, 'dietary staff can evaluate camper menus through minimal identity lookup');
    $special = api('POST', '/records/special_meals', $guest, ['camper_id' => $camper, 'menu_id' => $menu, 'request' => 'Milk-free meal', 'status' => 'requested'], 201)['data']['id'];
    api('GET', '/records/special_meals/' . $special, $other, null, 404);
    api('POST', '/records/special_meals', $guest, ['camper_id' => $camper, 'menu_id' => $draft, 'request' => 'No draft link', 'status' => 'requested'], 404);
    api('PATCH', '/records/special_meals/' . $special, $kitchen, ['status' => 'planned']);
    api('POST', '/records/special_meals', $kitchen, ['camper_id' => $camper, 'menu_id' => $menu, 'request' => 'No create', 'status' => 'requested'], 403);
    api('DELETE', '/records/special_meals/' . $special, $kitchen, null, 403);
    api('DELETE', '/records/menus/' . $menu, $kitchen, null, 403);
    $activityFields = ['name' => 'Adaptive games', 'scheduled_on' => '2099-06-01', 'capacity' => 1, 'status' => 'available'];
    $activity = api('POST', '/records/activities', $program, $activityFields, 201)['data']['id'];
    $signup = api('POST', '/activities/' . $activity . '/signup', $guest, ['camper_id' => $camper], 201)['data']['id'];
    api('POST', '/activities/' . $activity . '/signup', $guest, ['camper_id' => $camper], 409);
    api('POST', '/activities/' . $activity . '/signup', $other, ['camper_id' => $second], 409);
    api('POST', '/activities/' . $activity . '/signup', $guest, ['camper_id' => $second], 403);
    api('DELETE', '/records/activities/' . $activity, $program, null, 409);
    api('DELETE', '/records/activity_signups/' . $signup, $guest, null, 403);
    api('PATCH', '/records/activity_signups/' . $signup, $guest, ['status' => 'cancelled']);
    api('PATCH', '/records/activity_signups/' . $signup, $guest, ['status' => 'enrolled'], 403);
    $otherSignup = api('POST', '/activities/' . $activity . '/signup', $other, ['camper_id' => $second], 201)['data']['id'];
    api('GET', '/activities', $guest);
    $attendance = api('GET', '/records/participation?camper_id=' . $camper, $program)['data'];
    expect(count($attendance) === 1 && $attendance[0]['status'] === 'cancelled', 'signup synchronizes program participation');
    $otherAttendance = api('GET', '/records/participation?camper_id=' . $second, $program)['data'][0]['id'];
    api('PATCH', '/records/participation/' . $otherAttendance, $program, ['status' => 'attended']);
    api('PATCH', '/records/activity_signups/' . $otherSignup, $other, ['status' => 'enrolled']);
    expect(api('GET', '/records/participation/' . $otherAttendance, $program)['data']['status'] === 'attended', 'no-op signup update cannot erase attendance');
    api('PATCH', '/records/activity_signups/' . $otherSignup, $other, ['status' => 'cancelled'], 409);
    expect((int) $db->query('SELECT COUNT(*) FROM activity_enrollments')->fetchColumn() === 1, 'rejected cancellation preserves capacity accounting');
    api('GET', '/records/participation', $guest, null, 403);
    api('POST', '/records/participation', $program, ['camper_id' => $camper, 'activity_id' => $activity, 'status' => 'registered'], 403);
    $db->exec('DELETE FROM rate_limits');
    $grant = api('POST', '/records/grants', $finance, [
        'name' => 'Access fund', 'amount_cents' => 50000, 'fiscal_year' => '2027',
        'application_status' => 'available', 'application_instructions' => 'Submit a financial support application.',
    ], 201)['data']['id'];
    $internalGrant = api('POST', '/records/grants', $finance, ['name' => 'Internal fund allocation', 'amount_cents' => 90000, 'fiscal_year' => '2028'], 201)['data'];
    expect($internalGrant['application_status'] === 'internal', 'grant ledger defaults to unpublished internal state');
    $closedGrant = api('POST', '/records/grants', $finance, ['name' => 'Closed fund', 'amount_cents' => 70000, 'fiscal_year' => '2027', 'application_status' => 'closed'], 201)['data']['id'];
    api('GET', '/records/grants', $guest, null, 403);
    api('GET', '/records/grants/' . $grant, $guest, null, 403);
    $grantCatalog = api('GET', '/records/grant_opportunities', $guest)['data'];
    expect($grantCatalog === [[
        'id' => $grant, 'name' => 'Access fund', 'application_instructions' => 'Submit a financial support application.',
    ]], 'guest enumerates only available grants and no ledger amounts or fiscal fields');
    api('GET', '/records/grant_opportunities/' . $internalGrant['id'], $guest, null, 404);
    api('GET', '/records/grant_opportunities/' . $closedGrant, $guest, null, 404);
    api('PATCH', '/records/grant_opportunities/' . $grant, $guest, ['name' => 'Cannot publish'], 403);
    api('PATCH', '/records/grants/' . $internalGrant['id'], $guest, ['application_status' => 'available'], 403);
    foreach ([$internalGrant['id'], $closedGrant] as $unavailableGrant) {
        api('POST', '/records/grant_applications', $guest, ['grant_id' => $unavailableGrant, 'requested_cents' => 1000, 'statement' => 'Not available', 'status' => 'submitted'], 404);
    }
    $application = api('POST', '/records/grant_applications', $guest, ['grant_id' => $grant, 'requested_cents' => 1000, 'statement' => 'Financial support request', 'status' => 'submitted'], 201)['data']['id'];
    api('GET', '/records/grant_applications/' . $application, $other, null, 404);
    api('POST', '/records/grant_applications', $guest, ['owner_id' => 13, 'grant_id' => $grant, 'requested_cents' => 1000, 'statement' => 'No', 'status' => 'submitted'], 403);
    api('PATCH', '/records/grant_applications/' . $application, $guest, ['status' => 'approved'], 403);
    $bill = api('POST', '/records/billing', $finance, ['owner_id' => 12, 'reference' => 'INV-1', 'amount_cents' => 1000, 'status' => 'pending'], 201)['data']['id'];
    $ownBalance = api('GET', '/records/billing/' . $bill, $guest)['data'];
    expect($ownBalance['amount_cents'] === 1000 && $ownBalance['status'] === 'pending', 'guest can view own balance without changing payment state');
    api('GET', '/records/billing/' . $bill, $other, null, 404);
    api('POST', '/records/billing', $guest, ['reference' => 'INV-SELF', 'amount_cents' => 0, 'status' => 'paid'], 403);
    api('PATCH', '/records/billing/' . $bill, $guest, ['status' => 'paid'], 403);
    api('DELETE', '/records/billing/' . $bill, $guest, null, 403);
    api('POST', '/records/billing', $finance, ['reference' => 'INV-2', 'amount_cents' => 1000, 'status' => 'pending', 'card_number' => 'not-accepted'], 422);
    $report = api('POST', '/records/aggregate_reports', $finance, ['period' => '2027', 'occupancy_count' => 100, 'revenue_cents' => 100000], 201)['data']['id'];
    api('GET', '/records/aggregate_reports/' . $report, $sessions[1]);
    api('POST', '/records/aggregate_reports', $sessions[1], ['period' => '2027', 'occupancy_count' => 100, 'revenue_cents' => 100000], 403);
    api('PATCH', '/records/reservations/' . $confirmed, $guest, ['status' => 'cancelled']);
    api('DELETE', '/records/grant_applications/' . $application, $guest, null, 403);
    api('PATCH', '/records/grant_applications/' . $application, $sessions[1], ['status' => 'approved']);
    api('PATCH', '/records/grant_applications/' . $application, $guest, ['statement' => 'Cannot alter reviewed application'], 403);
    $ownApplication = api('POST', '/records/grant_applications', $sessions[1], [
        'grant_id' => $grant, 'requested_cents' => 500, 'statement' => 'Staff applicant', 'status' => 'submitted',
    ], 201)['data']['id'];
    api('PATCH', '/records/grant_applications/' . $ownApplication, $sessions[1], ['status' => 'approved'], 403);
    api('PATCH', '/records/grants/' . $grant, $finance, ['application_status' => 'closed']);
    api('GET', '/records/grant_opportunities/' . $grant, $guest, null, 404);
    expect(api('GET', '/records/grant_opportunities', $guest)['data'] === [], 'closed grant disappears from guest catalog');
    api('PATCH', '/records/grant_applications/' . $ownApplication, $finance, ['status' => 'approved']);
    $configuration = api('GET', '/records/configuration/1', $sessions[1])['data'];
    expect($configuration['session_ttl_seconds'] === 3600 && !isset($configuration['DB_PASSWORD'], $configuration['APP_ENCRYPTION_KEY']), 'configuration exposes only safe limits');
    api('PATCH', '/records/configuration/1', $sessions[1], ['environment' => 'production'], 403);
    $auditView = api('GET', '/records/audit_events?limit=3', $sessions[1]);
    expect(count($auditView['data']) === 3 && is_int($auditView['next_after']) && !isset($auditView['data'][0]['address_hash']), 'executive audit view has safe metadata and cursor');
    api('GET', '/records/audit_events/' . $auditView['data'][0]['id'], $sessions[1]);
    api('GET', '/records/audit_events', $guest, null, 403);
    api('GET', '/records/configuration', $adminSession, null, 403);
    $db->exec('DELETE FROM rate_limits');
    $content = api('POST', '/records/public_content', $sessions[1], ['title' => 'Camp mission', 'body' => 'Inclusive camp', 'status' => 'draft'], 201)['data']['id'];
    api('PATCH', '/records/public_content/' . $content, $sessions[1], ['status' => 'approved']);
    api('DELETE', '/records/public_content/' . $content, $sessions[1]);
    api('POST', '/records/budgets', $sessions[1], ['name' => 'Programs', 'fiscal_year' => '2027', 'amount_cents' => 100000], 201);
    $approval = api('POST', '/records/financial_approvals', $sessions[1], ['reference' => 'FIN-1', 'amount_cents' => 1000, 'status' => 'approved'], 201)['data']['id'];
    api('GET', '/records/financial_approvals/' . $approval, $finance);
    api('PATCH', '/records/financial_approvals/' . $approval, $finance, ['status' => 'declined'], 403);
    foreach ([
        'waivers' => ['document_reference' => 'WAIVER-1', 'status' => 'pending'],
        'consents' => ['purpose' => 'Transport', 'document_reference' => 'CONSENT-1', 'status' => 'pending'],
        'demographics' => ['contact_name' => 'Example family', 'contact_phone' => '555-0100'],
        'rosters' => ['cabin' => 'A', 'group_name' => 'Group 1'],
    ] as $resource => $fields) {
        $id = api('POST', '/records/' . $resource, $adminSession, ['camper_id' => $camper] + $fields, 201)['data']['id'];
        api('GET', '/records/' . $resource . '/' . $id, $adminSession);
        api('GET', '/records/' . $resource . '/' . $id, $sessions[1], null, 403);
        api('DELETE', '/records/' . $resource . '/' . $id, $adminSession, null, 403);
    }
    foreach ([
        'policies' => ['title' => 'Arrival', 'body' => 'Arrival procedure', 'effective_on' => '2027-01-01'],
        'templates' => ['name' => 'Welcome', 'body' => 'Blank welcome template', 'version' => '1'],
        'staff_onboarding' => ['staff_reference' => 'STAFF-1', 'checklist' => ['Orientation'], 'status' => 'pending'],
        'compliance_reports' => ['period' => '2027', 'reviewed_items' => 20, 'open_items' => 2],
    ] as $resource => $fields) {
        $id = api('POST', '/records/' . $resource, $adminSession, $fields, 201)['data']['id'];
        api('DELETE', '/records/' . $resource . '/' . $id, $adminSession, null, $resource === 'templates' ? 200 : 403);
    }
    $prescription = api('POST', '/records/prescriptions', $clinical, ['camper_id' => $camper, 'medication' => 'Synthetic medication', 'instructions' => 'Verified prescriber direction'], 201)['data']['id'];
    $scheduleFields = ['prescription_id' => $prescription, 'scheduled_at' => '2099-06-01T12:00:00Z', 'dose_instructions' => 'Verified instruction', 'status' => 'verified'];
    $schedule = api('POST', '/records/medication_schedules', $clinical, ['camper_id' => $camper] + $scheduleFields, 201)['data']['id'];
    $unusedSchedule = api('POST', '/records/medication_schedules', $clinical, ['camper_id' => $camper] + $scheduleFields, 201)['data']['id'];
    api('DELETE', '/records/medication_schedules/' . $unusedSchedule, $clinical);
    api('POST', '/records/medication_schedules', $clinical, ['camper_id' => $second] + $scheduleFields, 422);
    $sibling = api('POST', '/records/campers', $adminSession, ['owner_id' => 12, 'display_name' => 'Sibling camper'], 201)['data']['id'];
    api('POST', '/records/medication_schedules', $clinical, ['camper_id' => $sibling] + $scheduleFields, 422);
    $administration = api('POST', '/records/medication_administrations', $clinical, ['camper_id' => $camper, 'schedule_id' => $schedule, 'recorded_at' => '2099-06-01T12:05:00Z', 'status' => 'given'], 201)['data']['id'];
    api('DELETE', '/records/medication_schedules/' . $schedule, $clinical, null, 409);
    api('DELETE', '/records/medication_administrations/' . $administration, $clinical, null, 403);
    api('POST', '/records/medication_administrations', $clinical, ['camper_id' => $second, 'schedule_id' => $schedule, 'recorded_at' => '2099-06-01T12:05:00Z', 'status' => 'given'], 422);
    api('POST', '/records/medication_stock', $clinical, ['medication' => 'Synthetic medication', 'lot_reference' => 'LOT-1', 'quantity_units' => 10, 'expires_on' => '2099-12-01'], 201);
    $clinicalIncident = api('POST', '/records/clinical_incidents', $clinical, ['camper_id' => $camper, 'occurred_at' => '2026-10-16T12:00:00Z', 'clinical_report' => 'Clinical-only incident detail'], 201)['data']['id'];
    api('PATCH', '/records/clinical_incidents/' . $clinicalIncident, $clinical, ['follow_up' => 'Reviewed']);
    api('DELETE', '/records/clinical_incidents/' . $clinicalIncident, $clinical, null, 403);
    foreach ([1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12] as $role) {
        api('GET', '/records/clinical_incidents/' . $clinicalIncident, $sessions[$role], null, 403);
    }
    $context = api('POST', '/records/behavior_health_context', $clinical, ['camper_id' => $camper, 'relevant_precautions' => 'Curated relevant precaution only', 'reviewed_on' => '2026-10-16'], 201)['data']['id'];
    api('GET', '/records/behavior_health_context/' . $context, $sessions[4]);
    api('PATCH', '/records/behavior_health_context/' . $context, $sessions[4], ['relevant_precautions' => 'No clinical context editing'], 403);
    $tracking = api('POST', '/records/behavioral_tracking', $sessions[4], ['camper_id' => $camper, 'observed_at' => '2026-10-16T12:00:00Z', 'observation' => 'Behavioral observation'], 201)['data']['id'];
    api('DELETE', '/records/behavioral_tracking/' . $tracking, $sessions[4], null, 403);
    $supportPlan = api('POST', '/records/behavioral_plans', $sessions[4], ['camper_id' => $camper, 'support_instructions' => 'Support plan example'], 201)['data']['id'];
    api('DELETE', '/records/behavioral_plans/' . $supportPlan, $sessions[4]);
    $strategy = api('POST', '/records/consultation_notes', $sessions[4], ['camper_id' => $camper, 'consulted_on' => '2026-10-16', 'note' => 'Counselor-facing support strategy'], 201)['data']['id'];
    $unassignedStrategy = api('POST', '/records/consultation_notes', $sessions[4], ['camper_id' => $second, 'consulted_on' => '2026-10-16', 'note' => 'Unassigned camper strategy'], 201)['data']['id'];
    expect(api('GET', '/records/consultation_notes/' . $strategy, $counselor)['data']['note'] === 'Counselor-facing support strategy', 'counselor can read assigned consultation strategies');
    api('GET', '/records/consultation_notes/' . $unassignedStrategy, $counselor, null, 404);
    expect(array_column(api('GET', '/records/consultation_notes', $counselor)['data'], 'id') === [$strategy], 'counselor strategy listing excludes unassigned campers');
    api('PATCH', '/records/consultation_notes/' . $strategy, $counselor, ['note' => 'Not allowed'], 403);
    api('DELETE', '/records/consultation_notes/' . $strategy, $counselor, null, 403);
    api('POST', '/records/consultation_notes', $counselor, ['camper_id' => $camper, 'consulted_on' => '2026-10-16', 'note' => 'Not allowed'], 403);
    api('GET', '/records/behavioral_plans', $counselor, null, 403);
    api('GET', '/records/behavioral_tracking', $counselor, null, 403);
    $safety = api('POST', '/records/camper_safety_alerts', $clinical, ['camper_id' => $camper, 'precaution' => 'Activity precaution', 'instructions' => 'Curated activity safety instruction', 'reviewed_on' => '2026-10-16'], 201)['data']['id'];
    api('GET', '/records/camper_safety_alerts/' . $safety, $program);
    api('GET', '/records/care_profiles/' . $care, $program, null, 403);
    $adaptation = api('POST', '/records/activity_adaptations', $program, ['camper_id' => $camper, 'activity_id' => $activity, 'instructions' => 'Adaptive activity instructions'], 201)['data']['id'];
    api('PATCH', '/records/activity_adaptations/' . $adaptation, $program, ['instructions' => 'Reviewed adaptation']);
    api('DELETE', '/records/activity_adaptations/' . $adaptation, $program, null, 403);
    api('POST', '/records/accommodations', $sessions[5], ['camper_id' => $camper, 'request' => 'No create', 'status' => 'requested'], 403);
    $facilityAudit = api('POST', '/records/facility_audits', $sessions[5], ['location' => 'Building A', 'audited_on' => '2026-10-16', 'findings' => 'Accessible entry', 'status' => 'open'], 201)['data']['id'];
    api('PATCH', '/records/facility_audits/' . $facilityAudit, $sessions[5], ['status' => 'complete']);
    api('DELETE', '/records/facility_audits/' . $facilityAudit, $sessions[5], null, 403);
    $inspection = api('POST', '/records/inspections', $sessions[8], ['location' => 'Building A', 'inspected_on' => '2026-10-16', 'findings' => 'Inspection complete', 'status' => 'complete'], 201)['data']['id'];
    api('DELETE', '/records/inspections/' . $inspection, $sessions[8], null, 403);
    [$code, $output] = cli(['seed-task', 'emergency_alerts'], json_encode(['location' => 'Building A', 'instructions' => 'Use assembly point', 'status' => 'active']));
    expect($code === 0, 'trusted CLI seeds emergency alert');
    $alert = json_decode($output, true)['id'];
    api('PATCH', '/records/emergency_alerts/' . $alert, $sessions[8], ['status' => 'resolved']);
    api('POST', '/records/emergency_alerts', $sessions[8], ['location' => 'Building A', 'instructions' => 'No create', 'status' => 'active'], 403);
    [$code, $output] = cli(['seed-task', 'sensory_setup'], json_encode(['location' => 'Sensory room', 'instructions' => 'Low light', 'status' => 'open']));
    expect($code === 0, 'trusted CLI seeds sensory task');
    api('PATCH', '/records/sensory_setup/' . json_decode($output, true)['id'], $sessions[9], ['status' => 'complete']);
    $supply = api('POST', '/records/supply_requests', $sessions[9], ['item' => 'Cleaning cloths', 'quantity' => 20, 'location' => 'Dining hall'], 201)['data']['id'];
    api('GET', '/records/supply_requests/' . $supply, $sessions[9]);
    api('PATCH', '/records/supply_requests/' . $supply, $sessions[9], ['quantity' => 30], 403);
    api('DELETE', '/records/supply_requests/' . $supply, $sessions[9], null, 403);
    $db->exec('DELETE FROM rate_limits');
    // Imported/legacy arbitrary JSON must not bypass output field allowlists.
    $db->prepare('UPDATE records SET payload = ? WHERE id = ?')->execute([\Camp\encryptPayload($menuFields + ['clinical_note' => 'DO NOT EXPOSE'], $key), $menu]);
    $menuResponse = api('GET', '/records/menus/' . $menu, $guest);
    expect(!isset($menuResponse['data']['clinical_note']), 'projection rejects unknown stored fields');
    $db->prepare('UPDATE records SET payload = ? WHERE id = ?')->execute([\Camp\encryptPayload($menuFields, $key), $menu]);
    $stored = $db->query('SELECT payload FROM records')->fetchAll(PDO::FETCH_COLUMN);
    expect(!str_contains(implode('', $stored), 'Confidential'), 'health data encrypted at rest');
    $audit = $db->query('SELECT * FROM audit_events')->fetchAll();
    expect(count($audit) > 100 && !str_contains(json_encode($audit), 'Confidential'), 'persistent audit excludes health payloads');
    expect((int) $db->query('SELECT COUNT(*) FROM sessions WHERE LENGTH(token_hash) = 64')->fetchColumn() >= 15, 'session tokens hashed');
    // Membership union without hidden administrator privileges.
    [$code] = cli(['membership', '14', '9']);
    expect($code === 0, 'CLI additive membership');
    $sessions[14] = login(14);
    $permissions = api('GET', '/auth/me', $sessions[14])['permissions'];
    expect(isset($permissions['work_orders'], $permissions['sanitation']) && !isset($permissions['campers']), 'additive least-privilege union');
    [$code] = cli(['assign', '7', (string) $camper, 'remove']);
    expect($code === 0, 'CLI assignment removal');
    api('GET', '/records/care_profiles/' . $care, $counselor, null, 404);
    [$code] = cli(['password', '14'], bin2hex(random_bytes(16)) . "\n");
    expect($code === 0, 'CLI password rotation');
    api('GET', '/auth/me', $sessions[14], null, 401);
    [$code] = cli(['disable-user', '15']);
    expect($code === 0, 'CLI user disable');
    api('GET', '/auth/me', $sessions[15], null, 401);
    [$code, $output] = cli(['client', 'Limited', 'menus']);
    expect($code === 0, 'scoped client');
    $limited = json_decode($output, true);
    $fullToken = $clientToken;
    $fullSecret = $clientSecret;
    $clientToken = $limited['api_token'];
    $clientSecret = $limited['api_secret'];
    api('GET', '/auth/me', $guest, null, 401);
    $limitedGuest = login(12);
    $limitedMe = api('GET', '/auth/me', $limitedGuest);
    expect(array_keys($limitedMe['permissions']) === ['menus'], 'client scopes intersect role grants');
    api('GET', '/records/campers', $limitedGuest, null, 403);
    [$code] = cli(['revoke-client', (string) $limited['id']]);
    expect($code === 0, 'CLI client revocation');
    api('GET', '/auth/me', $limitedGuest, null, 401);
    $clientToken = $fullToken;
    $clientSecret = $fullSecret;
    $db->exec('DELETE FROM rate_limits');
    $portalActivity = api('POST', '/records/activities', $program, array_replace($activityFields, ['name' => 'Portal adaptive games', 'capacity' => 2]), 201)['data']['id'];
    api('POST', '/records/special_meals', $guest, ['camper_id' => $sibling, 'menu_id' => $menu, 'request' => 'SIBLING PRIVATE MEAL', 'status' => 'requested'], 201);
    api('POST', '/records/special_meals', $other, ['camper_id' => $second, 'menu_id' => $menu, 'request' => 'OTHER FAMILY PRIVATE MEAL', 'status' => 'requested'], 201);
    $portalAssertionsStart = $count;
    putenv('APP_ENV=development');
    putenv('PORTAL_API_BASE_URL=' . $base . '/api/v1');
    putenv('PORTAL_API_TOKEN=' . $clientToken);
    putenv('PORTAL_API_SECRET=' . $clientSecret);
    putenv('PORTAL_TERMS_URL=https://policies.example.test/terms');
    putenv('PORTAL_PRIVACY_URL=https://policies.example.test/privacy');
    $portalUrl = startServer(true) . '/public/index.php';
    putenv('APP_ENV=test');
    $browser = curl_init();
    curl_setopt_array($browser, [CURLOPT_RETURNTRANSFER => true, CURLOPT_COOKIEFILE => '', CURLOPT_TIMEOUT => 15]);
    [$status, $html] = portalRequest($browser, $portalUrl);
    expect($status === 200 && str_contains($html, 'Staff &amp; guest sign in'), 'portal serves login form with configured process environment');
    $beforeLoginCsrf = portalCsrf($html);
    [$status, $html] = portalRequest($browser, $portalUrl, [
        'csrf' => $beforeLoginCsrf, 'action' => 'login', 'email' => 'role12@example.test', 'password' => $password,
    ]);
    expect($status === 200 && str_contains($html, 'Signed in as Test role 12.'), 'portal login reaches authenticated API');
    expect(portalCsrf($html) !== $beforeLoginCsrf, 'portal rotates CSRF after successful login');
    expect(!str_contains($html, $clientToken) && !str_contains($html, $clientSecret) && !str_contains($html, $password), 'portal never renders client credentials or password');
    $portalSession = (int) $db->query('SELECT MAX(id) FROM sessions WHERE user_id = 12')->fetchColumn();
    [$status, $html] = portalRequest($browser, $portalUrl, [
        'csrf' => portalCsrf($html), 'action' => 'record', 'resource' => 'campers', 'method' => 'GET', 'record_id' => '',
    ]);
    expect($status === 200 && str_contains($html, 'First camper') && !str_contains($html, 'Second camper'), 'portal camper lookup respects household ownership');
    [$status, $html] = portalRequest($browser, $portalUrl, [
        'csrf' => portalCsrf($html), 'action' => 'record', 'resource' => 'special_meals', 'method' => 'POST', 'record_id' => '',
        'payload' => json_encode(['camper_id' => $camper, 'menu_id' => $menu, 'request' => 'Portal milk-free <b>request</b>', 'status' => 'requested']),
    ]);
    $portalMeal = portalResult($html)['data'];
    expect($status === 200 && $portalMeal['camper_id'] === $camper && $portalMeal['status'] === 'requested', 'portal flat-JSON editor creates own special meal');
    [$status, $html] = portalRequest($browser, $portalUrl, [
        'csrf' => portalCsrf($html), 'action' => 'menus', 'camper_id' => $camper,
    ]);
    expect($status === 200 && str_contains($html, '<s>Lunch</s>') && str_contains($html, '<s>Sesame lunch</s>'), 'portal strikes allergy and sensitivity conflicts');
    expect(str_contains($html, 'Your special meal') && str_contains($html, 'Portal milk-free &lt;b&gt;request&lt;/b&gt;'), 'portal displays own special meal with HTML escaping');
    expect(!str_contains($html, 'SIBLING PRIVATE MEAL') && !str_contains($html, 'OTHER FAMILY PRIVATE MEAL'), 'portal meal view filters both camper and family ownership');
    expect(!str_contains($html, 'Portal milk-free <b>request</b>'), 'portal special-meal content cannot inject markup');
    [$status, $html] = portalRequest($browser, $portalUrl, [
        'csrf' => portalCsrf($html), 'action' => 'activities',
    ]);
    expect($status === 200 && str_contains($html, 'Portal adaptive games'), 'portal activity listing reaches API');
    [$status, $html] = portalRequest($browser, $portalUrl, [
        'csrf' => portalCsrf($html), 'action' => 'signup', 'record_id' => $portalActivity, 'camper_id' => $camper,
    ]);
    $portalSignup = portalResult($html)['data'];
    expect($status === 200 && $portalSignup['camper_id'] === $camper && $portalSignup['activity_id'] === $portalActivity, 'portal enrolls own camper through signup route');
    $portalEnrollment = $db->prepare('SELECT COUNT(*) FROM activity_enrollments WHERE activity_id = ? AND camper_id = ?');
    $portalEnrollment->execute([$portalActivity, $camper]);
    expect((int) $portalEnrollment->fetchColumn() === 1, 'portal signup persists enrollment in MySQL');
    // Seed bounded synthetic pages directly; all UI reads still go through the real scoped API.
    $pageFixtures = [
        'menus' => [null, null, 'published', array_replace($menuFields, ['name' => 'Portal paged menu'])],
        'special_meals' => [12, $camper, '', ['menu_id' => $menu, 'request' => 'Portal paged meal', 'status' => 'requested']],
        'activities' => [null, null, 'available', array_replace($activityFields, ['name' => 'Portal paged activity'])],
        'reservations' => [12, $camper, '', ['arrival_date' => '2099-06-01', 'departure_date' => '2099-06-05', 'status' => 'requested']],
    ];
    $fixtureInsert = $db->prepare('INSERT INTO records (resource, owner_id, camper_id, visibility, payload) VALUES (?, ?, ?, ?, ?)');
    $fixtureLink = $db->prepare("INSERT INTO record_links (record_id, field_name, target_id) VALUES (?, 'menu_id', ?)");
    $db->beginTransaction();
    for ($i = 1; $i <= 55; $i++) {
        foreach ($pageFixtures as $resource => [$fixtureOwner, $fixtureCamper, $visibility, $payload]) {
            foreach (['name', 'request'] as $field) {
                if (isset($payload[$field])) {
                    $payload[$field] .= ' ' . $i;
                }
            }
            $payload = \Camp\validateFields($payload, \Camp\catalog()[$resource]);
            $fixtureInsert->execute([$resource, $fixtureOwner, $fixtureCamper, $visibility, \Camp\encryptPayload($payload, $key)]);
            if ($resource === 'special_meals') {
                $fixtureLink->execute([(int) $db->lastInsertId(), $menu]);
            }
        }
    }
    $db->commit();
    [$status, $html] = portalRequest($browser, $portalUrl, [
        'csrf' => portalCsrf($html), 'action' => 'menus', 'camper_id' => $camper,
    ]);
    $firstMenuPage = portalResult($html);
    expect($status === 200 && count($firstMenuPage['data']) === 50
        && str_contains($html, 'Next menus') && str_contains($html, 'Next special meals'), 'portal exposes both menu and special-meal pagination');
    $nextMenus = portalNextForm($html, 'Next menus');
    [$status, $html] = portalRequest($browser, $portalUrl, $nextMenus);
    $nextMenuPage = portalResult($html);
    expect($status === 200 && $nextMenuPage['data'] && $nextMenuPage['next_after'] === null
        && min(array_column($nextMenuPage['data'], 'id')) > (int) $nextMenus['menu_after'], 'portal advances menus without repeating records');
    $nextSpecialMeals = portalNextForm($html, 'Next special meals');
    expect($nextSpecialMeals['menu_after'] === $nextMenus['menu_after'], 'special-meal navigation preserves independent menu cursor');
    [$status, $html] = portalRequest($browser, $portalUrl, $nextSpecialMeals);
    expect($status === 200 && str_contains($html, 'Portal paged meal 55')
        && !str_contains($html, 'Portal paged meal 1 (') && portalResult($html)['data'] === $nextMenuPage['data'], 'portal advances special meals while preserving menu page');
    [$status, $html] = portalRequest($browser, $portalUrl, ['csrf' => portalCsrf($html), 'action' => 'activities']);
    expect($status === 200 && count(portalResult($html)['data']) === 50 && str_contains($html, 'Next activities'), 'portal exposes available-activity pagination');
    $nextActivities = portalNextForm($html, 'Next activities');
    [$status, $html] = portalRequest($browser, $portalUrl, $nextActivities);
    $nextActivityPage = portalResult($html);
    expect($status === 200 && $nextActivityPage['data'] && $nextActivityPage['next_after'] === null
        && min(array_column($nextActivityPage['data'], 'id')) > (int) $nextActivities['after'], 'portal advances available activities without repeating records');
    [$status, $html] = portalRequest($browser, $portalUrl, [
        'csrf' => portalCsrf($html), 'action' => 'record', 'resource' => 'reservations', 'method' => 'GET', 'record_id' => '',
    ]);
    $firstRecordPage = portalResult($html);
    expect($status === 200 && count($firstRecordPage['data']) === 50 && is_int($firstRecordPage['next_after']), 'portal generic record listing returns usable cursor');
    [$status, $html] = portalRequest($browser, $portalUrl, [
        'csrf' => portalCsrf($html), 'action' => 'record', 'resource' => 'reservations', 'method' => 'GET',
        'record_id' => '', 'after' => $firstRecordPage['next_after'],
    ]);
    $nextRecordPage = portalResult($html);
    expect($status === 200 && $nextRecordPage['data'] && $nextRecordPage['next_after'] === null
        && min(array_column($nextRecordPage['data'], 'id')) > $firstRecordPage['next_after'], 'portal generic record editor forwards page cursor correctly');
    [$status, $html] = portalRequest($browser, $portalUrl, [
        'csrf' => portalCsrf($html), 'action' => 'logout',
    ]);
    expect($status === 200 && str_contains($html, 'Staff &amp; guest sign in') && !str_contains($html, 'Signed in as'), 'portal logout returns to login view');
    $revoked = $db->prepare('SELECT revoked_at FROM sessions WHERE id = ?');
    $revoked->execute([$portalSession]);
    $revocationTime = $revoked->fetchColumn();
    expect(is_string($revocationTime) && $revocationTime !== '', 'portal logout revokes API session');
    $sharedPortalUsers = [];
    for ($role = 1; $role <= 12; $role++) {
        [$status, $html] = portalRequest($browser, $portalUrl, [
            'csrf' => portalCsrf($html), 'action' => 'login', 'email' => "role$role@example.test", 'password' => $password,
        ]);
        expect($status === 200 && str_contains($html, 'Signed in as Test role ' . $role . '.'), 'shared portal egress allows valid login ' . $role);
        $sharedPortalUsers[] = $role;
        [$status, $html] = portalRequest($browser, $portalUrl, ['csrf' => portalCsrf($html), 'action' => 'logout']);
        expect($status === 200 && str_contains($html, 'Staff &amp; guest sign in'), 'shared portal user can sign out ' . $role);
    }
    expect(count(array_unique($sharedPortalUsers)) > 10, 'more than ten distinct valid portal users authenticate without resetting rate counters');
    require __DIR__ . '/portal-onboarding-cases.php';
    curl_close($browser);
    $portalAssertions = $count - $portalAssertionsStart;
    api('POST', '/auth/logout', $guest);
    api('GET', '/auth/me', $guest, null, 401);
    $expired = login(12);
    $db->prepare('UPDATE sessions SET expires_at = UTC_TIMESTAMP() - INTERVAL 1 SECOND WHERE token_hash = ?')->execute([hash('sha256', $expired)]);
    api('GET', '/auth/me', $expired, null, 401);
    $db->exec('DELETE FROM rate_limits');
    for ($i = 0; $i < 15; $i++) {
        expect(request('POST', '/auth/login', null, ['email' => 'unknown@example.test', 'password' => 'incorrect-password'])[0] === 401, 'failed login ' . $i);
    }
    expect(request('POST', '/auth/login', null, ['email' => 'unknown@example.test', 'password' => 'incorrect-password'])[0] === 429, 'persistent account-level brute-force rate limit');
    $db->exec('DELETE FROM rate_limits');
    for ($i = 0; $i < 2; $i++) {
        expect(request('POST', '/auth/login', null, ['email' => "unknown-network-$i@example.test", 'password' => 'incorrect-password'])[0] === 401, 'network budget records actual credential failure ' . $i);
    }
    $failureBucket = static fn(int $window): string => hash('sha256', 'login-failures:'
        . hash_hmac('sha256', '127.0.0.1', $key) . ':' . $window);
    $window = intdiv(time(), 900);
    $failureCount = $db->prepare('SELECT COALESCE(SUM(hits), 0) FROM rate_limits WHERE bucket IN (?, ?)');
    $failureCount->execute([$failureBucket($window), $failureBucket($window - 1)]);
    expect((int) $failureCount->fetchColumn() === 2, 'network failure budget counts failures only');
    $seedBudget = $db->prepare('INSERT INTO rate_limits (bucket, hits, expires_at) VALUES (?, 100, ?) ON DUPLICATE KEY UPDATE hits = 100');
    foreach ([$window, $window + 1] as $budgetWindow) {
        $seedBudget->execute([$failureBucket($budgetWindow), gmdate('Y-m-d H:i:s', time() + 1800)]);
    }
    expect(request('POST', '/auth/login', null, ['email' => 'another-network-failure@example.test', 'password' => 'incorrect-password'], true, [
        'X-Forwarded-For: 203.0.113.99', 'Forwarded: for=203.0.113.99',
    ])[0] === 429, 'exhausted network failure budget throttles failures and ignores spoofed forwarding headers');
    $failureCount->execute([$failureBucket($window), $failureBucket($window + 1)]);
    $beforeSuccess = (int) $failureCount->fetchColumn();
    expect(request('POST', '/auth/login', null, ['email' => 'role2@example.test', 'password' => $password])[0] === 200, 'valid credentials remain usable after shared network failure budget is exhausted');
    $failureCount->execute([$failureBucket($window), $failureBucket($window + 1)]);
    expect((int) $failureCount->fetchColumn() === $beforeSuccess, 'successful authentication does not consume network failure budget');
    $db->exec('DELETE FROM rate_limits');
    putenv('APP_ENV=production');
    putenv('APP_REQUIRE_TLS=true');
    $base = startServer();
    expect(request('GET', '/auth/me', $clinical, null, true, ['X-Forwarded-Proto: https', 'Forwarded: proto=https'])[0] === 403, 'untrusted proxy headers cannot bypass TLS');
    putenv('APP_ENV=test');
    putenv('APP_REQUIRE_TLS=false');
    $db->prepare('UPDATE api_clients SET expires_at = UTC_TIMESTAMP() - INTERVAL 1 SECOND WHERE id = ?')->execute([$clientId]);
    $base = startServer();
    api('GET', '/auth/me', $clinical, null, 401);
    [$code] = cli(['cleanup']);
    expect($code === 0, 'CLI cleanup');
    echo "PASS: $count MySQL/HTTP/portal integration assertions ($portalAssertions portal assertions)\n";
} finally {
    if (is_file($mailCapture)) {
        unlink($mailCapture);
    }
    foreach ($servers as $server) {
        proc_terminate($server);
        proc_close($server);
    }
    if (isset($portalSessionDir) && is_dir($portalSessionDir)) {
        foreach (glob($portalSessionDir . '/sess_*') as $sessionFile) {
            unlink($sessionFile);
        }
        rmdir($portalSessionDir);
    }
    $db = null;
    $admin->exec("DROP DATABASE IF EXISTS `$name`");
    $admin->exec('DROP USER IF EXISTS ' . $admin->quote($name) . "@'localhost'");
}
