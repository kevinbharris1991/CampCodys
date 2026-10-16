<?php
declare(strict_types=1);

require dirname(__DIR__) . '/api/v1/bootstrap.php';

// Uses a disposable, uniquely named database and user. Never points the app at a live database.
// TEST_MYSQL_DSN must be an administrative MySQL DSN without dbname, including charset=utf8mb4.
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
function startServer(): string
{
    global $root, $servers;
    $socket = stream_socket_server('tcp://127.0.0.1:0', $error, $message);
    $address = stream_socket_get_name($socket, false);
    fclose($socket);
    $port = (int) substr(strrchr($address, ':'), 1);
    $process = proc_open([PHP_BINARY, '-S', '127.0.0.1:' . $port, $root . '/tests/router.php'], [
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
function login(int $user): string
{
    global $db, $password;
    $db->exec('DELETE FROM rate_limits');
    [$status, $response] = request('POST', '/auth/login', null, ['email' => "role$user@example.test", 'password' => $password]);
    expect($status === 200 && strlen($response['access_token'] ?? '') === 64 && $response['expires_in'] === 3600, 'login ' . $user);
    return $response['access_token'];
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
    [$code, $output] = cli(['client', 'Integration', 'all']);
    expect($code === 0, 'CLI client provisioning');
    $credentials = json_decode($output, true, 32, JSON_THROW_ON_ERROR);
    $clientId = $credentials['id'];
    $clientToken = $credentials['api_token'];
    $clientSecret = $credentials['api_secret'];
    expect($db->query('SELECT secret_hash FROM api_clients LIMIT 1')->fetchColumn() !== $clientSecret, 'client secret hashed');
    [$code, $output] = cli(['user', 'operator-created@example.test', 'Provisioned user'], $password . "\n");
    expect($code === 0 && isset(json_decode($output, true)['id']), 'CLI user provisioning');
    [$code] = cli(['membership', '14', '8']);
    expect($code === 0, 'CLI role membership');
    $base = startServer();
    expect(request('POST', '/auth/login', null, ['email' => 'role1@example.test', 'password' => $password], false)[0] === 401, 'login requires client credentials');
    expect(request('GET', '/resources', null, null, false)[0] === 401, 'resources require client credentials');
    expect(request('GET', '/resources')[0] === 401, 'resources require session');
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
    $camper = api('POST', '/records/campers', $adminSession, ['owner_id' => 12, 'display_name' => 'First camper'], 201)['data']['id'];
    $second = api('POST', '/records/campers', $adminSession, ['owner_id' => 13, 'display_name' => 'Second camper'], 201)['data']['id'];
    api('POST', '/records/campers', $adminSession, ['owner_id' => 12, 'display_name' => 'Camper', 'clinical_notes' => 'no'], 422);
    api('POST', '/records/campers', $adminSession, ['owner_id' => 99999, 'display_name' => 'Camper'], 422);
    api('GET', '/records/campers/' . $second, $guest, null, 404);
    $owned = api('GET', '/records/campers', $guest);
    expect(count($owned['data']) === 1 && $owned['data'][0]['id'] === $camper, 'guest lists only own campers');
    foreach ([1, 8, 9, 10, 11] as $role) {
        api('GET', '/records/campers', $sessions[$role], null, 403);
    }
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
    $grant = api('POST', '/records/grants', $finance, ['name' => 'Access fund', 'amount_cents' => 50000, 'fiscal_year' => '2027'], 201)['data']['id'];
    $application = api('POST', '/records/grant_applications', $guest, ['grant_id' => $grant, 'requested_cents' => 1000, 'statement' => 'Financial support request', 'status' => 'submitted'], 201)['data']['id'];
    api('GET', '/records/grant_applications/' . $application, $other, null, 404);
    api('POST', '/records/grant_applications', $guest, ['owner_id' => 13, 'grant_id' => $grant, 'requested_cents' => 1000, 'statement' => 'No', 'status' => 'submitted'], 403);
    api('PATCH', '/records/grant_applications/' . $application, $guest, ['status' => 'approved'], 403);
    api('POST', '/records/billing', $finance, ['owner_id' => 12, 'reference' => 'INV-1', 'amount_cents' => 1000, 'status' => 'pending'], 201);
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
    }
    foreach ([
        'policies' => ['title' => 'Arrival', 'body' => 'Arrival procedure', 'effective_on' => '2027-01-01'],
        'templates' => ['name' => 'Welcome', 'body' => 'Blank welcome template', 'version' => '1'],
        'staff_onboarding' => ['staff_reference' => 'STAFF-1', 'checklist' => ['Orientation'], 'status' => 'pending'],
        'compliance_reports' => ['period' => '2027', 'reviewed_items' => 20, 'open_items' => 2],
    ] as $resource => $fields) {
        api('POST', '/records/' . $resource, $adminSession, $fields, 201);
    }
    $prescription = api('POST', '/records/prescriptions', $clinical, ['camper_id' => $camper, 'medication' => 'Synthetic medication', 'instructions' => 'Verified prescriber direction'], 201)['data']['id'];
    $scheduleFields = ['prescription_id' => $prescription, 'scheduled_at' => '2099-06-01T12:00:00Z', 'dose_instructions' => 'Verified instruction', 'status' => 'verified'];
    $schedule = api('POST', '/records/medication_schedules', $clinical, ['camper_id' => $camper] + $scheduleFields, 201)['data']['id'];
    api('POST', '/records/medication_schedules', $clinical, ['camper_id' => $second] + $scheduleFields, 422);
    $sibling = api('POST', '/records/campers', $adminSession, ['owner_id' => 12, 'display_name' => 'Sibling camper'], 201)['data']['id'];
    api('POST', '/records/medication_schedules', $clinical, ['camper_id' => $sibling] + $scheduleFields, 422);
    api('POST', '/records/medication_administrations', $clinical, ['camper_id' => $camper, 'schedule_id' => $schedule, 'recorded_at' => '2099-06-01T12:05:00Z', 'status' => 'given'], 201);
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
    api('POST', '/records/behavioral_tracking', $sessions[4], ['camper_id' => $camper, 'observed_at' => '2026-10-16T12:00:00Z', 'observation' => 'Behavioral observation'], 201);
    api('POST', '/records/consultation_notes', $sessions[4], ['camper_id' => $camper, 'consulted_on' => '2026-10-16', 'note' => 'Consultation note'], 201);
    $safety = api('POST', '/records/camper_safety_alerts', $clinical, ['camper_id' => $camper, 'precaution' => 'Activity precaution', 'instructions' => 'Curated activity safety instruction', 'reviewed_on' => '2026-10-16'], 201)['data']['id'];
    api('GET', '/records/camper_safety_alerts/' . $safety, $program);
    api('GET', '/records/care_profiles/' . $care, $program, null, 403);
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
    api('POST', '/auth/logout', $guest);
    api('GET', '/auth/me', $guest, null, 401);
    $expired = login(12);
    $db->prepare('UPDATE sessions SET expires_at = UTC_TIMESTAMP() - INTERVAL 1 SECOND WHERE token_hash = ?')->execute([hash('sha256', $expired)]);
    api('GET', '/auth/me', $expired, null, 401);
    $db->exec('DELETE FROM rate_limits');
    for ($i = 0; $i < 10; $i++) {
        expect(request('POST', '/auth/login', null, ['email' => 'unknown@example.test', 'password' => 'incorrect-password'])[0] === 401, 'failed login ' . $i);
    }
    expect(request('POST', '/auth/login', null, ['email' => 'unknown@example.test', 'password' => 'incorrect-password'])[0] === 429, 'persistent login rate limit');
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
    echo "PASS: $count MySQL/HTTP integration assertions\n";
} finally {
    foreach ($servers as $server) {
        proc_terminate($server);
        proc_close($server);
    }
    $db = null;
    $admin->exec("DROP DATABASE IF EXISTS `$name`");
    $admin->exec('DROP USER IF EXISTS ' . $admin->quote($name) . "@'localhost'");
}
