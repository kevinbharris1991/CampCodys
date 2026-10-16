<?php
declare(strict_types=1);

require dirname(__DIR__) . '/api/v1/bootstrap.php';

$count = 0;
function check(bool $condition, string $name): void
{
    global $count;
    if (!$condition) {
        throw new RuntimeException('Failed: ' . $name);
    }
    $count++;
}
function invalid(callable $test, string $name): void
{
    try {
        $test();
    } catch (\Camp\ApiError) {
        check(true, $name);
        return;
    }
    check(false, $name);
}

function invalidConfig(string $name): void
{
    $rejected = false;
    try {
        \Camp\config(__DIR__);
    } catch (RuntimeException) {
        $rejected = true;
    }
    check($rejected, $name);
}

$key = random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
$payload = ['medication' => 'Private example', 'instructions' => 'Sensitive example'];
$encrypted = \Camp\encryptPayload($payload, $key);
check(!str_contains($encrypted, 'Private'), 'ciphertext does not contain plaintext');
check(\Camp\decryptPayload($encrypted, $key) === $payload, 'encrypted round trip');
check(\Camp\encryptPayload($payload, $key) !== $encrypted, 'fresh nonce');
$rejected = false;
try {
    \Camp\decryptPayload($encrypted, random_bytes(32));
} catch (RuntimeException) {
    $rejected = true;
}
check($rejected, 'wrong key rejected');
$raw = base64_decode($encrypted);
$raw[30] = chr(ord($raw[30]) ^ 1);
$rejected = false;
try {
    \Camp\decryptPayload(base64_encode($raw), $key);
} catch (RuntimeException) {
    $rejected = true;
}
check($rejected, 'tampering rejected');
$catalog = \Camp\catalog();
check(count(\Camp\roleGrants()) === 12, 'all roles mapped');
foreach (\Camp\roleGrants() as $resources) {
    foreach ($resources as $resource => $actions) {
        check(isset($catalog[$resource]), 'grant references known resource');
        foreach ($actions as $action => $scopes) {
            check(in_array($action, ['read', 'create', 'update', 'delete'], true), 'known action');
            check(!array_diff($scopes, ['all', 'own', 'assigned', 'published']), 'known scopes');
        }
    }
}
foreach ([1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12] as $role) {
    check(!isset(\Camp\roleGrants()[$role]['clinical_notes']), 'clinical separation ' . $role);
}
foreach ([8, 9, 10, 11] as $role) {
    check(!isset(\Camp\roleGrants()[$role]['campers']), 'no camper identity ' . $role);
}
check(!isset(\Camp\roleGrants()[7]['incidents']['read']), 'counselor incident create-only');
check(!isset(\Camp\roleGrants()[7]['activities']), 'counselor has no global schedule access');
check(\Camp\roleGrants()[7]['daily_logs']['read'] === ['assigned'], 'counselor assignment scope');
check(\Camp\roleGrants()[12]['prescriptions']['read'] === ['own'], 'guest prescription ownership');
$expected = [
    [1, 'public_content', ['read', 'create', 'update', 'delete']],
    [1, 'budgets', ['read', 'create', 'update']],
    [1, 'financial_approvals', ['read', 'create', 'update']],
    [1, 'audit_events', ['read']],
    [1, 'configuration', ['read']],
    [2, 'waivers', ['read', 'create', 'update', 'delete']],
    [2, 'consents', ['read', 'create', 'update', 'delete']],
    [2, 'demographics', ['read', 'create', 'update', 'delete']],
    [2, 'rosters', ['read', 'create', 'update', 'delete']],
    [2, 'policies', ['read', 'create', 'update', 'delete']],
    [2, 'templates', ['read', 'create', 'update', 'delete']],
    [3, 'medication_schedules', ['read', 'create', 'update']],
    [3, 'medication_administrations', ['read', 'create', 'update']],
    [3, 'medication_stock', ['read', 'create', 'update']],
    [3, 'clinical_incidents', ['read', 'create', 'update']],
    [4, 'behavioral_tracking', ['read', 'create', 'update']],
    [4, 'consultation_notes', ['read', 'create', 'update']],
    [4, 'behavior_health_context', ['read']],
    [5, 'accommodations', ['read', 'update']],
    [5, 'equipment', ['read', 'create', 'update', 'delete']],
    [5, 'facility_audits', ['read', 'create', 'update']],
    [5, 'work_orders', ['read', 'create']],
    [6, 'participation', ['read', 'update']],
    [6, 'camper_safety_alerts', ['read']],
    [8, 'work_orders', ['read', 'update']],
    [8, 'inspections', ['read', 'create', 'update']],
    [8, 'emergency_alerts', ['read', 'update']],
    [9, 'sanitation', ['read', 'update']],
    [9, 'sensory_setup', ['read', 'update']],
    [9, 'supply_requests', ['read', 'create']],
    [10, 'menus', ['read', 'create', 'update']],
    [10, 'special_meals', ['read', 'update']],
];
foreach ($expected as [$role, $resource, $actions]) {
    check(array_keys(\Camp\roleGrants()[$role][$resource]) === $actions, "exact role $role $resource actions");
}
foreach (\Camp\roleGrants()[12] as $resource => $actions) {
    check(!isset($actions['delete']), 'guests cannot physically delete ' . $resource);
}
check(\Camp\validateFields(['display_name' => 'Camper'], $catalog['campers']) === ['display_name' => 'Camper'], 'valid field');
invalid(fn() => \Camp\validateFields(['display_name' => 'Camper', 'clinical_note' => 'leak'], $catalog['campers']), 'unknown field');
invalid(fn() => \Camp\validateFields([], $catalog['campers']), 'required field');
invalid(fn() => \Camp\validateFields(['quantity' => '1', 'name' => 'Supply'], $catalog['supplies']), 'strict integer');
invalid(fn() => \Camp\validateFields(['quantity' => -1, 'name' => 'Supply'], $catalog['supplies']), 'integer bounds');
invalid(fn() => \Camp\validateFields(['recorded_on' => '2026-02-30', 'note' => 'x'], $catalog['clinical_notes']), 'real date');
invalid(fn() => \Camp\validateFields(['allergens' => ['milk' => 'yes']], $catalog['menus'], true), 'list shape');
invalid(fn() => \Camp\validateFields(['allergens' => [15]], $catalog['menus'], true), 'list element type');
invalid(fn() => \Camp\validateFields(['status' => 'confirmed'], $catalog['menus'], true), 'enum values');
invalid(fn() => \Camp\validateFields(['display_name' => "\0"], $catalog['campers']), 'control character');
invalid(fn() => \Camp\validateFields(['observed_at' => '2026-02-30T00:00:00Z', 'observation' => 'x'], $catalog['behavioral_tracking']), 'real datetime');
invalid(fn() => \Camp\validateFields(['observed_at' => '2026-10-16T25:00:00Z', 'observation' => 'x'], $catalog['behavioral_tracking']), 'valid hour');
check(\Camp\validateFields(['observed_at' => '2026-10-16T12:30:00Z', 'observation' => 'x'], $catalog['behavioral_tracking'])['observed_at'] === '2026-10-16T12:30:00Z', 'UTC datetime accepted');
check(\Camp\validateFields([], $catalog['campers'], true) === [], 'partial fields');

foreach (['APP_ENV', 'APP_REQUIRE_TLS', 'DB_DSN', 'DB_USER', 'DB_PASSWORD', 'APP_ENCRYPTION_KEY'] as $name) {
    putenv($name);
}
putenv('DB_SSL_CA');
invalidConfig('missing config fails closed');
putenv('APP_ENV=production');
putenv('APP_REQUIRE_TLS=false');
putenv('DB_DSN=mysql:host=localhost;dbname=example;charset=utf8mb4');
putenv('DB_USER=example');
putenv('DB_PASSWORD=example-test-only');
putenv('APP_ENCRYPTION_KEY=' . base64_encode($key));
invalidConfig('production cannot disable TLS');
putenv('APP_REQUIRE_TLS=true');
check(\Camp\config(__DIR__)['key'] === $key, 'valid config');
putenv('DB_DSN=mysql:host=database.example.test;dbname=example;charset=utf8mb4');
invalidConfig('production remote database requires verified TLS');
putenv('DB_DSN=mysql:host=localhost;host=database.example.test;dbname=example;charset=utf8mb4');
invalidConfig('duplicate host cannot bypass database TLS');
putenv('DB_DSN=mysql:host=localhost;dbname=example;charset=utf8mb4');
putenv('APP_ENCRYPTION_KEY=REPLACE_WITH_BASE64_32_BYTE_KEY');
invalidConfig('placeholder rejected');
echo "PASS: $count unit assertions\n";
