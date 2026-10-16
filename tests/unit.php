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
// RFC 4226/6238 SHA-1 reference secret and counters (six-digit truncation).
$totpSecret = \Camp\base32Encode('12345678901234567890');
check($totpSecret === 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 'RFC base32 encoding');
foreach ([0 => '755224', 1 => '287082', 2 => '359152', 3 => '969429', 4 => '338314', 5 => '254676'] as $step => $code) {
    check(\Camp\totpCode($totpSecret, $step) === $code, 'RFC HOTP counter ' . $step);
}
check(\Camp\totpCode($totpSecret, 1) === '287082', 'RFC 6238 time 59 truncated to six digits');
check(\Camp\totpStep($totpSecret, '287082', -1, 59) === 1, 'TOTP current window');
check(\Camp\totpStep($totpSecret, '755224', -1, 59) === 0, 'TOTP previous window');
check(\Camp\totpStep($totpSecret, '359152', -1, 59) === 2, 'TOTP next window');
check(\Camp\totpStep($totpSecret, '287082', 1, 59) === null, 'TOTP replay rejected');
check(\Camp\totpStep($totpSecret, '755224', 1, 59) === null, 'TOTP older step rejected');
check(\Camp\totpStep($totpSecret, '969429', -1, 59) === null, 'TOTP outside window rejected');
check(\Camp\totpStep($totpSecret, '12345', -1, 59) === null, 'TOTP exactly six digits');
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
check(\Camp\projectPayload(\Camp\encryptPayload(['display_name' => 'Camper', 'clinical_note' => 'Never expose'], $key), $catalog['camper_names'], $key) === ['display_name' => 'Camper'], 'directory projects only a validated display name');
$rejected = false;
try {
    \Camp\projectPayload(\Camp\encryptPayload(['display_name' => ['clinical_note' => 'Never expose']], $key), $catalog['camper_names'], $key);
} catch (RuntimeException) {
    $rejected = true;
}
check($rejected, 'nested arbitrary JSON in a named field fails closed');
$publicGrant = \Camp\projectPayload(\Camp\encryptPayload([
    'name' => 'Access scholarship', 'amount_cents' => 123456, 'fiscal_year' => '2027',
    'application_status' => 'available', 'application_instructions' => 'Submit your application.',
], $key), $catalog['grant_opportunities'], $key);
check($publicGrant === ['name' => 'Access scholarship', 'application_instructions' => 'Submit your application.'], 'grant catalog projection excludes all finance and publication-control fields');
check(!isset(\Camp\roleGrants()[12]['grants']), 'guest cannot access grant funding ledger');
check($catalog['grant_applications']['fields']['grant_id']['target'] === 'grant_opportunities', 'guest applications reference safe grant catalog');
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
check(\Camp\roleGrants()[7]['consultation_notes']['read'] === ['assigned'], 'counselor strategies are assignment-scoped');
check(!isset(\Camp\roleGrants()[7]['behavioral_plans']) && !isset(\Camp\roleGrants()[7]['behavioral_tracking']), 'counselors cannot read full behavioral plans or tracking');
check(\Camp\roleGrants()[12]['prescriptions']['read'] === ['own'], 'guest prescription ownership');
$expected = [
    [1, 'public_content', ['read', 'create', 'update', 'delete']],
    [1, 'budgets', ['read', 'create', 'update']],
    [1, 'financial_approvals', ['read', 'create', 'update']],
    [1, 'audit_events', ['read']],
    [1, 'configuration', ['read']],
    [1, 'grant_opportunities', ['read']],
    [2, 'campers', ['read', 'create', 'update']],
    [2, 'reservations', ['read', 'create', 'update']],
    [2, 'waivers', ['read', 'create', 'update']],
    [2, 'consents', ['read', 'create', 'update']],
    [2, 'demographics', ['read', 'create', 'update']],
    [2, 'rosters', ['read', 'create', 'update']],
    [2, 'policies', ['read', 'create', 'update']],
    [2, 'staff_onboarding', ['read', 'create', 'update']],
    [2, 'compliance_reports', ['read', 'create', 'update']],
    [2, 'templates', ['read', 'create', 'update', 'delete']],
    [3, 'medication_schedules', ['read', 'create', 'update', 'delete']],
    [3, 'medication_administrations', ['read', 'create', 'update']],
    [3, 'medication_stock', ['read', 'create', 'update']],
    [3, 'clinical_incidents', ['read', 'create', 'update']],
    [4, 'behavioral_tracking', ['read', 'create', 'update']],
    [4, 'behavioral_plans', ['read', 'create', 'update', 'delete']],
    [4, 'consultation_notes', ['read', 'create', 'update']],
    [4, 'behavior_health_context', ['read']],
    [5, 'accommodations', ['read', 'update']],
    [5, 'equipment', ['read', 'create', 'update', 'delete']],
    [5, 'facility_audits', ['read', 'create', 'update']],
    [5, 'work_orders', ['read', 'create']],
    [6, 'participation', ['read', 'update']],
    [6, 'activity_adaptations', ['read', 'create', 'update']],
    [6, 'camper_safety_alerts', ['read']],
    [7, 'consultation_notes', ['read']],
    [8, 'work_orders', ['read', 'update']],
    [8, 'inspections', ['read', 'create', 'update']],
    [8, 'emergency_alerts', ['read', 'update']],
    [9, 'sanitation', ['read', 'update']],
    [9, 'sensory_setup', ['read', 'update']],
    [9, 'supply_requests', ['read', 'create']],
    [10, 'menus', ['read', 'create', 'update']],
    [10, 'special_meals', ['read', 'update']],
    [10, 'camper_names', ['read']],
    [12, 'dietary_profiles', ['read']],
    [12, 'billing', ['read']],
    [12, 'grant_opportunities', ['read']],
    [11, 'grant_opportunities', ['read']],
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
putenv('APP_PUBLIC_URL');
putenv('APP_MAIL_FROM');
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
putenv('APP_PUBLIC_URL=https://camp.example.test/public/');
putenv('APP_MAIL_FROM=accounts@example.test');
check(\Camp\config(__DIR__)['APP_MAIL_FROM'] === 'accounts@example.test', 'registration config from process environment');
foreach ([
    'http://camp.example.test/public/', '//camp.example.test/public/', 'https://camp.example.test/public',
    'https://camp.example.test/public/?evil=1', 'https://camp.example.test/public/#evil',
    'https://user@camp.example.test/public/', 'https://camp.example.test/other/',
] as $url) {
    putenv('APP_PUBLIC_URL=' . $url);
    invalidConfig('unsafe registration origin rejected');
}
putenv('APP_PUBLIC_URL=https://camp.example.test/public/');
putenv("APP_MAIL_FROM=accounts@example.test\r\nBcc:bad@example.test");
invalidConfig('mail header injection rejected');
putenv('APP_MAIL_FROM=accounts@example.test');
putenv('DB_DSN=mysql:host=database.example.test;dbname=example;charset=utf8mb4');
invalidConfig('production remote database requires verified TLS');
putenv('DB_DSN=mysql:host=localhost;host=database.example.test;dbname=example;charset=utf8mb4');
invalidConfig('duplicate host cannot bypass database TLS');
putenv('DB_DSN=mysql:host=localhost;dbname=example;charset=utf8mb4');
putenv('APP_ENCRYPTION_KEY=REPLACE_WITH_BASE64_32_BYTE_KEY');
invalidConfig('placeholder rejected');
echo "PASS: $count unit assertions\n";
