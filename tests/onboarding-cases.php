<?php
declare(strict_types=1);

function authCall(string $path, array|string $body, int $status = 200, array $headers = []): array
{
    [$actual, $result] = request('POST', '/auth/' . $path, null, $body, true, $headers);
    expect($actual === $status, "auth/$path expected $status got $actual: " . ($result['error'] ?? ''));
    return $result;
}

function signupFixture(string $email): array
{
    global $db, $mailCapture;
    $db->exec('DELETE FROM rate_limits');
    $before = is_file($mailCapture) ? strlen(file_get_contents($mailCapture)) : 0;
    $fields = ['name' => 'Registration Test', 'date_of_birth' => '1996-04-15', 'email' => $email,
        'gender' => 'prefer_not_to_say', 'terms_accepted' => true, 'privacy_accepted' => true];
    $response = authCall('register', $fields, 200, ['Host: untrusted.example.test', 'X-Forwarded-Host: evil.example.test']);
    $mail = substr(file_get_contents($mailCapture), $before);
    expect((bool) preg_match('~https://registration\.example\.test/public/\?activate=([a-f0-9]{64})~', $mail, $match), 'activation uses fixed trusted origin');
    expect(!str_contains($mail, 'evil.example.test') && !str_contains($mail, '1996-04-15'), 'activation mail excludes injected origins and profile data');
    expect(array_keys($response) === ['message'], 'registration exposes no tokens or account details');
    return [$fields, $match[1], $response];
}

function authRace(string $path, array $body): array
{
    global $base, $clientToken, $clientSecret;
    $multi = curl_multi_init();
    $handles = [];
    foreach ([$base, startServer()] as $server) {
        $handle = curl_init($server . '/api/v1/auth/' . $path);
        curl_setopt_array($handle, [
            CURLOPT_POST => true, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 15,
            CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'X-API-Token: ' . $clientToken, 'X-API-Secret: ' . $clientSecret],
            CURLOPT_POSTFIELDS => json_encode($body, JSON_THROW_ON_ERROR),
        ]);
        $handles[] = $handle;
        curl_multi_add_handle($multi, $handle);
    }
    do {
        do {
            $result = curl_multi_exec($multi, $running);
        } while ($result === CURLM_CALL_MULTI_PERFORM);
        if ($running) {
            curl_multi_select($multi, 0.05);
        }
    } while ($running);
    $responses = [];
    foreach ($handles as $handle) {
        $responses[] = [curl_getinfo($handle, CURLINFO_RESPONSE_CODE), json_decode(curl_multi_getcontent($handle), true, 32, JSON_THROW_ON_ERROR)];
        curl_multi_remove_handle($multi, $handle);
        curl_close($handle);
    }
    curl_multi_close($multi);
    usort($responses, static fn(array $a, array $b): int => $a[0] <=> $b[0]);
    return $responses;
}

$onboardingStart = $count;
try {
    $registration = ['name' => 'Registration Test', 'date_of_birth' => '1996-04-15', 'email' => 'new-guest@example.test',
        'gender' => 'prefer_not_to_say', 'terms_accepted' => true, 'privacy_accepted' => true];
    foreach ([
        ['terms_accepted' => false], ['privacy_accepted' => false], ['terms_accepted' => 'true'],
        ['date_of_birth' => '2025-02-30'], ['date_of_birth' => '2099-01-01'], ['email' => "no\r\nBcc:bad@example.test"],
        ['name' => ''], ['gender' => ['invalid']], ['gender' => 'unsupported'], ['role_id' => 1],
    ] as $invalid) {
        authCall('register', array_replace($registration, $invalid), 422);
    }
    [$registration, $activation, $generic] = signupFixture('new-guest@example.test');
    $size = filesize($mailCapture);
    expect(authCall('register', $registration) === $generic, 'duplicate pending email is generic');
    clearstatcache(true, $mailCapture);
    expect(filesize($mailCapture) === $size, 'duplicate registration does not overwrite token or resend email');
    expect(authCall('register', array_replace($registration, ['email' => 'role1@example.test'])) === $generic, 'existing operator email is generic');
    $pending = $db->query("SELECT * FROM account_onboarding WHERE email = 'new-guest@example.test'")->fetch();
    expect($pending['activation_hash'] === hash('sha256', $activation) && !str_contains(json_encode($pending), $activation), 'activation token stored only as hash');
    expect($pending['terms_accepted_at'] !== null && $pending['privacy_accepted_at'] !== null, 'separate consent dates recorded');
    expect(!str_contains($pending['profile'], '1996-04-15'), 'registration demographic data encrypted');
    authCall('profile', ['onboarding_token' => $activation, 'username' => 'newguest', 'password' => $password, 'password_confirmation' => $password], 401);
    authCall('mfa/confirm', ['onboarding_token' => $activation, 'code' => '000000'], 401);
    authCall('login', ['email' => $registration['email'], 'password' => $password], 401);
    $onboarding = authCall('activate', ['token' => $activation])['onboarding_token'];
    authCall('activate', ['token' => $activation], 401);
    expect($db->query("SELECT activation_hash FROM account_onboarding WHERE email = 'new-guest@example.test'")->fetchColumn() === null, 'activation consumed atomically');
    $onboardingRow = $db->query("SELECT * FROM account_onboarding WHERE email = 'new-guest@example.test'")->fetch();
    expect($onboardingRow['onboarding_hash'] === hash('sha256', $onboarding) && !str_contains(json_encode($onboardingRow), $onboarding), 'onboarding token stored only as hash');
    authCall('mfa/setup', ['onboarding_token' => $onboarding], 409);
    authCall('mfa/confirm', ['onboarding_token' => $onboarding, 'code' => '000000'], 409);
    $profileBody = ['onboarding_token' => $onboarding, 'username' => 'newguest', 'password' => $password, 'password_confirmation' => $password];
    foreach ([
        ['username' => 'a@b'], ['username' => 'ab'], ['password_confirmation' => 'different'],
        ['password' => 'short', 'password_confirmation' => 'short'], ['password' => str_repeat('x', 1025)],
        ['profile_picture' => 'data:image/png;base64,AAAA'], ['profile_picture' => base64_encode('<svg/>')],
        ['profile_picture' => null], ['role' => 'Executive Director'],
    ] as $invalid) {
        authCall('profile', array_replace($profileBody, $invalid), 422);
    }
    // A real PNG plus permitted trailing image bytes exercises the entire decoded size boundary.
    $png = base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Wl6RZsAAAAASUVORK5CYII=');
    $maxPicture = base64_encode(str_pad($png, 262144, "\xff"));
    authCall('profile', $profileBody + ['profile_picture' => base64_encode(str_pad($png, 262145, "\0"))], 422);
    authCall('profile', str_repeat('x', 786433), 413);
    $details = authCall('profile', $profileBody + ['profile_picture' => $maxPicture]);
    expect(strlen($details['mfa_secret']) === 32 && str_starts_with($details['mfa_uri'], 'otpauth://totp/'), 'profile returns native interoperable TOTP details');
    expect(authCall('mfa/setup', ['onboarding_token' => $onboarding]) === $details, 'MFA setup resumes same secret');
    authCall('profile', $profileBody, 409);
    authCall('profile', array_replace($profileBody, ['password' => 'changed password here']), 409);
    authCall('login', ['email' => 'newguest', 'password' => $password], 401);
    expect((int) $db->query("SELECT COUNT(*) FROM users WHERE email = 'new-guest@example.test'")->fetchColumn() === 0, 'no user exists before MFA confirmation');
    expect(request('GET', '/auth/me', $onboarding)[0] === 401, 'onboarding capability cannot authorize session routes');
    $stored = $db->query("SELECT * FROM account_onboarding WHERE email = 'new-guest@example.test'")->fetch();
    expect(!str_contains($stored['profile'], $details['mfa_secret']) && !str_contains($stored['profile'], $maxPicture), 'MFA secret and photo encrypted');
    expect(\Camp\decryptPayload($stored['profile'], $key)['profile_picture'] === $maxPicture, 'maximum-sized profile picture round trips encrypted');
    authCall('mfa/confirm', ['onboarding_token' => $onboarding, 'code' => 123456], 422);
    $badCode = str_pad((string) (((int) \Camp\totpCode($details['mfa_secret'], intdiv(time(), 30)) + 123) % 1000000), 6, '0', STR_PAD_LEFT);
    authCall('mfa/confirm', ['onboarding_token' => $onboarding, 'code' => $badCode], 401);
    $enrolCode = \Camp\totpCode($details['mfa_secret'], intdiv(time(), 30));
    $session = authCall('mfa/confirm', ['onboarding_token' => $onboarding, 'code' => $enrolCode]);
    expect(strlen($session['access_token']) === 64 && $session['expires_in'] === 3600, 'MFA confirmation creates session');
    $me = api('GET', '/auth/me', $session['access_token']);
    expect(array_column($me['groups'], 'id') === [12], 'public registration grants Guest and nothing else');
    api('GET', '/records/clinical_notes', $session['access_token'], null, 403);
    authCall('mfa/confirm', ['onboarding_token' => $onboarding, 'code' => $enrolCode], 401);
    authCall('mfa/setup', ['onboarding_token' => $onboarding], 401);
    authCall('profile', $profileBody, 401);
    $beforeSessions = (int) $db->query('SELECT COUNT(*) FROM sessions')->fetchColumn();
    $challenge = authCall('login', ['email' => 'NEWGUEST', 'password' => $password]);
    expect(array_keys($challenge) === ['mfa_token'], 'username login requires TOTP challenge, not session');
    expect((int) $db->query('SELECT COUNT(*) FROM sessions')->fetchColumn() === $beforeSessions, 'password stage alone creates no session');
    authCall('mfa/verify', ['mfa_token' => $challenge['mfa_token'], 'code' => $enrolCode], 401);
    $challengeRow = $db->query('SELECT * FROM mfa_challenges')->fetch();
    expect($challengeRow['token_hash'] === hash('sha256', $challenge['mfa_token']) && !str_contains(json_encode($challengeRow), $challenge['mfa_token']), 'MFA challenge stored hashed');
    expect(request('GET', '/auth/me', $challenge['mfa_token'])[0] === 401, 'MFA challenge cannot authorize protected routes');
    $nextCode = \Camp\totpCode($details['mfa_secret'], intdiv(time(), 30) + 1);
    $session2 = authCall('mfa/verify', ['mfa_token' => $challenge['mfa_token'], 'code' => $nextCode]);
    api('GET', '/auth/me', $session2['access_token']);
    authCall('mfa/verify', ['mfa_token' => $challenge['mfa_token'], 'code' => $nextCode], 401);
    $challenge2 = authCall('login', ['email' => $registration['email'], 'password' => $password])['mfa_token'];
    authCall('mfa/verify', ['mfa_token' => $challenge2, 'code' => $nextCode], 401);
    $db->prepare('UPDATE mfa_challenges SET expires_at = UTC_TIMESTAMP() - INTERVAL 1 SECOND WHERE token_hash = ?')->execute([hash('sha256', $challenge2)]);
    authCall('mfa/verify', ['mfa_token' => $challenge2, 'code' => $badCode], 401);
    $userId = $me['user']['id'];
    $challenge3 = authCall('login', ['email' => 'newguest', 'password' => $password])['mfa_token'];
    [$code] = cli(['password', (string) $userId], $password . "\n");
    expect($code === 0, 'operator can change MFA account password without removing MFA');
    authCall('mfa/verify', ['mfa_token' => $challenge3, 'code' => $nextCode], 401);
    api('GET', '/auth/me', $session2['access_token'], null, 401);
    expect(isset(authCall('login', ['email' => 'newguest', 'password' => $password])['mfa_token']), 'password rotation preserves MFA requirement');
    expect(isset(authCall('login', ['email' => 'role1@example.test', 'password' => $password])['access_token']), 'legacy operator password login preserved');
    [$secondFields, $secondActivation] = signupFixture('other-signup@example.test');
    $secondToken = authCall('activate', ['token' => $secondActivation])['onboarding_token'];
    authCall('profile', array_replace($profileBody, ['onboarding_token' => $secondToken]), 409);
    $profileRace = authRace('profile', array_replace($profileBody, ['onboarding_token' => $secondToken, 'username' => 'otherguest']));
    expect(array_column($profileRace, 0) === [200, 409], 'concurrent profile requests establish exactly one secret without resets');
    $secondDetails = $profileRace[0][1];
    expect($secondDetails['mfa_secret'] !== $details['mfa_secret'], 'accounts receive independent TOTP secrets');
    [$code, $out] = cli(['client', 'Different onboarding client', 'menus']);
    expect($code === 0, 'second client provisioned');
    $client2 = json_decode($out, true);
    $originalToken = $clientToken;
    $originalSecret = $clientSecret;
    $clientToken = $client2['api_token'];
    $clientSecret = $client2['api_secret'];
    authCall('mfa/setup', ['onboarding_token' => $secondToken], 401);
    $clientToken = $originalToken;
    $clientSecret = $originalSecret;
    $badSecondCode = '000000';
    while (\Camp\totpStep($secondDetails['mfa_secret'], $badSecondCode, -1) !== null) {
        $badSecondCode = str_pad((string) ((int) $badSecondCode + 1), 6, '0', STR_PAD_LEFT);
    }
    for ($i = 0; $i < 8; $i++) {
        authCall('mfa/confirm', ['onboarding_token' => $secondToken, 'code' => $badSecondCode], 401);
    }
    authCall('mfa/confirm', ['onboarding_token' => $secondToken, 'code' => $badSecondCode], 429);
    expect($db->query("SELECT stage FROM account_onboarding WHERE email = 'other-signup@example.test'")->fetchColumn() === 'profile',
        'rollback preserves enrollment stage but cannot roll back MFA failure budget');
    $db->prepare('UPDATE account_onboarding SET expires_at = UTC_TIMESTAMP() - INTERVAL 1 SECOND WHERE onboarding_hash = ?')->execute([hash('sha256', $secondToken)]);
    authCall('mfa/setup', ['onboarding_token' => $secondToken], 401);
    [$expiredFields, $expiredActivation] = signupFixture('expired-signup@example.test');
    $db->prepare('UPDATE account_onboarding SET expires_at = UTC_TIMESTAMP() - INTERVAL 1 SECOND WHERE activation_hash = ?')->execute([hash('sha256', $expiredActivation)]);
    authCall('activate', ['token' => $expiredActivation], 401);
    [$retryFields, $replacementActivation] = signupFixture('expired-signup@example.test');
    expect($replacementActivation !== $expiredActivation, 'expired pending registration can restart without resetting a live profile');
    authCall('activate', ['token' => $expiredActivation], 401);
    [$raceFields, $raceActivation] = signupFixture('concurrent-signup@example.test');
    $activationRace = authRace('activate', ['token' => $raceActivation]);
    expect(array_column($activationRace, 0) === [200, 401], 'concurrent activation exchanges consume capability exactly once');
    $raceOnboarding = $activationRace[0][1]['onboarding_token'];
    $raceDetails = authCall('profile', array_replace($profileBody, ['onboarding_token' => $raceOnboarding, 'username' => 'concurrentguest']));
    $confirmRace = authRace('mfa/confirm', [
        'onboarding_token' => $raceOnboarding, 'code' => \Camp\totpCode($raceDetails['mfa_secret'], intdiv(time(), 30)),
    ]);
    expect(array_column($confirmRace, 0) === [200, 401], 'concurrent MFA confirmations create exactly one user/session');
    expect((int) $db->query("SELECT COUNT(*) FROM users WHERE email = 'concurrent-signup@example.test'")->fetchColumn() === 1,
        'concurrent confirmation cannot duplicate account');
    $raceChallenge = authCall('login', ['email' => 'concurrentguest', 'password' => $password])['mfa_token'];
    $raceSessionsBefore = (int) $db->query('SELECT COUNT(*) FROM sessions')->fetchColumn();
    $verifyRace = authRace('mfa/verify', [
        'mfa_token' => $raceChallenge, 'code' => \Camp\totpCode($raceDetails['mfa_secret'], intdiv(time(), 30) + 1),
    ]);
    expect(array_column($verifyRace, 0) === [200, 401], 'concurrent MFA challenge replay has exactly one winner');
    expect((int) $db->query('SELECT COUNT(*) FROM sessions')->fetchColumn() === $raceSessionsBefore + 1,
        'concurrent challenge replay mints only one session');
    $db->exec("UPDATE account_onboarding SET expires_at = UTC_TIMESTAMP() - INTERVAL 1 SECOND WHERE stage <> 'complete'");
    $db->exec('UPDATE mfa_challenges SET expires_at = UTC_TIMESTAMP() - INTERVAL 1 SECOND');
    [$code] = cli(['cleanup']);
    expect($code === 0 && (int) $db->query("SELECT COUNT(*) FROM account_onboarding WHERE stage <> 'complete'")->fetchColumn() === 0, 'CLI cleanup purges expired incomplete profiles');
    expect((int) $db->query('SELECT COUNT(*) FROM mfa_challenges')->fetchColumn() === 0, 'CLI cleanup purges expired challenges');
    expect((int) $db->query("SELECT COUNT(*) FROM account_onboarding WHERE stage = 'complete'")->fetchColumn() === 2, 'cleanup retains completed MFA profiles and consent');
    $workingBase = $base;
    putenv('TEST_MAIL_CAPTURE=');
    $base = startServer();
    authCall('register', array_replace($registration, ['email' => 'mail-failure@example.test']), 503);
    expect((int) $db->query("SELECT COUNT(*) FROM account_onboarding WHERE email = 'mail-failure@example.test'")->fetchColumn() === 0,
        'native mail transport failure rolls back registration without returning activation capability');
    putenv('TEST_MAIL_CAPTURE=' . $mailCapture);
    putenv('APP_PUBLIC_URL=');
    putenv('APP_MAIL_FROM=');
    $base = startServer();
    authCall('register', array_replace($registration, ['email' => 'unconfigured@example.test']), 503);
    expect(isset(authCall('login', ['email' => 'role1@example.test', 'password' => $password])['access_token']),
        'missing optional registration config does not disable existing operator login');
    putenv('APP_PUBLIC_URL=https://registration.example.test/public/');
    putenv('APP_MAIL_FROM=accounts@example.test');
    $base = $workingBase;
    $db->exec('DELETE FROM rate_limits');
    $token = str_repeat('a', 64);
    for ($i = 0; $i < 8; $i++) {
        authCall('mfa/verify', ['mfa_token' => $token, 'code' => '000000'], 401);
    }
    authCall('mfa/verify', ['mfa_token' => $token, 'code' => '000000'], 429);
    $db->exec('DELETE FROM rate_limits');
    for ($i = 0; $i < 10; $i++) {
        authCall('register', [], 422);
    }
    authCall('register', [], 429);
    $events = json_encode($db->query('SELECT * FROM audit_events')->fetchAll());
    expect(!str_contains($events, $activation) && !str_contains($events, $onboarding) && !str_contains($events, $details['mfa_secret']), 'audit never records authentication capabilities or MFA secrets');
    echo 'PASS: ' . ($count - $onboardingStart) . " new onboarding assertions\n";
} finally {
    $db->exec('DELETE FROM rate_limits');
    if (is_file($mailCapture)) {
        unlink($mailCapture);
    }
}
