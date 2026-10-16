<?php
declare(strict_types=1);

$db->exec('DELETE FROM rate_limits');
[$status, $html] = portalRequest($browser, $portalUrl . '?page=register');
expect($status === 200 && str_contains($html, 'Create your account'), 'portal registration page is available');
expect(str_contains($html, 'name="terms_accepted"') && str_contains($html, 'name="privacy_accepted"')
    && str_contains($html, 'https://policies.example.test/terms') && str_contains($html, 'https://policies.example.test/privacy'),
    'portal provides separately linked policy acceptances');
expect(!str_contains($html, 'name="password"') && !str_contains($html, 'name="username"')
    && !str_contains($html, 'name="profile_picture"'), 'initial registration does not ask for later-stage fields');
$portalRegistration = ['csrf' => portalCsrf($html), 'action' => 'register', 'name' => 'Private Portal Name',
    'date_of_birth' => '1998-05-04', 'email' => 'portal-new-guest@example.test', 'gender' => 'prefer_not_to_say',
    'terms_accepted' => '1', 'privacy_accepted' => '1'];
[$status, $html] = portalRequest($browser, $portalUrl . '?page=register', array_replace($portalRegistration, ['csrf' => 'invalid']));
expect($status === 403 && str_contains($html, 'Invalid form token'), 'portal registration requires CSRF');
[$status, $html] = portalRequest($browser, $portalUrl . '?page=register', array_diff_key($portalRegistration, ['privacy_accepted' => true]));
expect($status === 200 && str_contains($html, 'must each be accepted separately'), 'portal cannot bypass privacy acceptance');
[$status, $html] = portalRequest($browser, $portalUrl . '?page=register', array_diff_key($portalRegistration, ['terms_accepted' => true]));
expect($status === 200 && str_contains($html, 'must each be accepted separately'), 'portal cannot bypass terms acceptance');
[$status, $html] = portalRequest($browser, $portalUrl . '?page=profile', [
    'csrf' => portalCsrf($html), 'action' => 'profile', 'username' => 'skippedactivation',
    'password' => $password, 'password_confirmation' => $password,
]);
expect($status === 200 && str_contains($html, 'Open your email activation link first') && !str_contains($html, 'Your dashboard'),
    'portal profile submission cannot skip email activation');
[$status, $html] = portalRequest($browser, $portalUrl . '?page=mfa', [
    'csrf' => $portalRegistration['csrf'], 'action' => 'confirm_mfa', 'code' => '000000',
]);
expect($status === 200 && !str_contains($html, 'Your dashboard')
    && !str_contains($html, 'Configure multi-factor authentication'), 'portal cannot confirm MFA before activation/profile');
[$status, $html] = portalRequest($browser, $portalUrl . '?page=register', $portalRegistration);
expect($status === 200 && str_contains($html, 'Check your email') && !str_contains($html, 'Your dashboard'),
    'portal registration requires email instead of creating session');
$mail = file_get_contents($mailCapture);
expect((bool) preg_match('~https://registration\.example\.test/public/\?activate=([a-f0-9]{64})~', $mail, $match),
    'portal registration delivers native transport email');
$portalActivation = $match[1];
[$status, $html] = portalRequest($browser, $portalUrl . '?activate=' . $portalActivation);
expect($status === 200 && str_contains($html, 'Set up your profile') && str_contains($html, 'name="profile_picture"')
    && str_contains($html, 'name="password_confirmation"'), 'activation link opens optional-photo profile step');
expect(!str_contains(curl_getinfo($browser, CURLINFO_EFFECTIVE_URL), $portalActivation) && !str_contains($html, $portalActivation),
    'portal removes activation capability from URL and rendered HTML');
expect($db->query("SELECT stage FROM account_onboarding WHERE email = 'portal-new-guest@example.test'")->fetchColumn() === 'pending',
    'mail-scanner GET alone does not consume activation');
$portalProfile = ['csrf' => portalCsrf($html), 'action' => 'profile', 'username' => 'portalnewguest',
    'password' => $password, 'password_confirmation' => 'not matching'];
[$status, $html] = portalRequest($browser, $portalUrl . '?page=profile', array_replace($portalProfile, ['csrf' => 'invalid']));
expect($status === 403 && str_contains($html, 'Invalid form token')
    && $db->query("SELECT stage FROM account_onboarding WHERE email = 'portal-new-guest@example.test'")->fetchColumn() === 'pending',
    'profile CSRF failure cannot consume email activation');
[$status, $html] = portalRequest($browser, $portalUrl . '?page=profile', $portalProfile);
expect($status === 200 && str_contains($html, 'Password confirmation must match'), 'portal displays safe profile validation errors');
$portalProfile['password_confirmation'] = $password;
$portalProfile['csrf'] = portalCsrf($html);
[$status, $html] = portalRequest($browser, $portalUrl . '?page=profile', $portalProfile);
expect($status === 200 && str_contains($html, 'Configure multi-factor authentication') && !str_contains($html, 'Your dashboard'),
    'successful profile advances only to mandatory MFA');
expect((bool) preg_match('~<pre>([A-Z2-7]{32})</pre>~', $html, $secretMatch), 'portal renders authenticator setup key');
$portalSecret = $secretMatch[1];
[$status, $html] = portalRequest($browser, $portalUrl . '?page=mfa', [
    'csrf' => 'invalid', 'action' => 'confirm_mfa', 'code' => \Camp\totpCode($portalSecret, intdiv(time(), 30)),
]);
expect($status === 403 && str_contains($html, 'Invalid form token')
    && (int) $db->query("SELECT COUNT(*) FROM users WHERE email = 'portal-new-guest@example.test'")->fetchColumn() === 0,
    'MFA enrollment CSRF failure cannot create account or session');
[$status, $html] = portalRequest($browser, $portalUrl . '?page=profile');
expect($status === 200 && str_contains($html, $portalSecret) && !str_contains($html, 'name="password"'),
    'profile reload preserves MFA setup without permitting profile reset');
// A new browser has neither the email activation token nor the onboarding session capability.
$recoveryBrowser = curl_init();
curl_setopt_array($recoveryBrowser, [CURLOPT_RETURNTRANSFER => true, CURLOPT_COOKIEFILE => '', CURLOPT_TIMEOUT => 15]);
[$status, $recoveryHtml] = portalRequest($recoveryBrowser, $portalUrl . '?page=register');
$recoveryFields = array_replace($portalRegistration, [
    'csrf' => portalCsrf($recoveryHtml), 'name' => 'Do Not Replace Existing Name', 'date_of_birth' => '2000-01-01',
]);
[$status, $recoveryHtml] = portalRequest($recoveryBrowser, $portalUrl . '?page=register', $recoveryFields);
expect($status === 200 && str_contains($recoveryHtml, 'Check your email'), 'lost browser session can request recovery through registration');
preg_match_all('~https://registration\.example\.test/public/\?activate=([a-f0-9]{64})~', file_get_contents($mailCapture), $recoveryMatches);
$recoveryActivation = end($recoveryMatches[1]);
[$status, $recoveryHtml] = portalRequest($recoveryBrowser, $portalUrl . '?activate=' . $recoveryActivation);
[$status, $recoveryHtml] = portalRequest($recoveryBrowser, $portalUrl . '?page=profile', [
    'csrf' => portalCsrf($recoveryHtml), 'action' => 'profile', 'username' => 'mustnotreplace',
    'password' => 'must not replace established password', 'password_confirmation' => 'must not replace established password',
]);
expect($status === 200 && str_contains($recoveryHtml, 'Configure multi-factor authentication')
    && str_contains($recoveryHtml, $portalSecret), 'recovery in fresh browser resumes identical authenticator instead of resetting profile');
$recoveredProfile = $db->query("SELECT * FROM account_onboarding WHERE email = 'portal-new-guest@example.test'")->fetch();
expect($recoveredProfile['username'] === 'portalnewguest' && password_verify($password, $recoveredProfile['password_hash'])
    && \Camp\decryptPayload($recoveredProfile['profile'], $key)['name'] === 'Private Portal Name',
    'portal recovery cannot overwrite username, password or original demographic profile');
curl_close($browser);
$browser = $recoveryBrowser;
$html = $recoveryHtml;
$portalCode = \Camp\totpCode($portalSecret, intdiv(time(), 30));
$portalBadCode = str_pad((string) (((int) $portalCode + 123) % 1000000), 6, '0', STR_PAD_LEFT);
[$status, $html] = portalRequest($browser, $portalUrl . '?page=mfa', [
    'csrf' => portalCsrf($html), 'action' => 'confirm_mfa', 'code' => $portalBadCode,
]);
expect($status === 200 && str_contains($html, 'Invalid or already used authenticator code') && !str_contains($html, 'Your dashboard'),
    'portal rejects incorrect enrollment code without session');
[$status, $html] = portalRequest($browser, $portalUrl . '?page=mfa', [
    'csrf' => portalCsrf($html), 'action' => 'confirm_mfa', 'code' => $portalCode,
]);
expect($status === 200 && str_contains($html, 'Your dashboard') && str_contains($html, 'Signed in as portalnewguest.')
    && str_contains($html, '<li>Guest</li>'), 'portal MFA confirmation opens Guest dashboard');
expect(!str_contains($html, $portalSecret) && !str_contains($html, $password) && !str_contains($html, 'Private Portal Name')
    && !str_contains($html, $clientToken) && !str_contains($html, $clientSecret), 'dashboard excludes setup secrets and private profile details');
$completed = $db->query("SELECT * FROM account_onboarding WHERE email = 'portal-new-guest@example.test'")->fetch();
expect(!isset(\Camp\decryptPayload($completed['profile'], $key)['profile_picture']), 'portal permits profile without photo');
[$status, $html] = portalRequest($browser, $portalUrl, ['csrf' => portalCsrf($html), 'action' => 'logout']);
expect($status === 200 && str_contains($html, 'Staff &amp; guest sign in'), 'new portal account can log out');
[$status, $html] = portalRequest($browser, $portalUrl, [
    'csrf' => portalCsrf($html), 'action' => 'login', 'email' => 'PORTALNEWGUEST', 'password' => $password,
]);
expect($status === 200 && str_contains($html, 'Verify your sign in') && !str_contains($html, 'Your dashboard'),
    'subsequent portal username login requires MFA');
[$status, $html] = portalRequest($browser, $portalUrl . '?page=mfa-login', [
    'csrf' => 'invalid', 'action' => 'verify_mfa', 'code' => \Camp\totpCode($portalSecret, intdiv(time(), 30) + 1),
]);
expect($status === 403 && str_contains($html, 'Invalid form token') && !str_contains($html, 'Your dashboard'),
    'MFA login verification requires valid CSRF');
[$status, $html] = portalRequest($browser, $portalUrl . '?page=mfa-login', [
    'csrf' => portalCsrf($html), 'action' => 'verify_mfa', 'code' => $portalCode,
]);
expect($status === 200 && str_contains($html, 'Invalid or already used authenticator code') && !str_contains($html, 'Your dashboard'),
    'portal cannot reuse enrollment code at login');
[$status, $html] = portalRequest($browser, $portalUrl . '?page=mfa-login', [
    'csrf' => portalCsrf($html), 'action' => 'verify_mfa', 'code' => \Camp\totpCode($portalSecret, intdiv(time(), 30) + 1),
]);
expect($status === 200 && str_contains($html, 'Your dashboard') && str_contains($html, 'Signed in as portalnewguest.'),
    'fresh authenticator code completes subsequent portal login');
[$status, $html] = portalRequest($browser, $portalUrl, ['csrf' => portalCsrf($html), 'action' => 'logout']);
expect($status === 200 && !str_contains($html, 'Your dashboard'), 'MFA portal session logs out cleanly');
$workingEnvironment = getenv('APP_ENV');
foreach ([
    ['PORTAL_TERMS_URL', ''], ['PORTAL_PRIVACY_URL', ''],
    ['PORTAL_TERMS_URL', 'http://untrusted.example.test/terms'],
] as [$policySetting, $unsafePolicy]) {
    putenv('APP_ENV=development');
    putenv($policySetting . '=' . $unsafePolicy);
    $blockedPortal = startServer(true) . '/public/index.php';
    putenv('APP_ENV=' . $workingEnvironment);
    putenv('PORTAL_TERMS_URL=https://policies.example.test/terms');
    putenv('PORTAL_PRIVACY_URL=https://policies.example.test/privacy');
    $policyBrowser = curl_init();
    curl_setopt_array($policyBrowser, [CURLOPT_RETURNTRANSFER => true, CURLOPT_COOKIEFILE => '', CURLOPT_TIMEOUT => 15]);
    [, $policyLogin] = portalRequest($policyBrowser, $blockedPortal);
    $policyCsrf = portalCsrf($policyLogin);
    [$status, $policyHtml] = portalRequest($policyBrowser, $blockedPortal . '?page=register');
    expect($status === 200 && str_contains($policyHtml, 'Registration is temporarily unavailable')
        && !str_contains($policyHtml, 'name="terms_accepted"'), 'portal hides registration for missing or insecure policy configuration');
    [$status, $policyHtml] = portalRequest($policyBrowser, $blockedPortal . '?page=register', array_replace($portalRegistration, [
        'csrf' => $policyCsrf, 'email' => 'must-not-register@example.test',
    ]));
    expect($status === 200 && str_contains($policyHtml, 'Registration is unavailable until the terms and privacy policy are configured')
        && (int) $db->query("SELECT COUNT(*) FROM account_onboarding WHERE email = 'must-not-register@example.test'")->fetchColumn() === 0,
        'crafted registration POST cannot bypass fail-closed policy configuration');
    curl_close($policyBrowser);
}
$db->exec('DELETE FROM rate_limits');
