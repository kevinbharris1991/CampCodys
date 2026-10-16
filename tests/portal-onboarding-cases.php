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
[$status, $html] = portalRequest($browser, $portalUrl . '?page=profile', $portalProfile);
expect($status === 200 && str_contains($html, 'Password confirmation must match'), 'portal displays safe profile validation errors');
$portalProfile['password_confirmation'] = $password;
$portalProfile['csrf'] = portalCsrf($html);
[$status, $html] = portalRequest($browser, $portalUrl . '?page=profile', $portalProfile);
expect($status === 200 && str_contains($html, 'Configure multi-factor authentication') && !str_contains($html, 'Your dashboard'),
    'successful profile advances only to mandatory MFA');
expect((bool) preg_match('~<pre>([A-Z2-7]{32})</pre>~', $html, $secretMatch), 'portal renders authenticator setup key');
$portalSecret = $secretMatch[1];
[$status, $html] = portalRequest($browser, $portalUrl . '?page=profile');
expect($status === 200 && str_contains($html, $portalSecret) && !str_contains($html, 'name="password"'),
    'profile reload preserves MFA setup without permitting profile reset');
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
$db->exec('DELETE FROM rate_limits');
