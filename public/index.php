<?php
declare(strict_types=1);

ini_set('display_errors', '0');
$development = getenv('APP_ENV') === 'development';
ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
session_name('campcodys_portal');
session_set_cookie_params([
    'lifetime' => 0, 'path' => '/public/', 'secure' => !$development,
    'httponly' => true, 'samesite' => 'Strict',
]);
header('Content-Type: text/html; charset=utf-8');
header('Cache-Control: no-store');
header('Pragma: no-cache');
header("Content-Security-Policy: default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
if (!$development) {
    header('Strict-Transport-Security: max-age=31536000');
    if (($_SERVER['HTTPS'] ?? '') !== 'on') {
        http_response_code(400);
        exit('HTTPS is required.');
    }
}
session_start();
if (isset($_SESSION['last_seen']) && time() - $_SESSION['last_seen'] > 900) {
    $_SESSION = [];
    session_regenerate_id(true);
}
$_SESSION['last_seen'] = time();
$_SESSION['csrf'] ??= bin2hex(random_bytes(32));

function escape(mixed $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function api(string $method, string $path, ?array $body = null): array
{
    $base = rtrim(getenv('PORTAL_API_BASE_URL') ?: '', '/');
    $url = parse_url($base);
    $local = getenv('APP_ENV') === 'development'
        && in_array($url['host'] ?? '', ['127.0.0.1', 'localhost', '[::1]'], true);
    if (!$url || isset($url['user']) || isset($url['pass']) || isset($url['query'])
        || isset($url['fragment']) || (($url['scheme'] ?? '') !== 'https'
        && !(($url['scheme'] ?? '') === 'http' && $local))) {
        throw new RuntimeException('Portal API URL is not configured securely.');
    }
    $clientToken = getenv('PORTAL_API_TOKEN') ?: '';
    $clientSecret = getenv('PORTAL_API_SECRET') ?: '';
    if ($clientToken === '' || $clientSecret === '') {
        throw new RuntimeException('Portal API credentials are not configured.');
    }
    $headers = ['Accept: application/json', 'Content-Type: application/json',
        'X-API-Token: ' . $clientToken, 'X-API-Secret: ' . $clientSecret];
    if (isset($_SESSION['access_token'])) {
        $headers[] = 'Authorization: Bearer ' . $_SESSION['access_token'];
    }
    $curl = curl_init($base . $path);
    curl_setopt_array($curl, [
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
    ]);
    if ($body !== null) {
        curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode((object) $body, JSON_THROW_ON_ERROR));
    }
    $response = curl_exec($curl);
    $status = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
    curl_close($curl);
    if ($response === false || $status === 0) {
        throw new RuntimeException('The API is currently unavailable.');
    }
    if ($status === 401) {
        unset($_SESSION['access_token']);
        $failure = json_decode($response, true);
        if (str_starts_with($path, '/auth/') && is_string($failure['error'] ?? null)) {
            throw new RuntimeException($failure['error'], $status);
        }
        throw new RuntimeException('Sign in again. Your session or API credentials were not accepted.');
    }
    if ($status >= 400) {
        $failure = json_decode($response, true);
        if (in_array($status, [409, 413, 422, 429], true) && is_string($failure['error'] ?? null)) {
            throw new RuntimeException($failure['error'], $status);
        }
        throw new RuntimeException('API request rejected (HTTP ' . $status . '). Check your permissions and the API documentation.');
    }
    return $response === '' ? [] : json_decode($response, true, 64, JSON_THROW_ON_ERROR);
}

function policyUrl(string $setting): string
{
    $value = getenv($setting) ?: '';
    $url = parse_url($value);
    $local = getenv('APP_ENV') === 'development'
        && in_array($url['host'] ?? '', ['127.0.0.1', 'localhost', '[::1]'], true);
    return $url && !isset($url['user']) && !isset($url['pass']) && isset($url['host'])
        && !preg_match('/[\x00-\x20]/', $value)
        && (($url['scheme'] ?? '') === 'https' || (($url['scheme'] ?? '') === 'http' && $local))
        ? $value : '';
}

function signedIn(array $login): void
{
    if (!is_string($login['access_token'] ?? null)) {
        throw new RuntimeException('Unexpected sign-in response.');
    }
    $_SESSION = ['access_token' => $login['access_token'], 'csrf' => bin2hex(random_bytes(32)), 'last_seen' => time()];
    session_regenerate_id(true);
    header('Location: /public/');
    exit;
}

$termsUrl = policyUrl('PORTAL_TERMS_URL');
$privacyUrl = policyUrl('PORTAL_PRIVACY_URL');
$page = is_string($_GET['page'] ?? null) ? $_GET['page'] : '';
if (isset($_GET['activate']) && !isset($_SESSION['access_token'])) {
    if (!is_string($_GET['activate']) || !preg_match('/\A[a-f0-9]{64}\z/D', $_GET['activate'])) {
        http_response_code(400);
        exit('Invalid activation link.');
    }
    $_SESSION = ['activation_token' => $_GET['activate'], 'csrf' => bin2hex(random_bytes(32)), 'last_seen' => time()];
    session_regenerate_id(true);
    header('Location: /public/?page=profile');
    exit;
}
$notice = $_SESSION['notice'] ?? '';
unset($_SESSION['notice']);
if (!isset($_SESSION['access_token']) && isset($_SESSION['mfa_setup']) && $page === 'profile') {
    header('Location: /public/?page=mfa');
    exit;
}
$error = '';
$result = null;
$me = null;
$resources = [];
$mealView = false;
$activityView = false;
$specialMeals = [];
$mealCamper = null;
$menuAfter = '';
$specialAfter = '';
try {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!is_string($_POST['csrf'] ?? null) || !hash_equals($_SESSION['csrf'], $_POST['csrf'])) {
            http_response_code(403);
            throw new RuntimeException('Invalid form token. Reload the page.');
        }
        $action = $_POST['action'] ?? '';
        if ($action === 'register') {
            $page = 'register';
            if ($termsUrl === '' || $privacyUrl === '') {
                throw new RuntimeException('Registration is unavailable until the terms and privacy policy are configured.');
            }
            api('POST', '/auth/register', [
                'name' => (string) ($_POST['name'] ?? ''),
                'date_of_birth' => (string) ($_POST['date_of_birth'] ?? ''),
                'email' => (string) ($_POST['email'] ?? ''),
                'gender' => (string) ($_POST['gender'] ?? ''),
                'terms_accepted' => ($_POST['terms_accepted'] ?? '') === '1',
                'privacy_accepted' => ($_POST['privacy_accepted'] ?? '') === '1',
            ]);
            $_SESSION['notice'] = 'Check your email for an activation link. If this address is eligible, an email will arrive shortly.';
            header('Location: /public/?page=check-email');
            exit;
        } elseif ($action === 'profile') {
            $page = 'profile';
            if (!isset($_SESSION['activation_token']) && !isset($_SESSION['onboarding_token'])) {
                throw new RuntimeException('Open your email activation link first.');
            }
            $body = [
                'username' => (string) ($_POST['username'] ?? ''),
                'password' => (string) ($_POST['password'] ?? ''),
                'password_confirmation' => (string) ($_POST['password_confirmation'] ?? ''),
            ];
            $photo = $_FILES['profile_picture'] ?? null;
            if ($photo !== null && ($photo['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_NO_FILE) {
                if ($photo['error'] !== UPLOAD_ERR_OK || !is_uploaded_file($photo['tmp_name'])
                    || filesize($photo['tmp_name']) > 262144) {
                    throw new RuntimeException('Upload a JPEG or PNG picture no larger than 256 KiB.');
                }
                $bytes = file_get_contents($photo['tmp_name']);
                if ($bytes === false) {
                    throw new RuntimeException('Could not read your picture.');
                }
                $body['profile_picture'] = base64_encode($bytes);
            }
            if (isset($_SESSION['activation_token'])) {
                $activation = api('POST', '/auth/activate', ['token' => $_SESSION['activation_token']]);
                if (!is_string($activation['onboarding_token'] ?? null)) {
                    throw new RuntimeException('Unexpected activation response.');
                }
                $_SESSION['onboarding_token'] = $activation['onboarding_token'];
                unset($_SESSION['activation_token']);
                session_regenerate_id(true);
            }
            try {
                $setup = api('POST', '/auth/profile', ['onboarding_token' => $_SESSION['onboarding_token']] + $body);
            } catch (RuntimeException $exception) {
                if ($exception->getCode() !== 409) {
                    throw $exception;
                }
                try {
                    $setup = api('POST', '/auth/mfa/setup', ['onboarding_token' => $_SESSION['onboarding_token']]);
                } catch (RuntimeException) {
                    throw $exception;
                }
            }
            $_SESSION['mfa_setup'] = $setup;
            header('Location: /public/?page=mfa');
            exit;
        } elseif ($action === 'confirm_mfa' && isset($_SESSION['onboarding_token'], $_SESSION['mfa_setup'])) {
            $page = 'mfa';
            signedIn(api('POST', '/auth/mfa/confirm', [
                'onboarding_token' => $_SESSION['onboarding_token'],
                'code' => (string) ($_POST['code'] ?? ''),
            ]));
        } elseif ($action === 'verify_mfa' && isset($_SESSION['mfa_token'])) {
            $page = 'mfa-login';
            signedIn(api('POST', '/auth/mfa/verify', [
                'mfa_token' => $_SESSION['mfa_token'], 'code' => (string) ($_POST['code'] ?? ''),
            ]));
        } elseif ($action === 'login') {
            $login = api('POST', '/auth/login', [
                'email' => (string) ($_POST['email'] ?? ''),
                'password' => (string) ($_POST['password'] ?? ''),
            ]);
            if (is_string($login['mfa_token'] ?? null)) {
                $_SESSION = ['mfa_token' => $login['mfa_token'], 'csrf' => bin2hex(random_bytes(32)), 'last_seen' => time()];
                session_regenerate_id(true);
                header('Location: /public/?page=mfa-login');
                exit;
            }
            signedIn($login);
        } elseif ($action === 'logout') {
            try {
                api('POST', '/auth/logout', []);
            } finally {
                $_SESSION = [];
                session_regenerate_id(true);
                $_SESSION['csrf'] = bin2hex(random_bytes(32));
            }
        } elseif (isset($_SESSION['access_token'])) {
            if ($action === 'menus') {
                $camper = filter_var($_POST['camper_id'] ?? '', FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
                if (!$camper) {
                    throw new RuntimeException('Enter your authorized camper ID for meal matching.');
                }
                $menuAfter = (string) ($_POST['menu_after'] ?? '');
                $specialAfter = (string) ($_POST['special_after'] ?? '');
                foreach ([$menuAfter, $specialAfter] as $cursor) {
                    if ($cursor !== '' && !preg_match('/\A[1-9][0-9]{0,17}\z/D', $cursor)) {
                        throw new RuntimeException('Invalid meal page cursor.');
                    }
                }
                $result = api('GET', '/menus?camper_id=' . $camper . ($menuAfter === '' ? '' : '&after=' . $menuAfter));
                $specialMeals = api('GET', '/records/special_meals?camper_id=' . $camper . ($specialAfter === '' ? '' : '&after=' . $specialAfter));
                $mealCamper = $camper;
                $mealView = true;
            } elseif ($action === 'activities') {
                $after = (string) ($_POST['after'] ?? '');
                if ($after !== '' && !preg_match('/\A[1-9][0-9]{0,17}\z/D', $after)) {
                    throw new RuntimeException('Invalid activity page cursor.');
                }
                $result = api('GET', '/activities' . ($after === '' ? '' : '?after=' . $after));
                $activityView = true;
            } elseif ($action === 'signup') {
                $id = filter_var($_POST['record_id'] ?? '', FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
                $camper = filter_var($_POST['camper_id'] ?? '', FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
                if (!$id || !$camper) {
                    throw new RuntimeException('Enter positive activity and authorized camper IDs.');
                }
                $result = api('POST', '/activities/' . $id . '/signup', ['camper_id' => $camper]);
            } elseif ($action === 'record') {
                $resource = (string) ($_POST['resource'] ?? '');
                if (!preg_match('/\A[a-z_]+\z/D', $resource)) {
                    throw new RuntimeException('Select a valid resource.');
                }
                $method = (string) ($_POST['method'] ?? 'GET');
                if (!in_array($method, ['GET', 'POST', 'PATCH', 'DELETE'], true)) {
                    throw new RuntimeException('Invalid operation.');
                }
                $id = (string) ($_POST['record_id'] ?? '');
                if (($id !== '' && !preg_match('/\A[1-9][0-9]*\z/D', $id))
                    || (in_array($method, ['PATCH', 'DELETE'], true) && $id === '')) {
                    throw new RuntimeException('This operation requires a positive record ID.');
                }
                $body = null;
                if (in_array($method, ['POST', 'PATCH'], true)) {
                    $raw = (string) ($_POST['payload'] ?? '{}');
                    if (strlen($raw) > 32768 || !str_starts_with(ltrim($raw), '{')) {
                        throw new RuntimeException('Supply a JSON object smaller than 32 KiB.');
                    }
                    $body = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
                }
                $after = (string) ($_POST['after'] ?? '');
                if ($after !== '' && !preg_match('/\A[1-9][0-9]{0,17}\z/D', $after)) {
                    throw new RuntimeException('Invalid record page cursor.');
                }
                $query = $method === 'GET' && $id === '' && $after !== '' ? '?after=' . $after : '';
                $result = api($method, '/records/' . $resource . ($id === '' ? '' : '/' . $id) . $query, $body);
            }
        }
    }
    if (isset($_SESSION['access_token'])) {
        $me = api('GET', '/auth/me');
        $resources = api('GET', '/resources');
    }
} catch (JsonException) {
    $error = 'Invalid JSON. Check the request format.';
} catch (Throwable $exception) {
    $error = $exception instanceof RuntimeException ? $exception->getMessage() : 'Request failed. Contact your administrator.';
}
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Camp Cody's | Staff &amp; Guest Portal</title>
    <link rel="stylesheet" href="/public/style.css">
</head>
<body>
<header><p class="eyebrow">Welcome to</p><h1>Camp Cody's</h1><p>Accessible adventures. Individual support. Shared belonging.</p></header>
<main>
    <p><a href="/developers/api/v1/">Developer documentation</a></p>
    <?php if ($error !== ''): ?><p role="alert" class="error"><?= escape($error) ?></p><?php endif; ?>
    <?php if ($notice !== ''): ?><p role="status"><?= escape($notice) ?></p><?php endif; ?>
    <?php if (!isset($_SESSION['access_token']) && $page === 'register'): ?>
    <section>
        <h2>Create your account</h2>
        <p>First, tell us about yourself. We will email an activation link so you can choose your username and password and secure your account.</p>
        <?php if ($termsUrl === '' || $privacyUrl === ''): ?>
        <p role="alert">Registration is temporarily unavailable. Contact camp staff.</p>
        <?php else: ?>
        <form method="post">
            <input type="hidden" name="csrf" value="<?= escape($_SESSION['csrf']) ?>">
            <input type="hidden" name="action" value="register">
            <label>Name <input name="name" required autocomplete="name" maxlength="120"></label>
            <label>Date of birth <input name="date_of_birth" type="date" required autocomplete="bday" max="<?= escape(gmdate('Y-m-d')) ?>"></label>
            <label>Email address <input name="email" type="email" required autocomplete="email" maxlength="254"></label>
            <label>Gender <select name="gender" required>
                <option value="">Choose an option</option>
                <option value="female">Female</option><option value="male">Male</option>
                <option value="non_binary">Non-binary</option><option value="self_described">Self-described</option>
                <option value="prefer_not_to_say">Prefer not to say</option>
            </select></label>
            <label class="consent"><input name="terms_accepted" type="checkbox" value="1" required> I agree to the <a href="<?= escape($termsUrl) ?>">terms of service</a>.</label>
            <label class="consent"><input name="privacy_accepted" type="checkbox" value="1" required> I accept the <a href="<?= escape($privacyUrl) ?>">privacy policy</a>.</label>
            <button type="submit">Register</button>
        </form>
        <?php endif; ?>
        <p><a href="/public/">Already registered? Sign in</a></p>
    </section>
    <?php elseif (!isset($_SESSION['access_token']) && $page === 'profile'): ?>
    <section>
        <h2>Set up your profile</h2>
        <?php if (!isset($_SESSION['activation_token']) && !isset($_SESSION['onboarding_token'])): ?>
        <p>Open the activation link in your email to continue.</p>
        <?php else: ?>
        <form method="post" enctype="multipart/form-data">
            <input type="hidden" name="csrf" value="<?= escape($_SESSION['csrf']) ?>">
            <input type="hidden" name="action" value="profile">
            <input type="hidden" name="MAX_FILE_SIZE" value="262144">
            <label>Profile picture (optional, JPEG or PNG, up to 256 KiB) <input name="profile_picture" type="file" accept="image/jpeg,image/png"></label>
            <label>Username <input name="username" required autocomplete="username" minlength="3" maxlength="40" pattern="[A-Za-z0-9][A-Za-z0-9_.\-]{2,39}" aria-describedby="username-help"></label>
            <p id="username-help">Use 3–40 letters, numbers, underscores, dots, or hyphens, starting with a letter or number.</p>
            <label>Password <input name="password" type="password" required autocomplete="new-password" minlength="12" maxlength="1024"></label>
            <label>Confirm password <input name="password_confirmation" type="password" required autocomplete="new-password" minlength="12" maxlength="1024"></label>
            <button type="submit">Continue to MFA</button>
        </form>
        <?php endif; ?>
    </section>
    <?php elseif (!isset($_SESSION['access_token']) && $page === 'mfa' && isset($_SESSION['mfa_setup'])): ?>
    <section>
        <h2>Configure multi-factor authentication</h2>
        <p>Add a time-based account in your authenticator app using this setup key. Keep it private.</p>
        <pre><?= escape($_SESSION['mfa_setup']['mfa_secret'] ?? '') ?></pre>
        <p>Account: your registration email address. Use six-digit codes, a 30-second interval, and SHA-1.</p>
        <form method="post">
            <input type="hidden" name="csrf" value="<?= escape($_SESSION['csrf']) ?>">
            <input type="hidden" name="action" value="confirm_mfa">
            <label>Authenticator code <input name="code" required inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6"></label>
            <button type="submit">Enable MFA and open dashboard</button>
        </form>
    </section>
    <?php elseif (!isset($_SESSION['access_token']) && $page === 'mfa-login' && isset($_SESSION['mfa_token'])): ?>
    <section>
        <h2>Verify your sign in</h2>
        <form method="post">
            <input type="hidden" name="csrf" value="<?= escape($_SESSION['csrf']) ?>">
            <input type="hidden" name="action" value="verify_mfa">
            <label>Authenticator code <input name="code" required inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6"></label>
            <button type="submit">Open dashboard</button>
        </form>
    </section>
    <?php elseif (!isset($_SESSION['access_token']) && $page === 'check-email'): ?>
    <section><h2>Check your email</h2><p>Follow your activation link to complete your profile and configure MFA.</p><p><a href="/public/">Return to sign in</a></p></section>
    <?php elseif (!isset($_SESSION['access_token'])): ?>
    <section>
        <h2>Staff &amp; guest sign in</h2>
        <p>Access is limited to your assigned groups and records. <a href="/public/?page=register">Register a new account</a>.</p>
        <form method="post">
            <input type="hidden" name="csrf" value="<?= escape($_SESSION['csrf']) ?>">
            <input type="hidden" name="action" value="login">
            <label>Email or username <input name="email" required autocomplete="username" maxlength="254"></label>
            <label>Password <input name="password" type="password" required autocomplete="current-password"></label>
            <button type="submit">Sign in securely</button>
        </form>
    </section>
    <?php elseif ($me !== null): ?>
    <section>
        <h2>Your dashboard</h2>
        <p>Signed in as <?= escape($me['user']['display_name'] ?? $me['user']['email'] ?? '') ?>.</p>
        <ul><?php foreach ($me['groups'] ?? [] as $group): ?><li><?= escape($group['name']) ?></li><?php endforeach; ?></ul>
        <form method="post">
            <input type="hidden" name="csrf" value="<?= escape($_SESSION['csrf']) ?>">
            <button name="action" value="logout">Sign out</button>
        </form>
    </section>
    <section>
        <h2>Meals &amp; activities</h2>
        <p>Guests can check dietary suitability and available activities. Always confirm meal safety with dietary staff.</p>
        <p>Find your camper ID by reading the <code>campers</code> resource below. Only linked/assigned campers are accessible.</p>
        <form method="post">
            <input type="hidden" name="csrf" value="<?= escape($_SESSION['csrf']) ?>">
            <label>Camper ID for dietary matching <input name="camper_id" type="number" min="1" required></label>
            <button name="action" value="menus">View meals</button>
        </form>
        <form method="post">
            <input type="hidden" name="csrf" value="<?= escape($_SESSION['csrf']) ?>">
            <button name="action" value="activities">View activities</button>
        </form>
        <form method="post">
            <input type="hidden" name="csrf" value="<?= escape($_SESSION['csrf']) ?>">
            <label>Activity ID <input name="record_id" type="number" min="1" required></label>
            <label>Camper ID <input name="camper_id" type="number" min="1" required></label>
            <button name="action" value="signup">Sign up for activity</button>
        </form>
    </section>
    <section>
        <h2>Authorized records</h2>
        <p>This foundation portal exposes the API's record editor. Only permitted operations and fields are accepted by the server.
            Consult the <a href="/developers/api/v1/">field reference</a> before submitting JSON. Do not enter payment card details.</p>
        <form method="post">
            <input type="hidden" name="csrf" value="<?= escape($_SESSION['csrf']) ?>">
            <input type="hidden" name="action" value="record">
            <label>Resource <select name="resource" required>
                <?php foreach (($me['permissions'] ?? []) as $name => $permissions): ?>
                    <option value="<?= escape($name) ?>"><?= escape($name) ?> (<?= escape(implode(', ', $permissions)) ?>)</option>
                <?php endforeach; ?>
            </select></label>
            <label>Operation <select name="method">
                <option value="GET">Read</option><option value="POST">Create</option>
                <option value="PATCH">Update</option><option value="DELETE">Delete</option>
            </select></label>
            <label>Record ID (blank to list or create) <input name="record_id" type="number" min="1"></label>
            <label>List page cursor (use the previous result's next_after) <input name="after" type="number" min="1"></label>
            <label>Request JSON (create/update) <textarea name="payload" rows="8" spellcheck="false">{}</textarea></label>
            <button type="submit">Send request</button>
        </form>
        <details><summary>Resource schemas</summary><pre><?= escape(json_encode($resources, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)) ?></pre></details>
    </section>
    <?php endif; ?>
    <?php if ($mealView): ?>
    <section aria-live="polite"><h2>Your meal review</h2>
        <?php foreach ($result['data'] ?? [] as $meal): ?>
            <article><h3>
                <?php if (($meal['allergy_evaluation']['status'] ?? '') === 'potential_conflict'): ?>
                    <s><?= escape($meal['name']) ?></s> — potential allergy/sensitivity conflict
                <?php else: ?><?= escape($meal['name']) ?><?php endif; ?>
            </h3>
            <p><?= escape($meal['service_date'] ?? '') ?> · <?= escape($meal['allergy_evaluation']['status'] ?? 'not_assessed') ?></p>
            <p><?= escape($meal['allergy_evaluation']['notice'] ?? '') ?></p></article>
        <?php endforeach; ?>
        <h3>Your special meal</h3>
        <?php if (empty($specialMeals['data'])): ?><p>No special meal has been recorded. Contact dietary staff.</p><?php endif; ?>
        <?php foreach ($specialMeals['data'] ?? [] as $meal): ?>
            <p>Menu <?= escape($meal['menu_id']) ?>: <?= escape($meal['request']) ?> (<?= escape($meal['status']) ?>)</p>
        <?php endforeach; ?>
        <?php foreach (['Next menus' => ['menu_after', $result['next_after'] ?? null], 'Next special meals' => ['special_after', $specialMeals['next_after'] ?? null]] as $label => [$field, $next]): ?>
            <?php if ($next !== null): ?>
            <form method="post">
                <input type="hidden" name="csrf" value="<?= escape($_SESSION['csrf']) ?>">
                <input type="hidden" name="action" value="menus">
                <input type="hidden" name="camper_id" value="<?= escape($mealCamper) ?>">
                <input type="hidden" name="menu_after" value="<?= escape($field === 'menu_after' ? $next : $menuAfter) ?>">
                <input type="hidden" name="special_after" value="<?= escape($field === 'special_after' ? $next : $specialAfter) ?>">
                <button type="submit"><?= escape($label) ?></button>
            </form>
            <?php endif; ?>
        <?php endforeach; ?>
    </section>
    <?php endif; ?>
    <?php if ($result !== null): ?>
    <section aria-live="polite"><h2>API result</h2>
        <pre><?= escape(json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)) ?></pre>
        <?php if ($activityView && ($result['next_after'] ?? null) !== null): ?>
        <form method="post">
            <input type="hidden" name="csrf" value="<?= escape($_SESSION['csrf']) ?>">
            <input type="hidden" name="action" value="activities">
            <input type="hidden" name="after" value="<?= escape($result['next_after']) ?>">
            <button type="submit">Next activities</button>
        </form>
        <?php endif; ?>
    </section>
    <?php endif; ?>
</main>
<footer>Camp Cody's · Private portal · Use only on an authorized, secure device.</footer>
</body>
</html>
