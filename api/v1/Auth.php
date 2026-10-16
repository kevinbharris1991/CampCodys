<?php
declare(strict_types=1);

namespace Camp;

function base32Encode(string $bytes): string
{
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits = '';
    foreach (str_split($bytes) as $byte) {
        $bits .= str_pad(decbin(ord($byte)), 8, '0', STR_PAD_LEFT);
    }
    $result = '';
    foreach (str_split($bits, 5) as $chunk) {
        $result .= $alphabet[bindec(str_pad($chunk, 5, '0'))];
    }
    return $result;
}

function totpCode(string $secret, int $step): string
{
    if (!preg_match('/^[A-Z2-7]{32}$/D', $secret) || $step < 0) {
        throw new \RuntimeException('Invalid TOTP parameters');
    }
    $bits = '';
    foreach (str_split($secret) as $character) {
        $bits .= str_pad(decbin(strpos('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', $character)), 5, '0', STR_PAD_LEFT);
    }
    $key = '';
    foreach (str_split($bits, 8) as $byte) {
        $key .= chr(bindec($byte));
    }
    $hash = hash_hmac('sha1', pack('N2', intdiv($step, 4294967296), $step % 4294967296), $key, true);
    $offset = ord($hash[19]) & 15;
    $value = unpack('N', substr($hash, $offset, 4))[1] & 0x7fffffff;
    return str_pad((string) ($value % 1000000), 6, '0', STR_PAD_LEFT);
}

function totpStep(string $secret, string $code, int $lastStep, ?int $now = null): ?int
{
    if (!preg_match('/^[0-9]{6}$/D', $code)) {
        return null;
    }
    $current = intdiv($now ?? time(), 30);
    foreach ([$current, $current - 1, $current + 1] as $step) {
        if ($step > $lastStep && hash_equals(totpCode($secret, $step), $code)) {
            return $step;
        }
    }
    return null;
}

trait RegistrationAuth
{
    private function authFields(array $body, array $required, array $optional = []): void
    {
        if (array_diff(array_keys($body), array_merge($required, $optional))) {
            throw new ApiError(422, 'Unexpected field; submit only the documented fields');
        }
        foreach ($required as $name) {
            if (!array_key_exists($name, $body)) {
                throw new ApiError(422, 'Required field: ' . $name);
            }
        }
    }

    private function authToken(array $body, string $name): string
    {
        if (!is_string($body[$name] ?? null) || !preg_match('/^[a-f0-9]{64}$/D', $body[$name])) {
            throw new ApiError(401, 'Invalid or expired ' . str_replace('_', ' ', $name));
        }
        return hash('sha256', $body[$name]);
    }

    private function authText(mixed $value, int $max): bool
    {
        return is_string($value) && mb_check_encoding($value, 'UTF-8') && trim($value) !== ''
            && mb_strlen($value) <= $max && !preg_match('/[\x00-\x1f\x7f]/', $value);
    }

    private function register(): array
    {
        $this->rate('register:' . $this->addressHash, 10, 3600);
        $body = $this->body();
        $this->authFields($body, ['name', 'date_of_birth', 'email', 'gender', 'terms_accepted', 'privacy_accepted']);
        if (!$this->authText($body['name'], 120)) {
            throw new ApiError(422, 'Name must be nonempty text of at most 120 characters');
        }
        $dob = $body['date_of_birth'];
        if (!is_string($dob) || !preg_match('/^\d{4}-\d{2}-\d{2}$/D', $dob)
            || !($date = \DateTimeImmutable::createFromFormat('!Y-m-d', $dob, new \DateTimeZone('UTC')))
            || $date->format('Y-m-d') !== $dob || $dob > gmdate('Y-m-d') || $dob < '1900-01-01') {
            throw new ApiError(422, 'Date of birth must be a real date between 1900-01-01 and today (YYYY-MM-DD)');
        }
        if ($date->diff(new \DateTimeImmutable('today', new \DateTimeZone('UTC')))->y < 18) {
            throw new ApiError(422, 'You must be 18 or older to register');
        }
        if (!is_string($body['email']) || strlen($body['email']) > 254 || !filter_var(trim($body['email']), FILTER_VALIDATE_EMAIL)) {
            throw new ApiError(422, 'A valid email address is required');
        }
        if (!is_string($body['gender']) || !in_array($body['gender'], ['female', 'male', 'non_binary', 'self_described', 'prefer_not_to_say'], true)) {
            throw new ApiError(422, 'Gender must be female, male, non_binary, self_described or prefer_not_to_say');
        }
        if ($body['terms_accepted'] !== true || $body['privacy_accepted'] !== true) {
            throw new ApiError(422, 'Terms and privacy policy must each be accepted separately');
        }
        if (empty($this->config['APP_PUBLIC_URL']) || empty($this->config['APP_MAIL_FROM'])) {
            throw new ApiError(503, 'Registration email is not configured');
        }
        $email = strtolower(trim($body['email']));
        $this->rate('registration-email:' . hash_hmac('sha256', $email, $this->config['key']), 3, 3600);
        $message = ['message' => 'If this address is eligible, an activation email will arrive shortly.'];
        $this->db->beginTransaction();
        $row = $this->execute('SELECT * FROM account_onboarding WHERE email = ? FOR UPDATE', [$email])->fetch();
        if (($row && $row['stage'] === 'complete') || $this->execute('SELECT id FROM users WHERE email = ?', [$email])->fetchColumn()) {
            $this->db->commit();
            return $message;
        }
        $token = bin2hex(random_bytes(32));
        if (!$row) {
            $profile = ['name' => trim($body['name']), 'date_of_birth' => $dob, 'gender' => $body['gender']];
            try {
                $this->execute('INSERT INTO account_onboarding (email, profile, activation_hash, expires_at, terms_accepted_at, privacy_accepted_at) VALUES (?, ?, ?, ?, UTC_TIMESTAMP(), UTC_TIMESTAMP())', [
                    $email, encryptPayload($profile, $this->config['key']), hash('sha256', $token), gmdate('Y-m-d H:i:s', time() + 86400),
                ]);
            } catch (\PDOException $error) {
                if ($error->getCode() !== '23000') {
                    throw $error;
                }
                $this->db->rollBack();
                return $message;
            }
            $row = ['id' => (int) $this->db->lastInsertId()];
        }
        // Resends add a capability; they never reset credentials, secrets, consent or older valid links.
        $this->execute('INSERT INTO onboarding_activation_tokens (token_hash, account_id, expires_at) VALUES (?, ?, ?)', [
            hash('sha256', $token), $row['id'], gmdate('Y-m-d H:i:s', time() + 86400),
        ]);
        // Never derive an activation origin from Host, forwarded headers, or submitted data.
        $link = $this->config['APP_PUBLIC_URL'] . '?activate=' . $token;
        if (!mail($email, "Activate your Camp Cody's account",
            "Activate your account within 24 hours:\n\n" . $link . "\n\nIf you did not request this, ignore this message.\n",
            ['From' => $this->config['APP_MAIL_FROM'], 'Content-Type' => 'text/plain; charset=UTF-8'])) {
            throw new ApiError(503, 'Activation email could not be sent; please try again later');
        }
        $this->audit('auth.register');
        $this->db->commit();
        return $message;
    }

    private function activate(): array
    {
        $this->rate('activation:' . $this->addressHash, 30, 900);
        $body = $this->body();
        $this->authFields($body, ['token']);
        $hash = $this->authToken($body, 'token');
        $this->db->beginTransaction();
        $id = $this->execute('SELECT account_id FROM onboarding_activation_tokens WHERE token_hash = ?', [$hash])->fetchColumn();
        // Also accept unconsumed links issued before the additive recovery-token migration.
        if (!$id) {
            $id = $this->execute('SELECT id FROM account_onboarding WHERE activation_hash = ?', [$hash])->fetchColumn();
        }
        $row = $id ? $this->execute('SELECT * FROM account_onboarding WHERE id = ? FOR UPDATE', [$id])->fetch() : false;
        $link = $row ? $this->execute('SELECT token_hash FROM onboarding_activation_tokens WHERE token_hash = ? AND account_id = ? AND expires_at > UTC_TIMESTAMP() FOR UPDATE', [$hash, $row['id']])->fetchColumn() : false;
        $legacyLink = $row && $row['stage'] === 'pending' && hash_equals($row['activation_hash'] ?? '', $hash)
            && $row['expires_at'] > gmdate('Y-m-d H:i:s');
        if (!$row || $row['stage'] === 'complete' || (!$link && !$legacyLink)) {
            throw new ApiError(401, 'Invalid or expired activation token; register again after expiry');
        }
        $token = bin2hex(random_bytes(32));
        $next = $row['stage'] === 'profile' ? 'mfa' : 'profile';
        $this->execute('UPDATE account_onboarding SET stage = ?, activation_hash = NULL, onboarding_hash = ?, client_id = ?, expires_at = ? WHERE id = ?', [
            $next === 'mfa' ? 'profile' : 'activated', hash('sha256', $token), $this->client['id'], gmdate('Y-m-d H:i:s', time() + 86400), $row['id'],
        ]);
        $this->execute('DELETE FROM onboarding_activation_tokens WHERE account_id = ?', [$row['id']]);
        $this->audit('auth.activate');
        $this->db->commit();
        return ['onboarding_token' => $token, 'next_step' => $next];
    }

    private function onboarding(array $body): array
    {
        $hash = $this->authToken($body, 'onboarding_token');
        $row = $this->execute("SELECT * FROM account_onboarding WHERE onboarding_hash = ? AND client_id = ? AND stage IN ('activated', 'profile') AND expires_at > UTC_TIMESTAMP() FOR UPDATE", [$hash, $this->client['id']])->fetch();
        if (!$row) {
            throw new ApiError(401, 'Invalid or expired onboarding token; restart registration after expiry');
        }
        return $row;
    }

    private function mfaDetails(array $row): array
    {
        $profile = decryptPayload($row['profile'], $this->config['key']);
        return ['mfa_secret' => $profile['mfa_secret'], 'mfa_uri' => 'otpauth://totp/'
            . rawurlencode("Camp Cody's:" . $row['email']) . '?secret=' . $profile['mfa_secret']
            . '&issuer=' . rawurlencode("Camp Cody's") . '&algorithm=SHA1&digits=6&period=30'];
    }

    private function saveProfile(): array
    {
        $this->rate('profile:' . $this->addressHash, 30, 900);
        $body = $this->body(786432);
        $this->authFields($body, ['onboarding_token', 'username', 'password', 'password_confirmation'], ['profile_picture']);
        $this->db->beginTransaction();
        $row = $this->onboarding($body);
        if ($row['stage'] !== 'activated') {
            throw new ApiError(409, 'Profile is already established; resume MFA setup instead');
        }
        if (!is_string($body['username']) || !preg_match('/^[a-zA-Z0-9][a-zA-Z0-9_.-]{2,39}$/D', $body['username'])) {
            throw new ApiError(422, 'Username must be 3-40 letters, digits, dots, underscores or hyphens, starting with a letter or digit');
        }
        if (!is_string($body['password']) || strlen($body['password']) < 12 || strlen($body['password']) > 1024 || str_contains($body['password'], "\0")) {
            throw new ApiError(422, 'Password must be 12-1024 bytes without null characters');
        }
        if (!is_string($body['password_confirmation']) || !hash_equals($body['password'], $body['password_confirmation'])) {
            throw new ApiError(422, 'Password confirmation must match');
        }
        $profile = decryptPayload($row['profile'], $this->config['key']);
        if (isset($body['profile_picture'])) {
            $picture = $body['profile_picture'];
            $raw = is_string($picture) && strlen($picture) <= 349528 ? base64_decode($picture, true) : false;
            $image = $raw !== false ? @getimagesizefromstring($raw) : false;
            if ($raw === false || strlen($raw) > 262144 || base64_encode($raw) !== $picture || !$image
                || !in_array($image[2], [IMAGETYPE_JPEG, IMAGETYPE_PNG], true)
                || $image[0] > 4096 || $image[1] > 4096 || $image[0] * $image[1] > 16000000) {
                throw new ApiError(422, 'Profile picture must be raw base64 JPEG/PNG, at most 256 KiB and 4096 by 4096 pixels');
            }
            $profile['profile_picture'] = $picture;
        } elseif (array_key_exists('profile_picture', $body)) {
            throw new ApiError(422, 'Omit profile_picture when no image is supplied');
        }
        $profile['mfa_secret'] = base32Encode(random_bytes(20));
        $encrypted = encryptPayload($profile, $this->config['key']);
        try {
            $this->execute("UPDATE account_onboarding SET stage = 'profile', username = ?, password_hash = ?, profile = ? WHERE id = ?", [
                strtolower($body['username']), password_hash($body['password'], PASSWORD_ARGON2ID), $encrypted, $row['id'],
            ]);
        } catch (\PDOException $error) {
            if ($error->getCode() === '23000') {
                throw new ApiError(409, 'Username is unavailable; choose another');
            }
            throw $error;
        }
        $this->audit('auth.profile');
        $this->db->commit();
        return $this->mfaDetails(array_replace($row, ['profile' => $encrypted]));
    }

    private function setupMfa(): array
    {
        $this->rate('mfa-setup:' . $this->addressHash, 30, 900);
        $body = $this->body();
        $this->authFields($body, ['onboarding_token']);
        $this->db->beginTransaction();
        $row = $this->onboarding($body);
        if ($row['stage'] !== 'profile') {
            throw new ApiError(409, 'Complete your profile before MFA setup');
        }
        $result = $this->mfaDetails($row);
        $this->audit('auth.mfa.setup');
        $this->db->commit();
        return $result;
    }

    private function mfaBody(string $name): array
    {
        $this->rate('mfa:' . $this->addressHash, 60, 900);
        $body = $this->body();
        $this->authFields($body, [$name, 'code']);
        $hash = $this->authToken($body, $name);
        $this->rate('mfa-token:' . $hash, 8, 300);
        if (!is_string($body['code']) || !preg_match('/^[0-9]{6}$/D', $body['code'])) {
            throw new ApiError(422, 'Authenticator code must contain exactly six digits');
        }
        return $body;
    }

    private function confirmMfa(): array
    {
        $body = $this->mfaBody('onboarding_token');
        $this->db->beginTransaction();
        $row = $this->onboarding($body);
        if ($row['stage'] !== 'profile') {
            throw new ApiError(409, 'Complete your profile before confirming MFA');
        }
        $profile = decryptPayload($row['profile'], $this->config['key']);
        $step = totpStep($profile['mfa_secret'], $body['code'], -1);
        if ($step === null) {
            throw new ApiError(401, 'Invalid or already used authenticator code; check your device clock');
        }
        try {
            $this->execute('INSERT INTO users (email, display_name, password_hash) VALUES (?, ?, ?)', [
                $row['email'], $row['username'], $row['password_hash'],
            ]);
        } catch (\PDOException $error) {
            if ($error->getCode() === '23000') {
                throw new ApiError(409, 'Registration cannot be completed; contact support');
            }
            throw $error;
        }
        $id = (int) $this->db->lastInsertId();
        $this->execute('INSERT INTO memberships (user_id, role_id) VALUES (?, 12)', [$id]);
        $this->execute("UPDATE account_onboarding SET stage = 'complete', user_id = ?, onboarding_hash = NULL, password_hash = NULL, last_totp_step = ? WHERE id = ?", [$id, $step, $row['id']]);
        $this->execute('DELETE FROM onboarding_activation_tokens WHERE account_id = ?', [$row['id']]);
        $this->user = ['id' => $id];
        $result = $this->issueSession();
        $this->audit('auth.mfa.confirm');
        $this->db->commit();
        return $result;
    }

    private function verifyMfa(): array
    {
        $body = $this->mfaBody('mfa_token');
        $hash = $this->authToken($body, 'mfa_token');
        $challenge = $this->execute('SELECT user_id FROM mfa_challenges WHERE token_hash = ? AND client_id = ?', [$hash, $this->client['id']])->fetch();
        if (!$challenge) {
            throw new ApiError(401, 'Invalid or expired MFA token');
        }
        $this->db->beginTransaction();
        // Same lock ordering as password login and CLI password resets.
        $user = $this->execute('SELECT * FROM users WHERE id = ? FOR UPDATE', [$challenge['user_id']])->fetch();
        $challenge = $this->execute('SELECT * FROM mfa_challenges WHERE token_hash = ? AND client_id = ? AND expires_at > UTC_TIMESTAMP() FOR UPDATE', [$hash, $this->client['id']])->fetch();
        if (!$user || !$challenge || (int) $user['active'] !== 1 || !hash_equals($challenge['password_version'], hash('sha256', $user['password_hash']))) {
            throw new ApiError(401, 'Invalid or expired MFA token');
        }
        $row = $this->execute("SELECT * FROM account_onboarding WHERE user_id = ? AND stage = 'complete' FOR UPDATE", [$user['id']])->fetch();
        if (!$row) {
            throw new ApiError(401, 'Invalid or expired MFA token');
        }
        $profile = decryptPayload($row['profile'], $this->config['key']);
        $step = totpStep($profile['mfa_secret'], $body['code'], (int) $row['last_totp_step']);
        if ($step === null) {
            throw new ApiError(401, 'Invalid or already used authenticator code; wait for the next code and check your device clock');
        }
        $this->execute('UPDATE account_onboarding SET last_totp_step = ? WHERE id = ?', [$step, $row['id']]);
        $this->execute('DELETE FROM mfa_challenges WHERE token_hash = ?', [$hash]);
        $this->user = $user;
        $result = $this->issueSession();
        $this->audit('auth.mfa.verify');
        $this->db->commit();
        return $result;
    }

    private function issueSession(): array
    {
        $user = $this->user;
        $token = bin2hex(random_bytes(32));
        $this->execute('UPDATE sessions SET revoked_at = UTC_TIMESTAMP() WHERE user_id = ? AND expires_at <= UTC_TIMESTAMP() AND revoked_at IS NULL', [$user['id']]);
        $active = $this->execute('SELECT id FROM sessions WHERE user_id = ? AND revoked_at IS NULL ORDER BY id DESC', [$user['id']])->fetchAll();
        foreach (array_slice($active, 9) as $session) {
            $this->execute('UPDATE sessions SET revoked_at = UTC_TIMESTAMP() WHERE id = ?', [$session['id']]);
        }
        $this->execute('INSERT INTO sessions (user_id, client_id, token_hash, expires_at) VALUES (?, ?, ?, ?)', [
            $user['id'], $this->client['id'], hash('sha256', $token), gmdate('Y-m-d H:i:s', time() + 3600),
        ]);
        return ['access_token' => $token, 'expires_in' => 3600];
    }
}
