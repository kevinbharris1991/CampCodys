<?php
declare(strict_types=1);

namespace Camp;

final class App
{
    private ?array $user = null;
    private ?array $client = null;
    private array $roles = [];
    private array $grants = [];
    private string $requestId;
    private string $addressHash;

    public function __construct(private \PDO $db, private array $config)
    {
        $this->requestId = bin2hex(random_bytes(16));
        $this->addressHash = hash_hmac('sha256', $_SERVER['REMOTE_ADDR'] ?? 'unknown', $config['key']);
    }

    public function run(): never
    {
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        header('X-Content-Type-Options: nosniff');
        header('Referrer-Policy: no-referrer');
        header('X-Request-ID: ' . $this->requestId);
        try {
            if ($this->config['APP_REQUIRE_TLS'] === 'true' && !in_array($_SERVER['HTTPS'] ?? '', ['on', '1'], true)) {
                throw new ApiError(403, 'HTTPS is required');
            }
            $this->rate('request:' . $this->addressHash, 300, 60);
            $this->authenticateClient();
            $this->rate('client:' . $this->client['id'] . ':' . $this->addressHash, 180, 60);
            $method = $_SERVER['REQUEST_METHOD'] ?? '';
            $path = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH);
            if (!is_string($path) || !str_starts_with($path, '/api/v1/')) {
                throw new ApiError(404, 'Not found');
            }
            $path = substr($path, 7);
            if ($path === '/auth/login' && $method === 'POST') {
                $this->respond($this->login());
            }
            $this->authenticateUser();
            if ($path === '/auth/me' && $method === 'GET') {
                $this->audit('auth.me');
                $this->respond([
                    'user' => ['id' => (int) $this->user['id'], 'email' => $this->user['email'], 'display_name' => $this->user['display_name']],
                    'groups' => array_map(static fn(array $r): array => ['id' => (int) $r['id'], 'name' => $r['name']], $this->roles),
                    'permissions' => (object) $this->permissions(),
                ]);
            }
            if ($path === '/auth/logout' && $method === 'POST') {
                $this->db->beginTransaction();
                $this->execute('UPDATE sessions SET revoked_at = UTC_TIMESTAMP() WHERE token_hash = ?', [$this->sessionHash()]);
                $this->audit('auth.logout');
                $this->db->commit();
                $this->respond(['data' => ['revoked' => true]]);
            }
            if ($path === '/resources' && $method === 'GET') {
                $resources = [];
                foreach ($this->permissions() as $resource => $actions) {
                    $definition = catalog()[$resource];
                    $fields = [];
                    foreach ($definition['fields'] as $name => $field) {
                        $fields[] = ['name' => $name, 'required' => in_array($name, $definition['required'], true)] + $field;
                    }
                    if ($definition['scope'] === 'camper') {
                        array_unshift($fields, ['name' => 'camper_id', 'type' => 'reference', 'target' => 'campers', 'required' => true]);
                    } elseif ($definition['scope'] === 'identity') {
                        array_unshift($fields, ['name' => 'owner_id', 'type' => 'user_reference', 'required' => true]);
                    } elseif ($definition['scope'] === 'own') {
                        array_unshift($fields, ['name' => 'owner_id', 'type' => 'user_reference', 'required' => false]);
                    }
                    $resources[] = ['name' => $resource, 'label' => $definition['label'], 'fields' => $fields, 'actions' => $actions];
                }
                $this->audit('resources.list');
                $this->respond(['data' => $resources]);
            }
            if ($path === '/menus' && $method === 'GET') {
                $this->respond($this->menus());
            }
            if ($path === '/activities' && $method === 'GET') {
                $this->respond($this->records('activities', null, 'GET'));
            }
            if (preg_match('~^/activities/([1-9][0-9]{0,17})/signup$~D', $path, $match) && $method === 'POST') {
                $body = $this->body();
                if (array_keys($body) !== ['camper_id']) {
                    throw new ApiError(422, 'Only camper_id is accepted');
                }
                $body['activity_id'] = (int) $match[1];
                $this->respond($this->records('activity_signups', null, 'POST', $body), 201);
            }
            if (preg_match('~^/records/([a-z_]+)(?:/([1-9][0-9]{0,17}))?$~D', $path, $match)) {
                $id = isset($match[2]) ? (int) $match[2] : null;
                $this->respond($this->records($match[1], $id, $method), $method === 'POST' ? 201 : 200);
            }
            throw new ApiError(404, 'Not found');
        } catch (ApiError $error) {
            $this->fail($error->status, $error->getMessage());
        } catch (\Throwable) {
            $this->fail(503, 'Service unavailable');
        }
    }

    private function execute(string $sql, array $params = []): \PDOStatement
    {
        $query = $this->db->prepare($sql);
        $query->execute($params);
        return $query;
    }

    private function rate(string $name, int $limit, int $seconds): void
    {
        $bucket = hash('sha256', $name . ':' . intdiv(time(), $seconds));
        $expiry = gmdate('Y-m-d H:i:s', time() + $seconds * 2);
        $this->execute('INSERT INTO rate_limits (bucket, hits, expires_at) VALUES (?, 1, ?) ON DUPLICATE KEY UPDATE hits = hits + 1', [$bucket, $expiry]);
        $hits = (int) $this->execute('SELECT hits FROM rate_limits WHERE bucket = ?', [$bucket])->fetchColumn();
        if ($hits > $limit) {
            header('Retry-After: ' . $seconds);
            throw new ApiError(429, 'Too many requests');
        }
    }

    private function authenticateClient(): void
    {
        $token = $_SERVER['HTTP_X_API_TOKEN'] ?? '';
        $secret = $_SERVER['HTTP_X_API_SECRET'] ?? '';
        if (!preg_match('/^[a-f0-9]{48}$/D', $token) || !preg_match('/^[a-f0-9]{64}$/D', $secret)) {
            throw new ApiError(401, 'Invalid API credentials');
        }
        $client = $this->execute('SELECT * FROM api_clients WHERE token = ? AND active = 1 AND expires_at > UTC_TIMESTAMP()', [$token])->fetch();
        if (!$client || !hash_equals($client['secret_hash'], hash('sha256', $secret))) {
            throw new ApiError(401, 'Invalid API credentials');
        }
        $client['scopes'] = json_decode($client['scopes'], true, 32, JSON_THROW_ON_ERROR);
        $this->client = $client;
    }

    private function login(): array
    {
        $this->rate('login:' . $this->addressHash, 10, 900);
        $body = $this->body();
        if (count($body) !== 2 || !isset($body['email'], $body['password'])
            || !is_string($body['email']) || !is_string($body['password'])
            || strlen($body['email']) > 254 || strlen($body['password']) > 1024) {
            throw new ApiError(422, 'Email and password required');
        }
        $email = strtolower(trim($body['email']));
        $this->rate('account:' . hash_hmac('sha256', $email, $this->config['key']), 15, 900);
        $user = $this->execute('SELECT * FROM users WHERE email = ? AND active = 1', [$email])->fetch();
        // A dummy Argon2id hash avoids skipping expensive verification for unknown accounts.
        $hash = $user['password_hash'] ?? '$argon2id$v=19$m=65536,t=4,p=1$WHpILnZCR0ppN1VoNGx4Lw$7FwzUCFZ5W/iqRyTrDay4jVmEcP/JCqrKdUBL0Gqh3g';
        if (!password_verify($body['password'], $hash) || !$user) {
            throw new ApiError(401, 'Invalid email or password');
        }
        $this->user = $user;
        $token = bin2hex(random_bytes(32));
        $this->db->beginTransaction();
        $this->execute('SELECT id FROM users WHERE id = ? FOR UPDATE', [$user['id']]);
        $this->execute('UPDATE sessions SET revoked_at = UTC_TIMESTAMP() WHERE user_id = ? AND expires_at <= UTC_TIMESTAMP() AND revoked_at IS NULL', [$user['id']]);
        $active = $this->execute('SELECT id FROM sessions WHERE user_id = ? AND revoked_at IS NULL ORDER BY id DESC', [$user['id']])->fetchAll();
        foreach (array_slice($active, 9) as $session) {
            $this->execute('UPDATE sessions SET revoked_at = UTC_TIMESTAMP() WHERE id = ?', [$session['id']]);
        }
        $this->execute('INSERT INTO sessions (user_id, client_id, token_hash, expires_at) VALUES (?, ?, ?, ?)', [
            $user['id'], $this->client['id'], hash('sha256', $token), gmdate('Y-m-d H:i:s', time() + 3600),
        ]);
        if (password_needs_rehash($hash, PASSWORD_ARGON2ID)) {
            $this->execute('UPDATE users SET password_hash = ? WHERE id = ?', [password_hash($body['password'], PASSWORD_ARGON2ID), $user['id']]);
        }
        $this->audit('auth.login');
        $this->db->commit();
        return ['access_token' => $token, 'expires_in' => 3600];
    }

    private function sessionHash(): string
    {
        $header = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if (!preg_match('/^' . 'Bea' . 'rer ([a-f0-9]{64})$/D', $header, $matches)) {
            throw new ApiError(401, 'Session authorization required');
        }
        return hash('sha256', $matches[1]);
    }

    private function authenticateUser(): void
    {
        $user = $this->execute('SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.client_id = ? AND s.revoked_at IS NULL AND s.expires_at > UTC_TIMESTAMP() AND u.active = 1', [$this->sessionHash(), $this->client['id']])->fetch();
        if (!$user) {
            throw new ApiError(401, 'Invalid or expired session');
        }
        $this->user = $user;
        $this->roles = $this->execute('SELECT r.id, r.name FROM roles r JOIN memberships m ON m.role_id = r.id WHERE m.user_id = ? ORDER BY r.id', [$user['id']])->fetchAll();
        foreach ($this->roles as $role) {
            foreach (roleGrants()[(int) $role['id']] ?? [] as $resource => $actions) {
                foreach ($actions as $action => $scopes) {
                    if (in_array($action, $this->client['scopes'][$resource] ?? [], true)) {
                        $this->grants[$resource][$action] = array_values(array_unique(array_merge($this->grants[$resource][$action] ?? [], $scopes)));
                    }
                }
            }
        }
    }

    private function permissions(): array
    {
        $result = [];
        foreach ($this->grants as $resource => $actions) {
            $result[$resource] = array_keys($actions);
        }
        return $result;
    }

    private function scopes(string $resource, string $action): array
    {
        $scopes = $this->grants[$resource][$action] ?? [];
        if (!$scopes) {
            throw new ApiError(403, 'Permission denied');
        }
        return $scopes;
    }

    private function accessible(array $row, string $action): bool
    {
        $scopes = $this->scopes($row['resource'], $action);
        return in_array('all', $scopes, true)
            || (in_array('own', $scopes, true) && (int) $row['owner_id'] === (int) $this->user['id'])
            || (in_array('assigned', $scopes, true) && $this->execute(
                'SELECT 1 FROM counselor_assignments WHERE user_id = ? AND camper_id = ?',
                [$this->user['id'], $row['resource'] === 'campers' ? $row['id'] : $row['camper_id']]
            )->fetchColumn())
            || (in_array('published', $scopes, true) && $this->published($row));
    }

    private function published(array $row): bool
    {
        return match ($row['resource']) {
            'menus' => $row['visibility'] === 'published',
            'activities' => $row['visibility'] === 'available',
            'grants' => true,
            default => false,
        };
    }

    private function find(string $resource, int $id, string $action = 'read', bool $lock = false): array
    {
        $this->scopes($resource, $action);
        $row = $this->execute('SELECT * FROM records WHERE resource = ? AND id = ?' . ($lock ? ' FOR UPDATE' : ''), [$resource, $id])->fetch();
        if (!$row || !$this->accessible($row, $action)) {
            throw new ApiError(404, 'Record not found');
        }
        return $row;
    }

    private function projection(array $row): array
    {
        $payload = decryptPayload($row['payload'], $this->config['key']);
        // Never return fields not explicitly defined, even if old/imported payloads contain them.
        $payload = array_intersect_key($payload, catalog()[$row['resource']]['fields']);
        return [
            'id' => (int) $row['id'],
            'owner_id' => $row['owner_id'] === null ? null : (int) $row['owner_id'],
            'camper_id' => $row['camper_id'] === null ? null : (int) $row['camper_id'],
            'created_at' => $row['created_at'], 'updated_at' => $row['updated_at'],
        ] + $payload;
    }

    private function listRecords(string $resource): array
    {
        $scopes = $this->scopes($resource, 'read');
        $where = ['resource = ?'];
        $params = [$resource];
        $conditions = [];
        if (in_array('all', $scopes, true)) {
            $conditions[] = '1 = 1';
        }
        if (in_array('own', $scopes, true)) {
            $conditions[] = 'owner_id = ?';
            $params[] = $this->user['id'];
        }
        if (in_array('assigned', $scopes, true)) {
            $conditions[] = ($resource === 'campers' ? 'id' : 'camper_id') . ' IN (SELECT camper_id FROM counselor_assignments WHERE user_id = ?)';
            $params[] = $this->user['id'];
        }
        if (in_array('published', $scopes, true)) {
            $conditions[] = match ($resource) {
                'menus' => "visibility = 'published'",
                'activities' => "visibility = 'available'",
                'grants' => '1 = 1',
                default => '1 = 0',
            };
        }
        $where[] = '(' . implode(' OR ', $conditions) . ')';
        foreach ($_GET as $name => $value) {
            if (!in_array($name, ['after', 'limit', 'camper_id'], true)
                || !is_string($value) || !preg_match('/^[1-9][0-9]{0,17}$/D', $value)) {
                throw new ApiError(422, 'Invalid query');
            }
        }
        if (isset($_GET['after'])) {
            $where[] = 'id > ?';
            $params[] = (int) $_GET['after'];
        }
        if (isset($_GET['camper_id'])) {
            $where[] = 'camper_id = ?';
            $params[] = (int) $_GET['camper_id'];
        }
        $limit = min((int) ($_GET['limit'] ?? 50), 100);
        $rows = $this->execute('SELECT * FROM records WHERE ' . implode(' AND ', $where) . ' ORDER BY id LIMIT ' . ($limit + 1), $params)->fetchAll();
        $hasMore = count($rows) > $limit;
        $rows = array_slice($rows, 0, $limit);
        $this->audit('records.list', $resource);
        return ['data' => array_map($this->projection(...), $rows), 'next_after' => $hasMore ? (int) end($rows)['id'] : null];
    }

    private function records(string $resource, ?int $id, string $method, ?array $input = null): array
    {
        $definition = catalog()[$resource] ?? null;
        if (!$definition) {
            throw new ApiError(404, 'Not found');
        }
        $action = match ($method) {
            'GET' => 'read', 'POST' => 'create', 'PATCH', 'PUT' => 'update', 'DELETE' => 'delete',
            default => throw new ApiError(405, 'Method not allowed'),
        };
        $this->scopes($resource, $action);
        if (in_array($resource, ['audit_events', 'configuration'], true)) {
            return $this->systemRecords($resource, $id);
        }
        if (($method === 'POST' && $id !== null) || (in_array($method, ['PUT', 'PATCH', 'DELETE'], true) && $id === null)) {
            throw new ApiError(405, 'Method not allowed');
        }
        if ($method === 'GET') {
            if ($id === null) {
                return $this->listRecords($resource);
            }
            $row = $this->find($resource, $id);
            $this->audit('records.read', $resource, $id);
            return ['data' => $this->projection($row)];
        }
        $this->db->beginTransaction();
        $old = $id === null ? null : $this->find($resource, $id, $action, true);
        if ($method === 'DELETE') {
            $this->guestStatus($resource, $old, []);
            try {
                $this->execute('DELETE FROM records WHERE id = ?', [$id]);
            } catch (\PDOException $e) {
                if ($e->getCode() === '23000') {
                    throw new ApiError(409, 'Record has linked records');
                }
                throw $e;
            }
            $this->audit('records.delete', $resource, $id);
            $this->db->commit();
            return ['data' => ['id' => $id, 'deleted' => true]];
        }
        $body = $input ?? $this->body();
        if ($resource === 'activity_signups' && !$old && !isset($body['status'])) {
            $body['status'] = 'enrolled';
        }
        [$ownerId, $camperId] = $this->ownership($resource, $definition, $body, $old, $action);
        $candidate = ['id' => $id, 'resource' => $resource, 'owner_id' => $ownerId, 'camper_id' => $camperId, 'visibility' => ''];
        if (!$this->accessible($candidate, $action)) {
            throw new ApiError(403, 'Permission denied');
        }
        $fields = validateFields($body, $definition, $method === 'PATCH');
        $payload = $method === 'PATCH' ? array_replace(decryptPayload($old['payload'], $this->config['key']), $fields) : $fields;
        if ($resource === 'activity_signups') {
            $payload['status'] ??= 'enrolled';
        }
        $payload = validateFields($payload, $definition);
        if ($resource === 'participation' && $old) {
            $previous = decryptPayload($old['payload'], $this->config['key']);
            if ($payload['activity_id'] !== $previous['activity_id']) {
                throw new ApiError(422, 'Participation activity is immutable');
            }
            if (($payload['status'] === 'cancelled') !== ($previous['status'] === 'cancelled')) {
                throw new ApiError(409, 'Enrollment cancellation must use the signup record');
            }
        }
        if (isset($payload['arrival_date'], $payload['departure_date']) && $payload['arrival_date'] > $payload['departure_date']) {
            throw new ApiError(422, 'Departure must not precede arrival');
        }
        if ($resource === 'grant_applications' && (int) $ownerId === (int) $this->user['id'] && $payload['status'] !== 'submitted') {
            throw new ApiError(403, 'An applicant cannot approve or decline their own application');
        }
        $this->guestStatus($resource, $old, $payload);
        $links = $this->validateLinks($resource, $definition, $payload, $ownerId, $camperId);
        $visibility = in_array($resource, ['menus', 'activities'], true) ? $payload['status'] : '';
        if ($resource === 'activities' && $old) {
            $count = count($this->execute('SELECT record_id FROM activity_enrollments WHERE activity_id = ? FOR UPDATE', [$id])->fetchAll());
            if ($payload['capacity'] < $count) {
                throw new ApiError(409, 'Capacity is below current enrollment');
            }
        }
        if ($resource === 'activity_signups' && $payload['status'] === 'enrolled') {
            $this->checkEnrollment($payload['activity_id'], $camperId, $id);
        }
        $encrypted = encryptPayload($payload, $this->config['key']);
        if ($id === null) {
            $this->execute('INSERT INTO records (resource, owner_id, camper_id, visibility, payload) VALUES (?, ?, ?, ?, ?)', [$resource, $ownerId, $camperId, $visibility, $encrypted]);
            $id = (int) $this->db->lastInsertId();
        } else {
            $this->execute('UPDATE records SET payload = ?, visibility = ?, updated_at = UTC_TIMESTAMP() WHERE id = ?', [$encrypted, $visibility, $id]);
            $this->execute('DELETE FROM record_links WHERE record_id = ?', [$id]);
        }
        foreach ($links as $field => $target) {
            $this->execute('INSERT INTO record_links (record_id, field_name, target_id) VALUES (?, ?, ?)', [$id, $field, $target]);
        }
        if ($resource === 'activity_signups') {
            $this->execute('DELETE FROM activity_enrollments WHERE record_id = ?', [$id]);
            if ($payload['status'] === 'enrolled') {
                $this->execute('INSERT INTO activity_enrollments (activity_id, camper_id, record_id) VALUES (?, ?, ?)', [$payload['activity_id'], $camperId, $id]);
            }
            if (!$old || (decryptPayload($old['payload'], $this->config['key'])['status'] ?? 'enrolled') !== $payload['status']) {
                $this->syncParticipation($payload['activity_id'], $camperId, (int) $ownerId, $payload['status'] === 'enrolled' ? 'registered' : 'cancelled');
            }
        }
        $row = $this->execute('SELECT * FROM records WHERE id = ?', [$id])->fetch();
        $this->audit('records.' . $action, $resource, $id);
        $this->db->commit();
        // Create-only roles receive a receipt, not a read projection.
        return ['data' => isset($this->grants[$resource]['read']) && $this->accessible($row, 'read')
            ? $this->projection($row) : ['id' => $id]];
    }

    private function ownership(string $resource, array $definition, array &$body, ?array $old, string $action): array
    {
        $kind = $definition['scope'];
        $owner = $old['owner_id'] ?? null;
        $camper = $old['camper_id'] ?? null;
        if ($old) {
            foreach (['owner_id' => $owner, 'camper_id' => $camper] as $field => $expected) {
                if (array_key_exists($field, $body) && (!is_int($body[$field]) || $body[$field] !== (int) $expected || $expected === null)) {
                    throw new ApiError(422, 'Ownership is immutable');
                }
            }
        } elseif ($kind === 'camper') {
            if (!isset($body['camper_id']) || !is_int($body['camper_id']) || $body['camper_id'] < 1) {
                throw new ApiError(422, 'camper_id is required');
            }
            $camper = $body['camper_id'];
            $parent = $this->execute("SELECT * FROM records WHERE id = ? AND resource = 'campers' FOR UPDATE", [$camper])->fetch();
            if (!$parent) {
                throw new ApiError(404, 'Camper not found');
            }
            $owner = $parent['owner_id'];
            if (isset($body['owner_id']) && $body['owner_id'] !== (int) $owner) {
                throw new ApiError(422, 'Owner must match camper');
            }
        } elseif (in_array($kind, ['identity', 'own'], true)) {
            $owner = $body['owner_id'] ?? ($kind === 'own' ? (int) $this->user['id'] : null);
            if (!is_int($owner) || $owner < 1) {
                throw new ApiError(422, 'owner_id is required');
            }
            if (!in_array('all', $this->scopes($resource, $action), true) && $owner !== (int) $this->user['id']) {
                throw new ApiError(403, 'Permission denied');
            }
            if (!$this->execute('SELECT id FROM users WHERE id = ? AND active = 1', [$owner])->fetch()) {
                throw new ApiError(422, 'Invalid owner');
            }
        }
        if (($kind !== 'camper' && array_key_exists('camper_id', $body))
            || ($kind === 'none' && array_key_exists('owner_id', $body))) {
            throw new ApiError(422, 'Ownership field not allowed');
        }
        unset($body['owner_id'], $body['camper_id']);
        return [$owner, $camper];
    }

    private function guestStatus(string $resource, ?array $old, array $payload): void
    {
        $action = $old ? 'update' : 'create';
        // Restrictions apply when the acting grant is ownership-only; additive staff grants remain valid.
        $scopes = $this->grants[$resource][$action] ?? $this->grants[$resource]['delete'] ?? [];
        if (in_array('all', $scopes, true)) {
            return;
        }
        if ($resource === 'activity_signups') {
            $previous = $old ? decryptPayload($old['payload'], $this->config['key']) : null;
            if ((!$previous && ($payload['status'] ?? '') !== 'enrolled')
                || ($previous && (($payload['activity_id'] ?? null) !== $previous['activity_id']
                    || !in_array($payload['status'] ?? '', [$previous['status'] ?? 'enrolled', 'cancelled'], true)))) {
                throw new ApiError(403, 'Only cancellation of your existing enrollment is permitted');
            }
            return;
        }
        if ($resource === 'reservations' && $old && ($payload['status'] ?? '') === 'cancelled') {
            $previous = decryptPayload($old['payload'], $this->config['key']);
            if (in_array($previous['status'], ['requested', 'confirmed'], true)
                && array_diff_assoc(array_diff_key($payload, ['status' => true]), array_diff_key($previous, ['status' => true])) === []) {
                return;
            }
        }
        $initial = match ($resource) {
            'reservations', 'accommodations', 'special_meals' => 'requested',
            'grant_applications' => 'submitted',
            default => null,
        };
        if ($initial !== null && (($old && (decryptPayload($old['payload'], $this->config['key'])['status'] ?? '') !== $initial)
            || (isset($payload['status']) && $payload['status'] !== $initial))) {
            throw new ApiError(403, 'Staff review is required for this status');
        }
    }

    private function validateLinks(string $resource, array $definition, array $payload, ?int $ownerId, ?int $camperId): array
    {
        $links = [];
        foreach ($definition['fields'] as $field => $metadata) {
            if ($metadata['type'] === 'reference' && isset($payload[$field])) {
                $row = $this->find($metadata['target'], $payload[$field], 'read', true);
                if (catalog()[$metadata['target']]['scope'] === 'camper'
                    && ((int) $row['camper_id'] !== $camperId || (int) $row['owner_id'] !== $ownerId)) {
                    throw new ApiError(422, 'Linked record must belong to the same camper and owner');
                }
                if ($resource === 'special_meals' && !$this->published($row)
                    && !in_array('all', $this->grants['special_meals']['update'] ?? [], true)) {
                    throw new ApiError(422, 'Published menu required');
                }
                $links[$field] = $payload[$field];
            }
        }
        return $links;
    }

    private function syncParticipation(int $activity, int $camper, int $owner, string $status): void
    {
        $existing = $this->execute("SELECT r.* FROM records r JOIN record_links l ON l.record_id = r.id AND l.field_name = 'activity_id' WHERE r.resource = 'participation' AND r.camper_id = ? AND l.target_id = ? FOR UPDATE", [$camper, $activity])->fetch();
        if ($existing) {
            $payload = decryptPayload($existing['payload'], $this->config['key']);
            if ($status === 'cancelled' && !in_array($payload['status'], ['registered', 'cancelled'], true)) {
                throw new ApiError(409, 'Participation already recorded; staff review required');
            }
            $payload['status'] = $status;
            $this->execute('UPDATE records SET payload = ?, updated_at = UTC_TIMESTAMP() WHERE id = ?', [encryptPayload($payload, $this->config['key']), $existing['id']]);
            $id = (int) $existing['id'];
        } else {
            $this->execute("INSERT INTO records (resource, owner_id, camper_id, payload) VALUES ('participation', ?, ?, ?)", [
                $owner, $camper, encryptPayload(['activity_id' => $activity, 'status' => $status], $this->config['key']),
            ]);
            $id = (int) $this->db->lastInsertId();
            $this->execute("INSERT INTO record_links (record_id, field_name, target_id) VALUES (?, 'activity_id', ?)", [$id, $activity]);
        }
        $this->audit('participation.sync', 'participation', $id);
    }

    private function systemRecords(string $resource, ?int $id): array
    {
        foreach ($_GET as $name => $value) {
            if (!in_array($name, ['after', 'limit'], true) || !is_string($value) || !preg_match('/^[1-9][0-9]{0,17}$/D', $value)) {
                throw new ApiError(422, 'Invalid query');
            }
        }
        if ($resource === 'configuration') {
            if ($id !== null && $id !== 1) {
                throw new ApiError(404, 'Record not found');
            }
            $record = [
                'id' => 1, 'environment' => $this->config['APP_ENV'], 'https_required' => $this->config['APP_REQUIRE_TLS'] === 'true',
                'session_ttl_seconds' => 3600, 'max_body_bytes' => 65536, 'max_list_size' => 100,
            ];
            $this->audit('configuration.read', $resource);
            return $id === null ? ['data' => isset($_GET['after']) ? [] : [$record], 'next_after' => null] : ['data' => $record];
        }
        $limit = min((int) ($_GET['limit'] ?? 50), 100);
        $params = [$id ?? (int) ($_GET['after'] ?? 0)];
        $rows = $this->execute('SELECT id, occurred_at, actor_id, client_id, event, resource, record_id, outcome, request_id FROM audit_events WHERE id '
            . ($id === null ? '> ?' : '= ?') . ' ORDER BY id LIMIT ' . ($limit + 1), $params)->fetchAll();
        if ($id !== null && !$rows) {
            throw new ApiError(404, 'Record not found');
        }
        $more = count($rows) > $limit;
        $rows = array_slice($rows, 0, $limit);
        foreach ($rows as &$row) {
            foreach (['id', 'actor_id', 'client_id', 'record_id'] as $field) {
                $row[$field] = $row[$field] === null ? null : (int) $row[$field];
            }
            $row['occurred_at'] = str_replace(' ', 'T', $row['occurred_at']) . 'Z';
        }
        unset($row);
        $this->audit('audit.read', $resource, $id);
        return $id === null ? ['data' => $rows, 'next_after' => $more ? (int) end($rows)['id'] : null] : ['data' => $rows[0]];
    }

    private function checkEnrollment(int $activity, int $camper, ?int $record): void
    {
        $row = $this->find('activities', $activity, 'read', true);
        $payload = decryptPayload($row['payload'], $this->config['key']);
        if ($payload['status'] !== 'available' || $payload['scheduled_on'] < gmdate('Y-m-d')) {
            throw new ApiError(409, 'Activity is not available');
        }
        $existing = $this->execute('SELECT record_id FROM activity_enrollments WHERE activity_id = ? AND camper_id = ?', [$activity, $camper])->fetchColumn();
        if ($existing && (int) $existing !== $record) {
            throw new ApiError(409, 'Already enrolled');
        }
        $count = count($this->execute('SELECT record_id FROM activity_enrollments WHERE activity_id = ? FOR UPDATE', [$activity])->fetchAll());
        if (!$existing && $count >= $payload['capacity']) {
            throw new ApiError(409, 'Activity is full');
        }
    }

    private function menus(): array
    {
        $camperId = $_GET['camper_id'] ?? null;
        $allergens = [];
        if ($camperId !== null) {
            if (!is_string($camperId) || !preg_match('/^[1-9][0-9]{0,17}$/D', $camperId)) {
                throw new ApiError(422, 'Invalid camper_id');
            }
            $this->find('campers', (int) $camperId);
            $this->scopes('allergies', 'read');
            $rows = $this->execute("SELECT * FROM records WHERE resource = 'allergies' AND camper_id = ?", [(int) $camperId])->fetchAll();
            foreach ($rows as $row) {
                if ($this->accessible($row, 'read')) {
                    $allergens[] = mb_strtolower(trim(decryptPayload($row['payload'], $this->config['key'])['allergen']));
                }
            }
            $this->audit('allergies.evaluate', 'allergies');
        }
        unset($_GET['camper_id']);
        $result = $this->listRecords('menus');
        foreach ($result['data'] as &$menu) {
            $declared = array_map(static fn(string $value): string => mb_strtolower(trim($value)), array_merge($menu['allergens'], $menu['ingredients']));
            $menu['allergy_evaluation'] = [
                'status' => !$allergens ? 'not_assessed' : (array_intersect($allergens, $declared) ? 'potential_conflict' : 'no_declared_match'),
                'notice' => 'Not a safety guarantee. Ingredient aliases, incomplete declarations and cross-contact require kitchen/clinical review.',
            ];
        }
        return $result;
    }

    private function body(): array
    {
        if (strtolower(trim(explode(';', $_SERVER['CONTENT_TYPE'] ?? '')[0])) !== 'application/json') {
            throw new ApiError(415, 'application/json is required');
        }
        $raw = file_get_contents('php://input', false, null, 0, 65537);
        if ($raw === false || strlen($raw) > 65536) {
            throw new ApiError(413, 'Request body too large');
        }
        try {
            $object = json_decode($raw, false, 16, JSON_THROW_ON_ERROR);
            if (!$object instanceof \stdClass) {
                throw new ApiError(422, 'JSON object required');
            }
            return json_decode($raw, true, 16, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw new ApiError(422, 'Invalid JSON');
        }
    }

    private function audit(string $event, ?string $resource = null, ?int $id = null, string $outcome = 'success'): void
    {
        $this->execute('INSERT INTO audit_events (actor_id, client_id, event, resource, record_id, outcome, request_id, address_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [
            $this->user['id'] ?? null, $this->client['id'] ?? null, $event, $resource, $id, $outcome, $this->requestId, $this->addressHash,
        ]);
    }

    private function fail(int $status, string $message): never
    {
        if ($this->db->inTransaction()) {
            $this->db->rollBack();
        }
        try {
            $this->audit('request.denied', null, null, (string) $status);
        } catch (\Throwable) {
            $status = 503;
            $message = 'Service unavailable';
        }
        $this->respond(['error' => $message, 'request_id' => $this->requestId], $status);
    }

    private function respond(array $body, int $status = 200): never
    {
        http_response_code($status);
        echo json_encode($body, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        exit;
    }
}
