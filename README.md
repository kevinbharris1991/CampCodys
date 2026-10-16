# Camp Cody's

Accessible camp API foundation, built with PHP 8.3 and MySQL 8.

## Structure

- `/api/v1`: JSON API, explicit permissions for all twelve organizational groups,
  encrypted record payloads, sessions and audit events.
- `/developers/api/v1/`: endpoint, authorization, security and client documentation,
  including Java (Android), JavaScript, PHP, Swift (iOS) and Python examples.
- `/public/`: server-rendered staff/guest portal; API credentials and bearer tokens
  stay on the server.
- `/bin`: trusted operator provisioning tools.

**Not a HIPAA certification or a production-ready clinical/payment system.**
Use synthetic data until risk assessment, BAAs, MFA, independent testing,
retention policies, immutable audit retention and operational safeguards are in
place. Read the security section of the developer reference before deployment.

## Requirements and configuration

PHP 8.3 with PDO MySQL, sodium, mbstring and cURL; MySQL 8 with InnoDB.
No third-party application packages are required.

Use `.env.example` as a configuration reference. Prefer a secret manager or
service-managed environment outside the web root. The API also supports a local
`.env` for development (never commit it; restrict permissions to the service
account). The portal reads its settings from the **process environment**, not
the API's `.env`.

Configure `DB_DSN` (including `charset=utf8mb4`), `DB_USER`, `DB_PASSWORD`,
`APP_ENCRYPTION_KEY`, `APP_ENV=production`, and `APP_REQUIRE_TLS=true`.
Generate the encryption key using the operator CLI. Back it up separately;
changing it without migrating existing ciphertext destroys access to records.
For a remote production database, set `DB_SSL_CA` to the trusted CA certificate
path; the API requires verified encrypted database transport.

The portal additionally needs:

```text
PORTAL_API_BASE_URL=https://your-camp-host/api/v1
PORTAL_API_TOKEN=<provisioned API client token>
PORTAL_API_SECRET=<provisioned API client secret>
APP_ENV=production
```

For self-registration, configure `APP_PUBLIC_URL` with the trusted HTTPS portal
URL (for example `https://your-camp-host/public/`) and `APP_MAIL_FROM` with your
sender email address in the API environment. Configure PHP's `mail()` transport
to deliver activation emails; never derive activation links from request headers.
Set `PORTAL_TERMS_URL` and `PORTAL_PRIVACY_URL` in the portal process environment
to your published HTTPS terms of service and privacy policy. Registration stays
unavailable until these policies are configured.

New guests must be 13 or older and register their name, date of birth, email and gender, accepting both
policies before submitting. The activation email opens profile setup, with an
optional JPEG/PNG picture (256 KiB maximum), a unique username and a confirmed
password (12–1024 bytes). A verified authenticator-app code is required to finish
MFA setup before opening the dashboard. Subsequent guest sign-ins require a
password and authenticator code. Operator-provisioned accounts retain their
existing sign-in behavior.

After updating an existing installation, run `php bin/console.php setup` using
the schema administrator to create the additive onboarding tables, and grant
the runtime identity the required data privileges on those tables.

## Initialize and provision

Run these commands from your checkout after configuring the environment. Create
an empty `camp_codys` database using your database administrator first.

```bash
php bin/console.php help
php bin/console.php key
# Store the generated key securely in APP_ENCRYPTION_KEY, then:
php bin/console.php setup
php bin/console.php roles

# Read the password without echoing it or including it in shell history.
read -r -s -p 'Initial operator password: ' CAMP_PASSWORD; printf '\n'
printf '%s' "$CAMP_PASSWORD" | php bin/console.php user operator@example.org 'Camp Operator'
unset CAMP_PASSWORD
# Use the ID returned above (1 below is only an example).
php bin/console.php membership 1 2
php bin/console.php client 'Trusted portal' all
```

The final command displays the client token/secret **once**. Transfer them
directly to the portal's secret configuration, not source files or logs.
`all` is a deliberately broad *client* resource ceiling, not a user admin
override; for service integrations, replace it with a comma-separated resource
allowlist. Clients expire after 90 days and user sessions after one hour.

Create each staff/guest user with `user` and assign the documented group ID
using `membership`. Sign in as Administration and create a `campers` record:

```json
{"owner_id":2,"display_name":"Synthetic Camper"}
```

Here `2` is an existing guest user's ID; substitute the verified owner.
Use the returned camper record ID as `camper_id` on reservations, health
disclosures and other scoped records. Link counselors with
`php bin/console.php assign COUNSELOR_USER_ID CAMPER_ID`.
See `GET /resources` for the complete schema and the developer page for requests.

Revocation commands: `password USER_ID` reads a new password on stdin;
`disable-user USER_ID`, `revoke-sessions USER_ID`, and
`revoke-client CLIENT_ID` revoke access. `membership USER_ID ROLE_ID remove`
removes a group; `assign USER_ID CAMPER_ID remove` removes an assignment.
Run `cleanup` periodically to remove expired rate buckets and old sessions;
it does not delete clinical records or audit history. Restrict CLI access to
authorized operators and record the human operator identity in your operational
audit system.

Housekeeping/facilities roles cannot create their own restricted task rosters.
Trusted operators can preload non-camper tasks using `seed-task`, for example:

```sh
printf '%s' '{"location":"Synthetic cabin","task":"Fragrance-free cleaning","status":"open"}' |
  php bin/console.php seed-task sanitation
```

This command accepts only the documented non-camper task types; see CLI help.
Program participation records are generated by activity signups and updated by
Program Directors. Cancel an enrollment by PATCHing its `activity_signups`
record with `{"status":"cancelled"}` rather than deleting attendance history.

## Isolated local development

Use only synthetic data and a disposable database. Set `APP_ENV=development`,
`APP_REQUIRE_TLS=false`, and the database/encryption settings in the API
environment. Start the API on a separate loopback port:

```sh
php -S 127.0.0.1:8081 api/v1/index.php
```

In a second terminal, export `APP_ENV=development`,
`PORTAL_API_BASE_URL=http://127.0.0.1:8081/api/v1`, and the provisioned
`PORTAL_API_TOKEN`/`PORTAL_API_SECRET`, then:

```sh
php -S 127.0.0.1:8080 -t .
```

Open `http://127.0.0.1:8080/public/` or
`http://127.0.0.1:8080/developers/api/v1/`. Separate processes avoid the
single-threaded PHP development server waiting on itself. Development HTTP
is not permitted in production. Do not expose either port publicly.

## Web server

Use Apache 2.4 with `mod_rewrite`, TLS, and permission to apply the supplied
`.htaccess` (`AllowOverride FileInfo Options AuthConfig`, including authorization to use
`Options -Indexes`). Point the virtual host document root at this repository.
The allowlist exposes only the API front controller, portal and developer page;
everything else, including `.env`, source modules, SQL, tests, CLI and `.git`,
must be inaccessible over HTTP. If `.htaccess` is disabled, configure equivalent
rules in the virtual host **before** serving this directory.
Configure a working PHP-FPM or mod_php handler for the two PHP front
controllers; PHP CLI alone is insufficient. Verify PHP executes and is never
served as source before enabling public access.

For Nginx or another server, explicitly route `/api/v1` and its subpaths to
`api/v1/index.php`, allow `/public/index.php`, `/public/style.css` and
`/developers/api/v1/index.html`, redirect their directory URLs appropriately,
and deny every other path. Pass the original request URI and Authorization
header to PHP. Never execute arbitrary `.php` paths.

PHP must receive trusted `HTTPS=on` in production, including behind a TLS
terminator. Do not pass through unvalidated `X-Forwarded-Proto`. Restrict the
upstream network to the proxy. Disable PHP error display and avoid logging
request/response bodies or credentials. Use private PHP session storage with
short garbage-collection lifetime and appropriate permissions. The portal
requires server-side access to its configured API URL. Run PHP under an
unprivileged identity with read-only access to application source/configuration;
keep writable session/log directories outside the document root.
Apply per-visitor rate limits at the public reverse proxy as well: API traffic
from this server-rendered portal shares the portal server's network address and
general API request quotas. Do not solve this by trusting arbitrary forwarded
IP headers.

The PHP built-in server is for isolated local development **only**. It does not
enforce `.htaccess`; never expose the repository's built-in server to a network
or use it with real PHI.

## Verification

Dependency-free checks are included:

```sh
php tests/unit.php
TEST_MYSQL_DSN='mysql:unix_socket=/var/run/mysqld/mysqld.sock;charset=utf8mb4' \
  TEST_MYSQL_USER=root php tests/integration.php
```

Integration checks require an administrative connection to a **disposable**
MySQL instance (set `TEST_MYSQL_PASSWORD` securely if required). They create
and remove a uniquely named test database and runtime identity, launch loopback
PHP processes, and use synthetic records. Never supply production credentials.
The administrative DSN must not contain `dbname`.

## Operational boundaries

- Public self-registration grants only Guest access after email activation,
  profile setup and MFA confirmation. Provision staff, client credentials,
  memberships and camper assignments using the trusted CLI. Verify guardian
  relationships before linking a guest to a camper; registration creates no
  camper relationships.
- Give the runtime database identity only required data privileges. Use a
  separate identity for schema setup and protect audit events with append-only
  database grants and external immutable storage. Grant per table: MySQL
  privileges are additive, so a database-wide UPDATE/DELETE grant cannot be
  negated by withholding those privileges on `audit_events`.
- Record and onboarding profile payloads are encrypted, but account email/display names, record
  ownership links, timestamps and audit metadata remain database metadata.
  Protect the entire database and its backups, not just the encrypted columns.
- Resource schemas and effective permissions are discoverable through
  `GET /api/v1/resources` and `GET /api/v1/auth/me`. The API rechecks permissions
  on each request, including ownership and counselor assignment.
- Separate curated care, dietary, safety and behavior views from full clinical
  records. Staff must not place PHI in unrestricted free-text resources.
- Reservation/billing state is not payment processing; use a separate compliant
  payment integration. Never collect card numbers or CVVs here.
- Meal allergen matching supports staff review; it does not certify meal safety
  or account for unknown ingredients and cross-contact.
