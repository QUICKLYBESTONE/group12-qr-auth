<?php
declare(strict_types=1);
/**
 * bootstrap.php - loaded by every page.
 * Contains: environment loading, database connection (PDO), DB-backed sessions,
 * security helpers (CSRF, XSS escaping), TOTP, encryption, QR code and validation.
 */

// ---------- 1. Environment variables ----------
// On Vercel the variables are injected. Locally we read a .env file (never committed).
$envFile = __DIR__ . '/../.env';
if (is_file($envFile)) {
    foreach (file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        if ($line[0] === '#' || !str_contains($line, '=')) continue;
        [$k, $v] = explode('=', $line, 2);
        $_ENV[trim($k)] = trim($v, " \t\"'");
    }
}
function env(string $key, ?string $default = null): ?string
{
    $v = $_ENV[$key] ?? getenv($key);
    return ($v === false || $v === null || $v === '') ? $default : (string)$v;
}
if (is_file(__DIR__ . '/../vendor/autoload.php')) require __DIR__ . '/../vendor/autoload.php';

// ---------- 2. Database (PDO + Neon PostgreSQL) ----------
function db(): PDO
{
    static $pdo = null;
    if ($pdo) return $pdo;
    $url = env('DATABASE_URL') ?? throw new RuntimeException('DATABASE_URL is not set');
    $p = parse_url($url);
    $dsn = sprintf('pgsql:host=%s;port=%d;dbname=%s;sslmode=require',
        $p['host'], $p['port'] ?? 5432, ltrim($p['path'], '/'));
    $pdo = new PDO($dsn, urldecode($p['user']), urldecode($p['pass'] ?? ''), [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,   // errors become exceptions
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,                    // real prepared statements
    ]);
    return $pdo;
}
/** Run a prepared statement and return it. Values are never glued into the SQL (stops SQL injection). */
function q(string $sql, array $params = []): PDOStatement
{
    $st = db()->prepare($sql);
    $st->execute($params);
    return $st;
}

// ---------- 3. Sessions stored in the database ----------
class DbSessionHandler implements SessionHandlerInterface
{
    public function open(string $path, string $name): bool { return true; }
    public function close(): bool { return true; }
    public function read(string $id): string|false
    {
        $r = q('SELECT data FROM sessions WHERE id = :id AND expires_at > now()', ['id' => $id])->fetchColumn();
        return $r === false ? '' : base64_decode($r);
    }
    public function write(string $id, string $data): bool
    {
        q("INSERT INTO sessions (id, data, expires_at) VALUES (:id, :d, now() + interval '30 minutes')
           ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, expires_at = EXCLUDED.expires_at",
          ['id' => $id, 'd' => base64_encode($data)]);
        return true;
    }
    public function destroy(string $id): bool { q('DELETE FROM sessions WHERE id = :id', ['id' => $id]); return true; }
    public function gc(int $max): int|false { return q('DELETE FROM sessions WHERE expires_at < now()')->rowCount(); }
}
function start_secure_session(): void
{
    $https = (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https') || !empty($_SERVER['HTTPS']);
    session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'secure' => $https, 'httponly' => true, 'samesite' => 'Lax']);
    session_set_save_handler(new DbSessionHandler(), true);
    session_start();
    // Idle timeout: 30 minutes of inactivity ends the session
    if (isset($_SESSION['last_activity']) && time() - $_SESSION['last_activity'] > 1800) {
        $_SESSION = [];
        session_regenerate_id(true);
        $_SESSION['flash'][] = ['warning', 'Your session expired. Please log in again.'];
    }
    $_SESSION['last_activity'] = time();
}
start_secure_session();
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header("Content-Security-Policy: default-src 'self'; style-src 'self' https://cdn.jsdelivr.net; script-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:; font-src 'self' https://cdn.jsdelivr.net");

// ---------- 4. Small helpers ----------
function e(?string $s): string { return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); } // XSS protection
function redirect(string $to): never { header('Location: ' . $to); exit; }
function flash(string $type, string $msg): void { $_SESSION['flash'][] = [$type, $msg]; }
function csrf_field(): string
{
    $_SESSION['csrf'] ??= bin2hex(random_bytes(32));
    return '<input type="hidden" name="csrf" value="' . e($_SESSION['csrf']) . '">';
}
function verify_csrf(): void
{
    $ok = isset($_POST['csrf'], $_SESSION['csrf']) && hash_equals($_SESSION['csrf'], (string)$_POST['csrf']);
    if (!$ok) { http_response_code(403); exit('Invalid or missing security token. Go back and reload the form.'); }
}
function audit(?string $userId, string $action, string $desc = ''): void
{
    q('INSERT INTO audit_logs (user_id, action, description) VALUES (:u, :a, :d)', ['u' => $userId, 'a' => $action, 'd' => $desc]);
}

// ---------- 5. Validation ----------
function password_errors(string $pw): array
{
    $err = [];
    if (strlen($pw) < 8) $err[] = 'at least 8 characters';
    if (!preg_match('/[A-Z]/', $pw)) $err[] = 'an uppercase letter';
    if (!preg_match('/[a-z]/', $pw)) $err[] = 'a lowercase letter';
    if (!preg_match('/\d/', $pw)) $err[] = 'a number';
    if (!preg_match('/[^A-Za-z0-9]/', $pw)) $err[] = 'a special character';
    return $err;
}
function normalize_phone(string $p): string { return preg_replace('/[\s\-()]/', '', $p); }
function validate_registration(array $in): array
{
    $e = [];
    $name = trim($in['full_name'] ?? ''); $email = trim($in['email'] ?? '');
    $phone = normalize_phone($in['phone'] ?? ''); $pw = $in['password'] ?? '';
    if (mb_strlen($name) < 3 || mb_strlen($name) > 120 || !preg_match("/^[\p{L}][\p{L} .'\-]+$/u", $name)) $e['full_name'] = 'Enter your full name (letters only, 3-120 characters).';
    if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 190) $e['email'] = 'Enter a valid email address.';
    if (!preg_match('/^\+?[0-9]{9,15}$/', $phone)) $e['phone'] = 'Enter a valid phone number (9-15 digits, optional +).';
    if ($pw_err = password_errors($pw)) $e['password'] = 'Password needs ' . implode(', ', $pw_err) . '.';
    if ($pw !== ($in['confirm_password'] ?? '')) $e['confirm_password'] = 'Passwords do not match.';
    if (empty($in['terms'])) $e['terms'] = 'You must accept the terms and conditions.';
    return $e;
}

// ---------- 6. TOTP (RFC 6238) - same algorithm as Google/Microsoft Authenticator ----------
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32_encode(string $bin): string
{
    $bits = ''; $out = '';
    foreach (str_split($bin) as $c) $bits .= str_pad(decbin(ord($c)), 8, '0', STR_PAD_LEFT);
    foreach (str_split($bits, 5) as $chunk) $out .= B32[bindec(str_pad($chunk, 5, '0'))];
    return $out;
}
function base32_decode(string $s): string
{
    $bits = ''; $out = '';
    foreach (str_split(strtoupper($s)) as $c) { $p = strpos(B32, $c); if ($p !== false) $bits .= str_pad(decbin($p), 5, '0', STR_PAD_LEFT); }
    foreach (str_split($bits, 8) as $byte) if (strlen($byte) === 8) $out .= chr(bindec($byte));
    return $out;
}
function totp_generate_secret(): string { return base32_encode(random_bytes(20)); } // 160-bit secret
function totp_code(string $b32secret, int $step, int $digits = 6): string
{
    $hash = hash_hmac('sha1', pack('J', $step), base32_decode($b32secret), true); // 8-byte big-endian counter
    $o = ord($hash[19]) & 0x0F;                                                    // dynamic truncation
    $n = ((ord($hash[$o]) & 0x7F) << 24) | (ord($hash[$o + 1]) << 16) | (ord($hash[$o + 2]) << 8) | ord($hash[$o + 3]);
    return str_pad((string)($n % (10 ** $digits)), $digits, '0', STR_PAD_LEFT);
}
/** Returns the matching time step (30s window, +/-1 step tolerance) or null. */
function totp_find_step(string $secret, string $code, ?int $now = null): ?int
{
    $cur = intdiv($now ?? time(), 30);
    for ($s = $cur - 1; $s <= $cur + 1; $s++) if (hash_equals(totp_code($secret, $s), $code)) return $s;
    return null;
}
function totp_uri(string $secret, string $email): string
{
    return 'otpauth://totp/' . rawurlencode('Group12 QR Auth:' . $email) . '?secret=' . $secret .
           '&issuer=' . rawurlencode('Group12 QR Auth') . '&algorithm=SHA1&digits=6&period=30';
}
function qr_data_uri(string $text): string
{
    // chillerlan/php-qrcode v5: render() returns a base64 SVG data URI by default
    return (new chillerlan\QRCode\QRCode(new chillerlan\QRCode\QROptions(['outputBase64' => true])))->render($text);
}

// ---------- 7. Encryption of TOTP secrets (libsodium secretbox) ----------
function enc_key(): string
{
    $k = base64_decode(env('TOTP_ENCRYPTION_KEY', ''), true);
    if ($k === false || strlen($k) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) throw new RuntimeException('TOTP_ENCRYPTION_KEY must be base64 of 32 bytes');
    return $k;
}
function encrypt_secret(string $plain): string
{
    $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    return base64_encode($nonce . sodium_crypto_secretbox($plain, $nonce, enc_key()));
}
function decrypt_secret(string $blob): string
{
    $raw = base64_decode($blob, true);
    $nl = SODIUM_CRYPTO_SECRETBOX_NONCEBYTES;
    $plain = sodium_crypto_secretbox_open(substr($raw, $nl), substr($raw, 0, $nl), enc_key());
    if ($plain === false) throw new RuntimeException('Could not decrypt secret');
    return $plain;
}

// ---------- 8. 2FA verification, throttling, recovery codes ----------
const MAX_FAILS = 5;
function is_locked(string $userId): bool
{
    // failures in last 15 minutes that happened after the last success
    $n = q("SELECT COUNT(*) FROM login_attempts WHERE user_id = :u1 AND attempt_status LIKE 'FAILED%'
            AND created_at > now() - interval '15 minutes'
            AND created_at > COALESCE((SELECT MAX(created_at) FROM login_attempts WHERE user_id = :u2 AND attempt_status = 'SUCCESS'), '-infinity')",
           ['u1' => $userId, 'u2' => $userId])->fetchColumn();
    return (int)$n >= MAX_FAILS;
}
function log_attempt(string $userId, string $status): void
{
    q('INSERT INTO login_attempts (user_id, attempt_status) VALUES (:u, :s)', ['u' => $userId, 's' => $status]);
}
/** Returns 'ok', 'replay' or 'invalid'. An accepted time step can never be used twice. */
function verify_user_totp(string $userId, string $code): string
{
    $row = q('SELECT encrypted_totp_secret, last_used_time_step FROM two_factor_auth WHERE user_id = :u', ['u' => $userId])->fetch();
    if (!$row || !preg_match('/^\d{6}$/', $code)) return 'invalid';
    $step = totp_find_step(decrypt_secret($row['encrypted_totp_secret']), $code);
    if ($step === null) return 'invalid';
    // Atomic replay check: only succeeds if this step is newer than the last accepted one
    $ok = q('UPDATE two_factor_auth SET last_used_time_step = :s1 WHERE user_id = :u AND (last_used_time_step IS NULL OR last_used_time_step < :s2)',
            ['s1' => $step, 'u' => $userId, 's2' => $step])->rowCount();
    return $ok === 1 ? 'ok' : 'replay';
}
function generate_recovery_codes(string $userId): array
{
    $codes = [];
    db()->beginTransaction();
    q('DELETE FROM recovery_codes WHERE user_id = :u', ['u' => $userId]);
    for ($i = 0; $i < 8; $i++) {
        $c = bin2hex(random_bytes(3)) . '-' . bin2hex(random_bytes(3));
        $codes[] = $c;
        q('INSERT INTO recovery_codes (user_id, code_hash) VALUES (:u, :h)', ['u' => $userId, 'h' => password_hash($c, PASSWORD_DEFAULT)]);
    }
    db()->commit();
    return $codes;
}
function use_recovery_code(string $userId, string $code): bool
{
    $rows = q('SELECT id, code_hash FROM recovery_codes WHERE user_id = :u AND used_at IS NULL', ['u' => $userId])->fetchAll();
    foreach ($rows as $r) {
        if (password_verify(strtolower(trim($code)), $r['code_hash'])) {
            return q('UPDATE recovery_codes SET used_at = now() WHERE id = :i AND used_at IS NULL', ['i' => $r['id']])->rowCount() === 1;
        }
    }
    return false;
}

// ---------- 9. Authorization ----------
function current_user(): ?array
{
    if (empty($_SESSION['user_id'])) return null;
    static $u = null;
    return $u ??= (q('SELECT * FROM users WHERE id = :i', ['i' => $_SESSION['user_id']])->fetch() ?: null);
}
function require_login(): array
{
    $u = current_user();
    if (!$u || $u['account_status'] !== 'ACTIVE') { $_SESSION = []; redirect('access-denied.php'); }
    return $u;
}
function require_admin(): array
{
    $u = require_login();
    if ($u['role'] !== 'ADMIN') { http_response_code(403); redirect('access-denied.php'); }
    return $u;
}
