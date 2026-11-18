<?php
// Offline unit tests (no database needed):  php tests/run_tests.php
// Needs a key:  TOTP_ENCRYPTION_KEY=$(php -r 'echo base64_encode(random_bytes(32));') php tests/run_tests.php
putenv('DATABASE_URL=postgresql://x:y@localhost/x');
$_ENV['DATABASE_URL'] = 'postgresql://x:y@localhost/x';
function t(string $name, bool $ok): void { echo ($ok ? 'PASS' : 'FAIL') . " - $name\n"; if (!$ok) $GLOBALS['fail'] = true; }
// Load only the pure functions (bootstrap would open a DB session, so we skip it)
$src = file_get_contents(__DIR__ . '/../app/bootstrap.php');
$start = strpos($src, '// ---------- 5. Validation'); $end = strpos($src, '// ---------- 8.');
eval('?>' . "<?php\n" . 'function env(string $k, ?string $d=null): ?string { $v = getenv($k); return $v === false ? $d : $v; }' . substr($src, $start, $end - $start));
$std = base32_encode('12345678901234567890');
t('base32 RFC vector', $std === 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
t('TOTP RFC 6238 (T=59 -> 287082)', totp_code($std, intdiv(59, 30)) === '287082');
t('TOTP accepts current code', totp_find_step($std, totp_code($std, intdiv(1111111109, 30)), 1111111109) !== null);
t('TOTP rejects wrong code', totp_find_step($std, '000000', 1111111109) === null);
t('TOTP rejects expired code (5 min old)', totp_find_step($std, totp_code($std, intdiv(1111111109 - 300, 30)), 1111111109) === null);
$s = encrypt_secret('ABC'); t('encrypt/decrypt round trip', decrypt_secret($s) === 'ABC' && $s !== 'ABC');
t('weak password rejected', count(password_errors('abc')) > 0);
t('strong password accepted', password_errors('Str0ng#Pass') === []);
$good = ['full_name'=>'Jean Claude','email'=>'a@b.rw','phone'=>'+250 788 123 456','password'=>'Str0ng#Pass','confirm_password'=>'Str0ng#Pass','terms'=>'on'];
t('valid registration', validate_registration($good) === []);
t('invalid email', isset(validate_registration(['email'=>'bad'] + $good)['email']));
t('invalid phone', isset(validate_registration(['phone'=>'12'] + $good)['phone']));
t('password mismatch', isset(validate_registration(['confirm_password'=>'x'] + $good)['confirm_password']));
t('terms required', isset(validate_registration(['terms'=>''] + $good)['terms']));
exit(empty($GLOBALS['fail']) ? 0 : 1);
