<?php
// Run ONCE from your computer (not web accessible):  php scripts/create-admin.php admin@example.com "Admin Name" "StrongPass#123"
// It creates an ACTIVE admin and prints the authenticator setup key in your terminal only.
if (PHP_SAPI !== 'cli') exit('CLI only');
require __DIR__ . '/../app/bootstrap.php';
[, $email, $name, $pw] = $argv + [null, null, null, null];
if (!$email || !$name || !$pw || password_errors($pw) || !filter_var($email, FILTER_VALIDATE_EMAIL)) exit("Usage: php scripts/create-admin.php email \"Full Name\" \"StrongPassword\"\n");
$secret = totp_generate_secret();
db()->beginTransaction();
$id = q("INSERT INTO users (full_name, email, phone, password_hash, account_status, role) VALUES (:n,:e,'+250000000000',:h,'ACTIVE','ADMIN') RETURNING id",
        ['n' => $name, 'e' => $email, 'h' => password_hash($pw, PASSWORD_DEFAULT)])->fetchColumn();
q('INSERT INTO two_factor_auth (user_id, encrypted_totp_secret, is_enabled, verified_at) VALUES (:u,:s,TRUE,now())', ['u' => $id, 's' => encrypt_secret($secret)]);
db()->commit();
echo "Admin created.\nAdd this key in your authenticator app (Enter a setup key, type: time-based):\n$secret\n";
