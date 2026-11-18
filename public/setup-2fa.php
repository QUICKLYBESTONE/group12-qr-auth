<?php
require __DIR__ . '/../app/bootstrap.php'; require __DIR__ . '/../app/layout.php';
$uid = $_SESSION['pending_user_id'] ?? null;
if (!$uid) redirect('access-denied.php');
$user = q('SELECT email FROM users WHERE id = :i AND account_status = \'PENDING\'', ['i' => $uid])->fetch();
if (!$user) redirect('access-denied.php');
$enc = q('SELECT encrypted_totp_secret FROM two_factor_auth WHERE user_id = :u', ['u' => $uid])->fetchColumn();
// The QR holds ONLY the TOTP provisioning URI (secret + label). No password or personal data.
$qr = qr_data_uri(totp_uri(decrypt_secret($enc), $user['email']));
page_header('Set up authenticator'); ?>
<div class="row justify-content-center"><div class="col-lg-7"><div class="card"><div class="card-body p-4 text-center">
<h3>Step 2: Scan the QR code</h3>
<ol class="text-start">
  <li>Install <b>Google Authenticator</b> or <b>Microsoft Authenticator</b> on your phone.</li>
  <li>Tap <b>+</b> / <b>Add account</b> and choose <b>Scan a QR code</b>.</li>
  <li>Point the camera at the code below. A new entry called "Group12 QR Auth" appears.</li>
</ol>
<div class="qr-box my-3"><img src="<?= e($qr) ?>" alt="TOTP QR code"></div>
<p class="text-muted small">Do not share or screenshot this code. It is shown only to you during setup.</p>
<a class="btn btn-navy" href="/verify-otp.php">I scanned it &ndash; continue</a>
</div></div></div></div>
<?php page_footer();
