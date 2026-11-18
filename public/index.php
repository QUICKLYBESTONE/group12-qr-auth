<?php require __DIR__ . '/../app/bootstrap.php'; require __DIR__ . '/../app/layout.php'; page_header('Home'); ?>
<div class="hero text-center mb-4">
  <h1 class="fw-bold">Secure QR Authentication System</h1>
  <p class="lead">Registration protected by QR-based two-factor authentication and one-time passwords.</p>
  <a class="btn btn-light btn-lg me-2" href="/register.php">Create account</a>
  <a class="btn btn-outline-light btn-lg" href="/login.php">Login</a>
</div>
<div class="row g-3">
  <?php foreach ([['1. Register','Fill in the form. Your password is hashed and never stored in plain text.'],
                  ['2. Scan the QR code','Scan with Google or Microsoft Authenticator. The QR holds only a secret key, never your personal data.'],
                  ['3. Enter the OTP','Type the 6-digit code. Your account changes from PENDING to ACTIVE.']] as [$t,$d]): ?>
  <div class="col-md-4"><div class="card h-100"><div class="card-body"><h5><?= e($t) ?></h5><p class="mb-0"><?= e($d) ?></p></div></div></div>
  <?php endforeach; ?>
</div>
<?php page_footer();
