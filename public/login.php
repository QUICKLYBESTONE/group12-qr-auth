<?php
require __DIR__ . '/../app/bootstrap.php'; require __DIR__ . '/../app/layout.php';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf();
    $email = trim($_POST['email'] ?? '');
    $u = q('SELECT * FROM users WHERE lower(email) = lower(:e)', ['e' => $email])->fetch();
    // Same message for unknown email and wrong password (does not reveal which emails exist)
    $generic = 'Invalid email or password.';
    if (!$u) { password_verify('x', '$2y$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012'); flash('danger', $generic); }
    elseif (is_locked($u['id'])) flash('danger', 'Too many failed attempts. Try again in 15 minutes.');
    elseif (!password_verify($_POST['password'] ?? '', $u['password_hash'])) {
        log_attempt($u['id'], 'FAILED_PASSWORD'); flash('danger', $generic);
    } elseif ($u['account_status'] !== 'ACTIVE') {
        flash('warning', $u['account_status'] === 'PENDING'
            ? 'Your account is not activated yet. Register again with a new email or contact the administrator.'
            : 'This account has been deactivated.');
    } else {
        session_regenerate_id(true);
        $_SESSION['mfa_user_id'] = $u['id']; $_SESSION['mfa_started'] = time();   // password OK, OTP still needed
        redirect('verify-otp.php');
    }
}
page_header('Login'); ?>
<div class="row justify-content-center"><div class="col-md-6 col-lg-5"><div class="card"><div class="card-body p-4">
<h3 class="mb-3">Login</h3>
<form method="post" data-validate="login" novalidate><?= csrf_field() ?>
  <div class="mb-3"><label class="form-label">Email</label><input class="form-control" type="email" name="email" required autofocus></div>
  <div class="mb-3"><label class="form-label">Password</label><input class="form-control" type="password" name="password" required></div>
  <button class="btn btn-navy w-100">Continue to OTP</button>
</form><p class="mt-3 mb-0 small">No account? <a href="/register.php">Register</a></p>
</div></div></div></div>
<?php page_footer();
