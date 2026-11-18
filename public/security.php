<?php
require __DIR__ . '/../app/bootstrap.php'; require __DIR__ . '/../app/layout.php';
$u = require_login(); $errors = [];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf();
    $new = $_POST['new_password'] ?? '';
    if (!password_verify($_POST['current_password'] ?? '', $u['password_hash'])) $errors['current_password'] = 'Current password is wrong.';
    if ($pe = password_errors($new)) $errors['new_password'] = 'Password needs ' . implode(', ', $pe) . '.';
    if ($new !== ($_POST['confirm_password'] ?? '')) $errors['confirm_password'] = 'Passwords do not match.';
    if (!$errors) {
        q('UPDATE users SET password_hash = :h, updated_at = now() WHERE id = :i', ['h' => password_hash($new, PASSWORD_DEFAULT), 'i' => $u['id']]);
        audit($u['id'], 'PASSWORD_CHANGED', 'User changed password');
        flash('success', 'Password changed.'); redirect('security.php');
    }
}
page_header('Account security'); ?>
<div class="row g-3">
<div class="col-md-6"><div class="card"><div class="card-body">
  <h4>Change password</h4>
  <form method="post" data-validate="password" novalidate><?= csrf_field() ?>
    <?php foreach ([['current_password','Current password'],['new_password','New password'],['confirm_password','Confirm new password']] as [$n,$l]): ?>
    <div class="mb-3"><label class="form-label"><?= e($l) ?></label><input class="form-control" type="password" name="<?= $n ?>" required><?= field_error($errors, $n) ?></div>
    <?php endforeach; ?>
    <button class="btn btn-navy">Update password</button></form></div></div></div>
<div class="col-md-6"><div class="card"><div class="card-body">
  <h4>Two-factor authentication</h4><p>Your account is protected by an authenticator app (TOTP).</p>
  <a class="btn btn-outline-secondary" href="/recovery-codes.php">Recovery codes</a></div></div></div>
</div>
<?php page_footer();
