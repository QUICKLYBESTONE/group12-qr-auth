<?php
require __DIR__ . '/../app/bootstrap.php'; require __DIR__ . '/../app/layout.php';
$user = current_user();
if ($_SERVER['REQUEST_METHOD'] === 'POST') {               // regenerate (logged-in users, password required)
    verify_csrf(); $user = require_login();
    if (password_verify($_POST['password'] ?? '', $user['password_hash'])) {
        $_SESSION['new_recovery_codes'] = generate_recovery_codes($user['id']);
        audit($user['id'], 'RECOVERY_REGENERATED', 'New recovery codes generated');
    } else flash('danger', 'Wrong password.');
    redirect('recovery-codes.php');
}
$codes = $_SESSION['new_recovery_codes'] ?? null;
unset($_SESSION['new_recovery_codes']);                     // codes are displayed only once
if (!$codes && !$user) redirect('access-denied.php');
$left = $user ? (int)q('SELECT COUNT(*) FROM recovery_codes WHERE user_id = :u AND used_at IS NULL', ['u' => $user['id']])->fetchColumn() : 0;
page_header('Recovery codes'); ?>
<div class="row justify-content-center"><div class="col-lg-6"><div class="card"><div class="card-body p-4">
<h3>Recovery codes</h3>
<?php if ($codes): ?>
  <div class="alert alert-warning">Save these codes now. Each works once and they will <b>not</b> be shown again.</div>
  <ul class="code-list"><?php foreach ($codes as $c): ?><li><?= e($c) ?></li><?php endforeach; ?></ul>
  <?php if (!$user): ?><a class="btn btn-navy" href="/login.php">I saved them &ndash; go to login</a><?php endif; ?>
<?php else: ?>
  <p>You have <b><?= $left ?></b> unused recovery codes. For safety they cannot be displayed again.</p>
<?php endif; ?>
<?php if ($user && $user['account_status'] === 'ACTIVE'): ?>
  <hr><h6>Generate new codes (old ones stop working)</h6>
  <form method="post"><?= csrf_field() ?><input class="form-control mb-2" type="password" name="password" placeholder="Confirm your password" required>
  <button class="btn btn-outline-secondary">Regenerate</button></form>
<?php endif; ?>
</div></div></div></div>
<?php page_footer();
