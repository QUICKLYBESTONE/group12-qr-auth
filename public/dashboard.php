<?php
require __DIR__ . '/../app/bootstrap.php'; require __DIR__ . '/../app/layout.php';
$u = require_login();
$tf = q('SELECT is_enabled, verified_at FROM two_factor_auth WHERE user_id = :u', ['u' => $u['id']])->fetch();
$fmt = fn($d) => $d ? date('d M Y, H:i', strtotime($d)) . ' UTC' : 'Never';
page_header('Dashboard'); ?>
<h2>Welcome, <?= e($u['full_name']) ?> &#128075;</h2>
<div class="card mt-3"><div class="card-body"><table class="table mb-0">
<tr><th>Full name</th><td><?= e($u['full_name']) ?></td></tr>
<tr><th>Email</th><td><?= e($u['email']) ?></td></tr>
<tr><th>Account status</th><td><span class="badge bg-success"><?= e($u['account_status']) ?></span></td></tr>
<tr><th>2FA status</th><td><?= $tf && $tf['is_enabled'] ? '<span class="badge bg-success">Enabled</span>' : '<span class="badge bg-secondary">Disabled</span>' ?></td></tr>
<tr><th>QR authentication</th><td><?= $tf && $tf['verified_at'] ? 'Verified on ' . e($fmt($tf['verified_at'])) : 'Not verified' ?></td></tr>
<tr><th>Registered</th><td><?= e($fmt($u['created_at'])) ?></td></tr>
<tr><th>Last login</th><td><?= e($fmt($u['last_login_at'])) ?></td></tr>
</table></div></div>
<a class="btn btn-navy mt-3" href="/security.php">Manage account security</a>
<?php page_footer();
