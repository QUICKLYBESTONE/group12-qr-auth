<?php
require __DIR__ . '/../app/bootstrap.php'; require __DIR__ . '/../app/layout.php';
$admin = require_admin();
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf();
    $target = $_POST['user_id'] ?? '';
    if ($target === $admin['id']) flash('warning', 'You cannot deactivate yourself.');
    else {
        $n = q("UPDATE users SET account_status = 'DEACTIVATED', updated_at = now() WHERE id = :i AND role = 'USER'", ['i' => $target])->rowCount();
        if ($n) { audit($admin['id'], 'ADMIN_DEACTIVATE', "Deactivated user $target"); flash('success', 'Account deactivated.'); }
    }
    redirect('admin.php');
}
$s = trim($_GET['q'] ?? '');
// Note: passwords, TOTP secrets and recovery codes are never selected here.
$users = q("SELECT u.id, u.full_name, u.email, u.account_status, u.role, u.created_at, COALESCE(t.is_enabled, FALSE) AS tfa
            FROM users u LEFT JOIN two_factor_auth t ON t.user_id = u.id
            WHERE (:s1 = '' OR u.full_name ILIKE :s2 OR u.email ILIKE :s3) ORDER BY u.created_at DESC LIMIT 100",
           ['s1' => $s, 's2' => "%$s%", 's3' => "%$s%"])->fetchAll();
$logs = q('SELECT a.created_at, a.action, a.description, u.email FROM audit_logs a LEFT JOIN users u ON u.id = a.user_id ORDER BY a.created_at DESC LIMIT 20')->fetchAll();
page_header('Admin'); ?>
<h2>Administrator dashboard</h2>
<form class="d-flex my-3" method="get"><input class="form-control me-2" name="q" value="<?= e($s) ?>" placeholder="Search name or email"><button class="btn btn-navy">Search</button></form>
<div class="card mb-4"><div class="table-responsive"><table class="table table-hover mb-0 align-middle">
<thead><tr><th>Name</th><th>Email</th><th>Registered</th><th>Status</th><th>2FA</th><th></th></tr></thead><tbody>
<?php foreach ($users as $r): ?><tr>
<td><?= e($r['full_name']) ?></td><td><?= e($r['email']) ?></td><td><?= e(date('d M Y', strtotime($r['created_at']))) ?></td>
<td><?= e($r['account_status']) ?></td><td><?= $r['tfa'] ? 'Verified' : 'No' ?></td>
<td><?php if ($r['role'] === 'USER' && $r['account_status'] !== 'DEACTIVATED'): ?>
<form method="post"><?= csrf_field() ?><input type="hidden" name="user_id" value="<?= e($r['id']) ?>"><button class="btn btn-sm btn-outline-danger">Deactivate</button></form><?php endif; ?></td>
</tr><?php endforeach; ?></tbody></table></div></div>
<h4>Recent audit logs</h4>
<div class="card"><div class="table-responsive"><table class="table table-sm mb-0"><thead><tr><th>Time</th><th>User</th><th>Action</th><th>Details</th></tr></thead><tbody>
<?php foreach ($logs as $l): ?><tr><td><?= e(date('d M H:i', strtotime($l['created_at']))) ?></td><td><?= e($l['email'] ?? '-') ?></td><td><?= e($l['action']) ?></td><td><?= e($l['description']) ?></td></tr><?php endforeach; ?>
</tbody></table></div></div>
<?php page_footer();
