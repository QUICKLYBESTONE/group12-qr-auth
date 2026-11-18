<?php
// Shared page header/footer (navbar, flash messages)
function page_header(string $title): void
{
    $u = current_user();
    ?><!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= e($title) ?> | Group 12 QR Auth</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="/assets/css/style.css" rel="stylesheet">
</head><body>
<nav class="navbar navbar-expand-md navbar-dark bg-navy"><div class="container">
  <a class="navbar-brand fw-bold" href="/index.php">&#128274; Group 12 QR Auth</a>
  <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#nav"><span class="navbar-toggler-icon"></span></button>
  <div class="collapse navbar-collapse" id="nav"><ul class="navbar-nav ms-auto">
  <?php if ($u && ($u['account_status'] === 'ACTIVE')): ?>
    <li class="nav-item"><a class="nav-link" href="/dashboard.php">Dashboard</a></li>
    <li class="nav-item"><a class="nav-link" href="/security.php">Security</a></li>
    <?php if ($u['role'] === 'ADMIN'): ?><li class="nav-item"><a class="nav-link" href="/admin.php">Admin</a></li><?php endif; ?>
    <li class="nav-item"><form method="post" action="/logout.php" class="d-inline"><?= csrf_field() ?><button class="btn btn-link nav-link">Logout</button></form></li>
  <?php else: ?>
    <li class="nav-item"><a class="nav-link" href="/login.php">Login</a></li>
    <li class="nav-item"><a class="nav-link" href="/register.php">Register</a></li>
  <?php endif; ?>
  </ul></div></div></nav>
<main class="container py-4">
<?php foreach ($_SESSION['flash'] ?? [] as [$t, $m]): ?>
  <div class="alert alert-<?= e($t) ?>" role="alert"><?= e($m) ?></div>
<?php endforeach; unset($_SESSION['flash']); }

function page_footer(): void { ?>
</main>
<footer class="text-center text-muted small py-3">Group 12 &ndash; Secure QR Authentication System (college project)</footer>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script src="/assets/js/validate.js"></script>
</body></html><?php }

/** Show a field error under an input */
function field_error(array $errors, string $f): string
{
    return isset($errors[$f]) ? '<div class="invalid-feedback d-block">' . e($errors[$f]) . '</div>' : '';
}
