<?php
require __DIR__ . '/../app/bootstrap.php'; require __DIR__ . '/../app/layout.php';
$errors = []; $old = [];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf();
    $old = $_POST;
    $errors = validate_registration($_POST);                    // backend validation
    $email = trim($_POST['email'] ?? '');
    if (!$errors) {
        try {
            db()->beginTransaction();                            // all-or-nothing
            $exists = q('SELECT 1 FROM users WHERE lower(email) = lower(:e)', ['e' => $email])->fetchColumn();
            if ($exists) { db()->rollBack(); $errors['email'] = 'This email is already registered.'; }
            else {
                $id = q('INSERT INTO users (full_name, email, phone, password_hash, account_status)
                         VALUES (:n, :e, :p, :h, \'PENDING\') RETURNING id',
                        ['n' => trim($_POST['full_name']), 'e' => $email, 'p' => normalize_phone($_POST['phone']),
                         'h' => password_hash($_POST['password'], PASSWORD_DEFAULT)])->fetchColumn();
                q('INSERT INTO two_factor_auth (user_id, encrypted_totp_secret) VALUES (:u, :s)',
                  ['u' => $id, 's' => encrypt_secret(totp_generate_secret())]);
                db()->commit();
                audit($id, 'REGISTER', 'Account created (PENDING)');
                session_regenerate_id(true);
                $_SESSION['pending_user_id'] = $id;
                redirect('setup-2fa.php');
            }
        } catch (PDOException $ex) {
            if (db()->inTransaction()) db()->rollBack();
            if ($ex->getCode() === '23505') $errors['email'] = 'This email is already registered.'; // unique violation
            else { error_log($ex->getMessage()); flash('danger', 'Something went wrong. Please try again.'); }
        }
    }
}
page_header('Register'); ?>
<div class="row justify-content-center"><div class="col-lg-6"><div class="card"><div class="card-body p-4">
<h3 class="mb-3">Create your account</h3>
<form method="post" data-validate="password" novalidate><?= csrf_field() ?>
  <?php foreach ([['full_name','Full name','text'],['email','Email address','email'],['phone','Phone number (e.g. +250788123456)','tel']] as [$n,$l,$t]): ?>
  <div class="mb-3"><label class="form-label"><?= e($l) ?></label>
    <input class="form-control" type="<?= $t ?>" name="<?= $n ?>" value="<?= e($old[$n] ?? '') ?>" required><?= field_error($errors, $n) ?></div>
  <?php endforeach; ?>
  <div class="mb-3"><label class="form-label">Password</label><input class="form-control" type="password" name="password" required autocomplete="new-password">
    <div class="form-text">8+ characters with upper and lower case, a number and a special character.</div><?= field_error($errors, 'password') ?></div>
  <div class="mb-3"><label class="form-label">Confirm password</label><input class="form-control" type="password" name="confirm_password" required autocomplete="new-password"><?= field_error($errors, 'confirm_password') ?></div>
  <div class="form-check mb-3"><input class="form-check-input" type="checkbox" name="terms" id="terms" <?= !empty($old['terms']) ? 'checked' : '' ?>>
    <label class="form-check-label" for="terms">I accept the terms and conditions (academic demo system).</label><?= field_error($errors, 'terms') ?></div>
  <button class="btn btn-navy w-100">Register</button>
</form></div></div></div></div>
<?php page_footer();
