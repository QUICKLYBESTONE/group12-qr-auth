<?php
/**
 * One page, two modes:
 *  - activate: new user proves the authenticator works -> PENDING becomes ACTIVE
 *  - login:    step 2 of login (OTP or recovery code)
 */
require __DIR__ . '/../app/bootstrap.php'; require __DIR__ . '/../app/layout.php';
if (!empty($_SESSION['pending_user_id'])) { $mode = 'activate'; $uid = $_SESSION['pending_user_id']; }
elseif (!empty($_SESSION['mfa_user_id']) && time() - ($_SESSION['mfa_started'] ?? 0) < 300) { $mode = 'login'; $uid = $_SESSION['mfa_user_id']; }
else { unset($_SESSION['mfa_user_id']); redirect('access-denied.php'); }

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf();
    $code = trim($_POST['otp'] ?? ''); $rec = trim($_POST['recovery'] ?? '');
    if (is_locked($uid)) {
        flash('danger', 'Too many failed attempts. Try again in 15 minutes.');
    } else {
        $ok = false;
        if ($mode === 'login' && $rec !== '') {
            $ok = use_recovery_code($uid, $rec);
            if ($ok) audit($uid, 'RECOVERY_CODE_USED', 'Logged in with a recovery code');
        } else {
            $res = verify_user_totp($uid, $code);
            $ok = $res === 'ok';
            if ($res === 'replay') flash('danger', 'That code was already used. Wait for the next code.');
        }
        if ($ok) {
            log_attempt($uid, 'SUCCESS');
            if ($mode === 'activate') {
                db()->beginTransaction();
                q('UPDATE users SET account_status = \'ACTIVE\', updated_at = now() WHERE id = :u', ['u' => $uid]);
                q('UPDATE two_factor_auth SET is_enabled = TRUE, verified_at = now() WHERE user_id = :u', ['u' => $uid]);
                db()->commit();
                audit($uid, 'ACCOUNT_ACTIVATED', 'PENDING -> ACTIVE after OTP verification');
                $codes = generate_recovery_codes($uid);
                session_regenerate_id(true);
                unset($_SESSION['pending_user_id']);
                $_SESSION['new_recovery_codes'] = $codes;
                flash('success', 'Account activated! Save your recovery codes, then log in.');
                redirect('recovery-codes.php');
            }
            session_regenerate_id(true);                         // new session ID after login
            unset($_SESSION['mfa_user_id'], $_SESSION['mfa_started']);
            $_SESSION['user_id'] = $uid;
            q('UPDATE users SET last_login_at = now() WHERE id = :u', ['u' => $uid]);
            audit($uid, 'LOGIN', 'Successful login');
            redirect('dashboard.php');
        }
        if (!isset($res) || $res !== 'replay') flash('danger', 'Invalid code. Please try again.');
        log_attempt($uid, 'FAILED_OTP');
        audit($uid, 'OTP_FAILED', 'Incorrect OTP or recovery code');
    }
}
page_header('Verify OTP'); ?>
<div class="row justify-content-center"><div class="col-md-6 col-lg-5"><div class="card"><div class="card-body p-4">
<h3><?= $mode === 'activate' ? 'Step 3: Verify your OTP' : 'Two-factor verification' ?></h3>
<p>Open your authenticator app and enter the 6-digit code. Codes change every 30 seconds.</p>
<form method="post" data-validate="otp" novalidate><?= csrf_field() ?>
  <input class="form-control otp-input mb-3" name="otp" inputmode="numeric" maxlength="6" autocomplete="one-time-code" autofocus placeholder="000000">
  <?php if ($mode === 'login'): ?>
  <details class="mb-3"><summary>Lost your phone? Use a recovery code</summary>
    <input class="form-control mt-2" name="recovery" placeholder="xxxxxx-xxxxxx"></details>
  <?php endif; ?>
  <button class="btn btn-navy w-100"><?= $mode === 'activate' ? 'Verify and activate' : 'Verify and log in' ?></button>
</form></div></div></div></div>
<?php page_footer();
