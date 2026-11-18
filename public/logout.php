<?php
require __DIR__ . '/../app/bootstrap.php';
if ($_SERVER['REQUEST_METHOD'] !== 'POST') redirect('index.php');
verify_csrf();
if (!empty($_SESSION['user_id'])) audit($_SESSION['user_id'], 'LOGOUT', 'User logged out');
$_SESSION = [];
session_destroy();
setcookie(session_name(), '', time() - 3600, '/');
session_start(); flash('success', 'You have been logged out.');
redirect('login.php');
