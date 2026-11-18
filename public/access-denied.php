<?php
require __DIR__ . '/../app/bootstrap.php'; require __DIR__ . '/../app/layout.php';
http_response_code(403); page_header('Access denied'); ?>
<div class="text-center py-5"><h1>403</h1><p class="lead">Access denied. Please log in with an authorized account.</p><a class="btn btn-navy" href="/login.php">Go to login</a></div>
<?php page_footer();
