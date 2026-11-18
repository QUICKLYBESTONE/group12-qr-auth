<?php
require __DIR__ . '/../app/bootstrap.php'; require __DIR__ . '/../app/layout.php';
http_response_code(404); page_header('Page not found'); ?>
<div class="text-center py-5"><h1>404</h1><p class="lead">We couldn't find that page.</p><a class="btn btn-navy" href="/index.php">Back to home</a></div>
<?php page_footer();
