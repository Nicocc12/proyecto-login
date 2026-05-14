<?php
// logout.php – Cierre de sesión seguro

declare(strict_types=1);

require_once __DIR__ . '/config/security.php';

setSecurityHeaders();
startSecureSession();

// 1. Destruir todos los datos de sesión
$_SESSION = [];

// 2. Eliminar la cookie de sesión del navegador
if (ini_get('session.use_cookies')) {
    $params = session_get_cookie_params();
    setcookie(
        session_name(),
        '',
        time() - 42000,
        $params['path'],
        $params['domain'],
        $params['secure'],
        $params['httponly']
    );
}

// 3. Destruir la sesión en el servidor
session_destroy();

// 4. Redirigir al login
header('Location: login.php');
exit;
