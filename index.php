<?php
// index.php – Dashboard (requiere sesión activa)

declare(strict_types=1);

require_once __DIR__ . '/config/security.php';

setSecurityHeaders();
startSecureSession();

// Guard: redirigir si no está autenticado
if (empty($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

// Dato seguro para mostrar — siempre escapado con e()
$userEmail = $_SESSION['user_email'] ?? '';
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard — TaskVault</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Syne:wght@400;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="css/styles.css">
</head>
<body class="dashboard-body">

<header class="dashboard-header">
    <div class="header-brand">
        <span class="brand-icon">⬡</span>
        <span class="brand-name">TaskVault</span>
    </div>
    <div class="header-user">
        <span class="user-email">
            <!-- htmlspecialchars via e() — protección XSS -->
            <?= e($userEmail) ?>
        </span>
        <a href="logout.php" class="btn btn--outline btn--sm">Cerrar sesión</a>
    </div>
</header>

<main class="dashboard-main">
    <section class="welcome-section">
        <h2 class="welcome-title">¡Bienvenido/a!</h2>
        <p class="welcome-sub">
            Sesión activa como <strong><?= e($userEmail) ?></strong>
        </p>
    </section>

    <section class="security-grid">
        <h3 class="section-title">Protecciones activas</h3>
        <div class="cards-grid">

            <div class="sec-card">
                <span class="sec-card__icon">🛡</span>
                <h4>SQL Injection</h4>
                <p>Todas las consultas usan <code>Prepared Statements</code> con PDO. Ninguna entrada del usuario se concatena directamente en el SQL.</p>
            </div>

            <div class="sec-card">
                <span class="sec-card__icon">🔐</span>
                <h4>XSS</h4>
                <p>Todo output se escapa con <code>htmlspecialchars()</code>. El header <code>Content-Security-Policy</code> bloquea scripts externos.</p>
            </div>

            <div class="sec-card">
                <span class="sec-card__icon">🔑</span>
                <h4>CSRF</h4>
                <p>Cada formulario POST incluye un token de un solo uso generado por sesión y validado antes de procesar.</p>
            </div>

            <div class="sec-card">
                <span class="sec-card__icon">🔒</span>
                <h4>Contraseñas</h4>
                <p>Almacenadas con <code>password_hash()</code> (bcrypt). Nunca en texto plano. Verificación con <code>password_verify()</code>.</p>
            </div>

            <div class="sec-card">
                <span class="sec-card__icon">♻️</span>
                <h4>Session Hijacking</h4>
                <p>El ID de sesión se regenera con <code>session_regenerate_id(true)</code> al iniciar sesión exitosamente.</p>
            </div>

            <div class="sec-card">
                <span class="sec-card__icon">🚫</span>
                <h4>Fuerza Bruta</h4>
                <p>Máximo 5 intentos por email. Bloqueo automático de 15 minutos registrado en la tabla <code>login_attempts</code>.</p>
            </div>

        </div>
    </section>
</main>

</body>
</html>
