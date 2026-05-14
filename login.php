<?php
// login.php – Inicio de sesión seguro

declare(strict_types=1);

require_once __DIR__ . '/config/security.php';

setSecurityHeaders();
startSecureSession();

// Redirigir si ya está autenticado
if (!empty($_SESSION['user_id'])) {
    header('Location: index.php');
    exit;
}

$errors    = [];
$formEmail = '';

// ──────────────────────────────────────────────
// Procesamiento POST
// ──────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // 1. Validar CSRF
    requireValidCsrf('login');

    $email    = trim($_POST['email']    ?? '');
    $password = $_POST['password']      ?? '';
    $ip       = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $formEmail = $email;

    // 2. Validación básica de formato
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'Credenciales incorrectas.'; // Mensaje genérico
    }

    if (empty($errors)) {
        // 3. Verificar bloqueo por intentos excesivos
        if (isLoginBlocked($email)) {
            $mins = getBlockMinutesLeft($email);
            $errors[] = "Demasiados intentos fallidos. Intentá de nuevo en {$mins} minuto(s).";
        }
    }

    if (empty($errors)) {
        $db   = getDB();

        // 4. Buscar usuario — Prepared Statement (sin SQLi posible)
        $stmt = $db->prepare(
            'SELECT id, email, password_hash FROM users WHERE email = :email LIMIT 1'
        );
        $stmt->execute([':email' => $email]);
        $user = $stmt->fetch();

        // 5. Verificar contraseña con password_verify()
        if (!$user || !password_verify($password, $user['password_hash'])) {
            recordFailedLogin($email, $ip);
            // Mensaje genérico — no revelar si el email existe
            $errors[] = 'Credenciales incorrectas.';
        } else {
            // ── Login exitoso ──

            // 6. Limpiar intentos fallidos
            clearLoginAttempts($email);

            // 7. Regenerar ID de sesión (previene Session Fixation)
            session_regenerate_id(true);

            // 8. Guardar datos en sesión
            $_SESSION['user_id']    = (int)$user['id'];
            $_SESSION['user_email'] = $user['email'];
            $_SESSION['logged_at']  = time();

            header('Location: index.php');
            exit;
        }
    }
}

$csrfToken = generateCsrfToken('login');
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Iniciar sesión — TaskVault</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Syne:wght@400;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>

<main class="auth-container">
    <div class="auth-card">
        <div class="auth-brand">
            <span class="brand-icon">⬡</span>
            <h1 class="brand-name">TaskVault</h1>
        </div>
        <h2 class="auth-title">Iniciar sesión</h2>

        <?php if (!empty($errors)): ?>
            <div class="alert alert--error" role="alert" aria-live="assertive">
                <?php foreach ($errors as $err): ?>
                    <p><?= e($err) ?></p>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>

        <form method="POST" action="login.php" novalidate id="loginForm">
            <!-- Token CSRF -->
            <input type="hidden" name="csrf_token" value="<?= e($csrfToken) ?>">

            <div class="form-group">
                <label for="email" class="form-label">Email</label>
                <input
                    type="email"
                    id="email"
                    name="email"
                    class="form-input"
                    value="<?= e($formEmail) ?>"
                    autocomplete="email"
                    required
                    aria-required="true"
                    maxlength="255"
                >
            </div>

            <div class="form-group">
                <label for="password" class="form-label">Contraseña</label>
                <div class="input-password-wrap">
                    <input
                        type="password"
                        id="password"
                        name="password"
                        class="form-input"
                        autocomplete="current-password"
                        required
                        aria-required="true"
                    >
                    <button type="button" class="toggle-pass" aria-label="Mostrar contraseña" data-target="password">
                        <span class="eye-icon">👁</span>
                    </button>
                </div>
            </div>

            <button type="submit" class="btn btn--primary">
                Ingresar
            </button>
        </form>

        <p class="auth-switch">¿No tenés cuenta? <a href="register.php">Registrate</a></p>
    </div>
</main>

<script src="js/validation.js"></script>
</body>
</html>
