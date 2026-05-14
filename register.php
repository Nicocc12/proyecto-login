<?php
// register.php – Registro de nuevo usuario

declare(strict_types=1);

require_once __DIR__ . '/config/security.php';

setSecurityHeaders();
startSecureSession();

// Redirigir si ya está autenticado
if (!empty($_SESSION['user_id'])) {
    header('Location: index.php');
    exit;
}

$errors   = [];
$success  = false;
$formEmail = '';

// ──────────────────────────────────────────────
// Procesamiento del formulario POST
// ──────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // 1. Validar token CSRF
    requireValidCsrf('register');

    // 2. Sanitizar entradas
    $email    = trim($_POST['email']    ?? '');
    $password = $_POST['password']      ?? '';
    $confirm  = $_POST['confirm']       ?? '';
    $formEmail = $email;

    // 3. Validaciones del servidor
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'El formato del email no es válido.';
    }
    if (strlen($email) > 255) {
        $errors[] = 'El email es demasiado largo.';
    }
    if (strlen($password) < 8) {
        $errors[] = 'La contraseña debe tener al menos 8 caracteres.';
    }
    if (!preg_match('/[A-Z]/', $password)) {
        $errors[] = 'La contraseña debe incluir al menos una mayúscula.';
    }
    if (!preg_match('/[0-9]/', $password)) {
        $errors[] = 'La contraseña debe incluir al menos un número.';
    }
    if ($password !== $confirm) {
        $errors[] = 'Las contraseñas no coinciden.';
    }

    // 4. Verificar si el email ya existe (prepared statement – sin SQLi)
    if (empty($errors)) {
        $db   = getDB();
        $stmt = $db->prepare('SELECT id FROM users WHERE email = :email LIMIT 1');
        $stmt->execute([':email' => $email]);

        if ($stmt->fetch()) {
            // Mensaje genérico – no revelar si el email existe
            $errors[] = 'No fue posible crear la cuenta. Verificá los datos.';
        }
    }

    // 5. Crear usuario
    if (empty($errors)) {
        // Hash con bcrypt (costo 12 por defecto en PHP 8)
        $hash = password_hash($password, PASSWORD_DEFAULT);

        $db->prepare(
            'INSERT INTO users (email, password_hash) VALUES (:email, :hash)'
        )->execute([':email' => $email, ':hash' => $hash]);

        $success = true;
        $formEmail = '';
    }
}

$csrfToken = generateCsrfToken('register');
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registro — TaskVault</title>
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
        <h2 class="auth-title">Crear cuenta</h2>

        <?php if ($success): ?>
            <div class="alert alert--success" role="alert">
                ✓ Cuenta creada correctamente.
                <a href="login.php" class="alert-link">Iniciá sesión</a>
            </div>
        <?php endif; ?>

        <?php if (!empty($errors)): ?>
            <div class="alert alert--error" role="alert" aria-live="assertive">
                <ul class="error-list">
                    <?php foreach ($errors as $err): ?>
                        <li><?= e($err) ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>

        <?php if (!$success): ?>
        <form method="POST" action="register.php" novalidate id="registerForm">
            <!-- Token CSRF oculto -->
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
                    aria-describedby="email-hint"
                    maxlength="255"
                >
                <span id="email-hint" class="field-hint">Usá un email real al que tengas acceso.</span>
            </div>

            <div class="form-group">
                <label for="password" class="form-label">Contraseña</label>
                <div class="input-password-wrap">
                    <input
                        type="password"
                        id="password"
                        name="password"
                        class="form-input"
                        autocomplete="new-password"
                        required
                        aria-required="true"
                        aria-describedby="strength-label"
                        minlength="8"
                    >
                    <button type="button" class="toggle-pass" aria-label="Mostrar contraseña" data-target="password">
                        <span class="eye-icon">👁</span>
                    </button>
                </div>
                <!-- Indicador de fortaleza de contraseña -->
                <div class="strength-bar" aria-hidden="true">
                    <div class="strength-fill" id="strengthFill"></div>
                </div>
                <span id="strength-label" class="strength-text" aria-live="polite"></span>
            </div>

            <div class="form-group">
                <label for="confirm" class="form-label">Confirmá la contraseña</label>
                <div class="input-password-wrap">
                    <input
                        type="password"
                        id="confirm"
                        name="confirm"
                        class="form-input"
                        autocomplete="new-password"
                        required
                        aria-required="true"
                    >
                    <button type="button" class="toggle-pass" aria-label="Mostrar confirmación" data-target="confirm">
                        <span class="eye-icon">👁</span>
                    </button>
                </div>
                <span id="confirm-error" class="field-error" aria-live="polite"></span>
            </div>

            <button type="submit" class="btn btn--primary" id="submitBtn">
                Crear cuenta
            </button>
        </form>
        <?php endif; ?>

        <p class="auth-switch">¿Ya tenés cuenta? <a href="login.php">Iniciá sesión</a></p>
    </div>
</main>

<script src="js/validation.js"></script>
</body>
</html>
