<?php
// config/security.php
// Funciones de seguridad reutilizables en toda la aplicación.

declare(strict_types=1);

require_once __DIR__ . '/database.php';

// ──────────────────────────────────────────────
// 1. Headers de seguridad HTTP
// ──────────────────────────────────────────────

/**
 * Envía cabeceras HTTP que endurecen la seguridad del navegador.
 * Llamar al inicio de CADA archivo PHP antes de cualquier output.
 */
function setSecurityHeaders(): void
{
    header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:");
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
    // En producción con HTTPS, descomentar la siguiente línea:
    // header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}

// ──────────────────────────────────────────────
// 2. Gestión de sesiones segura
// ──────────────────────────────────────────────

/**
 * Inicia la sesión con flags de cookie seguros.
 * Debe llamarse antes de usar $_SESSION.
 */
function startSecureSession(): void
{
    if (session_status() === PHP_SESSION_NONE) {
        session_set_cookie_params([
            'lifetime' => 0,           // expira al cerrar el navegador
            'path'     => '/',
            'domain'   => '',
            'secure'   => false,       // Cambiar a TRUE en producción con HTTPS
            'httponly' => true,        // Inaccesible desde JavaScript (protege contra XSS)
            'samesite' => 'Strict',    // Protección CSRF adicional
        ]);
        session_start();
    }
}

// ──────────────────────────────────────────────
// 3. Tokens CSRF
// ──────────────────────────────────────────────

/**
 * Genera un token CSRF y lo almacena en sesión.
 * Si ya existe uno para la acción dada, lo reutiliza.
 */
function generateCsrfToken(string $action = 'default'): string
{
    startSecureSession();

    if (empty($_SESSION['csrf_tokens'][$action])) {
        $_SESSION['csrf_tokens'][$action] = bin2hex(random_bytes(32));
    }

    return $_SESSION['csrf_tokens'][$action];
}

/**
 * Valida el token CSRF enviado en el formulario.
 * Usa hash_equals para evitar timing attacks.
 * Destruye el token después de validarlo (one-time use).
 */
function validateCsrfToken(string $token, string $action = 'default'): bool
{
    startSecureSession();

    $stored = $_SESSION['csrf_tokens'][$action] ?? '';

    if (!$stored || !hash_equals($stored, $token)) {
        return false;
    }

    // Invalidar el token usado (one-time use)
    unset($_SESSION['csrf_tokens'][$action]);
    return true;
}

/**
 * Aborta la petición si el token CSRF es inválido.
 */
function requireValidCsrf(string $action = 'default'): void
{
    $token = $_POST['csrf_token'] ?? '';

    if (!validateCsrfToken($token, $action)) {
        http_response_code(403);
        die('Token CSRF inválido. Recargá la página e intentá de nuevo.');
    }
}

// ──────────────────────────────────────────────
// 4. Rate limiting – límite de intentos de login
// ──────────────────────────────────────────────

define('MAX_LOGIN_ATTEMPTS', 5);
define('BLOCK_DURATION_MINUTES', 15);

/**
 * Verifica si un email está bloqueado por exceso de intentos fallidos.
 * Retorna true si está bloqueado, false si puede intentar.
 */
function isLoginBlocked(string $email): bool
{
    $db = getDB();

    $stmt = $db->prepare(
        'SELECT blocked_until
           FROM login_attempts
          WHERE email = :email
            AND blocked_until IS NOT NULL
            AND blocked_until > NOW()
          LIMIT 1'
    );
    $stmt->execute([':email' => $email]);
    $row = $stmt->fetch();

    return (bool) $row;
}

/**
 * Devuelve los minutos que faltan para el desbloqueo (0 si no está bloqueado).
 */
function getBlockMinutesLeft(string $email): int
{
    $db = getDB();

    $stmt = $db->prepare(
        'SELECT CEIL(TIMESTAMPDIFF(SECOND, NOW(), blocked_until) / 60) AS mins
           FROM login_attempts
          WHERE email = :email
            AND blocked_until IS NOT NULL
            AND blocked_until > NOW()
          LIMIT 1'
    );
    $stmt->execute([':email' => $email]);
    $row = $stmt->fetch();

    return $row ? max(1, (int)$row['mins']) : 0;
}

/**
 * Registra un intento fallido.
 * Si alcanza MAX_LOGIN_ATTEMPTS, establece blocked_until.
 */
function recordFailedLogin(string $email, string $ip): void
{
    $db = getDB();

    // Insertar el intento
    $db->prepare(
        'INSERT INTO login_attempts (email, ip_address) VALUES (:email, :ip)'
    )->execute([':email' => $email, ':ip' => $ip]);

    // Contar intentos recientes (últimos 15 min)
    $stmt = $db->prepare(
        'SELECT COUNT(*) AS total
           FROM login_attempts
          WHERE email = :email
            AND attempted_at > DATE_SUB(NOW(), INTERVAL :mins MINUTE)
            AND blocked_until IS NULL'
    );
    $stmt->execute([':email' => $email, ':mins' => BLOCK_DURATION_MINUTES]);
    $count = (int) $stmt->fetchColumn();

    if ($count >= MAX_LOGIN_ATTEMPTS) {
        // Bloquear todas las filas recientes del email
        $db->prepare(
            'UPDATE login_attempts
                SET blocked_until = DATE_ADD(NOW(), INTERVAL :mins MINUTE)
              WHERE email = :email
                AND attempted_at > DATE_SUB(NOW(), INTERVAL :mins2 MINUTE)'
        )->execute([
            ':email' => $email,
            ':mins'  => BLOCK_DURATION_MINUTES,
            ':mins2' => BLOCK_DURATION_MINUTES,
        ]);
    }
}

/**
 * Limpia los intentos fallidos cuando el login es exitoso.
 */
function clearLoginAttempts(string $email): void
{
    $db = getDB();
    $db->prepare('DELETE FROM login_attempts WHERE email = :email')
       ->execute([':email' => $email]);
}

// ──────────────────────────────────────────────
// 5. Output seguro
// ──────────────────────────────────────────────

/**
 * Escapa output HTML para prevenir XSS.
 * Siempre usar esta función al imprimir datos del usuario.
 */
function e(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}
