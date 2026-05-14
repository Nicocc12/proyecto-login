<?php
// config/database.php
// Conexión PDO a MySQL – única fuente de verdad para la BD.

declare(strict_types=1);

define('DB_HOST', 'localhost');
define('DB_PORT', '3306');
define('DB_NAME', 'login_seguro');
define('DB_USER', 'root');        // Cambiar en producción
define('DB_PASS', '');            // Cambiar en producción
define('DB_CHARSET', 'utf8mb4');

/**
 * Devuelve una instancia PDO configurada de forma segura.
 * Se usa PDO::ERRMODE_EXCEPTION para que los errores SQL
 * lancen excepciones (nunca se muestran al usuario).
 */
function getDB(): PDO
{
    static $pdo = null;

    if ($pdo === null) {
        $dsn = sprintf(
            'mysql:host=%s;port=%s;dbname=%s;charset=%s',
            DB_HOST, DB_PORT, DB_NAME, DB_CHARSET
        );

        $options = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,  // prepared statements reales
        ];

        try {
            $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
        } catch (PDOException $e) {
            // Loguear el error real, mostrar mensaje genérico
            error_log('DB connection error: ' . $e->getMessage());
            http_response_code(500);
            die('Error interno del servidor. Intente más tarde.');
        }
    }

    return $pdo;
}
