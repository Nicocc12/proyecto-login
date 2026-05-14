# TaskVault — Sistema de Login Seguro

> Proyecto educativo · Desarrollo de Sistemas Web · 3° Año  
> Tecnologías: **PHP 8** · **MySQL** · **HTML/CSS/JS** · **PDO**

---

## Tabla de contenidos

1. [Descripción del proyecto](#descripción-del-proyecto)
2. [Estructura de archivos](#estructura-de-archivos)
3. [Diagrama de base de datos](#diagrama-de-base-de-datos)
4. [Instalación y deploy](#instalación-y-deploy)
5. [Medidas de seguridad implementadas](#medidas-de-seguridad-implementadas)
6. [Commits significativos](#commits-significativos)

---

## Descripción del proyecto

TaskVault es una plataforma de gestión de tareas personales con un sistema de autenticación construido desde cero aplicando las mejores prácticas de seguridad web. La aplicación protege contra las seis vulnerabilidades críticas más comunes: SQLi, XSS, CSRF, contraseñas en texto plano, session hijacking y fuerza bruta.

---

## Estructura de archivos

```
proyecto-login/
├── index.php              # Dashboard (requiere sesión)
├── login.php              # Formulario + lógica de login
├── register.php           # Formulario + lógica de registro
├── logout.php             # Cierre de sesión seguro
├── config/
│   ├── database.php       # Conexión PDO centralizada
│   └── security.php       # CSRF, headers, rate limiting, output escaping
├── css/
│   └── styles.css         # Estilos responsivos
├── js/
│   └── validation.js      # Validación client-side + indicador de fortaleza
└── sql/
    └── schema.sql         # Script de creación de tablas e índices
```

---

## Diagrama de base de datos

```
┌─────────────────────────────────┐     ┌──────────────────────────────────────┐
│             users               │     │          login_attempts              │
├─────────────────────────────────┤     ├──────────────────────────────────────┤
│ id           INT UNSIGNED PK AI │     │ id           INT UNSIGNED PK AI      │
│ email        VARCHAR(255) UNIQUE│     │ email        VARCHAR(255)            │
│ password_hash VARCHAR(255)      │     │ attempted_at DATETIME                │
│ created_at   DATETIME           │     │ ip_address   VARCHAR(45)             │
└─────────────────────────────────┘     │ blocked_until DATETIME (nullable)    │
                                        └──────────────────────────────────────┘

Índices:
  users            → UNIQUE INDEX uq_email (email)
  login_attempts   → INDEX idx_email_attempt (email, attempted_at)
```

- **users**: almacena el email y el hash bcrypt de la contraseña. Nunca texto plano.
- **login_attempts**: registra cada intento fallido. `blocked_until` se completa cuando el email supera los 5 intentos (bloqueo de 15 min).

---

## Instalación y deploy

### Requisitos previos

| Herramienta | Versión mínima |
|-------------|----------------|
| PHP         | 8.0            |
| MySQL       | 5.7 / MariaDB 10.3 |
| Apache/Nginx | cualquier reciente |
| Composer    | (no requerido) |

### Pasos

1. **Clonar el repositorio**

```bash
git clone https://github.com/tu-usuario/proyecto-login.git
cd proyecto-login
```

2. **Crear la base de datos**

```bash
mysql -u root -p < sql/schema.sql
```

3. **Configurar credenciales DB**

Editar `config/database.php` y completar:

```php
define('DB_USER', 'tu_usuario');
define('DB_PASS', 'tu_contraseña');
```

4. **Configurar el servidor web**

- Apuntar el Document Root al directorio `proyecto-login/`.
- Con **XAMPP/LAMP**: copiar la carpeta a `htdocs/` y acceder en `http://localhost/proyecto-login/`.

5. **Acceder a la aplicación**

- Registro: `http://localhost/proyecto-login/register.php`
- Login:    `http://localhost/proyecto-login/login.php`

---

## Medidas de seguridad implementadas

| # | Vulnerabilidad | Solución implementada | Fragmento de código |
|---|----------------|-----------------------|---------------------|
| 1 | **SQL Injection** | Prepared Statements con PDO. Ninguna entrada del usuario se concatena en el SQL. | `$stmt = $db->prepare('SELECT id FROM users WHERE email = :email LIMIT 1'); $stmt->execute([':email' => $email]);` |
| 2 | **XSS – Cross-Site Scripting** | Todo output se escapa con `htmlspecialchars()` vía la función `e()`. Header `Content-Security-Policy` configurado. | `function e(string $v): string { return htmlspecialchars($v, ENT_QUOTES\|ENT_HTML5, 'UTF-8'); }` |
| 3 | **CSRF – Cross-Site Request Forgery** | Token de 64 hex chars generado por sesión con `random_bytes(32)`. Se valida antes de procesar cualquier POST con `hash_equals()`. | `$_SESSION['csrf_tokens'][$action] = bin2hex(random_bytes(32));` |
| 4 | **Contraseñas en texto plano** | Hash con `password_hash($pass, PASSWORD_DEFAULT)` (bcrypt). Verificación con `password_verify()`. | `$hash = password_hash($password, PASSWORD_DEFAULT);` |
| 5 | **Session Hijacking / Fixation** | `session_regenerate_id(true)` al login exitoso. Cookies con flags `HttpOnly`, `SameSite=Strict`. | `session_regenerate_id(true);` + `session_set_cookie_params(['httponly' => true, 'samesite' => 'Strict'])` |
| 6 | **Fuerza Bruta** | Máximo 5 intentos por email en 15 min. Bloqueo registrado en `login_attempts.blocked_until`. Verificación al inicio del POST. | `if (isLoginBlocked($email)) { $errors[] = "Bloqueado por {$mins} min."; }` |

---

## Commits significativos

Los commits deben reflejar el progreso real del proyecto. Ejemplo de historia sugerida:

```
1. feat: inicialización del proyecto – estructura de archivos y schema SQL
2. feat: conexión PDO y funciones de seguridad (CSRF, headers, rate limiting)
3. feat: registro seguro con hash de contraseñas y prepared statements
4. feat: login con validación, session regeneration y bloqueo por fuerza bruta
5. feat: frontend – formularios responsivos, validación JS e indicador de fortaleza
```

---

## Créditos

Proyecto desarrollado para la materia **Desarrollo de Sistemas Web** (Prof. Trinidad, Miguel Angel).
