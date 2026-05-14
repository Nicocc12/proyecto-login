/**
 * js/validation.js
 * Validación del lado del cliente para registro y login.
 * NOTA: Esta validación mejora la UX, pero el servidor (PHP)
 * repite TODAS las validaciones. Nunca se puede saltear el backend.
 */

'use strict';

// ──────────────────────────────────────────────
// 1. Toggle mostrar / ocultar contraseña
// ──────────────────────────────────────────────
document.querySelectorAll('.toggle-pass').forEach(function (btn) {
    btn.addEventListener('click', function () {
        var targetId = btn.getAttribute('data-target');
        var input = document.getElementById(targetId);
        if (!input) return;

        var isPassword = input.type === 'password';
        input.type = isPassword ? 'text' : 'password';

        var icon = btn.querySelector('.eye-icon');
        if (icon) {
            icon.textContent = isPassword ? '🙈' : '👁';
        }

        btn.setAttribute('aria-label', isPassword ? 'Ocultar contraseña' : 'Mostrar contraseña');
    });
});

// ──────────────────────────────────────────────
// 2. Indicador de fortaleza de contraseña
// ──────────────────────────────────────────────

/**
 * Calcula un nivel de fortaleza del 1 al 4.
 * Criterios:
 *  +1 longitud ≥ 8
 *  +1 tiene mayúscula y minúscula
 *  +1 tiene número
 *  +1 tiene carácter especial
 */
function getPasswordStrength(value) {
    var score = 0;
    if (value.length >= 8)                        score++;
    if (/[a-z]/.test(value) && /[A-Z]/.test(value)) score++;
    if (/[0-9]/.test(value))                       score++;
    if (/[^A-Za-z0-9]/.test(value))               score++;
    return score;
}

var STRENGTH_LABELS = {
    0: '',
    1: 'Muy débil',
    2: 'Débil',
    3: 'Buena',
    4: 'Muy fuerte ✓',
};

var passwordInput = document.getElementById('password');
var strengthFill  = document.getElementById('strengthFill');
var strengthText  = document.getElementById('strength-label');

if (passwordInput && strengthFill && strengthText) {
    passwordInput.addEventListener('input', function () {
        var val   = passwordInput.value;
        var level = val.length === 0 ? 0 : Math.max(1, getPasswordStrength(val));

        strengthFill.setAttribute('data-level', level);
        strengthFill.style.width = (level * 25) + '%';
        strengthText.textContent = STRENGTH_LABELS[level] || '';
    });
}

// ──────────────────────────────────────────────
// 3. Validación del formulario de REGISTRO
// ──────────────────────────────────────────────
var registerForm = document.getElementById('registerForm');

if (registerForm) {
    var emailInput   = document.getElementById('email');
    var confirmInput = document.getElementById('confirm');
    var confirmError = document.getElementById('confirm-error');

    // Validar coincidencia en tiempo real
    if (confirmInput && confirmError) {
        confirmInput.addEventListener('input', validateConfirm);
        if (passwordInput) {
            passwordInput.addEventListener('input', validateConfirm);
        }
    }

    function validateConfirm() {
        if (!confirmInput.value) {
            confirmError.textContent = '';
            confirmInput.classList.remove('is-invalid');
            return true;
        }
        if (confirmInput.value !== passwordInput.value) {
            confirmError.textContent = 'Las contraseñas no coinciden.';
            confirmInput.classList.add('is-invalid');
            return false;
        }
        confirmError.textContent = '';
        confirmInput.classList.remove('is-invalid');
        return true;
    }

    registerForm.addEventListener('submit', function (e) {
        var valid = true;

        // Validar email
        if (emailInput && !emailInput.validity.valid) {
            emailInput.classList.add('is-invalid');
            valid = false;
        } else if (emailInput) {
            emailInput.classList.remove('is-invalid');
        }

        // Validar contraseña mínima
        if (passwordInput && passwordInput.value.length < 8) {
            passwordInput.classList.add('is-invalid');
            valid = false;
        } else if (passwordInput) {
            passwordInput.classList.remove('is-invalid');
        }

        // Validar confirmación
        if (!validateConfirm()) {
            valid = false;
        }

        if (!valid) {
            e.preventDefault();
        }
    });
}

// ──────────────────────────────────────────────
// 4. Validación del formulario de LOGIN
// ──────────────────────────────────────────────
var loginForm = document.getElementById('loginForm');

if (loginForm) {
    var loginEmail = document.getElementById('email');
    var loginPass  = document.getElementById('password');

    loginForm.addEventListener('submit', function (e) {
        var valid = true;

        if (loginEmail && !loginEmail.validity.valid) {
            loginEmail.classList.add('is-invalid');
            valid = false;
        } else if (loginEmail) {
            loginEmail.classList.remove('is-invalid');
        }

        if (loginPass && loginPass.value.trim() === '') {
            loginPass.classList.add('is-invalid');
            valid = false;
        } else if (loginPass) {
            loginPass.classList.remove('is-invalid');
        }

        if (!valid) {
            e.preventDefault();
        }
    });
}
