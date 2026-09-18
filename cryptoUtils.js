/**
 * cryptoUtils.js
 * ─────────────────────────────────────────────────────────────
 * Cifrado / descifrado en el lado del cliente (Zero-Knowledge).
 *
 * Usa la API nativa del navegador `window.crypto.subtle` (WebCrypto):
 *   - No depende de librerías externas (crypto-js incluido).
 *   - AES-256-GCM para el cifrado (autenticado: detecta manipulación).
 *   - PBKDF2 (100.000 iteraciones, SHA-256) para derivar la clave AES
 *     a partir de la "Clave Maestra" que introduce el usuario.
 *
 * IMPORTANTE (modelo de seguridad):
 *   - La Clave Maestra NUNCA sale del navegador ni se envía al servidor.
 *   - Si el usuario pierde la Clave Maestra, los datos son IRRECUPERABLES
 *     (ese es precisamente el punto de "Zero-Knowledge": ni tú ni Firebase
 *     podéis descifrarlos sin ella). Debes avisar de esto claramente en tu UI.
 *   - Como los datos están cifrados, Firestore/Firebase ya NO puede hacer
 *     `where()` ni consultas de texto sobre esos campos. Cualquier filtro o
 *     búsqueda tendrá que hacerse en el cliente, después de descifrar.
 * ─────────────────────────────────────────────────────────────
 */

const PBKDF2_ITERATIONS = 100000;
const SALT_BYTES = 16;   // 128 bits
const IV_BYTES = 12;     // 96 bits, tamaño recomendado para AES-GCM

/* ---------- Helpers de codificación ---------- */

function bytesToBase64(bytes) {
    let binary = '';
    bytes.forEach((b) => { binary += String.fromCharCode(b); });
    return btoa(binary);
}

function base64ToBytes(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
}

/* ---------- Derivación de clave a partir de la contraseña maestra ---------- */

/**
 * Deriva una CryptoKey AES-256-GCM a partir de la clave maestra (string)
 * y una sal (Uint8Array). La misma clave maestra + la misma sal siempre
 * producen la misma CryptoKey.
 */
async function deriveKey(secretKey, saltBytes) {
    const enc = new TextEncoder();
    const baseKey = await window.crypto.subtle.importKey(
        'raw',
        enc.encode(secretKey),
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );

    return window.crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: saltBytes,
            iterations: PBKDF2_ITERATIONS,
            hash: 'SHA-256'
        },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

/* ---------- API principal ---------- */

/**
 * Cifra un texto plano con la clave maestra del usuario.
 * @param {string} text - Texto en claro a cifrar (p.ej. un nombre, teléfono...).
 * @param {string} secretKey - Clave maestra del usuario (nunca se envía a la nube).
 * @returns {Promise<string>} Cadena Base64 auto-contenida: salt + iv + ciphertext.
 *          Este es el único valor que debe guardarse en Firestore.
 */
async function encryptData(text, secretKey) {
    if (text === null || text === undefined) return text; // no cifrar null/undefined
    if (!secretKey) throw new Error('encryptData: falta la clave maestra (secretKey)');

    const enc = new TextEncoder();
    const salt = window.crypto.getRandomValues(new Uint8Array(SALT_BYTES));
    const iv = window.crypto.getRandomValues(new Uint8Array(IV_BYTES));

    const key = await deriveKey(secretKey, salt);

    const ciphertextBuffer = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        enc.encode(String(text))
    );

    // Empaquetamos todo en un solo string: [salt(16)][iv(12)][ciphertext...]
    const combined = new Uint8Array(salt.length + iv.length + ciphertextBuffer.byteLength);
    combined.set(salt, 0);
    combined.set(iv, salt.length);
    combined.set(new Uint8Array(ciphertextBuffer), salt.length + iv.length);

    return bytesToBase64(combined);
}

/**
 * Descifra una cadena generada por encryptData().
 * @param {string} ciphertext - Cadena Base64 devuelta por encryptData.
 * @param {string} secretKey - Clave maestra del usuario.
 * @returns {Promise<string>} Texto original en claro.
 *          Si la clave es incorrecta o el dato está corrupto, lanza un Error
 *          (AES-GCM es "autenticado": detecta manipulación o clave errónea).
 */
async function decryptData(ciphertext, secretKey) {
    if (ciphertext === null || ciphertext === undefined) return ciphertext;
    if (!secretKey) throw new Error('decryptData: falta la clave maestra (secretKey)');

    try {
        const combined = base64ToBytes(ciphertext);
        const salt = combined.slice(0, SALT_BYTES);
        const iv = combined.slice(SALT_BYTES, SALT_BYTES + IV_BYTES);
        const data = combined.slice(SALT_BYTES + IV_BYTES);

        const key = await deriveKey(secretKey, salt);

        const plainBuffer = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            key,
            data
        );

        return new TextDecoder().decode(plainBuffer);
    } catch (e) {
        // Clave incorrecta, dato corrupto, o dato que en realidad no estaba cifrado.
        console.error('decryptData: no se pudo descifrar', e);
        throw new Error('No se pudo descifrar el dato. Clave incorrecta o datos corruptos.');
    }
}

/* ---------- Helpers de conveniencia para objetos completos ---------- */

/**
 * Cifra únicamente los campos indicados de un objeto (los demás se dejan igual).
 * Útil para cifrar "nombre", "telefono", "direccion", "notas"... de un registro,
 * manteniendo el `id` y otros campos técnicos en claro.
 *
 * @param {Object} obj - Objeto original (p.ej. un registro de cliente).
 * @param {string[]} fields - Nombres de campos a cifrar, p.ej. ['nombre','telefono','direccion','notas'].
 * @param {string} secretKey - Clave maestra.
 * @returns {Promise<Object>} Copia del objeto con esos campos cifrados.
 */
async function encryptFields(obj, fields, secretKey) {
    const result = { ...obj };
    for (const field of fields) {
        if (Object.prototype.hasOwnProperty.call(obj, field)) {
            result[field] = await encryptData(obj[field], secretKey);
        }
    }
    return result;
}

/**
 * Descifra únicamente los campos indicados de un objeto.
 * Si un campo falla al descifrar (p.ej. porque estaba vacío o no cifrado),
 * se deja el valor original y se avisa por consola, para no romper el render.
 */
async function decryptFields(obj, fields, secretKey) {
    const result = { ...obj };
    for (const field of fields) {
        if (Object.prototype.hasOwnProperty.call(obj, field) && obj[field]) {
            try {
                result[field] = await decryptData(obj[field], secretKey);
            } catch (e) {
                console.warn(`No se pudo descifrar el campo "${field}" del registro`, obj.id, e);
                result[field] = '⚠️ [No se pudo descifrar]';
            }
        }
    }
    return result;
}

/* ---------- Identificador determinista (para usar como ID de documento) ---------- */

/**
 * Genera un identificador determinista y NO reversible a partir de un texto
 * (p.ej. un teléfono) y la Clave Maestra, usando HMAC-SHA256.
 *
 * A diferencia de encryptData(), esta función NO lleva salt aleatorio: el
 * mismo texto + la misma Clave Maestra producen siempre el mismo resultado.
 * Eso es justo lo que hace falta para usarlo como ID de documento en
 * Firestore (para poder buscar por teléfono sin exponer el teléfono como ID).
 *
 * Sin la Clave Maestra, no es viable adivinar qué teléfono corresponde a un
 * ID dado (es una función HMAC con clave secreta, no un hash público).
 *
 * IMPORTANTE: esto es de un solo sentido. No sirve para recuperar el texto
 * original — para eso están encryptData/decryptData.
 *
 * @param {string} text - Texto a partir del cual generar el identificador (p.ej. un teléfono).
 * @param {string} secretKey - Clave maestra del usuario.
 * @returns {Promise<string>} Cadena hexadecimal de 64 caracteres, válida como ID de documento de Firestore.
 */
async function hashLookupKey(text, secretKey) {
    if (!secretKey) throw new Error('hashLookupKey: falta la clave maestra (secretKey)');
    const enc = new TextEncoder();
    const hmacKey = await window.crypto.subtle.importKey(
        'raw',
        enc.encode(secretKey),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    const sigBuffer = await window.crypto.subtle.sign('HMAC', hmacKey, enc.encode(String(text)));
    const bytes = new Uint8Array(sigBuffer);
    return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

export { encryptData, decryptData, encryptFields, decryptFields, hashLookupKey };
