// Q-EKH Protocol v3 — enkripsi hibrida pasca-kuantum TERAUTENTIKASI.
//
// Kesepakatan kunci : X25519 (native WebCrypto) + ML-KEM-768 (@noble/post-quantum),
//   digabung manual lewat HKDF-SHA256 (rahasia PQ digabung lebih dulu, baru rahasia
//   klasik) — urutan yang sama dipakai konstruksi hybrid standar seperti X-Wing/TLS 1.3.
// Tanda tangan : Ed25519 (native WebCrypto) + SLH-DSA-SHA2-192s (@noble/post-quantum).
//   Keduanya harus valid. Fondasi matematikanya sengaja beda dari ML-KEM (lattice),
//   supaya lapisan tanda tangan tetap aman walau lattice suatu saat ada celah.
// Enkripsi pesan : AES-256-GCM, kunci diturunkan via HKDF dengan salt acak per pesan.
//
// Hanya 2 pustaka eksternal yang dipakai, dan API keduanya sudah diverifikasi
// langsung dari dokumentasi resmi sebelum dipakai di sini.
import { ml_kem768 } from 'https://esm.sh/@noble/post-quantum@0.7.0/ml-kem.js';
import { slh_dsa_sha2_192s } from 'https://esm.sh/@noble/post-quantum@0.7.0/slh-dsa.js';

document.addEventListener('DOMContentLoaded', () => {

    const tabButtons = document.querySelectorAll('.tab-button');
    const contentSections = document.querySelectorAll('.content-section');

    const generateBtn = document.getElementById('generateBtn');
    const genPublicKeyEl = document.getElementById('genPublicKey');
    const genPrivateKeyEl = document.getElementById('genPrivateKey');
    const genFingerprintEl = document.getElementById('genFingerprint');
    const copyGenPublicBtn = document.getElementById('copyGenPublicBtn');
    const copyGenPrivateBtn = document.getElementById('copyGenPrivateBtn');

    const publicKeyEl = document.getElementById('publicKey');
    const recipientFingerprintEl = document.getElementById('recipientFingerprint');
    const senderPrivateKeyEl = document.getElementById('senderPrivateKey');
    const plainTextEl = document.getElementById('plainText');
    const encryptBtn = document.getElementById('encryptBtn');
    const encryptedTextEl = document.getElementById('encryptedText');
    const copyEncryptedBtn = document.getElementById('copyEncryptedBtn');

    const privateKeyEl = document.getElementById('privateKey');
    const senderVerifyKeyEl = document.getElementById('senderVerifyKey');
    const senderVerifyFingerprintEl = document.getElementById('senderVerifyFingerprint');
    const cipherTextEl = document.getElementById('cipherText');
    const decryptBtn = document.getElementById('decryptBtn');
    const decryptedTextEl = document.getElementById('decryptedText');
    const verificationStatusEl = document.getElementById('verificationStatus');
    const copyDecryptedBtn = document.getElementById('copyDecryptedBtn');

    const PROTOCOL_VERSION = 'QEKH-v3';
    const HKDF_INFO = new TextEncoder().encode('QEKH-v3-HKDF');

    // --- Tab Switching ---
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            tabButtons.forEach(btn => btn.classList.remove('active'));
            contentSections.forEach(sec => sec.classList.remove('active'));
            button.classList.add('active');
            const targetTab = button.getAttribute('data-tab');
            document.getElementById(`${targetTab}-view`).classList.add('active');
        });
    });

    // --- Copy Buttons ---
    const setupCopyButton = (button, textarea) => {
        button.addEventListener('click', () => {
            const textToCopy = textarea.value;
            if (!textToCopy || textToCopy.startsWith('ERROR:')) return;
            navigator.clipboard.writeText(textToCopy).then(() => {
                const originalText = button.textContent;
                button.textContent = 'Tersalin!';
                button.classList.add('copied');
                setTimeout(() => {
                    button.textContent = originalText;
                    button.classList.remove('copied');
                }, 2000);
            });
        });
    };

    // --- Byte / Base64 Helpers ---
    const arrayBufferToBase64 = (buffer) => {
        const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
        let binary = '';
        const chunkSize = 0x8000;
        for (let i = 0; i < bytes.length; i += chunkSize) {
            binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
        }
        return btoa(binary);
    };
    const base64ToUint8Array = (base64) => Uint8Array.from(atob(base64), c => c.charCodeAt(0));

    const concatBytes = (...arrays) => {
        const parts = arrays.map(a => (a instanceof Uint8Array ? a : new Uint8Array(a)));
        const total = parts.reduce((sum, p) => sum + p.length, 0);
        const result = new Uint8Array(total);
        let offset = 0;
        for (const p of parts) {
            result.set(p, offset);
            offset += p.length;
        }
        return result;
    };

    // ===================================================================
    //                          CRYPTO LOGIC
    // ===================================================================

    async function generateX25519Keys() {
        return await window.crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    }

    async function generateEd25519Keys() {
        return await window.crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    }

    async function computeFingerprint(x25519PkBytes, kyberPkBytes, ed25519PkBytes, slhdsaPkBytes) {
        const combined = concatBytes(x25519PkBytes, kyberPkBytes, ed25519PkBytes, slhdsaPkBytes);
        const hashBuffer = await window.crypto.subtle.digest('SHA-256', combined);
        const hex = Array.from(new Uint8Array(hashBuffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('')
            .toUpperCase();
        return hex.match(/.{1,4}/g).join(' ');
    }

    async function deriveEncryptionKey(combinedSecretBytes, salt) {
        const importedKey = await window.crypto.subtle.importKey(
            'raw', combinedSecretBytes, { name: 'HKDF' }, false, ['deriveKey']
        );
        const derivedKey = await window.crypto.subtle.deriveKey(
            { name: 'HKDF', salt: salt, info: HKDF_INFO, hash: 'SHA-256' },
            importedKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
        combinedSecretBytes.fill(0); // best-effort: hapus rahasia mentah dari memori
        return derivedKey;
    }

    function buildSignablePayload(x25519PublicKeyRaw, kyberCipherText, salt, iv, ciphertext) {
        return concatBytes(
            new TextEncoder().encode(PROTOCOL_VERSION),
            x25519PublicKeyRaw,
            kyberCipherText,
            salt,
            iv,
            ciphertext
        );
    }

    async function encryptMessage(key, plaintext) {
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encodedPlaintext = new TextEncoder().encode(plaintext);
        const ciphertext = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, encodedPlaintext);
        return { iv, ciphertext: new Uint8Array(ciphertext) };
    }

    async function decryptMessage(key, iv, ciphertext) {
        const decrypted = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ciphertext);
        return new TextDecoder().decode(decrypted);
    }

    // --- Key Generation ---
    generateBtn.addEventListener('click', async () => {
        generateBtn.disabled = true;
        generateBtn.textContent = 'Membuat Kunci...';
        [genPublicKeyEl, genPrivateKeyEl].forEach(el => el.value = 'Harap tunggu, membuat 4 pasang kunci...');
        genFingerprintEl.textContent = 'Menghitung...';

        try {
            const x25519KeyPair = await generateX25519Keys();
            const kyberKeys = ml_kem768.keygen();
            const ed25519KeyPair = await generateEd25519Keys();
            const slhKeys = slh_dsa_sha2_192s.keygen();
