// Mengimpor fungsi ML-KEM (Kyber) level 768 dari pustaka @noble/post-quantum
// Ini sesuai dengan keamanan setara AES-192, keseimbangan yang baik antara keamanan dan kinerja.
// Catatan: versi dinaikkan dari 0.5.1 -> 0.7.0 (versi terbaru saat perbaikan ini dibuat)
// untuk mendapat perbaikan/patch terbaru dari pustaka. Tes ulang generate->enkripsi->dekripsi
// setelah deploy untuk memastikan semuanya tetap kompatibel.
import { ml_kem768 } from 'https://esm.sh/@noble/post-quantum@0.7.0/ml-kem.js';

document.addEventListener('DOMContentLoaded', () => {

    // --- DOM Element Selection ---
    const tabButtons = document.querySelectorAll('.tab-button');
    const contentSections = document.querySelectorAll('.content-section');
    
    // Key Generation elements
    const generateBtn = document.getElementById('generateBtn');
    const genPublicKeyEl = document.getElementById('genPublicKey');
    const genPrivateKeyEl = document.getElementById('genPrivateKey');
    const genFingerprintEl = document.getElementById('genFingerprint');
    const copyGenPublicBtn = document.getElementById('copyGenPublicBtn');
    const copyGenPrivateBtn = document.getElementById('copyGenPrivateBtn');

    // Encryption elements
    const publicKeyEl = document.getElementById('publicKey');
    const recipientFingerprintEl = document.getElementById('recipientFingerprint');
    const plainTextEl = document.getElementById('plainText');
    const encryptBtn = document.getElementById('encryptBtn');
    const encryptedTextEl = document.getElementById('encryptedText');
    const copyEncryptedBtn = document.getElementById('copyEncryptedBtn');

    // Decryption elements
    const privateKeyEl = document.getElementById('privateKey');
    const cipherTextEl = document.getElementById('cipherText');
    const decryptBtn = document.getElementById('decryptBtn');
    const decryptedTextEl = document.getElementById('decryptedText');
    const copyDecryptedBtn = document.getElementById('copyDecryptedBtn');

    // Versi format payload terenkripsi. Dipakai untuk mendeteksi ciphertext dari versi
    // protokol lama, agar gagal dengan pesan yang jelas, bukan error yang membingungkan.
    const PROTOCOL_VERSION = 'QEKH-v1';
    // String konteks tetap untuk domain-separation di HKDF (bukan rahasia, hanya identitas protokol).
    const HKDF_INFO = new TextEncoder().encode('QEKH-Hybrid-Key-v1');

    // --- Tab Switching Logic ---
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            tabButtons.forEach(btn => btn.classList.remove('active'));
            contentSections.forEach(sec => sec.classList.remove('active'));
            button.classList.add('active');
            const targetTab = button.getAttribute('data-tab');
            document.getElementById(`${targetTab}-view`).classList.add('active');
        });
    });
    
    // --- Reusable Copy Function ---
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

    // --- Helper Functions for Key Conversion ---
    // Dibuat per-chunk (32KB) supaya tidak menabrak batas jumlah argumen saat buffer-nya
    // besar (misalnya plaintext panjang) - versi lama bisa gagal ("call stack exceeded")
    // karena memakai spread operator langsung ke argumen fungsi.
    const arrayBufferToBase64 = (buffer) => {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        const chunkSize = 0x8000; // 32KB per chunk
        for (let i = 0; i < bytes.length; i += chunkSize) {
            binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
        }
        return btoa(binary);
    };
    const base64ToUint8Array = (base64) => Uint8Array.from(atob(base64), c => c.charCodeAt(0));

    // ===================================================================
    //                  CRYPTO LOGIC (HIBRIDA)
    // ===================================================================

    async function generateEcdhKeys() {
        return await window.crypto.subtle.generateKey(
            { name: "ECDH", namedCurve: "P-384" },
            true, // extractable
            ["deriveBits"]
        );
    }

    function generateKyberKeys() {
        return ml_kem768.keygen();
    }

    // Menghitung Fingerprint dari kunci publik hibrida berdasarkan BYTE MENTAH kunci
    // (bukan dari teks JSON hasil stringify), supaya hasilnya konsisten di semua
    // browser tanpa tergantung urutan field JWK saat di-serialize.
    async function computeFingerprint(ecdhPublicKey, kyberPublicKeyBytes) {
        const rawEcdh = new Uint8Array(await window.crypto.subtle.exportKey('raw', ecdhPublicKey));
        const combined = new Uint8Array(rawEcdh.length + kyberPublicKeyBytes.length);
        combined.set(rawEcdh, 0);
        combined.set(kyberPublicKeyBytes, rawEcdh.length);
        const hashBuffer = await window.crypto.subtle.digest('SHA-256', combined);
        const hex = Array.from(new Uint8Array(hashBuffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('')
            .toUpperCase();
        return hex.match(/.{1,4}/g).join(' ');
    }

    async function deriveHybridKey(ecdhSecretBytes, kyberSecretBytes, salt) {
        const combinedSecret = new Uint8Array(ecdhSecretBytes.length + kyberSecretBytes.length);
        combinedSecret.set(ecdhSecretBytes, 0);
        combinedSecret.set(kyberSecretBytes, ecdhSecretBytes.length);

        const importedKey = await window.crypto.subtle.importKey(
            'raw', combinedSecret, { name: 'HKDF' }, false, ['deriveKey']
        );

        const derivedKey = await window.crypto.subtle.deriveKey(
            { name: 'HKDF', salt: salt, info: HKDF_INFO, hash: 'SHA-256' },
            importedKey,
            { name: 'AES-GCM', length: 256 },
            false, // non-extractable
            ['encrypt', 'decrypt']
        );

        // Best-effort "menghapus" rahasia dari memori setelah tidak dipakai lagi.
        // JS tidak menjamin ini bersih 100% (engine/GC bisa saja sudah menyalinnya
        // di tempat lain), tapi ini tetap mengurangi jendela waktu rahasia mentah
        // bertahan di memori.
        combinedSecret.fill(0);
        ecdhSecretBytes.fill(0);
        kyberSecretBytes.fill(0);

        return derivedKey;
    }

    async function encryptMessage(key, plaintext) {
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encodedPlaintext = new TextEncoder().encode(plaintext);
        const ciphertext = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv }, key, encodedPlaintext
        );
        return { iv, ciphertext };
    }

    async function decryptMessage(key, iv, ciphertext) {
        const decrypted = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv }, key, ciphertext
        );
        return new TextDecoder().decode(decrypted);
    }

    // --- Key Generation Logic ---
    generateBtn.addEventListener('click', async () => {
        generateBtn.disabled = true;
        generateBtn.textContent = 'Membuat Kunci...';
        [genPublicKeyEl, genPrivateKeyEl].forEach(el => el.value = 'Harap tunggu, proses pembuatan kunci hibrida...');
        genFingerprintEl.textContent = 'Menghitung...';

        try {
            const [ecdhKeyPair, kyberKeyPair] = await Promise.all([
                generateEcdhKeys(),
                generateKyberKeys()
            ]);

            const ecdhPublicKeyJwk = await window.crypto.subtle.exportKey('jwk', ecdhKeyPair.publicKey);
            const ecdhPrivateKeyJwk = await window.crypto.subtle.exportKey('jwk', ecdhKeyPair.privateKey);

            const hybridPublicKey = {
                ecdh: ecdhPublicKeyJwk,
                kyber: arrayBufferToBase64(kyberKeyPair.publicKey)
            };
            const hybridPrivateKey = {
                ecdh: ecdhPrivateKeyJwk,
                kyber: arrayBufferToBase64(kyberKeyPair.secretKey)
            };

            genPublicKeyEl.value = JSON.stringify(hybridPublicKey, null, 2);
            genPrivateKeyEl.value = JSON.stringify(hybridPrivateKey, null, 2);
            genFingerprintEl.textContent = await computeFingerprint(ecdhKeyPair.publicKey, kyberKeyPair.publicKey);

            // Rahasia (secret key) Kyber mentah sudah tidak diperlukan lagi setelah
            // di-encode ke base64 di atas.
            kyberKeyPair.secretKey.fill(0);

        } catch (error) {
            alert(`Gagal membuat kunci: ${error.message}`);
            [genPublicKeyEl, genPrivateKeyEl].forEach(el => el.value = '');
            genFingerprintEl.textContent = 'Buat kunci untuk melihat fingerprint...';
        } finally {
            generateBtn.disabled = false;
            generateBtn.textContent = 'Buat Pasangan Kunci Hibrida Baru';
        }
    });

    // --- Live Fingerprint Preview saat Kunci Publik Penerima Ditempel ---
    publicKeyEl.addEventListener('input', async () => {
        const raw = publicKeyEl.value.trim();
        if (!raw) {
            recipientFingerprintEl.textContent = '—';
            return;
        }
        try {
            const parsed = JSON.parse(raw);
            const ecdhKey = await window.crypto.subtle.importKey(
                'jwk', parsed.ecdh, { name: "ECDH", namedCurve: "P-384" }, true, []
            );
            const kyberBytes = base64ToUint8Array(parsed.kyber);
            recipientFingerprintEl.textContent = await computeFingerprint(ecdhKey, kyberBytes);
        } catch (error) {
            recipientFingerprintEl.textContent = '—';
        }
    });

    // --- Encryption Logic ---
    encryptBtn.addEventListener('click', async () => {
        const recipientPublicKeysJSON = publicKeyEl.value.trim();
        const plainText = plainTextEl.value;
        if (!recipientPublicKeysJSON || !plainText) {
            alert('Harap isi Kunci Publik Hibrida penerima dan Teks Biasa.');
            return;
        }

        try {
            const recipientPublicKeys = JSON.parse(recipientPublicKeysJSON);
            const recipientEcdhPublicKey = await window.crypto.subtle.importKey(
                'jwk', recipientPublicKeys.ecdh, { name: "ECDH", namedCurve: "P-384" }, true, []
            );
            const recipientKyberPublicKey = base64ToUint8Array(recipientPublicKeys.kyber);

            const senderEcdhKeyPair = await generateEcdhKeys();

            const ecdhSecretBits = await window.crypto.subtle.deriveBits(
                { name: "ECDH", public: recipientEcdhPublicKey },
                senderEcdhKeyPair.privateKey,
                384 // panjang penuh rahasia bersama P-384 (bit) - tidak dipotong
            );
            const ecdhSecretBytes = new Uint8Array(ecdhSecretBits);

            const { cipherText: kyberCipherText, sharedSecret: kyberSharedSecret } = ml_kem768.encapsulate(recipientKyberPublicKey);

            const salt = window.crypto.getRandomValues(new Uint8Array(32));
            const hybridKey = await deriveHybridKey(ecdhSecretBytes, kyberSharedSecret, salt);

            const { iv, ciphertext } = await encryptMessage(hybridKey, plainText);

            const senderEcdhPublicKeyJwk = await window.crypto.subtle.exportKey('jwk', senderEcdhKeyPair.publicKey);
            const payload = {
                version: PROTOCOL_VERSION,
                senderEcdhPublicKey: senderEcdhPublicKeyJwk,
                kyberCipherText: arrayBufferToBase64(kyberCipherText),
                salt: arrayBufferToBase64(salt),
                iv: arrayBufferToBase64(iv),
                ciphertext: arrayBufferToBase64(ciphertext)
            };
            
            encryptedTextEl.value = btoa(JSON.stringify(payload));

        } catch (error) {
            alert(`Terjadi kesalahan saat enkripsi: ${error.message}`);
            encryptedTextEl.value = '';
        }
    });
    
    // --- Decryption Logic ---
    decryptBtn.addEventListener('click', async () => {
        const privateKeysJSON = privateKeyEl.value.trim();
        const encryptedPayloadB64 = cipherTextEl.value.trim();
        if (!privateKeysJSON || !encryptedPayloadB64) {
            alert('Harap isi Kunci Privat Hibrida Anda dan Ciphertext.');
            return;
        }
        decryptedTextEl.value = '';

        try {
            const privateKeys = JSON.parse(privateKeysJSON);
            const recipientEcdhPrivateKey = await window.crypto.subtle.importKey(
                'jwk', privateKeys.ecdh, { name: "ECDH", namedCurve: "P-384" }, true, ["deriveBits"]
            );
            const recipientKyberPrivateKey = base64ToUint8Array(privateKeys.kyber);

            const payload = JSON.parse(atob(encryptedPayloadB64));

            if (payload.version !== PROTOCOL_VERSION) {
                throw new Error('Format ciphertext tidak dikenali (kemungkinan dibuat oleh versi protokol yang lebih lama).');
            }

            const senderEcdhPublicKey = await window.crypto.subtle.importKey(
                'jwk', payload.senderEcdhPublicKey, { name: "ECDH", namedCurve: "P-384" }, true, []
            );
            const kyberCipherText = base64ToUint8Array(payload.kyberCipherText);
            const salt = base64ToUint8Array(payload.salt);
            const iv = base64ToUint8Array(payload.iv);
            const ciphertext = base64ToUint8Array(payload.ciphertext);

            const ecdhSecretBits = await window.crypto.subtle.deriveBits(
                { name: "ECDH", public: senderEcdhPublicKey },
                recipientEcdhPrivateKey,
                384
            );
            const ecdhSecretBytes = new Uint8Array(ecdhSecretBits);
            
            const kyberSharedSecret = ml_kem768.decapsulate(kyberCipherText, recipientKyberPrivateKey);

            const hybridKey = await deriveHybridKey(ecdhSecretBytes, kyberSharedSecret, salt);

            const decryptedText = await decryptMessage(hybridKey, iv, ciphertext);

            decryptedTextEl.value = decryptedText;

        } catch (error) {
            decryptedTextEl.value = `ERROR: ${error.message}. Pastikan Kunci Privat dan Ciphertext valid.`;
        }
    });

    // --- Setup all Copy Buttons ---
    setupCopyButton(copyGenPublicBtn, genPublicKeyEl);
    setupCopyButton(copyGenPrivateBtn, genPrivateKeyEl);
    setupCopyButton(copyEncryptedBtn, encryptedTextEl);
    setupCopyButton(copyDecryptedBtn, decryptedTextEl);
});
