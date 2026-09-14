// Q-EKH Protocol v2 — enkripsi hibrida pasca-kuantum TERAUTENTIKASI.
//
// Enkripsi/kesepakatan kunci : X25519 + ML-KEM-768 lewat kombinator X-Wing
//   (draft-connolly-cfrg-xwing-kem) — dipakai langsung dari pustaka, bukan
//   digabung manual, supaya kombinasi ECC+PQC-nya mengikuti desain yang
//   sudah dipublikasikan dan dianalisis, bukan racikan sendiri.
// Tanda tangan (autentikasi) : Ed25519 (klasik, cepat) + SLH-DSA-SHA2-192s
//   (berbasis hash, PQ) — DUA tanda tangan sekaligus, keduanya harus valid.
//   Fondasi matematikanya sengaja beda dari ML-KEM (lattice), jadi lapisan
//   tanda tangan tetap aman walau suatu saat kriptografi lattice ada celah.
// Enkripsi pesan : AES-256-GCM, kunci diturunkan lewat HKDF-SHA256 dengan
//   salt acak per pesan.
//
// Catatan jujur: @noble/post-quantum baru "self-audited" (diaudit pembuatnya
// sendiri per v0.6.1, bukan audit pihak ketiga independen), dan tidak
// mengklaim constant-time di JS murni. Wajar untuk proyek pribadi/edukasi,
// tapi bukan pengganti pustaka bersertifikasi untuk kebutuhan berisiko tinggi.
import { ml_kem768_x25519 as XWing } from 'https://esm.sh/@noble/post-quantum@0.7.0/hybrid.js';
import { slh_dsa_sha2_192s } from 'https://esm.sh/@noble/post-quantum@0.7.0/slh-dsa.js';

document.addEventListener('DOMContentLoaded', () => {

    // --- DOM Element Selection ---
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

    const PROTOCOL_VERSION = 'QEKH-v2';
    const HKDF_INFO = new TextEncoder().encode('QEKH-v2-XWing-HKDF');

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
        const chunkSize = 0x8000; // 32KB per chunk, hindari batas argumen fungsi
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
    //             CRYPTO LOGIC (X-WING + TANDA TANGAN GANDA)
    // ===================================================================

    async function generateSigningKeys() {
        const ed25519KeyPair = await window.crypto.subtle.generateKey(
            { name: 'Ed25519' }, true, ['sign', 'verify']
        );
        const slhKeys = slh_dsa_sha2_192s.keygen();
        return { ed25519KeyPair, slhKeys };
    }

    // Fingerprint dihitung dari byte mentah ketiga kunci publik (X-Wing, Ed25519,
    // SLH-DSA) sekaligus, supaya mengikat seluruh identitas — bukan cuma sebagian.
    async function computeFingerprint(xwingPkBytes, ed25519PkBytes, slhdsaPkBytes) {
        const combined = concatBytes(xwingPkBytes, ed25519PkBytes, slhdsaPkBytes);
        const hashBuffer = await window.crypto.subtle.digest('SHA-256', combined);
        const hex = Array.from(new Uint8Array(hashBuffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('')
            .toUpperCase();
        return hex.match(/.{1,4}/g).join(' ');
    }

    async function deriveEncryptionKey(xwingSharedSecret, salt) {
        const importedKey = await window.crypto.subtle.importKey(
            'raw', xwingSharedSecret, { name: 'HKDF' }, false, ['deriveKey']
        );
        const derivedKey = await window.crypto.subtle.deriveKey(
            { name: 'HKDF', salt: salt, info: HKDF_INFO, hash: 'SHA-256' },
            importedKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
        // Best-effort: hapus rahasia mentah dari memori begitu tidak diperlukan lagi.
        xwingSharedSecret.fill(0);
        return derivedKey;
    }

    // Byte yang ditandatangani = identitas protokol + semua komponen ciphertext.
    // Harus dibangun IDENTIK di sisi kirim maupun terima, dalam urutan yang sama.
    function buildSignablePayload(xwingCipherText, salt, iv, ciphertext) {
        return concatBytes(
            new TextEncoder().encode(PROTOCOL_VERSION),
            xwingCipherText,
            salt,
            iv,
            ciphertext
        );
    }

    async function encryptMessage(key, plaintext) {
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encodedPlaintext = new TextEncoder().encode(plaintext);
        const ciphertext = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv }, key, encodedPlaintext
        );
        return { iv, ciphertext: new Uint8Array(ciphertext) };
    }

    async function decryptMessage(key, iv, ciphertext) {
        const decrypted = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv }, key, ciphertext
        );
        return new TextDecoder().decode(decrypted);
    }

    // --- Key Generation ---
    generateBtn.addEventListener('click', async () => {
        generateBtn.disabled = true;
        generateBtn.textContent = 'Membuat Kunci...';
        [genPublicKeyEl, genPrivateKeyEl].forEach(el => el.value = 'Harap tunggu, membuat 3 pasang kunci (X-Wing, Ed25519, SLH-DSA)...');
        genFingerprintEl.textContent = 'Menghitung...';

        try {
            const xwingKeys = XWing.keygen();
            const { ed25519KeyPair, slhKeys } = await generateSigningKeys();

            const ed25519PublicRaw = new Uint8Array(await window.crypto.subtle.exportKey('raw', ed25519KeyPair.publicKey));
            const ed25519PrivatePkcs8 = new Uint8Array(await window.crypto.subtle.exportKey('pkcs8', ed25519KeyPair.privateKey));

            const hybridPublicKey = {
                xwing: arrayBufferToBase64(xwingKeys.publicKey),
                ed25519: arrayBufferToBase64(ed25519PublicRaw),
                slhdsa: arrayBufferToBase64(slhKeys.publicKey)
            };
            const hybridPrivateKey = {
                xwing: arrayBufferToBase64(xwingKeys.secretKey),
                ed25519: arrayBufferToBase64(ed25519PrivatePkcs8),
                slhdsa: arrayBufferToBase64(slhKeys.secretKey)
            };

            genPublicKeyEl.value = JSON.stringify(hybridPublicKey, null, 2);
            genPrivateKeyEl.value = JSON.stringify(hybridPrivateKey, null, 2);
            genFingerprintEl.textContent = await computeFingerprint(xwingKeys.publicKey, ed25519PublicRaw, slhKeys.publicKey);

            // Best-effort zeroing rahasia mentah yang sudah tidak diperlukan lagi.
            xwingKeys.secretKey.fill(0);
            slhKeys.secretKey.fill(0);
            ed25519PrivatePkcs8.fill(0);

        } catch (error) {
            alert(`Gagal membuat kunci: ${error.message}`);
            [genPublicKeyEl, genPrivateKeyEl].forEach(el => el.value = '');
            genFingerprintEl.textContent = 'Buat kunci untuk melihat fingerprint...';
        } finally {
            generateBtn.disabled = false;
            generateBtn.textContent = 'Buat Pasangan Kunci Hibrida Baru';
        }
    });

    // --- Live Fingerprint Preview: kunci penerima (tab Enkripsi) ---
    publicKeyEl.addEventListener('input', async () => {
        const raw = publicKeyEl.value.trim();
        if (!raw) { recipientFingerprintEl.textContent = '—'; return; }
        try {
            const parsed = JSON.parse(raw);
            const xwingPk = base64ToUint8Array(parsed.xwing);
            const edPk = base64ToUint8Array(parsed.ed25519);
            const slhPk = base64ToUint8Array(parsed.slhdsa);
            recipientFingerprintEl.textContent = await computeFingerprint(xwingPk, edPk, slhPk);
        } catch (error) {
            recipientFingerprintEl.textContent = '—';
        }
    });

    // --- Live Fingerprint Preview: kunci pengirim (tab Dekripsi) ---
    senderVerifyKeyEl.addEventListener('input', async () => {
        const raw = senderVerifyKeyEl.value.trim();
        if (!raw) { senderVerifyFingerprintEl.textContent = '—'; return; }
        try {
            const parsed = JSON.parse(raw);
            const xwingPk = base64ToUint8Array(parsed.xwing);
            const edPk = base64ToUint8Array(parsed.ed25519);
            const slhPk = base64ToUint8Array(parsed.slhdsa);
            senderVerifyFingerprintEl.textContent = await computeFingerprint(xwingPk, edPk, slhPk);
        } catch (error) {
            senderVerifyFingerprintEl.textContent = '—';
        }
    });

    // --- Encryption + Signing ---
    encryptBtn.addEventListener('click', async () => {
        const recipientPublicKeysJSON = publicKeyEl.value.trim();
        const senderPrivateKeysJSON = senderPrivateKeyEl.value.trim();
        const plainText = plainTextEl.value;
        if (!recipientPublicKeysJSON || !senderPrivateKeysJSON || !plainText) {
            alert('Harap isi Kunci Publik penerima, Kunci Privat Anda (untuk tanda tangan), dan Teks Biasa.');
            return;
        }

        try {
            const recipientPublicKeys = JSON.parse(recipientPublicKeysJSON);
            const recipientXwingPk = base64ToUint8Array(recipientPublicKeys.xwing);

            const senderPrivateKeys = JSON.parse(senderPrivateKeysJSON);
            const senderEd25519Private = await window.crypto.subtle.importKey(
                'pkcs8', base64ToUint8Array(senderPrivateKeys.ed25519), { name: 'Ed25519' }, false, ['sign']
            );
            const senderSlhSecret = base64ToUint8Array(senderPrivateKeys.slhdsa);

            const { cipherText: xwingCipherText, sharedSecret: xwingSharedSecret } = XWing.encapsulate(recipientXwingPk);

            const salt = window.crypto.getRandomValues(new Uint8Array(32));
            const hybridKey = await deriveEncryptionKey(xwingSharedSecret, salt);
            const { iv, ciphertext } = await encryptMessage(hybridKey, plainText);

            const signablePayload = buildSignablePayload(xwingCipherText, salt, iv, ciphertext);
            const sigEd25519 = new Uint8Array(await window.crypto.subtle.sign({ name: 'Ed25519' }, senderEd25519Private, signablePayload));
            const sigSlhDsa = slh_dsa_sha2_192s.sign(signablePayload, senderSlhSecret);

            const payload = {
                version: PROTOCOL_VERSION,
                xwingCipherText: arrayBufferToBase64(xwingCipherText),
                salt: arrayBufferToBase64(salt),
                iv: arrayBufferToBase64(iv),
                ciphertext: arrayBufferToBase64(ciphertext),
                sigEd25519: arrayBufferToBase64(sigEd25519),
                sigSlhDsa: arrayBufferToBase64(sigSlhDsa)
            };

            encryptedTextEl.value = btoa(JSON.stringify(payload));

        } catch (error) {
            alert(`Terjadi kesalahan saat enkripsi/tanda tangan: ${error.message}`);
            encryptedTextEl.value = '';
        }
    });

    // --- Decryption + Verification ---
    decryptBtn.addEventListener('click', async () => {
        const privateKeysJSON = privateKeyEl.value.trim();
        const encryptedPayloadB64 = cipherTextEl.value.trim();
        if (!privateKeysJSON || !encryptedPayloadB64) {
            alert('Harap isi Kunci Privat Hibrida Anda dan Ciphertext.');
            return;
        }
        decryptedTextEl.value = '';
        verificationStatusEl.className = 'verification-status';
        verificationStatusEl.textContent = '';

        let payload, xwingCipherTextBytes, saltBytes, ivBytes, ciphertextBytes;

        try {
            const privateKeys = JSON.parse(privateKeysJSON);
            const ownXwingSecret = base64ToUint8Array(privateKeys.xwing);

            payload = JSON.parse(atob(encryptedPayloadB64));
            if (payload.version !== PROTOCOL_VERSION) {
                throw new Error('Format ciphertext tidak dikenali (kemungkinan dari versi protokol lain).');
            }
            if (!payload.sigEd25519 || !payload.sigSlhDsa) {
                throw new Error('Ciphertext ini tidak memiliki tanda tangan yang lengkap.');
            }

            xwingCipherTextBytes = base64ToUint8Array(payload.xwingCipherText);
            saltBytes = base64ToUint8Array(payload.salt);
            ivBytes = base64ToUint8Array(payload.iv);
            ciphertextBytes = base64ToUint8Array(payload.ciphertext);

            const xwingSharedSecret = XWing.decapsulate(xwingCipherTextBytes, ownXwingSecret);
            const hybridKey = await deriveEncryptionKey(xwingSharedSecret, saltBytes);
            const plaintext = await decryptMessage(hybridKey, ivBytes, ciphertextBytes);

            decryptedTextEl.value = plaintext;

        } catch (error) {
            decryptedTextEl.value = `ERROR: ${error.message}. Pastikan Kunci Privat dan Ciphertext valid.`;
            return;
        }

        // --- Verifikasi tanda tangan, terpisah dari dekripsi di atas ---
        // (kegagalan verifikasi TIDAK menyembunyikan plaintext yang sudah berhasil
        // didekripsi — cuma ditandai dengan jelas lewat status di bawah.)
        const senderPublicJSON = senderVerifyKeyEl.value.trim();
        if (!senderPublicJSON) {
            verificationStatusEl.className = 'verification-status unverified';
            verificationStatusEl.textContent = '⚠️ Tidak diverifikasi — Kunci Publik Pengirim belum diisi. Isi untuk memastikan pesan ini benar dari pengirim yang Anda kenal.';
            return;
        }

        try {
            const senderPublicKeys = JSON.parse(senderPublicJSON);
            const senderEd25519Public = await window.crypto.subtle.importKey(
                'raw', base64ToUint8Array(senderPublicKeys.ed25519), { name: 'Ed25519' }, false, ['verify']
            );
            const senderSlhPublic = base64ToUint8Array(senderPublicKeys.slhdsa);

            const signablePayload = buildSignablePayload(xwingCipherTextBytes, saltBytes, ivBytes, ciphertextBytes);
            const sigEd25519 = base64ToUint8Array(payload.sigEd25519);
            const sigSlhDsa = base64ToUint8Array(payload.sigSlhDsa);

            const edValid = await window.crypto.subtle.verify({ name: 'Ed25519' }, senderEd25519Public, sigEd25519, signablePayload);
            const slhValid = slh_dsa_sha2_192s.verify(sigSlhDsa, signablePayload, senderSlhPublic);

            if (edValid && slhValid) {
                verificationStatusEl.className = 'verification-status verified';
                verificationStatusEl.textContent = '✅ Tanda tangan valid (Ed25519 & SLH-DSA cocok) — pesan ini benar berasal dari pemegang kunci privat yang cocok dengan Kunci Publik Pengirim di atas.';
            } else {
                verificationStatusEl.className = 'verification-status failed';
                verificationStatusEl.textContent = '❌ Tanda tangan TIDAK valid. Pesan ini mungkin dipalsukan atau diubah di tengah jalan — jangan percaya isinya.';
            }
        } catch (error) {
            verificationStatusEl.className = 'verification-status failed';
            verificationStatusEl.textContent = `❌ Gagal memverifikasi tanda tangan (${error.message}).`;
        }
    });

    // --- Setup all Copy Buttons ---
    setupCopyButton(copyGenPublicBtn, genPublicKeyEl);
    setupCopyButton(copyGenPrivateBtn, genPrivateKeyEl);
    setupCopyButton(copyEncryptedBtn, encryptedTextEl);
    setupCopyButton(copyDecryptedBtn, decryptedTextEl);
});
