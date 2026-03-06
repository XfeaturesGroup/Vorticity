const bufferToBase64 = (buffer) => {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
};

const base64ToBuffer = (base64) => {
    const binaryString = window.atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
};

export const generateKeyPair = async () => {
    return await window.crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveKey"]
    );
};

export const exportPublicKey = async (publicKey) => {
    const jwk = await window.crypto.subtle.exportKey("jwk", publicKey);
    return JSON.stringify(jwk);
};

export const importPublicKey = async (jwkString) => {
    const jwk = JSON.parse(jwkString);
    return await window.crypto.subtle.importKey(
        "jwk",
        jwk,
        { name: "ECDH", namedCurve: "P-256" },
        true,
        []
    );
};

export const deriveEncryptionKey = async (privateKey, publicKey) => {
    return await window.crypto.subtle.deriveKey(
        { name: "ECDH", public: publicKey },
        privateKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
};

export const encryptMessage = async (key, text) => {
    const encodedText = new TextEncoder().encode(text);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encodedText
    );

    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(encrypted), iv.length);

    return bufferToBase64(combined);
};

export const decryptMessage = async (key, encryptedBase64) => {
    try {
        const combined = base64ToBuffer(encryptedBase64);
        const iv = combined.slice(0, 12);
        const data = combined.slice(12);

        const decrypted = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            data
        );
        return new TextDecoder().decode(decrypted);
    } catch (e) {
        console.error("Ошибка расшифровки сообщения:", e);
        return "[Ошибка расшифровки]";
    }
};

export const deriveKeyFromPassword = async (password, salt) => {
    const encoder = new TextEncoder();
    const passwordData = encoder.encode(password);
    const baseKey = await window.crypto.subtle.importKey("raw", passwordData, "PBKDF2", false, ["deriveKey"]);
    return await window.crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: salt, iterations: 100000, hash: "SHA-256" },
        baseKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
};

export const encryptPrivateKeyForCloud = async (privateKey, password, saltText) => {
    const salt = new TextEncoder().encode(saltText);
    const encryptionKey = await deriveKeyFromPassword(password, salt);

    const exportedKey = await window.crypto.subtle.exportKey("jwk", privateKey);
    const keyData = new TextEncoder().encode(JSON.stringify(exportedKey));

    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, encryptionKey, keyData);

    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(encrypted), iv.length);

    return bufferToBase64(combined);
};

export const decryptPrivateKeyFromCloud = async (encryptedData, password, saltText) => {
    try {
        const salt = new TextEncoder().encode(saltText);
        const encryptionKey = await deriveKeyFromPassword(password, salt);

        const combined = base64ToBuffer(encryptedData);
        const iv = combined.slice(0, 12);
        const data = combined.slice(12);

        const decrypted = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, encryptionKey, data);
        const jwk = JSON.parse(new TextDecoder().decode(decrypted));

        return await window.crypto.subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey"]);
    } catch (e) {
        console.error("Ошибка расшифровки ключа из облака (возможно, неверный пароль):", e);
        return null;
    }
};

const openDB = () => {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open('VorticityKeys', 1);
        req.onupgradeneeded = (e) => {
            const db = e.target.result;
            if (!db.objectStoreNames.contains('keys')) db.createObjectStore('keys', { keyPath: 'userId' });
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
};

export const savePrivateKey = async (userId, privateKey) => {
    const db = await openDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction('keys', 'readwrite');
        tx.objectStore('keys').put({ userId, privateKey });
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
    });
};

export const getPrivateKey = async (userId) => {
    const db = await openDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction('keys', 'readonly');
        const req = tx.objectStore('keys').get(userId);
        req.onsuccess = () => resolve(req.result?.privateKey || null);
        req.onerror = () => reject(req.error);
    });
};