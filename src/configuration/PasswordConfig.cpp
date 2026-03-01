// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2019 The MMapper Authors

#include "PasswordConfig.h"

#include "../global/macros.h"

#ifdef Q_OS_WASM
#include <cstdlib>
#include <emscripten.h>

// clang-format off

// Store a password encrypted with AES-GCM-256 in IndexedDB.
// Generates a new CryptoKey on every save, exports the raw key bytes for
// storage. We store raw bytes (not the CryptoKey object) because Firefox
// throws DataCloneError when serializing non-extractable CryptoKey objects
// into IndexedDB via structured clone.
//
// Note: storing the raw key alongside the ciphertext means any same-origin JS
// can decrypt. This is a deliberate trade-off — Firefox throws DataCloneError
// when storing non-extractable CryptoKey objects in IndexedDB, and browser-
// specific code paths proved unreliable. The encryption provides data-at-rest
// protection and defense against accidental plaintext exposure in logs/UI.
//
// Fire-and-forget: uses EM_JS (not EM_ASYNC_JS) so the C++ call returns
// immediately without suspending the ASYNCIFY stack. The actual encrypt +
// IndexedDB write runs asynchronously in a JS promise chain. This prevents
// the Qt event loop from being blocked during saves, which was causing
// dropped keystrokes when typing fast.
EM_JS(void, wasm_store_password, (const char *key, const char *password), {
    var keyStr = UTF8ToString(key);
    var passwordStr = UTF8ToString(password);

    if (!Module._passwordSaveQueue) Module._passwordSaveQueue = Promise.resolve();
    Module._passwordSaveQueue = Module._passwordSaveQueue.then(async function() {
        try {
            var cryptoKey = await crypto.subtle.generateKey(
                { name: "AES-GCM", length: 256 },
                true,
                ["encrypt", "decrypt"]
            );

            var iv = crypto.getRandomValues(new Uint8Array(12));
            var encoded = new TextEncoder().encode(passwordStr);
            var ciphertext = await crypto.subtle.encrypt(
                { name: "AES-GCM", iv: iv },
                cryptoKey,
                encoded
            );

            var rawKey = new Uint8Array(await crypto.subtle.exportKey("raw", cryptoKey));

            var db = await new Promise(function(resolve, reject) {
                var req = indexedDB.open("mmapper-credentials", 1);
                req.onupgradeneeded = function() {
                    var db2 = req.result;
                    if (!db2.objectStoreNames.contains("passwords")) {
                        db2.createObjectStore("passwords");
                    }
                };
                req.onsuccess = function() { resolve(req.result); };
                req.onerror = function() { reject(req.error); };
            });

            await new Promise(function(resolve, reject) {
                var tx = db.transaction("passwords", "readwrite");
                var store = tx.objectStore("passwords");
                store.put({ rawKey: rawKey, iv: iv, ciphertext: new Uint8Array(ciphertext) }, keyStr);
                tx.oncomplete = function() { resolve(); };
                tx.onerror = function() { reject(tx.error); };
            });

            db.close();
        } catch (e) {
            console.error("wasm_store_password error:", e);
        }
    });
});

// Read and decrypt a password from IndexedDB.
// Returns a malloc'd UTF-8 string on success (may be empty if no password is stored),
// or NULL on error. Caller must free() the returned pointer.
EM_ASYNC_JS(char *, wasm_read_password, (const char *key), {
    try {
        const keyStr = UTF8ToString(key);

        const db = await new Promise((resolve, reject) => {
            const req = indexedDB.open("mmapper-credentials", 1);
            req.onupgradeneeded = () => {
                const db = req.result;
                if (!db.objectStoreNames.contains("passwords")) {
                    db.createObjectStore("passwords");
                }
            };
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => reject(req.error);
        });

        const record = await new Promise((resolve, reject) => {
            const tx = db.transaction("passwords", "readonly");
            const store = tx.objectStore("passwords");
            const getReq = store.get(keyStr);
            getReq.onsuccess = () => resolve(getReq.result);
            getReq.onerror = () => reject(getReq.error);
        });

        db.close();

        if (!record) {
            var emptyPtr = _malloc(1);
            HEAPU8[emptyPtr] = 0;
            return emptyPtr; // not found — empty string, not an error
        }

        // Import raw key bytes back into a CryptoKey for decryption.
        const cryptoKey = await crypto.subtle.importKey(
            "raw",
            record.rawKey,
            { name: "AES-GCM" },
            false, // non-extractable for decryption use
            ["decrypt"]
        );

        const decrypted = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: record.iv },
            cryptoKey,
            record.ciphertext
        );

        const password = new TextDecoder().decode(decrypted);
        const len = lengthBytesUTF8(password) + 1;
        const ptr = _malloc(len);
        stringToUTF8(password, ptr, len);
        return ptr;
    } catch (e) {
        console.error("wasm_read_password error:", e);
        return 0;
    }
});

// Delete a password entry from IndexedDB.
// Fire-and-forget: shares the same promise chain as wasm_store_password
// to prevent a delete from racing with an in-flight store.
EM_JS(void, wasm_delete_password, (const char *key), {
    var keyStr = UTF8ToString(key);

    if (!Module._passwordSaveQueue) Module._passwordSaveQueue = Promise.resolve();
    Module._passwordSaveQueue = Module._passwordSaveQueue.then(async function() {
        try {
            var db = await new Promise(function(resolve, reject) {
                var req = indexedDB.open("mmapper-credentials", 1);
                req.onupgradeneeded = function() {
                    var db2 = req.result;
                    if (!db2.objectStoreNames.contains("passwords")) {
                        db2.createObjectStore("passwords");
                    }
                };
                req.onsuccess = function() { resolve(req.result); };
                req.onerror = function() { reject(req.error); };
            });

            await new Promise(function(resolve, reject) {
                var tx = db.transaction("passwords", "readwrite");
                var store = tx.objectStore("passwords");
                store["delete"](keyStr);
                tx.oncomplete = function() { resolve(); };
                tx.onerror = function() { reject(tx.error); };
            });

            db.close();
        } catch (e) {
            console.error("wasm_delete_password error:", e);
        }
    });
});
// clang-format on

static const char *const WASM_PASSWORD_KEY = "password";

#elif !defined(MMAPPER_NO_QTKEYCHAIN)
static const QLatin1String PASSWORD_KEY("password");
static const QLatin1String APP_NAME("org.mume.mmapper");
#endif

PasswordConfig::PasswordConfig(QObject *const parent)
    : QObject(parent)
#if !defined(Q_OS_WASM) && !defined(MMAPPER_NO_QTKEYCHAIN)
    , m_readJob(APP_NAME)
    , m_writeJob(APP_NAME)
{
    m_readJob.setAutoDelete(false);
    m_writeJob.setAutoDelete(false);

    connect(&m_readJob, &QKeychain::ReadPasswordJob::finished, [this]() {
        if (m_readJob.error()) {
            emit sig_error(m_readJob.errorString());
        } else {
            emit sig_incomingPassword(m_readJob.textData());
        }
    });

    connect(&m_writeJob, &QKeychain::WritePasswordJob::finished, [this]() {
        if (m_writeJob.error()) {
            emit sig_error(m_writeJob.errorString());
        }
    });
}
#else
{
}
#endif

void PasswordConfig::setPassword(const QString &password)
{
#ifdef Q_OS_WASM
    // Fire-and-forget: save runs asynchronously in JS without blocking the event loop.
    // Errors are logged to the browser console.
    const QByteArray utf8 = password.toUtf8();
    wasm_store_password(WASM_PASSWORD_KEY, utf8.constData());
#elif !defined(MMAPPER_NO_QTKEYCHAIN)
    m_writeJob.setKey(PASSWORD_KEY);
    m_writeJob.setTextData(password);
    m_writeJob.start();
#else
    std::ignore = password;
    emit sig_error("Password setting is not available.");
#endif
}

void PasswordConfig::getPassword()
{
#ifdef Q_OS_WASM
    char *password = wasm_read_password(WASM_PASSWORD_KEY);
    if (!password) {
        emit sig_error("Failed to retrieve password from browser storage.");
    } else if (password[0] == '\0') {
        // Not found — no password stored yet. Silent, not an error.
        free(password);
    } else {
        emit sig_incomingPassword(QString::fromUtf8(password));
        free(password);
    }
#elif !defined(MMAPPER_NO_QTKEYCHAIN)
    m_readJob.setKey(PASSWORD_KEY);
    m_readJob.start();
#else
    emit sig_error("Password retrieval is not available.");
#endif
}

void PasswordConfig::deletePassword()
{
#ifdef Q_OS_WASM
    wasm_delete_password(WASM_PASSWORD_KEY);
#elif !defined(MMAPPER_NO_QTKEYCHAIN)
    // QtKeychain delete job (fire and forget)
    auto *deleteJob = new QKeychain::DeletePasswordJob(APP_NAME);
    deleteJob->setAutoDelete(true);
    deleteJob->setKey(PASSWORD_KEY);
    connect(deleteJob, &QKeychain::DeletePasswordJob::finished, [this, deleteJob]() {
        if (deleteJob->error()) {
            emit sig_error(deleteJob->errorString());
        }
    });
    deleteJob->start();
#else
    emit sig_error("Password deletion is not available.");
#endif
}
