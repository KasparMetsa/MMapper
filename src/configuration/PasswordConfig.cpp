// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2019 The MMapper Authors

#include "PasswordConfig.h"

#include "../global/macros.h"

#ifdef Q_OS_WASM
#include <cstdlib>
#include <emscripten.h>

// clang-format off

// Store a password encrypted with AES-GCM-256 in IndexedDB.
// Generates a new non-extractable CryptoKey on every save (more secure).
// Returns 0 on success, -1 on error.
EM_ASYNC_JS(int, wasm_store_password, (const char *key, const char *password), {
    try {
        const keyStr = UTF8ToString(key);
        const passwordStr = UTF8ToString(password);

        const cryptoKey = await crypto.subtle.generateKey(
            { name: "AES-GCM", length: 256 },
            false, // non-extractable
            ["encrypt", "decrypt"]
        );

        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encoded = new TextEncoder().encode(passwordStr);
        const ciphertext = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            cryptoKey,
            encoded
        );

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

        await new Promise((resolve, reject) => {
            const tx = db.transaction("passwords", "readwrite");
            const store = tx.objectStore("passwords");
            store.put({ cryptoKey: cryptoKey, iv: iv, ciphertext: new Uint8Array(ciphertext) }, keyStr);
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        });

        db.close();
        return 0;
    } catch (e) {
        console.error("wasm_store_password error:", e);
        return -1;
    }
});

// Read and decrypt a password from IndexedDB.
// Returns a malloc'd UTF-8 string on success, or NULL on error/not found.
// Caller must free() the returned pointer.
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
            return 0; // not found
        }

        const decrypted = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: record.iv },
            record.cryptoKey,
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
// Returns 0 on success, -1 on error.
EM_ASYNC_JS(int, wasm_delete_password, (const char *key), {
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

        await new Promise((resolve, reject) => {
            const tx = db.transaction("passwords", "readwrite");
            const store = tx.objectStore("passwords");
            store.delete(keyStr);
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        });

        db.close();
        return 0;
    } catch (e) {
        console.error("wasm_delete_password error:", e);
        return -1;
    }
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
    const QByteArray utf8 = password.toUtf8();
    const int result = wasm_store_password(WASM_PASSWORD_KEY, utf8.constData());
    if (result != 0) {
        emit sig_error("Failed to store password in browser storage.");
    }
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
    if (password) {
        emit sig_incomingPassword(QString::fromUtf8(password));
        free(password);
    } else {
        emit sig_error("Failed to retrieve password from browser storage.");
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
    const int result = wasm_delete_password(WASM_PASSWORD_KEY);
    if (result != 0) {
        emit sig_error("Failed to delete password from browser storage.");
    }
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
