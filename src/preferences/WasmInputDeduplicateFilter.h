#pragma once
// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2019 The MMapper Authors

#include <QObject>
#include <QString>

// Workaround for Qt WASM double character input bug.
// Qt's WASM platform plugin generates both a QKeyEvent (from JS keydown)
// and a QInputMethodEvent (from the hidden <input> element's input method
// context) for each keystroke. Both events insert the same character into
// the QLineEdit, causing every character to appear twice.
// Fix: allow the first insertion event and suppress the duplicate.
class WasmInputDeduplicateFilter final : public QObject
{
public:
    using QObject::QObject;
    ~WasmInputDeduplicateFilter() override;

protected:
    bool eventFilter(QObject *obj, QEvent *event) override;

private:
    QString m_lastText;
    bool m_suppressDuplicate = false;
};
