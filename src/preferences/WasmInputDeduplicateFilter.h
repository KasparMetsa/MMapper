#pragma once
// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2019 The MMapper Authors

#include <QEvent>
#include <QObject>
#include <QString>

// Workaround for Qt WASM double character input bug.
// Qt's WASM platform plugin generates both a QKeyEvent (from JS keydown)
// and a QInputMethodEvent (from the hidden <input> element's input method
// context) for each keystroke. Both events insert the same character into
// the QLineEdit, causing every character to appear twice.
// Fix: suppress a character only when the same text arrives from a
// *different* event type (KeyPress vs InputMethod), which is the hallmark
// of the Qt WASM double-fire bug.  Two same-type events with the same
// text (e.g. pressing "e" twice) are legitimate and pass through.
class WasmInputDeduplicateFilter final : public QObject
{
public:
    using QObject::QObject;
    ~WasmInputDeduplicateFilter() override;

protected:
    bool eventFilter(QObject *obj, QEvent *event) override;

private:
    QString m_lastText;
    QEvent::Type m_lastType = QEvent::None;
};
