// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2019 The MMapper Authors

#include "WasmInputDeduplicateFilter.h"

#include <QEvent>
#include <QInputMethodEvent>
#include <QKeyEvent>

WasmInputDeduplicateFilter::~WasmInputDeduplicateFilter() = default;

bool WasmInputDeduplicateFilter::eventFilter(QObject *obj, QEvent *event)
{
    // Qt WASM fires both KeyPress AND InputMethod events for the same keystroke,
    // causing double character insertion.  We suppress the second event of each
    // pair by remembering which event *type* produced the character.  A duplicate
    // is only suppressed when the same text arrives from a *different* event type
    // (the hallmark of the Qt WASM bug).  Two consecutive events of the *same*
    // type with the same text are legitimate repeat keypresses.
    if (event->type() == QEvent::KeyPress) {
        auto *ke = static_cast<QKeyEvent *>(event);
        const QString text = ke->text();
        if (!text.isEmpty() && text.at(0).isPrint()) {
            if (m_lastType == QEvent::InputMethod && m_lastText == text) {
                m_lastType = QEvent::None;
                m_lastText.clear();
                return true; // suppress duplicate from different event type
            }
            m_lastText = text;
            m_lastType = QEvent::KeyPress;
        } else {
            m_lastType = QEvent::None;
            m_lastText.clear();
        }
    } else if (event->type() == QEvent::InputMethod) {
        auto *ime = static_cast<QInputMethodEvent *>(event);
        const QString commit = ime->commitString();
        if (!commit.isEmpty()) {
            if (m_lastType == QEvent::KeyPress && m_lastText == commit) {
                m_lastType = QEvent::None;
                m_lastText.clear();
                return true; // suppress duplicate from different event type
            }
            m_lastText = commit;
            m_lastType = QEvent::InputMethod;
        }
    }
    return QObject::eventFilter(obj, event);
}
