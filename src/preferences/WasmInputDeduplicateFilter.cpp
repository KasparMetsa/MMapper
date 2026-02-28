// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2019 The MMapper Authors

#include "WasmInputDeduplicateFilter.h"

#include <QEvent>
#include <QInputMethodEvent>
#include <QKeyEvent>

WasmInputDeduplicateFilter::~WasmInputDeduplicateFilter() = default;

bool WasmInputDeduplicateFilter::eventFilter(QObject *obj, QEvent *event)
{
    if (event->type() == QEvent::KeyPress) {
        auto *ke = static_cast<QKeyEvent *>(event);
        const QString text = ke->text();
        if (!text.isEmpty() && text.at(0).isPrint()) {
            if (m_suppressDuplicate && m_lastText == text) {
                m_suppressDuplicate = false;
                return true; // suppress duplicate insertion
            }
            m_lastText = text;
            m_suppressDuplicate = true;
        } else {
            // Non-printable key (Backspace, arrows, etc.) — reset state
            m_suppressDuplicate = false;
            m_lastText.clear();
        }
    } else if (event->type() == QEvent::InputMethod) {
        auto *ime = static_cast<QInputMethodEvent *>(event);
        const QString commit = ime->commitString();
        if (!commit.isEmpty()) {
            if (m_suppressDuplicate && m_lastText == commit) {
                m_suppressDuplicate = false;
                return true; // suppress duplicate insertion
            }
            m_lastText = commit;
            m_suppressDuplicate = true;
        }
    }
    return QObject::eventFilter(obj, event);
}
