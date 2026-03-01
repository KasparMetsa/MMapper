// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2019 The MMapper Authors

#include "TestWasmInputFilter.h"

#include "../src/preferences/WasmInputDeduplicateFilter.h"

#include <QCoreApplication>
#include <QInputMethodEvent>
#include <QKeyEvent>
#include <QLineEdit>
#include <QtTest/QtTest>

TestWasmInputFilter::TestWasmInputFilter() = default;
TestWasmInputFilter::~TestWasmInputFilter() = default;

// Helper: send a printable KeyPress and return whether the filter suppressed it.
static bool sendKeyPress(QLineEdit &target, const QChar ch)
{
    QKeyEvent ev(QEvent::KeyPress, 0, Qt::NoModifier, QString(ch));
    return QCoreApplication::sendEvent(&target, &ev);
}

// Helper: send an InputMethodEvent with a commit string and return whether
// the filter suppressed it.
static bool sendInputMethod(QLineEdit &target, const QString &commit)
{
    QInputMethodEvent ev(QString(), {});
    ev.setCommitString(commit);
    return QCoreApplication::sendEvent(&target, &ev);
}

void TestWasmInputFilter::testSingleKeypressPassesThrough()
{
    QLineEdit edit;
    auto *filter = new WasmInputDeduplicateFilter(&edit);
    edit.installEventFilter(filter);

    // A single printable key should not be suppressed — the widget processes it.
    const bool accepted = sendKeyPress(edit, QChar('a'));
    // sendEvent returns true when the event is accepted by the target (QLineEdit
    // accepts key events). The filter must NOT have blocked it (returned true from
    // eventFilter), so QLineEdit still processes it.  We verify the character
    // actually reached the widget.
    Q_UNUSED(accepted);
    QCOMPARE(edit.text(), QString("a"));
}

void TestWasmInputFilter::testDuplicateKeypressAndInputMethodSuppressed()
{
    QLineEdit edit;
    auto *filter = new WasmInputDeduplicateFilter(&edit);
    edit.installEventFilter(filter);

    // Simulate Chrome-style duplicate: KeyPress "a" then InputMethod "a".
    sendKeyPress(edit, QChar('a'));
    QCOMPARE(edit.text(), QString("a"));

    sendInputMethod(edit, QStringLiteral("a"));
    // The duplicate InputMethod event should have been suppressed — text stays "a".
    QCOMPARE(edit.text(), QString("a"));
}

void TestWasmInputFilter::testDuplicateInputMethodAndKeypressSuppressed()
{
    QLineEdit edit;
    auto *filter = new WasmInputDeduplicateFilter(&edit);
    edit.installEventFilter(filter);

    // Reversed order: InputMethod "a" then KeyPress "a".
    sendInputMethod(edit, QStringLiteral("a"));
    QCOMPARE(edit.text(), QString("a"));

    sendKeyPress(edit, QChar('a'));
    // The duplicate KeyPress should have been suppressed — text stays "a".
    QCOMPARE(edit.text(), QString("a"));
}

void TestWasmInputFilter::testDifferentCharsNotSuppressed()
{
    QLineEdit edit;
    auto *filter = new WasmInputDeduplicateFilter(&edit);
    edit.installEventFilter(filter);

    // Two different characters should both pass through.
    sendKeyPress(edit, QChar('a'));
    QCOMPARE(edit.text(), QString("a"));

    sendInputMethod(edit, QStringLiteral("b"));
    QCOMPARE(edit.text(), QString("ab"));
}

void TestWasmInputFilter::testRepeatedSameCharNotSuppressed()
{
    QLineEdit edit;
    auto *filter = new WasmInputDeduplicateFilter(&edit);
    edit.installEventFilter(filter);

    // Typing "ee" — each keystroke produces KeyPress + InputMethod (Qt WASM bug).
    // The InputMethod duplicate of each pair should be suppressed, but the second
    // legitimate "e" keystroke must NOT be suppressed.

    // First "e": KeyPress passes, InputMethod suppressed
    sendKeyPress(edit, QChar('e'));
    QCOMPARE(edit.text(), QString("e"));
    sendInputMethod(edit, QStringLiteral("e"));
    QCOMPARE(edit.text(), QString("e")); // duplicate suppressed

    // Second "e": KeyPress must pass through (legitimate repeat), InputMethod suppressed
    sendKeyPress(edit, QChar('e'));
    QCOMPARE(edit.text(), QString("ee"));
    sendInputMethod(edit, QStringLiteral("e"));
    QCOMPARE(edit.text(), QString("ee")); // duplicate suppressed
}

void TestWasmInputFilter::testNonPrintableResetsState()
{
    QLineEdit edit;
    auto *filter = new WasmInputDeduplicateFilter(&edit);
    edit.installEventFilter(filter);

    // Type "a", then Backspace (non-printable resets state), then InputMethod "a".
    sendKeyPress(edit, QChar('a'));
    QCOMPARE(edit.text(), QString("a"));

    // Send Backspace — non-printable, resets the dedup state.
    QKeyEvent backspace(QEvent::KeyPress, Qt::Key_Backspace, Qt::NoModifier);
    QCoreApplication::sendEvent(&edit, &backspace);
    QCOMPARE(edit.text(), QString());

    // Now InputMethod "a" should NOT be suppressed because state was reset.
    sendInputMethod(edit, QStringLiteral("a"));
    QCOMPARE(edit.text(), QString("a"));
}

QTEST_MAIN(TestWasmInputFilter)
