/*
 * Rapid Analysis QEMU System Emulator
 *
 * Copyright (c) 2020 Cromulence LLC
 *
 * Distribution Statement A
 *
 * Approved for Public Release, Distribution Unlimited
 *
 * Authors:
 *  Joseph Walker
 *
 * The creation of this code was funded by the US Government. Use of this code for any
 * purpose other than those authorized by the funding US Government may be subject to restrictions.
 * 
 * Neither party is granted any right or license other than the existing licenses
 * and covenants expressly stated herein. Cromulence LLC retains all right, title and interest to
 * Reference Code and Technology Specifications and You retain all right, title and interest
 * in Your Modifications and associated specifications as permitted by the existing license.
 * Except as expressly permitted herein, You must not otherwise use any package, class or
 * interface naming conventions that appear to originate from Original Contributor.
 */

#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QString>
#include <QMainWindow>
#include <QWidget>
#include <QDockWidget>
#include <QLabel>
#include <QTabWidget>

#include "QConsole.h"
#include "QFrameBufferDisplay.h"

/**
 * 
 */
class MainWindow: public QMainWindow
{
    Q_OBJECT

public:
    /**
     * 
     * 
     * @param parent
     * @param flags
     */
    MainWindow(QWidget *parent = nullptr, Qt::WindowFlags flags = Qt::WindowFlags());

    /**
     * 
     */
    ~MainWindow();

    /**
     * 
     * 
     * @return
     */
    QFrameBufferDisplay *getFrameBufferDisplay() { return this->guestDisplay; }

    /**
     * 
     * 
     * @param event
     */
    virtual void closeEvent (QCloseEvent *event);

    /**
     * 
     * 
     * @param errorString
     */
    void showCriticalError(QString errorString);

public slots:

    /**
     * 
     * 
     * @param event
     */
    void guestKeyPress(QKeyEvent *event, bool keyDown);

private:

    QFrameBufferDisplay *guestDisplay;
    QConsole            *console;

};

#endif