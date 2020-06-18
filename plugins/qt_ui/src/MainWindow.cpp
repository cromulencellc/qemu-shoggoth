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

#include "MainWindow.h"   
#include "AppStrings.h" 
#include "QEMUWrapper.h"

#include <QLineEdit>
#include <QMessageBox>
#include <QVBoxLayout>
#include <iostream>

MainWindow::MainWindow(QWidget *parent, Qt::WindowFlags flags):
   QMainWindow(parent, flags)
{
    this->setWindowIcon(QIcon(":logo.svg"));
    this->setWindowTitle(getString("app_name", "QEMU"));
    //this->setDockOptions();

    // TODO: This should become a console widget
    QDockWidget *dock = new QDockWidget(getString("console_name", "Console"), 
                                        this);
    dock->setAllowedAreas(Qt::LeftDockWidgetArea | 
                          Qt::RightDockWidgetArea | 
                          Qt::BottomDockWidgetArea);
    dock->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    this->console = new QConsole(dock);
    dock->setWidget(this->console);
    this->addDockWidget(Qt::BottomDockWidgetArea, dock);

    this->setCentralWidget(new QWidget(this));
    this->guestDisplay = new QFrameBufferDisplay(new QImage(":logo-128x128.png"), 
                                                 this->centralWidget());

    QVBoxLayout* layout = new QVBoxLayout();
    layout->addWidget(this->guestDisplay);
    this->centralWidget()->setLayout(layout);;
    
    QObject::connect(this->guestDisplay, &QFrameBufferDisplay::keyPress, this, &MainWindow::guestKeyPress);
}

MainWindow::~MainWindow()
{

}

void MainWindow::guestKeyPress(QKeyEvent *event, bool keyDown)
{
    int code = event->nativeScanCode();
    QEMU_process_key_event(code, keyDown);
}

void MainWindow::closeEvent (QCloseEvent *event)
{
    QEMU_do_shutdown();
    event->accept();
}

void MainWindow::showCriticalError(QString errorString)
{
    QMessageBox::critical(this, 
                          QString("Critical Error"), 
                          errorString);
    QEMU_do_shutdown();
}