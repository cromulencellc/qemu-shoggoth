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

#include "QtWrapper.h"

#include <cstdlib>
#include <cstring>
#include <thread>
#include <mutex>
#include <glib.h>

#include <QDesktopWidget>
#include <QApplication>
#include <QScreen>
#include "MainWindow.h"

#include <QFile>

#define NUM_ARGS  (1)
#define NAME_SIZE (100)
#define APP_NAME  "qt-view"

struct UIStruct 
{
    int              argc;
    char             **argv;
    std::thread      *uiThread;
    std::mutex       updateMutex;
    MainWindow       *window;
    QImage       *screen;
    QApplication *app;
    const guint16    *keycode_map;
    int               keycode_map_len;    
};

#include <iostream>

static UIStruct *ui = NULL;

static QImage *testImage = NULL;

UIStruct *getUI()
{
    if (!ui)
    {
        ui = (UIStruct *) ::calloc(1, sizeof(UIStruct));
        if (ui)
        {
            int argc = NUM_ARGS;
            char **argv = (char **) ::malloc(argc * sizeof(char *));
            
            *argv = (char *) ::malloc(NAME_SIZE + 1);
            ::memset(*argv, 0, NAME_SIZE + 1);
            ::snprintf(*argv, NAME_SIZE, "%s", APP_NAME);

            ui->screen = NULL;
            ui->argc = argc;
            ui->argv = argv;
            ui->app = new QApplication(ui->argc, ui->argv);

            ui->updateMutex.lock();
            ui->window = new MainWindow();
            ui->window->showNormal();
            const QSize &winsize = QApplication::screens()[0]->size();
            ui->window->resize(QSize(winsize.width()*0.5, winsize.height()*0.7));
            ui->updateMutex.unlock();

            ui->app->processEvents();
            ui->app->sendPostedEvents();
        }
    }
    return ui;
}

void deleteUI()
{
    if (ui)
    {
        ::free(ui);
    }
}

void setView(UIStruct *uiPtr, void *pixels, int height, int width)
{
    (void)(pixels);
    (void)(width);
    (void)(height);

    if (uiPtr)
    {
        uiPtr->updateMutex.lock();

        if (uiPtr->window)
        {
           uiPtr->window->getFrameBufferDisplay()->onBufferReset((uint8_t *) pixels, width, height, QImage::Format_RGB32);
           uiPtr->app->processEvents();
           uiPtr->app->sendPostedEvents();
        }

        uiPtr->updateMutex.unlock();        
    }
    else
    {
        //This is an error case
    }
}

void updateView(UIStruct *uiPtr, int x, int y, int width, int height)
{
    if (uiPtr && uiPtr->window)
    {
        uiPtr->updateMutex.lock();
        uiPtr->window->getFrameBufferDisplay()->onBufferUpdate(x, y, width, height);
        uiPtr->app->processEvents();
        uiPtr->app->sendPostedEvents();
        uiPtr->updateMutex.unlock();        
    }
}

qt_os getOS()
{
 #if defined(Q_OS_MACOS)
 return MAC;
 #elif defined(Q_OS_WIN)
 return WINDOWS;
 #elif defined(Q_OS_LINUX)
 return LINUX;
 #elif defined(Q_OS_UNIX)
 return UNIX;
 #else
 return UNKNOWN;
 #endif    
}

const char *getOSName()
{
 #if defined(Q_OS_ANDROID)
 return "android";
 #elif defined(Q_OS_BLACKBERRY)
 return"blackberry";
 #elif defined(Q_OS_IOS)
 return "ios";
 #elif defined(Q_OS_MACOS)
 return "macos";
 #elif defined(Q_OS_TVOS)
 return "tvos";
 #elif defined(Q_OS_WATCHOS)
 return "watchos";
 #elif defined(Q_OS_WINCE)
 return "wince";
 #elif defined(Q_OS_WIN)
 return "windows";
 #elif defined(Q_OS_LINUX)
 return "linux";
 #elif defined(Q_OS_UNIX)
 return "unix";
 #else
 return "unknown";
 #endif
}

void showError(char *message, bool critical)
{
    UIStruct *uiPtr = getUI();
    if (uiPtr && uiPtr->window)
    {
        QString errorString(message);
        if (critical)
        {
            uiPtr->window->showCriticalError(errorString);
        }
    }
}

void setKeyMapData(UIStruct *uiPtr, const unsigned short *map, int mapLen)
{
    uiPtr->keycode_map = map;
    uiPtr->keycode_map_len = mapLen;
}

int getScanCode(int key)
{
    int retVal = 0;
    UIStruct *uiPtr = getUI();

    if (uiPtr && uiPtr->keycode_map)
    {
        if (key < uiPtr->keycode_map_len)
        {
            retVal = uiPtr->keycode_map[key];
        }
    }
    return retVal;
}
