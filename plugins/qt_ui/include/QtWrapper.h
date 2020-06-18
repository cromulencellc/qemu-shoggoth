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

#ifndef QTWRAPPER_H
#define QTWRAPPER_H

typedef enum qt_os {
    LINUX,
    WINDOWS,
    MAC,
    UNIX,
    UNKNOWN
} qt_os;

/**
 * The structure 
 */
typedef struct UIStruct UIStruct;

/**
 * 
 * 
 * @return 
 */
UIStruct *getUI();


/**
 * 
 * 
 * @param ui
 */
void deleteUI();

/**
 * 
 * @param uiPtr
 * @param pixels
 * @param height
 * @param width
 */
void setView(UIStruct *uiPtr, void *pixels, int height, int width);

/**
 * 
 * 
 * @param uiPtr
 * @param x
 * @param y
 * @param width
 * @param height
 */
void updateView(UIStruct *uiPtr, int x, int y, int width, int height);

/**
 * 
 * 
 * @return
 */
qt_os getOS();

/**
 * 
 * 
 * @return
 */
const char *getOSName();

/**
 * 
 * 
 * @param message
 * @param critical
 */
void showError(char *message, bool critical);

/**
 * 
 * 
 * @param uiPtr
 * @param map
 * @param mapLen
 */
void setKeyMapData(UIStruct *uiPtr, const unsigned short *map, int mapLen);

/**
 * 
 * 
 * @param key
 * @return
 */
int getScanCode(int key);

#endif