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
#ifndef QFRAMEBUFFERDISPLAY_H
#define QFRAMEBUFFERDISPLAY_H

#include <QPixmap>
#include <QWidget>
#include <QPainter>
#include <QPaintEvent>

class QFrameBufferDisplay: public QWidget
{
    Q_OBJECT

public:

    /**
     * 
     * 
     * @param frameBuffer
     * @param height
     * @param width
     * @param format
     * @param parent
     * @param f
     */
    QFrameBufferDisplay(uint8_t *frameBuffer,  
                        int width, 
                        int height,
                        QImage::Format format,
                        QWidget *parent = nullptr, 
                        Qt::WindowFlags f = Qt::WindowFlags());

    /**
     * 
     * 
     * @param initialImage
     * @param parent
     * @param f
     */
    QFrameBufferDisplay(QImage *initialImage,
                        QWidget *parent = nullptr, 
                        Qt::WindowFlags f = Qt::WindowFlags());
    
    /**
     * Destructor
     */
    ~QFrameBufferDisplay();

    /**
     * 
     * 
     * @param e
     */
    virtual void paintEvent(QPaintEvent *e);

    /**
     *
     * 
     * @param x
     * @param y
     * @param height
     * @param width 
     */
    void onBufferUpdate(int x, int y, int width, int height);


    /**
     * 
     * 
     * @param frameBuffer
     * @param height
     * @param width
     * @param format
     * @return
     */
    void onBufferReset(uint8_t *frameBuffer, 
                           int width, 
                           int height, 
                           QImage::Format format);

    /**
     * 
     * 
     * @param event
     */
    virtual void keyPressEvent(QKeyEvent *event);

    /**
     * 
     * 
     * @param event
     */
    virtual void keyReleaseEvent(QKeyEvent *event);

    /**
     * 
     * 
     * @param event
     */
    virtual void focusInEvent(QFocusEvent *event);

    /**
     * 
     * 
     * @param event
     */
    virtual void focusOutEvent(QFocusEvent *event);

    virtual bool event(QEvent *event);

signals:

    /**
     * 
     * 
     * @param event
     */
    void keyPress(QKeyEvent *event, bool keyDown);

private:

    QImage *screenImage;
};

#endif