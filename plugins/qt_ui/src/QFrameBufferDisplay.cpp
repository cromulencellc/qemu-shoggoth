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
#include "QFrameBufferDisplay.h"
#include <iostream>

QFrameBufferDisplay::QFrameBufferDisplay(uint8_t *frameBuffer, 
                                         int width, 
                                         int height, 
                                         QImage::Format format,
                                         QWidget *parent, 
                                         Qt::WindowFlags f):
    QWidget(parent, f),
    screenImage(new QImage(frameBuffer, width, height, format))
{
    this->setFocusPolicy(Qt::ClickFocus);
}

QFrameBufferDisplay::QFrameBufferDisplay(QImage *initialImage,
                                         QWidget *parent, 
                                         Qt::WindowFlags f):
    QWidget(parent, f),
    screenImage(initialImage)
{
    this->setFocusPolicy(Qt::ClickFocus);
}

QFrameBufferDisplay::~QFrameBufferDisplay()
{

}

void QFrameBufferDisplay::paintEvent(QPaintEvent *e)
{
    (void)(e);
         
    QPainter painter(this);
    painter.drawImage(e->rect(), *this->screenImage);
}

void QFrameBufferDisplay::focusInEvent(QFocusEvent *event)
{
    (void)event;
    // std::cout << "Focus Gained: " << event->gotFocus() << std::endl;
}

void QFrameBufferDisplay::focusOutEvent(QFocusEvent *event)
{
    (void)event;
    // std::cout << "Focus Lost: " << !event->gotFocus() << std::endl;
}

void QFrameBufferDisplay::keyPressEvent(QKeyEvent *event)
{
    emit keyPress(event, true);
}

void QFrameBufferDisplay::keyReleaseEvent(QKeyEvent *event)
{
    emit keyPress(event, false);
}

void QFrameBufferDisplay::QFrameBufferDisplay::onBufferReset(uint8_t *frameBuffer, 
                                                             int width,
                                                             int height, 
                                                             QImage::Format format)
{
    delete this->screenImage;
    this->screenImage = new QImage(frameBuffer, width, height, format);
    this->repaint(this->rect());
}

void QFrameBufferDisplay::onBufferUpdate(int x, int y, int width, int height)
{
    (void)(x);
    (void)(y);
    (void)(width);
    (void)(height);

    //TODO - We need to find the offset of the update pixels in the 
    //actual widget and have only that section of the widget redraw.

    //QRect area(x, y, width, height);
    this->repaint(this->rect());
}

bool QFrameBufferDisplay::event(QEvent *event)
{
    bool retVal = false;
    
     // We want to override tab key press
    if (event->type() == QEvent::KeyPress || event->type() == QEvent::KeyRelease) 
    {
        QKeyEvent *k = (QKeyEvent *)event;
        emit keyPress(k, event->type() == QEvent::KeyPress);
        retVal = true;
    }
    else
    {
        retVal = QWidget::event(event);
    }
    
    return retVal;
}