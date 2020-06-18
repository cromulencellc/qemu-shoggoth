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

#ifndef APPSTRINGS_H
#define APPSTRINGS_H

#include <QHash>
#include <QObject>

/**
 * 
 * 
 */
class AppStrings: public QObject
{
   Q_OBJECT

public:

   /**
    * 
    * 
    * @return
    */ 
   static AppStrings *instance();

   /**
    * 
    * 
    * @param name
    * @param deflt
    * @return
    */
   const QString get(QString name, QString deflt);

private:

   /**
    * 
    */
   AppStrings();

   QHash<QString, QString> strTab;
   static AppStrings *apStrInst;
};

/**
 * 
 * 
 * @param name
 * @param deflt
 * @return
 */
const QString getString(QString name, QString deflt);

#endif