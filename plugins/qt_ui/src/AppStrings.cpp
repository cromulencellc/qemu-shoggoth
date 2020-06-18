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

#include "AppStrings.h"

#include <QFile>
#include <QXmlStreamReader>
#include <QString>
#include <iostream>

AppStrings* AppStrings::apStrInst = nullptr;

AppStrings::AppStrings()
{
   QFile strFile(":strings.xml");
   if (strFile.open(QIODevice::ReadOnly | QIODevice::Text))
   {
      QXmlStreamReader xml(&strFile);

      if (xml.readNextStartElement() && xml.name() == "strings")
      {
         while(xml.readNextStartElement())
         {
            strTab.insert(xml.name().toString(), xml.readElementText());
         }
         strFile.close();
      }
   }
   else
   {

   }
}

AppStrings *AppStrings::instance() 
{
   if (AppStrings::apStrInst == nullptr)
   {
      AppStrings::apStrInst = new AppStrings();
   }
   return AppStrings::apStrInst;
}

const QString AppStrings::get(QString name, QString deflt)
{
   if (strTab.contains(name))
   {
      return strTab.value(name);
   }  
   return deflt; 
}

const QString getString(QString name, QString deflt)
{
   return AppStrings::instance()->get(name, deflt);
}