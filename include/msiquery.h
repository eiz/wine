/*
 * Copyright (C) 2002,2003 Mike McCormack
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef __WINE_MSIQUERY_H
#define __WINE_MSIQUERY_H

#include <msi.h>

typedef enum tagMSICONDITION
{
    MSICONDITION_FALSE = 0,
    MSICONDITION_TRUE  = 1,
    MSICONDITION_NONE  = 2,
    MSICONDITION_ERROR = 3,
} MSICONDITION;

#define MSI_NULL_INTEGER 0x80000000

typedef enum tagMSICOLINFO
{
    MSICOLINFO_NAMES = 0,
    MSICOLINFO_TYPES = 1
} MSICOLINFO;

typedef enum tagMSIMODIFY
{
    MSIMODIFY_REFRESH = 0,
    MSIMODIFY_INSERT = 1,
    MSIMODIFY_UPDATE = 2,
    MSIMODIFY_ASSIGN = 3,
    MSIMODIFY_REPLACE = 4,
    MSIMODIFY_MERGE = 5,
    MSIMODIFY_DELETE = 6,
    MSIMODIFY_INSERT_TEMPORARY = 7,
    MSIMODIFY_VALIDATE = 8,
    MSIMODIFY_VALIDATE_NEW = 9,
    MSIMODIFY_VALIDATE_FIELD = 10,
    MSIMODIFY_VALIDATE_DELETE = 11
} MSIMODIFY;

#define MSIDBOPEN_READONLY (LPCTSTR)0
#define MSIDBOPEN_TRANSACT (LPCTSTR)1
#define MSIDBOPEN_DIRECT   (LPCTSTR)2
#define MSIDBOPEN_CREATE   (LPCTSTR)3
#define MSIDBOPEN_CREATEDIRECT (LPCTSTR)4

typedef enum tagMSIRUNMODE
{
    MSIRUNMODE_ADMIN = 0,
    MSIRUNMODE_ADVERTISE = 1,
    MSIRUNMODE_MAINTENANCE = 2,
    MSIRUNMODE_ROLLBACKENABLED = 3,
    MSIRUNMODE_LOGENABLED = 4,
    MSIRUNMODE_OPERATIONS = 5,
    MSIRUNMODE_REBOOTATEND = 6,
    MSIRUNMODE_REBOOTNOW = 7,
    MSIRUNMODE_CABINET = 8,
    MSIRUNMODE_SOURCESHORTNAMES = 9,
    MSIRUNMODE_TARGETSHORTNAMES = 10,
    MSIRUNMODE_RESERVED11 = 11,
    MSIRUNMODE_WINDOWS9X = 12,
    MSIRUNMODE_ZAWENABLED = 13,
    MSIRUNMODE_RESERVED14 = 14,
    MSIRUNMODE_RESERVED15 = 15,
    MSIRUNMODE_SCHEDULED = 16,
    MSIRUNMODE_ROLLBACK = 17,
    MSIRUNMODE_COMMIT = 18
} MSIRUNMODE;

/* view manipulation */
UINT WINAPI MsiViewFetch(MSIHANDLE,MSIHANDLE*);
UINT WINAPI MsiViewExecute(MSIHANDLE,MSIHANDLE);
UINT WINAPI MsiViewClose(MSIHANDLE);
UINT WINAPI MsiDatabaseOpenViewA(MSIHANDLE,LPCSTR,MSIHANDLE*);
UINT WINAPI MsiDatabaseOpenViewW(MSIHANDLE,LPCWSTR,MSIHANDLE*);
#define     MsiDatabaseOpenView WINELIB_NAME_AW(MsiDatabaseOpenView)

/* record manipulation */
MSIHANDLE WINAPI MsiCreateRecord(unsigned int);
UINT WINAPI MsiRecordClearData(MSIHANDLE);
UINT WINAPI MsiRecordSetInteger(MSIHANDLE,unsigned int,int);
UINT WINAPI MsiRecordSetStringA(MSIHANDLE,unsigned int,LPCSTR);
UINT WINAPI MsiRecordSetStringW(MSIHANDLE,unsigned int,LPCWSTR);
#define     MsiRecordSetString WINELIB_NAME_AW(MsiRecordSetString)
UINT WINAPI MsiRecordGetStringA(MSIHANDLE,unsigned int,LPSTR,DWORD*);
UINT WINAPI MsiRecordGetStringW(MSIHANDLE,unsigned int,LPWSTR,DWORD*);
#define     MsiRecordGetString WINELIB_NAME_AW(MsiRecordGetString)
UINT WINAPI MsiRecordGetFieldCount(MSIHANDLE);
int WINAPI MsiRecordGetInteger(MSIHANDLE,unsigned int);
UINT WINAPI MsiRecordDataSize(MSIHANDLE,unsigned int);
BOOL WINAPI MsiRecordIsNull(MSIHANDLE,unsigned int);
UINT WINAPI MsiFormatRecordA(MSIHANDLE,MSIHANDLE,LPSTR,DWORD*);
UINT WINAPI MsiFormatRecordW(MSIHANDLE,MSIHANDLE,LPWSTR,DWORD*);
#define     MsiFormatRecord WINELIB_NAME_AW(MsiFormatRecord)
UINT WINAPI MsiRecordSetStreamA(MSIHANDLE,unsigned int,LPCSTR);
UINT WINAPI MsiRecordSetStreamW(MSIHANDLE,unsigned int,LPCWSTR);
#define     MsiRecordSetStream WINELIB_NAME_AW(MsiRecordSetStream)
UINT WINAPI MsiRecordReadStream(MSIHANDLE,unsigned int,char*,DWORD *);

UINT WINAPI MsiDatabaseGetPrimaryKeysA(MSIHANDLE,LPCSTR,MSIHANDLE*);
UINT WINAPI MsiDatabaseGetPrimaryKeysW(MSIHANDLE,LPCWSTR,MSIHANDLE*);
#define     MsiDatabaseGetPrimaryKeys WINELIB_NAME_AW(MsiDatabaseGetPrimaryKeys)

/* installing */
UINT WINAPI MsiDoActionA(MSIHANDLE,LPCSTR );
UINT WINAPI MsiDoActionW(MSIHANDLE,LPCWSTR );
#define     MsiDoAction WINELIB_NAME_AW(MsiDoAction)

/* database transforms */
UINT WINAPI MsiDatabaseApplyTransformA(MSIHANDLE,LPCSTR,int);
UINT WINAPI MsiDatabaseApplyTransformW(MSIHANDLE,LPCWSTR,int);
#define     MsiDatabaseApplyTransform WINELIB_NAME_AW(MsiDatabaseApplyTransform)
UINT WINAPI MsiDatabaseGenerateTransformA(MSIHANDLE,MSIHANDLE,LPCSTR,int,int);
UINT WINAPI MsiDatabaseGenerateTransformW(MSIHANDLE,MSIHANDLE,LPCWSTR,int,int);
#define     MsiDatabaseGenerateTransform WINELIB_NAME_AW(MsiDatabaseGenerateTransform)

UINT WINAPI MsiDatabaseCommit(MSIHANDLE);

/* install state */
UINT WINAPI MsiGetFeatureStateA(MSIHANDLE,LPSTR,INSTALLSTATE*,INSTALLSTATE*);
UINT WINAPI MsiGetFeatureStateW(MSIHANDLE,LPWSTR,INSTALLSTATE*,INSTALLSTATE*);
#define     MsiGetFeatureState WINELIB_NAME_AW(MsiGetFeatureState)
UINT WINAPI MsiGetComponentStateA(MSIHANDLE,LPSTR,INSTALLSTATE*,INSTALLSTATE*);
UINT WINAPI MsiGetComponentStateW(MSIHANDLE,LPWSTR,INSTALLSTATE*,INSTALLSTATE*);
#define     MsiGetComponentState WINELIB_NAME_AW(MsiGetComponentState)

MSICONDITION WINAPI MsiEvaluateConditionA(MSIHANDLE,LPCSTR);
MSICONDITION WINAPI MsiEvaluateConditionW(MSIHANDLE,LPCWSTR);
#define     MsiEvaluateCondition WINELIB_NAME_AW(MsiEvaluateCondition)

/* property functions */
UINT WINAPI MsiGetPropertyA(MSIHANDLE, LPCSTR, LPSTR, DWORD*);
UINT WINAPI MsiGetPropertyW(MSIHANDLE, LPCWSTR, LPWSTR, DWORD*);
#define     MsiGetProperty WINELIB_NAME_AW(MsiGetProperty)

UINT WINAPI MsiSetPropertyA(MSIHANDLE, LPCSTR, LPCSTR);
UINT WINAPI MsiSetPropertyW(MSIHANDLE, LPCWSTR, LPCWSTR);
#define     MsiSetProperty WINELIB_NAME_AW(MsiSetProperty)

UINT WINAPI MsiGetTargetPathA(MSIHANDLE,LPCSTR,LPSTR,DWORD*);
UINT WINAPI MsiGetTargetPathW(MSIHANDLE,LPCWSTR,LPWSTR,DWORD*);
#define     MsiGetTargetPath WINELIB_NAME_AW(MsiGetTargetPath)

UINT WINAPI MsiSetTargetPathA(MSIHANDLE, LPCSTR, LPCSTR);
UINT WINAPI MsiSetTargetPathW(MSIHANDLE, LPCWSTR, LPCWSTR);
#define     MsiSetTargetPath WINELIB_NAME_AW(MsiSetTargetPath)

UINT WINAPI MsiGetSourcePathA(MSIHANDLE,LPCSTR,LPSTR,DWORD*);
UINT WINAPI MsiGetSourcePathW(MSIHANDLE,LPCWSTR,LPWSTR,DWORD*);
#define     MsiGetSourcePath WINELIB_NAME_AW(MsiGetSourcePath)

MSIHANDLE WINAPI MsiGetActiveDatabase(MSIHANDLE);

UINT WINAPI MsiViewGetColumnInfo(MSIHANDLE, MSICOLINFO, MSIHANDLE*);
INT WINAPI MsiProcessMessage(MSIHANDLE, INSTALLMESSAGE, MSIHANDLE);

UINT WINAPI MsiSetFeatureStateA(MSIHANDLE, LPCSTR, INSTALLSTATE);
UINT WINAPI MsiSetFeatureStateW(MSIHANDLE, LPCWSTR, INSTALLSTATE);
#define     MsiSetFeatureState WINELIB_NAME_AW(MsiSetFeatureState)

UINT WINAPI MsiPreviewDialogA(MSIHANDLE, LPCSTR);
UINT WINAPI MsiPreviewDialogW(MSIHANDLE, LPCWSTR);
#define     MsiPreviewDialog WINELIB_NAME_AW(MsiPreviewDialog)

UINT WINAPI MsiPreviewBillboardA(MSIHANDLE, LPCSTR, LPCSTR);
UINT WINAPI MsiPreviewBillboardW(MSIHANDLE, LPCWSTR, LPCWSTR);
#define     MsiPreviewBillboard WINELIB_NAME_AW(MsiPreviewBillboard)

UINT WINAPI MsiGetSummaryInformationA(MSIHANDLE, LPCSTR, UINT, MSIHANDLE *);
UINT WINAPI MsiGetSummaryInformationW(MSIHANDLE, LPCWSTR, UINT, MSIHANDLE *);
#define     MsiGetSummaryInformation WINELIB_NAME_AW(MsiGetSummaryInformation)

UINT WINAPI MsiSummaryInfoGetPropertyA(MSIHANDLE,UINT,UINT*,INT*,FILETIME*,LPSTR,DWORD*);
UINT WINAPI MsiSummaryInfoGetPropertyW(MSIHANDLE,UINT,UINT*,INT*,FILETIME*,LPWSTR,DWORD*);
#define     MsiSummaryInfoGetProperty WINELIB_NAME_AW(MsiSummaryInfoGetProperty)

UINT WINAPI MsiSummaryInfoSetPropertyA(MSIHANDLE, UINT, UINT, INT, FILETIME*, LPSTR);
UINT WINAPI MsiSummaryInfoSetPropertyW(MSIHANDLE, UINT, UINT, INT, FILETIME*, LPWSTR);
#define     MsiSummaryInfoSetProperty WINELIB_NAME_AW(MsiSummaryInfoSetProperty)

UINT WINAPI MsiSummaryInfoPersist(MSIHANDLE);
UINT WINAPI MsiSummaryInfoGetPropertyCount(MSIHANDLE,UINT*);

UINT WINAPI MsiEnableUIPreview(MSIHANDLE, MSIHANDLE*);
BOOL WINAPI MsiGetMode(MSIHANDLE, MSIRUNMODE);

#endif /* __WINE_MSIQUERY_H */
