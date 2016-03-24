//=================================================================================
// AndroidSdApi.h
// Written By Zhu Chuntao 2011.10.13

#ifndef __ANDROIDSDAPI_H__
#define __ANDROIDSDAPI_H__

//常量定义

/* 结构体定义 */
typedef struct{
    unsigned long length;
    unsigned char data[64];
}SD_SYM_KEY;

typedef struct{
    unsigned long length;
    unsigned char data[64];
}SD_SYM_IV;

typedef struct{
    unsigned long bitlen;
    unsigned long e;
    unsigned char n[128];
}SD_RSA_PUBLICKEY;

//=========================================================================================
// 导出的函数

unsigned long SDAPI_GetVersion(
		int hDev,
		unsigned char *pucHwVer,
		unsigned char *pucSwVer
		);

unsigned long SDAPI_OpenDevice(
		int *phDev
		);

unsigned long SDAPI_CloseDevice(int *phDev);

unsigned long SDAPI_Login(
	int hDev,
	unsigned char *pucPin,
	unsigned long ulLen
	);

unsigned long SDAPI_Logout(int hDev);

unsigned long SDAPI_ChangeUserPin(
	int hDev,
	unsigned char* pucOldPin,
	unsigned long ulOldLen,
	unsigned char* pucNewPin,
	unsigned long ulNewLen
	);

unsigned long SDAPI_ReadCertificate(
	int hDev,
	unsigned char* pucCert,
	unsigned long* pulLen,
	unsigned long ulKeyType
	);

unsigned long SDAPI_ReadSerialNum(
	int hDev,
	unsigned char* pucSn,
	unsigned long* pulLen
	);

unsigned long SDAPI_ReadPublicKey(
	int hDev,
	SD_RSA_PUBLICKEY* pPubKey,
	unsigned long ulKeyType
	);

unsigned long SDAPI_PrivateKeyOperate(
	int hDev,
	unsigned long ulLength,
	unsigned char *pucDataIn,
	unsigned char *pucDataOut,
	unsigned long ulKeyType
	);

unsigned long SDAPI_PublicKeyOperate(
	int hDev,
	unsigned long ulLength,
	unsigned char *pucDataIn,
	unsigned char *pucDataOut,
	unsigned long ulKeyType
	);

unsigned long SDAPI_SignOperate(
	int hDev,
	unsigned long  ulHashAlg,
	unsigned char* pucDataIn,
	unsigned long  ulInLen,
	unsigned char* pucDataOut,
	unsigned long* pulOutLen,
	unsigned long  ulKeyType
	);

unsigned long SDAPI_EncryptData(
	int hDev,
	unsigned long ulAlg,
	SD_SYM_KEY* pKey,
	SD_SYM_IV*  pIV,
	unsigned char* pucDataIn,
	unsigned long  ulInlen,
	unsigned char* pucDataOut,
	unsigned long* pulOutlen,
	unsigned long ulPadding
	);

unsigned long SDAPI_DecryptData(
	int hDev,
	unsigned long ulAlg,
	SD_SYM_KEY* pKey,
	SD_SYM_IV*  pIV,
	unsigned char* pucDataIn,
	unsigned long  ulInlen,
	unsigned char* pucDataOut,
	unsigned long* pulOutlen,
	unsigned long  ulPadding
	);

unsigned long SDAPI_SetActiveContainer(
		int hDev,
		char *szContainerName
		);

unsigned long SDAPI_EnumContainerName(
		int hDev,
		char *szConName,
		int nBufLen,
		int bFromBegin
		);

unsigned long SDAPI_SetCipherKey(
		int hDev,
		unsigned long dwAlgo,
		unsigned char *lpData,
		unsigned long dwDataLen,
		unsigned char *lpIV,
		unsigned long dwIVLen
		);

unsigned long SDAPI_Cipher(
		int hDev,
		unsigned long dwAlgo,
		int bEncrypt,
		int bFinal,
		unsigned char *lpInData,
		unsigned long dwInDataLen,
		unsigned char *lpOutData,
		unsigned long *lpdwOutDataLen
		);

unsigned long SDAPI_ReadLaserSN(
		int hDev,
		char *lpLaserSn);
#endif


