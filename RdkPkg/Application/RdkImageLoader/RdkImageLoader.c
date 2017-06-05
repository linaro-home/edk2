/*
#  Copyright (c) 2016-2017, Linaro Limited. All rights reserved.
#
#  This program and the accompanying materials
#  are licensed and made available under the terms and conditions of the BSD License
#  which accompanies this distribution.  The full text of the license may be found at
#  http://opensource.org/licenses/bsd-license.php
#
#  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
#  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
#
 */
#include <Library/BaseMemoryLib.h>
#include "stdio.h" 

#include <Protocol/DevicePathFromText.h>
#include <Guid/ImageAuthentication.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Guid/AuthenticatedVariableFormat.h>
#include <Include/Guid/AuthenticatedVariableFormat.h>
#include "RdkImageLoader.h"
#include <stdio.h>
#include <Guid/ArmGlobalVariableHob.h>
#include <Library/ArmLib.h>
#include <Guid/Fdt.h>
#include "RdkDiskIo.h"

#define RDK_LINUX_KERNEL_NAME               L"VenHw(B549F005-4BD4-4020-A0CB-06F42BDA68C3)/HD(6,GPT,5C0F213C-17E1-4149-88C8-8B50FB4EC70E,0x7000,0x20000)/EFI/BOOT/Image"
#define RDK_FDT_NAME                        L"VenHw(B549F005-4BD4-4020-A0CB-06F42BDA68C3)/HD(6,GPT,5C0F213C-17E1-4149-88C8-8B50FB4EC70E,0x7000,0x20000)/EFI/BOOT/hi6220-hikey.dtb"
#define RDK_KEK_CRT_FILE_NAME               L"VenHw(B549F005-4BD4-4020-A0CB-06F42BDA68C3)/HD(6,GPT,5C0F213C-17E1-4149-88C8-8B50FB4EC70E,0x7000,0x20000)/EFI/BOOT/KEK.crt"

#define STRLEN(s) (sizeof(s)/sizeof(s[0]))


#define SECURE_ROOTFS

#define RSVD_READ_SIZE (1024*8)

EFI_STATUS EFIAPI OpenFileByDevicePath(	IN OUT EFI_DEVICE_PATH_PROTOCOL           **FilePath,
					OUT EFI_FILE_HANDLE                       *FileHandle,
					IN UINT64                                 OpenMode,
					IN UINT64                                 Attributes )
{
	EFI_STATUS                           Status;
	EFI_SIMPLE_FILE_SYSTEM_PROTOCOL      *EfiSimpleFileSystemProtocol;
	EFI_FILE_PROTOCOL                    *Handle1;
	EFI_FILE_PROTOCOL                    *Handle2;
	EFI_HANDLE                           DeviceHandle;

	//if ((FilePath == NULL || FileHandle == NULL)) {
	if ((FilePath == NULL )) {
		return EFI_INVALID_PARAMETER;
	}

	Status = gBS->LocateDevicePath (
			&gEfiSimpleFileSystemProtocolGuid,
			FilePath,
			&DeviceHandle
			);
	if (EFI_ERROR (Status)) {
		return Status;
	}

	Status = gBS->OpenProtocol(
			DeviceHandle,
			&gEfiSimpleFileSystemProtocolGuid,
			(VOID**)&EfiSimpleFileSystemProtocol,
			gImageHandle,
			NULL,
			EFI_OPEN_PROTOCOL_GET_PROTOCOL
			);
	if (EFI_ERROR (Status)) {
		return Status;
	}

	Status = EfiSimpleFileSystemProtocol->OpenVolume(EfiSimpleFileSystemProtocol, &Handle1);
	if (EFI_ERROR (Status)) {
		FileHandle = NULL;
		return Status;
	}

	//
	// go down directories one node at a time.
	//
	while (!IsDevicePathEnd (*FilePath)) {
		//
		// For file system access each node should be a file path component
		//
		if (DevicePathType    (*FilePath) != MEDIA_DEVICE_PATH ||
				DevicePathSubType (*FilePath) != MEDIA_FILEPATH_DP
		   ) {
			FileHandle = NULL;
			return (EFI_INVALID_PARAMETER);
		}
		//
		// Open this file path node
		//
		Handle2  = Handle1;
		Handle1 = NULL;

		//
		// Try to test opening an existing file
		//
		Status = Handle2->Open (
				Handle2,
				&Handle1,
				((FILEPATH_DEVICE_PATH*)*FilePath)->PathName,
				OpenMode &~EFI_FILE_MODE_CREATE,
				0
				);

		//
		// see if the error was that it needs to be created
		//
		if ((EFI_ERROR (Status)) && (OpenMode != (OpenMode &~EFI_FILE_MODE_CREATE))) {
			Status = Handle2->Open (
					Handle2,
					&Handle1,
					((FILEPATH_DEVICE_PATH*)*FilePath)->PathName,
					OpenMode,
					Attributes
					);
		}
		//
		// Close the last node
		//
		Handle2->Close (Handle2);

		if (EFI_ERROR(Status)) {
			return (Status);
		}

		//
		// Get the next node
		//
		*FilePath = NextDevicePathNode (*FilePath);
	}

	//
	// This is a weak spot since if the undefined SHELL_FILE_HANDLE format changes this must change also!
	//
	*FileHandle = (VOID*)Handle1;

	return EFI_SUCCESS;
}


EFI_STATUS ReadPlatformFileContent ( IN      EFI_FILE_HANDLE           FileHandle,
                                     IN OUT  VOID                      **BufferPtr,
				     OUT  UINTN                     *FileSize,
				     IN      UINTN                     AddtionAllocateSize )
{
	UINTN      BufferSize;
	UINT64     SourceFileSize;
	VOID       *Buffer;
	EFI_STATUS Status;

	if ((FileHandle == NULL) || (FileSize == NULL)) {
		return EFI_INVALID_PARAMETER;
	}

	Buffer = NULL;

	//
	// Get the file size
	//
	Status = FileHandle->SetPosition (FileHandle, (UINT64) -1);
	if (EFI_ERROR (Status)) {
		goto ON_EXIT;
	}

	Status = FileHandle->GetPosition (FileHandle, &SourceFileSize);
	if (EFI_ERROR (Status)) {
		goto ON_EXIT;
	}

	Status = FileHandle->SetPosition (FileHandle, 0);
	if (EFI_ERROR (Status)) {
		goto ON_EXIT;
	}

	BufferSize = (UINTN) SourceFileSize + AddtionAllocateSize;
	Buffer =  AllocateZeroPool(BufferSize);
	if (Buffer == NULL) {
		return EFI_OUT_OF_RESOURCES;
	}

	BufferSize = (UINTN) SourceFileSize;
	*FileSize  = BufferSize;

	Status = FileHandle->Read (FileHandle, &BufferSize, Buffer);
	if (EFI_ERROR (Status) || BufferSize != *FileSize) {
		FreePool (Buffer);
		Buffer = NULL;
		Status  = EFI_BAD_BUFFER_SIZE;
		goto ON_EXIT;
	}


ON_EXIT:

	*BufferPtr = Buffer;
	return Status;
}


EFI_STATUS CreateTimeBasedPayload ( IN OUT UINTN            *DataSize,
		                    IN OUT UINT8            **Data )
{
	EFI_STATUS                       Status;
	UINT8                            *NewData;
	UINT8                            *Payload;
	UINTN                            PayloadSize;
	EFI_VARIABLE_AUTHENTICATION_2    *DescriptorData;
	UINTN                            DescriptorSize;
	EFI_TIME                         Time;

	if (Data == NULL || DataSize == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	//
	// In Setup mode or Custom mode, the variable does not need to be signed but the
	// parameters to the SetVariable() call still need to be prepared as authenticated
	// variable. So we create EFI_VARIABLE_AUTHENTICATED_2 descriptor without certificate
	// data in it.
	//

	Payload     = *Data;
	PayloadSize = *DataSize;

	DescriptorSize    = OFFSET_OF (EFI_VARIABLE_AUTHENTICATION_2, AuthInfo) + OFFSET_OF (WIN_CERTIFICATE_UEFI_GUID, CertData);
	NewData = (UINT8*) AllocateZeroPool (DescriptorSize + PayloadSize);
	if (NewData == NULL) {
		return EFI_OUT_OF_RESOURCES;
	}

	if ((Payload != NULL) && (PayloadSize != 0)) {
		CopyMem (NewData + DescriptorSize, Payload, PayloadSize);
	}

	DescriptorData = (EFI_VARIABLE_AUTHENTICATION_2 *) (NewData);

	ZeroMem (&Time, sizeof (EFI_TIME));
	Status = gRT->GetTime (&Time, NULL);
	if (EFI_ERROR (Status)) {
		FreePool(NewData);
		return Status;
	}
	Time.Pad1       = 0;
	Time.Nanosecond = 0;
	Time.TimeZone   = 0;
	Time.Daylight   = 0;
	Time.Pad2       = 0;
	CopyMem (&DescriptorData->TimeStamp, &Time, sizeof (EFI_TIME));

	DescriptorData->AuthInfo.Hdr.dwLength         = OFFSET_OF (WIN_CERTIFICATE_UEFI_GUID, CertData);
	DescriptorData->AuthInfo.Hdr.wRevision        = 0x0200;
	DescriptorData->AuthInfo.Hdr.wCertificateType = WIN_CERT_TYPE_EFI_GUID;
	CopyGuid (&DescriptorData->AuthInfo.CertType, &gEfiCertPkcs7Guid);

	if (Payload != NULL) {
		FreePool(Payload);
	}

	*DataSize = DescriptorSize + PayloadSize;
	*Data     = NewData;
	return EFI_SUCCESS;
}

EFI_STATUS SetBootMode ( IN     UINT8         SecureBootMode )
{
	return gRT->SetVariable (
			EFI_CUSTOM_MODE_NAME,
			&gEfiCustomModeEnableGuid,
			EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS,
			sizeof (UINT8),
			&SecureBootMode
			);
}




EFI_STATUS SetVariable ( IN 	EFI_SIGNATURE_LIST  *PkCert,
	     		 IN 	UINTN  	DataSize,
			 IN      eKey    KeyType )
{
	UINT32  Attr;
	EFI_STATUS   Status=EFI_SUCCESS ;
	Attr = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_RUNTIME_ACCESS
		| EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
	if(KeyType == PK_KEY)
	{
		DEBUG ((EFI_D_INFO, "Setting PK Key\n"));
		Status = gRT->SetVariable(
				EFI_PLATFORM_KEY_NAME,
				&gEfiGlobalVariableGuid,
				Attr,
				DataSize,
				PkCert);
	}
	else if( KeyType == KEK_KEY)
	{
		DEBUG ((EFI_D_INFO, "Setting KEK Key\n"));
		Status = gRT->SetVariable(
				EFI_KEY_EXCHANGE_KEY_NAME,
				&gEfiGlobalVariableGuid,
				Attr,
				DataSize,
				PkCert);


		Status = gRT->SetVariable(
				EFI_IMAGE_SECURITY_DATABASE,
				&gEfiImageSecurityDatabaseGuid,
				Attr,
				DataSize,
				PkCert
				);

	}
	else
	{
	}
	return Status;

}

EFI_STATUS GetFileHandler ( OUT     EFI_FILE_HANDLE  *FileHandle,
			    IN  CONST CHAR16 *Path )
{
	EFI_STATUS   Status=EFI_SUCCESS;
	EFI_DEVICE_PATH_PROTOCOL  *KeyFileDevicePath = NULL;
	EFI_DEVICE_PATH_FROM_TEXT_PROTOCOL *DevicePathFromTextProtocol;

	Status = gBS->LocateProtocol (
			&gEfiDevicePathFromTextProtocolGuid,
			NULL,
			(VOID**)&DevicePathFromTextProtocol
			);
	ASSERT_EFI_ERROR(Status);

	//	KeyFileDevicePath = gEfiShellProtocol->GetDevicePathFromFilePath(Path);
	KeyFileDevicePath =  DevicePathFromTextProtocol->ConvertTextToDevicePath(Path);
	if(KeyFileDevicePath != NULL)
	{
		Status = OpenFileByDevicePath(&KeyFileDevicePath,FileHandle,EFI_FILE_MODE_READ,0);
		if(Status != EFI_SUCCESS)
		{
			DEBUG ((EFI_D_INFO, "Getting FileHandle of %s Failed\n",Path));
		}
	}
	return Status;

}

VOID PopulateCert ( OUT EFI_SIGNATURE_LIST  **Cert,
		    IN UINTN  DataSize,
		    IN UINT8  *Data )
{
	EFI_SIGNATURE_DATA  *CertData = NULL;

	if( (*Cert) == NULL)
	{
		(*Cert) = (EFI_SIGNATURE_LIST*) AllocateZeroPool ( sizeof(EFI_SIGNATURE_LIST) + 
				sizeof(EFI_SIGNATURE_DATA) - 1 + 
				DataSize );

		ASSERT ((*Cert) != NULL);
	}
	(*Cert)->SignatureListSize   = (UINT32) (sizeof(EFI_SIGNATURE_LIST)
			+ sizeof(EFI_SIGNATURE_DATA) - 1
			+ DataSize);
	(*Cert)->SignatureSize       = (UINT32) (sizeof(EFI_SIGNATURE_DATA) - 1 + DataSize);
	(*Cert)->SignatureHeaderSize = 0;
	CopyGuid (&(*Cert)->SignatureType, &gEfiCertX509Guid);


	CertData = (EFI_SIGNATURE_DATA*) ((UINTN)(*Cert)+ sizeof(EFI_SIGNATURE_LIST) + (*Cert)->SignatureHeaderSize);
	ASSERT (CertData != NULL);

	CopyGuid (&CertData->SignatureOwner, &gEfiGlobalVariableGuid);
	CopyMem (&CertData->SignatureData, Data, DataSize);

}


/**
  Create a time based data payload by concatenating the EFI_VARIABLE_AUTHENTICATION_2
  descriptor with the input data. NO authentication is required in this function.

  @param[in]   FileHandle       FileHandler of the key file

  @param[in]   KeyType           Gives Key Type (Platform Key,KEK Key)

  @retval EFI_SUCCESS              Key File will be registered 
  @retval EFI_OUT_OF_RESOURCES     There are not enough memory resourses to create time based payload.
  @retval EFI_INVALID_PARAMETER    The parameter is invalid.

 **/

EFI_STATUS RegisterCert ( UINT8  *KeyData,
			  UINTN  KeySize,
			  IN     eKey      KeyType )
{
	EFI_STATUS   Status;
	EFI_SIGNATURE_LIST  *Cert = NULL;

	Status = SetBootMode(CUSTOM_SECURE_BOOT_MODE);
	ASSERT_EFI_ERROR (Status);

	PopulateCert(&Cert, KeySize, KeyData);

	KeySize = Cert->SignatureListSize;

	Status = CreateTimeBasedPayload (&KeySize, (UINT8**) &Cert);
	ASSERT_EFI_ERROR (Status);

	Status = SetVariable(Cert,KeySize,KeyType);		
	return Status;

}

STATIC VOID RdkSetVariable ( VOID )
{
	UINT8 * KekCrtData;
	UINTN  KekCrtSize;
	EFI_STATUS Status;
	EFI_FILE_HANDLE KEK_FileHandle;

	Status = GetFileHandler(&KEK_FileHandle,RDK_KEK_CRT_FILE_NAME);
	if(Status == EFI_SUCCESS)
	{

		Status = ReadPlatformFileContent (KEK_FileHandle, (VOID**) &KekCrtData, &KekCrtSize, 0);
		ASSERT_EFI_ERROR (Status);
	}
	else
	{
		ASSERT_EFI_ERROR(Status);
	}

	Status = gRT->SetVariable (
			L"RdkRootCertificate",
			&gArmGlobalVariableGuid,
			EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
			KekCrtSize,
			KekCrtData
			);

	ASSERT_EFI_ERROR(Status);


	/* Read PK and KEK keys from reserved partition */	
	STATIC UINT8 *Buffer = NULL;
	Buffer = AllocateZeroPool(RSVD_READ_SIZE);
	RsvdDiskRead(Buffer, RSVD_READ_SIZE);

	INT32 i, Size, PkKeySize, KekKeySize;

	UINT8 * PkKey = Buffer;
	for(i=0, Size=0; i<8; i++)
	{
		Size = (PkKey[i] - '0') + (Size * 10);
	}
	PkKey += 8;
	PkKeySize = Size;

	UINT8 * KekKey = PkKey + PkKeySize;
	for(i=0, Size=0; i<8; i++)
	{
		Size = (KekKey[i] - '0') + (Size * 10);
	}
	KekKey += 8;
	KekKeySize = Size;

	INT8* SetupMode = NULL;
	eKey KeyType;

	KeyType = PK_KEY;
	Status = RegisterCert(PkKey,PkKeySize,KeyType);
	GetEfiGlobalVariable2 (L"SetupMode", (VOID**)&SetupMode, NULL);

	if (*SetupMode == 0)
	{
		DEBUG ((EFI_D_INFO, "PK Key Got Registered. Now System in User Mode\n"));
		KeyType = KEK_KEY;
		Status = RegisterCert(KekKey,KekKeySize,KeyType);
	}
	else if(*SetupMode == 1)
	{
		DEBUG ((EFI_D_INFO, "System in Standard System Mode ::: Secure Boot Not enabled\n"));
		ASSERT_EFI_ERROR(Status);

	}

	FreePool(Buffer);
}

CHAR16 p;

EFI_STATUS EFIAPI RdkImageLoaderEntryPoint ( IN EFI_HANDLE        ImageHandle,
					     IN EFI_SYSTEM_TABLE  *SystemTable )
{
	EFI_STATUS                          Status;
	EFI_DEVICE_PATH_PROTOCOL  *FilePath;
	EFI_HANDLE                Handle;
	EFI_LOADED_IMAGE_PROTOCOL *ImageInfo;
	EFI_BOOT_SERVICES       *BS=SystemTable->BootServices;
	UINTN  *ExitDataSize = 0;
	CHAR16  **ExitData= (CHAR16**)&p;

	*ExitData=NULL;
	FilePath = NULL;
	char cmd[] = "root=/dev/mmcblk0p9";
	CHAR16  LoadOption[100];

	InitDiskIo();

	UINTN                     FdtDevicePathSize;
	EFI_DEVICE_PATH_PROTOCOL *FdtDevicePath;
	EFI_DEVICE_PATH_FROM_TEXT_PROTOCOL *DevicePathFromTextProtocol;

	Status = gBS->LocateProtocol (
			&gEfiDevicePathFromTextProtocolGuid,
			NULL,
			(VOID**)&DevicePathFromTextProtocol
			);
	ASSERT_EFI_ERROR(Status);

	FdtDevicePath = DevicePathFromTextProtocol->ConvertTextToDevicePath (RDK_FDT_NAME);
	ASSERT (FdtDevicePath != NULL);

	FdtDevicePathSize = GetDevicePathSize (FdtDevicePath);
	Status = gRT->SetVariable (
			(CHAR16*)L"Fdt",
			&gArmGlobalVariableGuid,
			EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS ,
			FdtDevicePathSize,
			FdtDevicePath
			);

	EFI_FILE_HANDLE Fdt_FileHandle;
	Status= GetFileHandler(&Fdt_FileHandle,RDK_FDT_NAME);
	if(Status==EFI_SUCCESS)
	{

		UINT8  *FdtData;
		UINTN  FdtDataSize;


		Status = ReadPlatformFileContent (Fdt_FileHandle, (VOID**) &FdtData, &FdtDataSize, 0);
		if (EFI_ERROR (Status)) {
			ASSERT_EFI_ERROR (Status);
			return Status;
		}


		Status = gBS->InstallConfigurationTable (&gFdtTableGuid,(VOID*)FdtData);

		if (EFI_ERROR (Status)) {
			ASSERT_EFI_ERROR (Status);
			return Status;
		}

	}

	RdkSetVariable();

	//	FilePath = gEfiShellProtocol->GetDevicePathFromFilePath(RDK_LINUX_KERNEL_NAME);
	FilePath = DevicePathFromTextProtocol->ConvertTextToDevicePath(RDK_LINUX_KERNEL_NAME);
	Status = BS->LoadImage (TRUE,
			ImageHandle,
			FilePath,
			NULL,
			0,
			&Handle
			);

	ASSERT_EFI_ERROR (Status);
	UnicodeSPrintAsciiFormat(LoadOption,sizeof(LoadOption),cmd);

	Status = BS->HandleProtocol ( Handle, &gEfiLoadedImageProtocolGuid, (VOID **) &ImageInfo);
	ASSERT_EFI_ERROR (Status);
	ImageInfo->LoadOptionsSize  = sizeof(LoadOption);
	ImageInfo->LoadOptions      = LoadOption;

	Status = BS->StartImage (Handle, ExitDataSize, ExitData);
	ASSERT_EFI_ERROR (Status);
	return Status;
}
