#include <stdio.h>
#include <Protocol/BlockIo.h>
#include <Protocol/DiskIo.h>
#include <Protocol/AndroidFastbootPlatform.h>
#include <Protocol/SimpleTextOut.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/SimpleTextOut.h>
#include <Library/DevicePathLib.h>
#include "RdkDiskIo.h"

#define PARTITION_NAME_MAX_LENGTH 72/2

#define FLASH_DEVICE_PATH_SIZE(DevPath) ( GetDevicePathSize (DevPath) - \
		sizeof (EFI_DEVICE_PATH_PROTOCOL))

#define IS_ALPHA(Char) (((Char) <= L'z' && (Char) >= L'a') || \
		((Char) <= L'Z' && (Char) >= L'Z'))

typedef struct _DISKIO_PARTITION_LIST {
	LIST_ENTRY  Link;
	CHAR16      PartitionName[PARTITION_NAME_MAX_LENGTH];
	EFI_HANDLE  PartitionHandle;
} DISKIO_PARTITION_LIST;

STATIC LIST_ENTRY mPartitionListHead;
STATIC EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *mTextOut;

/*
 * Helper to free the partition list
 */
STATIC VOID FreePartitionList (	VOID )
{
	DISKIO_PARTITION_LIST *Entry;
	DISKIO_PARTITION_LIST *NextEntry;

	Entry = (DISKIO_PARTITION_LIST *) GetFirstNode (&mPartitionListHead);
	while (!IsNull (&mPartitionListHead, &Entry->Link)) {
		NextEntry = (DISKIO_PARTITION_LIST *) GetNextNode (&mPartitionListHead, &Entry->Link);

		RemoveEntryList (&Entry->Link);
		FreePool (Entry);

		Entry = NextEntry;
	}
}

/*
 * Read the PartitionName fields from the GPT partition entries, putting them
 * into an allocated array that should later be freed.
 */
STATIC	EFI_STATUS ReadPartitionEntries ( IN EFI_BLOCK_IO_PROTOCOL *BlockIo,
					  OUT EFI_PARTITION_ENTRY  **PartitionEntries )
{
	UINTN                       EntrySize;
	UINTN                       NumEntries;
	UINTN                       BufferSize;
	UINT32                      MediaId;
	EFI_PARTITION_TABLE_HEADER *GptHeader;
	EFI_STATUS                  Status;

	MediaId = BlockIo->Media->MediaId;

	//
	// Read size of Partition entry and number of entries from GPT header
	//
	GptHeader = AllocatePool (BlockIo->Media->BlockSize);
	if (GptHeader == NULL) {
		return EFI_OUT_OF_RESOURCES;
	}

	Status = BlockIo->ReadBlocks (BlockIo, MediaId, 1, BlockIo->Media->BlockSize, (VOID *) GptHeader);
	if (EFI_ERROR (Status)) {
		return Status;
	}

	// Check there is a GPT on the media
	if (GptHeader->Header.Signature != EFI_PTAB_HEADER_ID ||
			GptHeader->MyLBA != 1) {
		DEBUG ((EFI_D_ERROR,
					"Fastboot platform: No GPT on flash. "
					"Fastboot on Versatile Express does not support MBR.\n"
		       ));
		return EFI_DEVICE_ERROR;
	}

	EntrySize = GptHeader->SizeOfPartitionEntry;
	NumEntries = GptHeader->NumberOfPartitionEntries;

	FreePool (GptHeader);

	ASSERT (EntrySize != 0);
	ASSERT (NumEntries != 0);

	BufferSize = ALIGN_VALUE (EntrySize * NumEntries, BlockIo->Media->BlockSize);
	*PartitionEntries = AllocatePool (BufferSize);
	if (PartitionEntries == NULL) {
		return EFI_OUT_OF_RESOURCES;
	}

	Status = BlockIo->ReadBlocks (BlockIo, MediaId, 2, BufferSize, (VOID *) *PartitionEntries);
	if (EFI_ERROR (Status)) {
		FreePool (PartitionEntries);
		return Status;
	}

	return Status;
}

/*
 * Initialise: Open the Android NVM device and find the partitions on it. Save them in
 * a list along with the "PartitionName" fields for their GPT entries.
 * We will use these partition names as the key in
 * HiKeyFastbootPlatformFlashPartition.
 */
EFI_STATUS InitDiskIo (	VOID )
{
	EFI_STATUS                          Status;
	EFI_DEVICE_PATH_PROTOCOL           *FlashDevicePath;
	EFI_DEVICE_PATH_PROTOCOL           *FlashDevicePathDup;
	EFI_DEVICE_PATH_PROTOCOL           *DevicePath;
	EFI_DEVICE_PATH_PROTOCOL           *NextNode;
	HARDDRIVE_DEVICE_PATH              *PartitionNode;
	UINTN                               NumHandles;
	EFI_HANDLE                         *AllHandles;
	UINTN                               LoopIndex;
	EFI_HANDLE                          FlashHandle;
	EFI_BLOCK_IO_PROTOCOL              *FlashBlockIo;
	EFI_PARTITION_ENTRY                *PartitionEntries;
	DISKIO_PARTITION_LIST            *Entry;

	InitializeListHead (&mPartitionListHead);

	Status = gBS->LocateProtocol (&gEfiSimpleTextOutProtocolGuid, NULL, (VOID **) &mTextOut);
	if (EFI_ERROR (Status)) {
		DEBUG ((EFI_D_ERROR,
					"Fastboot platform: Couldn't open Text Output Protocol: %r\n", Status
		       ));
		return Status;
	}

	//
	// Get EFI_HANDLES for all the partitions on the block devices pointed to by
	// PcdFastbootFlashDevicePath, also saving their GPT partition labels.
	// There's no way to find all of a device's children, so we get every handle
	// in the system supporting EFI_BLOCK_IO_PROTOCOL and then filter out ones
	// that don't represent partitions on the flash device.
	//

	FlashDevicePath = ConvertTextToDevicePath ((CHAR16*)FixedPcdGetPtr (PcdAndroidFastbootNvmDevicePath));

	//
	// Open the Disk IO protocol on the flash device - this will be used to read
	// partition names out of the GPT entries
	//
	// Create another device path pointer because LocateDevicePath will modify it.
	FlashDevicePathDup = FlashDevicePath;
	Status = gBS->LocateDevicePath (&gEfiBlockIoProtocolGuid, &FlashDevicePathDup, &FlashHandle);
	if (EFI_ERROR (Status)) {
		DEBUG ((EFI_D_ERROR, "Warning: Couldn't locate Android NVM device (status: %r)\n", Status));
		// Failing to locate partitions should not prevent to do other Android FastBoot actions
		return EFI_SUCCESS;
	}

	Status = gBS->OpenProtocol (
			FlashHandle,
			&gEfiBlockIoProtocolGuid,
			(VOID **) &FlashBlockIo,
			gImageHandle,
			NULL,
			EFI_OPEN_PROTOCOL_GET_PROTOCOL
			);
	if (EFI_ERROR (Status)) {
		DEBUG ((EFI_D_ERROR, "Fastboot platform: Couldn't open Android NVM device (status: %r)\n", Status));
		return EFI_DEVICE_ERROR;
	}

	// Read the GPT partition entry array into memory so we can get the partition names
	Status = ReadPartitionEntries (FlashBlockIo, &PartitionEntries);
	if (EFI_ERROR (Status)) {
		DEBUG ((EFI_D_ERROR, "Warning: Failed to read partitions from Android NVM device (status: %r)\n", Status));
		// Failing to locate partitions should not prevent to do other Android FastBoot actions
		return EFI_SUCCESS;
	}

	// Get every Block IO protocol instance installed in the system
	Status = gBS->LocateHandleBuffer (
			ByProtocol,
			&gEfiBlockIoProtocolGuid,
			NULL,
			&NumHandles,
			&AllHandles
			);
	ASSERT_EFI_ERROR (Status);

	// Filter out handles that aren't children of the flash device
	for (LoopIndex = 0; LoopIndex < NumHandles; LoopIndex++) {
		// Get the device path for the handle
		Status = gBS->OpenProtocol (
				AllHandles[LoopIndex],
				&gEfiDevicePathProtocolGuid,
				(VOID **) &DevicePath,
				gImageHandle,
				NULL,
				EFI_OPEN_PROTOCOL_GET_PROTOCOL
				);
		ASSERT_EFI_ERROR (Status);

		// Check if it is a sub-device of the flash device
		if (!CompareMem (DevicePath, FlashDevicePath, FLASH_DEVICE_PATH_SIZE (FlashDevicePath))) {
			// Device path starts with path of flash device. Check it isn't the flash
			// device itself.
			NextNode = NextDevicePathNode (DevicePath);
			if (IsDevicePathEndType (NextNode)) {
				// Create entry
				Entry = AllocatePool (sizeof (DISKIO_PARTITION_LIST));
				if (Entry == NULL) {
					Status = EFI_OUT_OF_RESOURCES;
					FreePartitionList ();
					goto Exit;
				}

				// Copy handle and partition name
				Entry->PartitionHandle = AllHandles[LoopIndex];
				StrCpy (Entry->PartitionName, L"ptable");
				InsertTailList (&mPartitionListHead, &Entry->Link);
				continue;
			}

			// Assert that this device path node represents a partition.
			ASSERT (NextNode->Type == MEDIA_DEVICE_PATH &&
					NextNode->SubType == MEDIA_HARDDRIVE_DP);

			PartitionNode = (HARDDRIVE_DEVICE_PATH *) NextNode;

			// Assert that the partition type is GPT. ReadPartitionEntries checks for
			// presence of a GPT, so we should never find MBR partitions.
			// ("MBRType" is a misnomer - this field is actually called "Partition
			//  Format")
			ASSERT (PartitionNode->MBRType == MBR_TYPE_EFI_PARTITION_TABLE_HEADER);

			// The firmware may install a handle for "partition 0", representing the
			// whole device. Ignore it.
			if (PartitionNode->PartitionNumber == 0) {
				continue;
			}

			//
			// Add the partition handle to the list
			//

			// Create entry
			Entry = AllocatePool (sizeof (DISKIO_PARTITION_LIST));
			if (Entry == NULL) {
				Status = EFI_OUT_OF_RESOURCES;
				FreePartitionList ();
				goto Exit;
			}

			// Copy handle and partition name
			Entry->PartitionHandle = AllHandles[LoopIndex];
			StrnCpy (
					Entry->PartitionName,
					PartitionEntries[PartitionNode->PartitionNumber - 1].PartitionName, // Partition numbers start from 1.
					PARTITION_NAME_MAX_LENGTH
				);
			InsertTailList (&mPartitionListHead, &Entry->Link);

			// Print a debug message if the partition label is empty or looks like
			// garbage.
			if (!IS_ALPHA (Entry->PartitionName[0])) {
				DEBUG ((EFI_D_ERROR,
					"Warning: Partition %d doesn't seem to have a GPT partition label. "
					"You won't be able to flash it with Fastboot.\n",
					PartitionNode->PartitionNumber
				       ));
			}
		}
	}

Exit:
	FreePool (PartitionEntries);
	FreePool (FlashDevicePath);
	FreePool (AllHandles);
	return Status;

}

EFI_STATUS RsvdDiskRead ( IN VOID   *Image,
			  IN UINTN   Size )
{
	EFI_STATUS               Status;
	EFI_BLOCK_IO_PROTOCOL   *BlockIo;
	EFI_DISK_IO_PROTOCOL    *DiskIo;
	UINT32                   MediaId;
	UINTN                    PartitionSize;
	DISKIO_PARTITION_LIST *Entry;
	CHAR16                   PartitionNameUnicode[60];
	BOOLEAN                  PartitionFound;

	CHAR8 PartitionName[] = "reserved";

	AsciiStrToUnicodeStr (PartitionName, PartitionNameUnicode);
/*
	CHAR16 printbuf[100];
	UnicodeSPrint (printbuf, sizeof (printbuf), L"HIKEY: Flashing partion %s, size %d\r\n", PartitionNameUnicode, Size);
	mTextOut->OutputString (mTextOut, printbuf);
*/
	PartitionFound = FALSE;
	Entry = (DISKIO_PARTITION_LIST *) GetFirstNode (&(mPartitionListHead));
	while (!IsNull (&mPartitionListHead, &Entry->Link)) {
		// Search the partition list for the partition named by PartitionName
		if (StrCmp (Entry->PartitionName, PartitionNameUnicode) == 0) {
			PartitionFound = TRUE;
			break;
		}

		Entry = (DISKIO_PARTITION_LIST *) GetNextNode (&mPartitionListHead, &(Entry)->Link);
	}
	if (!PartitionFound) {
		return EFI_NOT_FOUND;
	}

	Status = gBS->OpenProtocol (
			Entry->PartitionHandle,
			&gEfiBlockIoProtocolGuid,
			(VOID **) &BlockIo,
			gImageHandle,
			NULL,
			EFI_OPEN_PROTOCOL_GET_PROTOCOL
			);
	if (EFI_ERROR (Status)) {
		DEBUG ((EFI_D_ERROR, "Fastboot platform: couldn't open Block IO for flash: %r\n", Status));
		return EFI_NOT_FOUND;
	}

	// Check image will fit on device
	PartitionSize = (BlockIo->Media->LastBlock + 1) * BlockIo->Media->BlockSize;
	if (PartitionSize < Size) {
		DEBUG ((EFI_D_ERROR, "Partition not big enough.\n"));
		DEBUG ((EFI_D_ERROR, "Partition Size:\t%ld\nImage Size:\t%ld\n", PartitionSize, Size));

		return EFI_VOLUME_FULL;
	}

	MediaId = BlockIo->Media->MediaId;

	Status = gBS->OpenProtocol (
			Entry->PartitionHandle,
			&gEfiDiskIoProtocolGuid,
			(VOID **) &DiskIo,
			gImageHandle,
			NULL,
			EFI_OPEN_PROTOCOL_GET_PROTOCOL
			);
	ASSERT_EFI_ERROR (Status);

	Status = DiskIo->ReadDisk (DiskIo, MediaId, 0, Size, Image);

	if (EFI_ERROR (Status)) {
		return Status;
	}

	BlockIo->FlushBlocks(BlockIo);
/*
	int i, size;

	for(i=0, size=0; i<8; i++)
	{
		size = (((char *)Image)[i] - '0') + (size * 10);
	}

	UnicodeSPrint (printbuf, sizeof (printbuf), L"Nvme converted string = %d\r\n", size);
	mTextOut->OutputString (mTextOut, printbuf);

	char * temp = (char *)Image + size + 8;
	for(i=0, size=0; i<8; i++)
	{
		size = (temp[i] - '0') + (size * 10);
	}

	UnicodeSPrint (printbuf, sizeof (printbuf), L"Nvme converted string = %d\r\n", size);
	mTextOut->OutputString (mTextOut, printbuf);
*/
	return Status;
}
