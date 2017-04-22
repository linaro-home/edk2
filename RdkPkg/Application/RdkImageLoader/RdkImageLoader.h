
#ifndef __RDKIMAGE_LOADER_H__
#define __RDKIMAGE_LOADER_H__

#include <Library/BdsLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PerformanceLib.h>
#include <Library/PrintLib.h>
#include <Library/ShellLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/DevicePathLib.h>

//#include <Protocol/ShellParameters.h>
//#include <Protocol/Shell.h>


//#define RDK_LINUX_KERNEL_NAME               L"fs0:\\Image"
//
// Definitions
//
#endif /* __RDKIMAGE_LOADER_H__ */


EFI_STATUS
EFIAPI
OpenFileByDevicePath(
  IN OUT EFI_DEVICE_PATH_PROTOCOL           **FilePath,
  OUT EFI_FILE_HANDLE                       *FileHandle,
  IN UINT64                                 OpenMode,
  IN UINT64                                 Attributes
);

CHAR16 *
ExtractFileNameFromDevicePath (
  IN   EFI_DEVICE_PATH_PROTOCOL *DevicePath
  );


typedef enum KEY
{
	PK_KEY=1,
	KEK_KEY,
	DB_KEY,
	DBX_KEY
}eKey;






