#ifndef __MODULE_H__
#define __MODULE_H__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <iostream>
#include <iostream>
#include <vector>
#include <ctype.h>
#include "base64.h"
#include "md5.h"

#define SEARCH_TYPE_STRING     10001
#define SEARCH_TYPE_UNICODE    10002
#define SEARCH_TYPE_BASE64     10003

#define REPLACE_TYPE_STRING    20001
#define REPLACE_TYPE_UNICODE   20002
#define REPLACE_TYPE_BASE64    20003

#if !defined (__arm__)
#include <mach/mach_vm.h>
#endif
#include <mach/mach.h> 
#include <mach/vm_region.h>
#include <mach/vm_map.h>
#include <mach-o/loader.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <libkern/OSByteOrder.h>

//#define SEARCH_TYPE_STRING 0x00001
//#define REPLACE_TYPE_STRING 0x000022
#define   DEFAULT_DISP_LINE_COUNT 3

#ifndef DYLD_ALL_IMAGE_INFOS_OFFSET_OFFSET
	#define DYLD_ALL_IMAGE_INFOS_OFFSET_OFFSET 0x1010
#endif

#ifdef __cplusplus
extern "C" {
#endif

	/* for iOS */
#if defined (__arm__)
	extern kern_return_t mach_vm_region
		(
		 vm_map_t target_task,
		 mach_vm_address_t *address,
		 mach_vm_size_t *size,
		 vm_region_flavor_t flavor,
		 vm_region_info_t info,
		 mach_msg_type_number_t *infoCnt,
		 mach_port_t *object_name
		);

	extern kern_return_t mach_vm_read_overwrite
		(
		 vm_map_t target_task,
		 mach_vm_address_t address,
		 mach_vm_size_t size,
		 mach_vm_address_t data,
		 mach_vm_size_t *outsize
		);

	extern kern_return_t mach_vm_read
		(
		 vm_map_t target_task,
		 mach_vm_address_t address,
		 mach_vm_size_t size,
		 vm_offset_t *data,
		 mach_msg_type_number_t *dataCnt
		);



	extern kern_return_t mach_vm_protect
		(
		 vm_map_t target_task,
		 mach_vm_address_t address,
		 mach_vm_size_t size,
		 boolean_t set_maximum,
		 vm_prot_t new_protection
		);

	extern kern_return_t mach_vm_write
		(
		 vm_map_t target_task,
		 mach_vm_address_t address,
		 vm_offset_t data,
		 mach_msg_type_number_t dataCnt
		);

#endif

#ifdef __cplusplus
}
#endif


using namespace std;

class CModule
{
	private:
		int      m_nParentProcessID;
		int      m_nDisplayMemLineCount;
		string   m_strModuleName;
		mach_vm_address_t m_lStartAddress;
		mach_vm_address_t m_lEndAddress;
		mach_vm_size_t    m_lMemorySize;
		vm_region_basic_info_data_t m_info;
		
		string GetFileType(unsigned long lnFileType);
		string GetShareMode(unsigned char chShareMode);
		string protection_bits_to_rwx (vm_prot_t p);
		string unparse_inheritance (vm_inherit_t i);
		string behavior_to_text (vm_behavior_t b);
		string GetFlags(unsigned long lnFlags);

	public:
		CModule(int nParentProcessID, mach_vm_address_t startAddress, mach_vm_size_t size, vm_region_basic_info_data_t info, int nDisplayMemLineCount);

		// GET & SET
		long int GetStartAddress();
		long int GetEndAddress();
		long int GetMemorySize();
		string   GetStrMemorySize();
		int      GetParentProcessID();
		string   GetModuleName();
		void     SetModuleName(string strModuleName);
	        
		int      GetDumpMemory    (unsigned char* pDumpData);
	
		bool     SearchOfMemory (vector<string>& vStrSearchList, bool bExtraSearch = false);
		bool     ReplaceOfMemory(vector<string>& vStrReplaceList);

		void     DisplayMemoryData(unsigned char* pData, int SearchPoint, int nLineNumber, int nSearchType);
		void     DisplayVMRegionInfo();

		void     SetDisplayLineCount(int nDisplayLineCount);
		
};
#endif
