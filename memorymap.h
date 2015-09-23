#ifndef __MEMORY_MAP_H__
#define __MEMORY_MAP_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <sys/types.h>
#include <vector>
#include <dirent.h>
#include <sys/stat.h>
#include <iterator>
#include "module.h"

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

class CMemoryMap 
{
	private:
		int             m_nProcessID;
		vector<CModule> m_vModuleList;
		string          m_strProcessName;
		int             m_nDisplayMemLineCount;
		string          m_strHomePath;
		int             m_niOSVersion;
		string          m_strAppPath;

	private:	
		string GetProcessNameUsingProcessID(string strProcessID);
		bool IsReadWrite(vm_prot_t protection);
	
	public:
		// Constructor
		CMemoryMap();

		// Get & Set 
		int    GetProcessID();
		int    SetProcessID(string strProcessID);
		string GetProcessName();
		//int    GetAllModuleInfo(vector<string>& vStrModuleList);
		//int    GetAllModuleName(vector<string>& vStrModuleList);
		int    GetProcessListByName(vector<string>& vProcessList, string strProcessName);
		int    GetModuleCount();
		string GetHomePath();

		// ModuleList Functions
		bool            LoadModuleList();
		vector<CModule> GetModuleList();
		void            ClearModuleList();
		

		void    DisplayLoadLibraryList();
		bool    DisplayAllVMRegionInfo();
		bool    SearchItem(vector<string> vStrSearchItemList);
		bool    ReplaceItem(vector<string> vStrReplaceItemList);

		void    SetDisplayLineCount(int nDisplayMemLineCount);
		void    SetiOSVersion(int niOSVersion);
};

#endif
