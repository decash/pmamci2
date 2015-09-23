#include "module.h"
#include <sys/wait.h>
#include <pthread.h>

CModule::CModule(int nParentProcessID, mach_vm_address_t startAddress, mach_vm_size_t size, vm_region_basic_info_data_t info, int nDisplayMemLineCount)
{
	m_nParentProcessID = nParentProcessID;
	m_lStartAddress    = startAddress ;
	m_lEndAddress      = startAddress + size;
	m_lMemorySize      = size;
	m_info             = info;
	m_nDisplayMemLineCount = nDisplayMemLineCount;
}

void CModule::SetDisplayLineCount(int nDisplayLineCount)
{
	m_nDisplayMemLineCount = nDisplayLineCount;
}

int CModule::GetDumpMemory(unsigned char* pDumpData)
{
	// 1. task_for_pid
	vm_map_t target_task = 0;
	kern_return_t ret;
	if (task_for_pid(mach_task_self(), m_nParentProcessID, &target_task))
	{
		printf("Can't execute task_for_pid!");
		return -1;
	}

	// 2. mach_vm_read_overwrite
	mach_vm_size_t readcnt = 0;
	ret = mach_vm_read_overwrite(target_task, m_lStartAddress, m_lMemorySize, (mach_vm_address_t)pDumpData, &readcnt);

	if (ret != KERN_SUCCESS)
	{
		printf("Fail to Dump Memory: %p, size : %d\n", (void*)m_lStartAddress, (int)m_lMemorySize); 
		return -2;
	}
	return 1;
}


string CModule::GetStrMemorySize()
{
	char strFileSize[20];
	memset(strFileSize, 0x00, 20);

	if     ( m_lMemorySize >= 1048576 )
		sprintf(strFileSize, "%ldMb", (long)m_lMemorySize / 1048576);
	else if( m_lMemorySize > 1024 )
		sprintf(strFileSize, "%ldKb", (long)m_lMemorySize / 1024);
	else   
		sprintf(strFileSize, "%ldb",  (long)m_lMemorySize);

	return string(strFileSize);
}


bool CModule::SearchOfMemory(vector<string>& vStrSearchList, bool bExtraSearch)
{
	// 1. task_for_pid
	vm_map_t target_task = 0;
	kern_return_t ret;
	if (task_for_pid(mach_task_self(), m_nParentProcessID, &target_task))
	{
		printf("Can't execute task_for_pid!");
		return false;
	}
	
	uint8_t* pData = (uint8_t*) malloc(m_lMemorySize);	
	if(pData == NULL) return false;

	// 2. mach_vm_read_overwrite
	mach_vm_size_t readcnt = 0;
	//task_suspend(target_task);
	ret = mach_vm_read_overwrite(target_task, m_lStartAddress, m_lMemorySize, (mach_vm_address_t)pData, &readcnt);
	//task_resume(target_task);


	if (ret != KERN_SUCCESS)
	{
		/*
		printf("--TEST Fail to Dump Memory: %x, size : %ld RET : x%x\n", (unsigned int)m_lStartAddress, (long)m_lMemorySize, ret); 
		printf ("0x%08x - 0x%08x[%6s] (%s/%s, %15s, %8s) %s %s \n",
			(unsigned int)m_lStartAddress,
			(unsigned int)m_lEndAddress,
			GetStrMemorySize().c_str(),
			protection_bits_to_rwx (m_info.protection).c_str(),
			protection_bits_to_rwx (m_info.max_protection).c_str(),
			GetShareMode(m_info.share_mode).c_str(),
			behavior_to_text (m_info.behavior).c_str(),
			unparse_inheritance (m_info.inheritance).c_str(),
			m_info.is_submap ? "submap" : "object" );
		*/
		free(pData);
		return false;
	}


	bool bSearchResult = false;
	vector<string>::iterator itr;
	for(itr = vStrSearchList.begin(); itr < vStrSearchList.end(); itr++)
	{
		string strKeyword = *itr;
		//cout << "  [*] TRY TO SEARCH [" << strKeyword << "] " << endl;

		int nKeywordSize = strKeyword.size();
		unsigned char* pStrKeyword = (unsigned char*) malloc(nKeywordSize);
		unsigned char* pUniKeyword = (unsigned char*) malloc(nKeywordSize * 2);
		memset(pStrKeyword, 0x00, nKeywordSize  );
		memset(pUniKeyword, 0x00, nKeywordSize*2);
		
		memcpy(pStrKeyword, strKeyword.c_str(), nKeywordSize);
		for(int i = 0; i < nKeywordSize; i++)
			pUniKeyword[i*2] = strKeyword[i];

		// SEARCHING for String Keyword
		for(long int i = 0; i < m_lMemorySize-nKeywordSize; i++)
		{
			if(memcmp(pData+i, pStrKeyword, nKeywordSize) == 0)
			{

				DisplayMemoryData(pData, i, m_nDisplayMemLineCount, SEARCH_TYPE_STRING);
				bSearchResult = true;
			}
		}

		// SEARCHING for UNICODE Keyword
		for(long int i = 0; i < m_lMemorySize-(nKeywordSize*2); i++)
		{
			if(memcmp(pData+i, pUniKeyword, nKeywordSize * 2) == 0)
			{
				DisplayMemoryData(pData, i, m_nDisplayMemLineCount, SEARCH_TYPE_UNICODE);
				bSearchResult = true;
			}
		}

		/*	
		// EXTRA SEARCH
		if( bExtraSearch == true )
		{
			// SEARCHING for STRING to BASE64 Keyword 
			string strSTRBase64Keyword = base64_encode(pStrKeyword, nKeywordSize);
			for(int i = 0; i < m_lMemorySize; i++)
			{
				if(memcmp(pData+i, strSTRBase64Keyword.c_str(), strSTRBase64Keyword.size()) == 0)
				{
					DisplayMemoryData(pData, i, m_nDisplayMemLineCount, SEARCH_TYPE_BASE64);
				}
			}
			
			// SEARCHING for UNICODE to BASE64 Keyword 
			string strUNIBase64Keyword = base64_encode(pUniKeyword, nKeywordSize*2);
			for(int i = 0; i < m_lMemorySize; i++)
			{
				if(memcmp(pData+i, strUNIBase64Keyword.c_str(), strUNIBase64Keyword.size()) == 0)
				{
					DisplayMemoryData(pData, i, m_nDisplayMemLineCount, SEARCH_TYPE_BASE64);
				}
			}

			// SEARCHING for STRING to MD5 Keyword 
			md5_state_t state;
			md5_byte_t digest[16];
			char hex_output[16*2 + 1];

			md5_init(&state);
			md5_append(&state, (const md5_byte_t*)pStrKeyword, nKeywordSize);
			md5_finish(&state, digest); 

			//for (int di = 0; di < 16; ++di)
			//sprintf(hex_output + di * 2, "%02x", digest[di]);
			//cout << "md5 : " << string(hex_output) << endl;
		
			for(int i = 0; i < m_lMemorySize; i++)
			{
				if(memcmp(pData+i, digest, 16) == 0)
				{
					DisplayMemoryData(pData, i, m_nDisplayMemLineCount, SEARCH_TYPE_BASE64);
				}
			}
		}
		*/

		free(pStrKeyword);
		free(pUniKeyword);
	}
	free(pData);
	return bSearchResult;
}

bool CModule::ReplaceOfMemory(vector<string>& vStrReplaceList)
{
	// 1. task_for_pid
	vm_map_t target_task = 0;
	kern_return_t ret;
	if (task_for_pid(mach_task_self(), m_nParentProcessID, &target_task))
	{
		printf("Can't execute task_for_pid!");
		return false;
	}
	
	// 2. mach_vm_read_overwrite
	uint8_t* pData = (uint8_t*) malloc(m_lMemorySize);	
	if(pData == NULL) return false;

	mach_vm_size_t readcnt = 0;
	ret = mach_vm_read_overwrite(target_task, m_lStartAddress, m_lMemorySize, (mach_vm_address_t)pData, &readcnt);

	if (ret != KERN_SUCCESS)
	{
		//printf("Fail to Dump Memory: %x, size : %ld\n", (unsigned int)m_lStartAddress, (long)m_lMemorySize); 
		free(pData);
		return false;
	}

	int nReplaceCnt = vStrReplaceList.size() / 2;
	for(int cnt = 0; cnt < nReplaceCnt; cnt++)
	{
		string strKeyword        = vStrReplaceList[cnt*2    ];
		string strReplaceKeyword = vStrReplaceList[cnt*2 + 1];


		int nKeywordSize = strKeyword.size();
		unsigned char* pStrKeyword        = (unsigned char*) malloc(nKeywordSize);
		unsigned char* pStrReplaceKeyword = (unsigned char*) malloc(nKeywordSize);
		unsigned char* pUniKeyword        = (unsigned char*) malloc(nKeywordSize * 2);
		unsigned char* pUniReplaceKeyword = (unsigned char*) malloc(nKeywordSize * 2);
		memset(pStrKeyword,        0x00, nKeywordSize  );
		memset(pStrReplaceKeyword, 0x00, nKeywordSize  );
		memset(pUniKeyword,        0x00, nKeywordSize*2);
		memset(pUniReplaceKeyword, 0x00, nKeywordSize*2);

		memcpy(pStrKeyword,        strKeyword.c_str(),        nKeywordSize);
		memcpy(pStrReplaceKeyword, strReplaceKeyword.c_str(), nKeywordSize);
		for(int i = 0; i < nKeywordSize; i++)
		{
			pUniKeyword[i*2]        = strKeyword[i];
			pUniReplaceKeyword[i*2] = strReplaceKeyword[i];
		}


		//cout << "  [*] TRY TO Replace [" << strKeyword << "] > [" << strReplaceKeyword << "] " << endl;
		
		// SEARCHING for String Keyword
		for(int i = 0; i < m_lMemorySize-nKeywordSize; i++)
		{
			if(memcmp(pData+i, pStrKeyword, nKeywordSize) == 0)
			{
				DisplayMemoryData(pData, i, m_nDisplayMemLineCount, SEARCH_TYPE_STRING);

				memcpy(pData+i, pStrReplaceKeyword, nKeywordSize);
				
			        /*	
				char strCheck[100];
				memset(strCheck, 0x00, 100);
				cout << " [*] Do YOU WANT CHANGE(c) or NOT(enter) : ";
				cin.getline(strCheck, 100);
				if(strCheck[0] == 'c')
				*/

				{
					vm_map_t target_task = 0;
					kern_return_t ret;
					if (task_for_pid(mach_task_self(), m_nParentProcessID, &target_task))
					{
						printf("Can't execute task_for_pid!");
						return false;
					}

					ret = mach_vm_write(target_task, m_lStartAddress+i, (vm_offset_t)pStrReplaceKeyword, (mach_msg_type_number_t)nKeywordSize);
					if( ret != KERN_SUCCESS )
					{
						printf("mach_vm_write failed at 0x%x with error!\n ", (unsigned int)m_lStartAddress+i);
						return false;
					}

					DisplayMemoryData(pData, i, m_nDisplayMemLineCount, REPLACE_TYPE_STRING);
				}
			}
		}

		// SEARCHING for UNICODE Keyword
		for(int i = 0; i < m_lMemorySize-(nKeywordSize*2); i++)
		{
			if(memcmp(pData+i, pUniKeyword, nKeywordSize * 2) == 0)
			{
				DisplayMemoryData(pData, i, m_nDisplayMemLineCount, SEARCH_TYPE_UNICODE);

				memcpy(pData+i, pUniReplaceKeyword, nKeywordSize*2);

				/*	
					char strCheck[100];
					memset(strCheck, 0x00, 100);
					cout << " [*] Do YOU WANT CHANGE(c) or NOT(enter) : ";
					cin.getline(strCheck, 100);
					if(strCheck[0] == 'c')
				*/
			
				{
					vm_map_t target_task = 0;
					kern_return_t ret;
					if (task_for_pid(mach_task_self(), m_nParentProcessID, &target_task))
					{
						printf("Can't execute task_for_pid!");
						return false;
					}

					// input bytes is big endian but it will be written little endian 
					ret = mach_vm_write(target_task, m_lStartAddress+i, (vm_offset_t)pUniReplaceKeyword, (mach_msg_type_number_t)nKeywordSize*2);
					if( ret != KERN_SUCCESS )
					{
						printf("mach_vm_write failed at 0x%x with error!\n ", (unsigned int)m_lStartAddress+i);
						return false;
					}

					DisplayMemoryData(pData, i, m_nDisplayMemLineCount, REPLACE_TYPE_UNICODE);
				}
			}
		}			

		free(pStrKeyword);
		free(pUniKeyword);
	}
	free(pData);
	return true;
}

void CModule::DisplayMemoryData(unsigned char* pData, int nSearchPoint, int nLineNumber, int nSearchType)
{
	if(nLineNumber < 3) 
		nLineNumber = 3;
	int nStartLine = (nLineNumber)  / 2;

	if     ( nSearchType == SEARCH_TYPE_STRING )
		printf("-FIND STRING AT [%08x]----------------------------------------------------\n", (unsigned int)m_lStartAddress + nSearchPoint);
	
	else if( nSearchType == SEARCH_TYPE_UNICODE )
		printf("-FIND UNICODE AT [%08x]---------------------------------------------------\n", (unsigned int)m_lStartAddress + nSearchPoint);

	else if( nSearchType == SEARCH_TYPE_BASE64 )
		printf("-FIND BASE64 ENCODED STRING AT [%08x]-------------------------------------\n", (unsigned int)m_lStartAddress + nSearchPoint);
	
	else if( nSearchType == REPLACE_TYPE_STRING )
		printf("-REPLACE STRING AT [%08x]-------------------------------------------------\n", (unsigned int)m_lStartAddress + nSearchPoint);
	
	else if( nSearchType == REPLACE_TYPE_UNICODE )
		printf("-REPLACE UNICODE STRING AT [%08x]-----------------------------------------\n", (unsigned int)m_lStartAddress + nSearchPoint);

	// FORMAT
	// 0x12345678  11 22 33 44 55 66 77 88 99 00 11 22 33 44 55 66  1.2.3.4.5.6.7.8. 
	// 0x12345678  11 22 33 44 55 66 77 88 99 00 11 22 33 44 55 66  F.I.N.D.S.T.R.01 
	// 0x12345678  11 22 33 44 55 66 77 88 99 00 11 22 33 44 55 66  FINDSTR123456789 
	// 0x12345678  11 22 33 44 55 66 77 88 99 00 11 22 33 44 55 66  1234567890123456 
	for(int i = 0; i < nLineNumber; i++)
	{
		int nOffset = nSearchPoint + 16 * (i-nStartLine);

		if(nOffset <= m_lMemorySize)
		{
			// 1. address 
			printf("0x%08x", (unsigned int)m_lStartAddress + nOffset );
			printf("  ");

			// 2. HEX
			for(int j = 0; j < 16; j++)
			{
				printf("%02x ", pData[nOffset + j] ); 
			}
			printf("  ");

			// 3. CHAR
			for(int j = 0; j <16; j++)
			{
				unsigned char ch = pData[nOffset + j];
				if( ch >= 33 && ch <= 125 ) printf("%c", ch); 
				else	                    printf("."); 
			}
			printf("\n");
		}
	}

	/*
        if     ( nSearchType == REPLACE_TYPE_STRING )
		printf("------------------------------------------------------------------------------\n");
	
	else if( nSearchType == REPLACE_TYPE_UNICODE )
		printf("------------------------------------------------------------------------------\n");
	*/
		printf("------------------------------------------------------------------------------\n");

	printf("\n");


}

long int CModule::GetStartAddress()
{
	return m_lStartAddress;
}

long int CModule::GetEndAddress()
{
	return m_lEndAddress;
}

long int CModule::GetMemorySize()
{
	return m_lMemorySize;
}

int CModule::GetParentProcessID()
{
	return m_nParentProcessID;
}

void CModule::SetModuleName(string strModuleName)
{
	m_strModuleName.clear();
	m_strModuleName = strModuleName;
}

string CModule::GetModuleName()
{
	return m_strModuleName;
}

void CModule::DisplayVMRegionInfo()
{
	printf ("0x%08x - 0x%08x[%6s] (%s/%s) %s %s \n",
			(unsigned int)m_lStartAddress,
			(unsigned int)m_lEndAddress,
			GetStrMemorySize().c_str(),
			
			protection_bits_to_rwx (m_info.protection).c_str(),
			protection_bits_to_rwx (m_info.max_protection).c_str(),
			
			//GetShareMode(m_info.share_mode).c_str(),
			//GetFileType(header.filetype).c_str(),
			//GetFlags(header.flags).c_str() );
			
			behavior_to_text (m_info.behavior).c_str(),
			unparse_inheritance (m_info.inheritance).c_str() );
			//m_info.is_submap ? "submap" : "object" );
}

string CModule::GetFlags(unsigned long lnFlags)
{
	switch( lnFlags )
	{
		 case MH_NOUNDEFS:
		 	return string("NOUNDEFS");
		 case MH_INCRLINK:
		 	return string("INCRLINK");
		 case MH_DYLDLINK://                = 0x00000004u,
		 	return string("DYLDLINK");
		 case MH_BINDATLOAD://              = 0x00000008u,
		 	return string("BINDATLOAD");
		 case MH_PREBOUND://                = 0x00000010u,
		 	return string("PREBOUND");
		 case MH_SPLIT_SEGS://              = 0x00000020u,
		 	return string("SPLIT_SEGS");
		 case MH_LAZY_INIT ://               = 0x00000040u,
		 	return string("LAZY_INIT");
		 case MH_TWOLEVEL ://                = 0x00000080u,
		 	return string("TWOLEVEL");
		 case MH_FORCE_FLAT ://              = 0x00000100u,
		 	return string("FORCE_FLAT");
		 case MH_NOMULTIDEFS ://             = 0x00000200u,
		 	return string("NOMULTIDEFS");
		 case MH_NOFIXPREBINDING ://         = 0x00000400u,
		 	return string("NOFIXPREBINDING");
		 case MH_PREBINDABLE ://             = 0x00000800u,
		 	return string("PREBINDABLE");
		 case MH_ALLMODSBOUND ://            = 0x00001000u,
		 	return string("ALLMODSBOUND");
		 case MH_SUBSECTIONS_VIA_SYMBOLS :// = 0x00002000u,
		 	return string("SUBSECTION_VIA_SYMBOLS");
		 case MH_CANONICAL ://               = 0x00004000u,
		 	return string("CANONICAL");
		 case MH_WEAK_DEFINES ://            = 0x00008000u,
		 	return string("WEAK_DEFINES");
		 case MH_BINDS_TO_WEAK ://           = 0x00010000u,
		 	return string("BINDS_TO_WEAK");
		 case MH_ALLOW_STACK_EXECUTION ://   = 0x00020000u,
		 	return string("ALLOW_STACK_EXECUTION");
		 case MH_ROOT_SAFE ://               = 0x00040000u,
		 	return string("ROOT_SAFE");
		 case MH_SETUID_SAFE ://             = 0x00080000u,
		 	return string("SETUID_SAFE");
		 case MH_NO_REEXPORTED_DYLIBS ://    = 0x00100000u,
		 	return string("NO_REEXPORTED_DYLIBS");
		 case MH_PIE ://                     = 0x00200000u,
		 	return string("PIE");
		 case MH_DEAD_STRIPPABLE_DYLIB ://   = 0x00400000u,
		 	return string("DEAD_STRIPPABLE_DYLIB");
		 case MH_HAS_TLV_DESCRIPTORS ://     = 0x00800000u,
		 	return string("HAS_TLV_DESCRIPTORS");
		 case MH_NO_HEAP_EXECUTION ://       = 0x01000000u,
		 	return string("NO_HEAP_EXECUTION");
		 //case MH_APP_EXTENSION_SAFE:
		 //	return string("APP_EXTENSION_SAFE");
		default:
			return string("?????");
	}
}
string CModule::GetFileType(unsigned long lnFileType)
{
	switch( lnFileType )
	{
		case MH_OBJECT:
			return string("OBJECT");
		case MH_EXECUTE:
			return string("EXECUTE");
		case MH_FVMLIB:
			return string("FVMLIB");
		case MH_CORE:
			return string("CORE");
		case MH_PRELOAD:
			return string("PRELOAD");
		case MH_DYLIB:
			return string("DYLIB");
		case MH_DYLINKER:
			return string("DYLINKER");
		case MH_BUNDLE:
			return string("BUNDLE");
		case MH_DYLIB_STUB:
			return string("DYLIB_STUB");
		case MH_DSYM:
			return string("DSYM");
		case MH_KEXT_BUNDLE:
			return string("KEXT_BUNDLE");
		default:
			return string("????");
		/*

			case	MH_OBJECT:
				return string("OBJECT");
			case	MH_EXECUTE:
				return string("EXECUTE");
			case	MH_FVMLIB:	
				return string("FVMLIB");
			case	MH_CORE:
				return string("CORE");
			case	MH_PRELOAD:
				return string("PRELOAD");
			case	MH_DYLIB:
				return string("DYLIB");
			case	MH_DYLINKER:
				return string("DYLINKER");
			case	MH_BUNDLE:
				return string("BUNDLE");
			case	MH_DYLIB_STUB:
				return string("DYLIB_STUB");
			case	MH_DSYM:
				return string("DSYM");
			case	MH_KEXT_BUNDLE:
				return string("KEXT_BUNDLE");
			case	MH_NOUNDEFS:
				return string("NOUNDEFS");
			case	MH_INCRLINK:
				return string("INCRLINK");
			case	MH_DYLDLINK:
				return string("DYLDLINK");
			case	MH_BINDATLOAD:
				return string("BINDATLOAD");
			case	MH_PREBOUND:
				return string("PREBOUND");
			case	MH_SPLIT_SEGS:
				return string("SPLIT_SEGS");
			case	MH_LAZY_INIT:
				return string("LAZY_INIT");
			case	MH_TWOLEVEL:
				return string("TWOLEVEL");
			case	MH_FORCE_FLAT:
				return string("FORCE_FLAT");
			case	MH_NOMULTIDEFS:
				return string("NOMULTIDEFS");
			case	MH_NOFIXPREBINDING:
				return string("NOFIXPREBINDING");
			case	MH_PREBINDABLE:
				return string("PREBINDABLE");
			case	MH_ALLMODSBOUND:
				return string("ALLMODSBOUND");
			case	MH_SUBSECTIONS_VIA_SYMBOLS:
				return string("SUBSECTIONS_VIA_SYMBOLS");
			case	MH_CANONICAL:
				return string("MH_CANONICAL");
			case	MH_WEAK_DEFINES:
				return string("WEAK_DEFINES");
			case	MH_BINDS_TO_WEAK:
				return string("BINDS_TO_WEAK");
			case	MH_ALLOW_STACK_EXECUTION: 
				return string("ALLOW_STACK_EXECUTION");
			case	MH_ROOT_SAFE: 
				return string("ROOT_SAFE");
			case	MH_SETUID_SAFE:
				return string("SETUID_SAFE");
			case	MH_NO_REEXPORTED_DYLIBS:
				return string("NO_REEXPORTED_DYLIBS");
			case	MH_PIE:
				return string("PID");
			case	MH_DEAD_STRIPPABLE_DYLIB:
				return string("DEAD_STRIPPABLE_DYLIB");
			case	MH_HAS_TLV_DESCRIPTORS:
				return string("HAS_TLV_DESCRIPTORS");
			case	MH_NO_HEAP_EXECUTION:
				return string("NO_HEAP_EXECUTION");
			default:
				return string("???????");
				*/

	}

}

string CModule::GetShareMode(unsigned char chShareMode)
{
	switch( chShareMode )
	{
		case SM_COW:
			return string("SM_COW");
		case SM_PRIVATE:
			return string("SM_PRIVATE");
		case SM_EMPTY:
			return string("SM_EMPTY");
		case SM_SHARED:
			return string("SM_SHARED");
		case SM_TRUESHARED:
			return string("SM_TRUESHARED");
		case SM_PRIVATE_ALIASED: 
			return string("SM_PRIVATE_ALIASED");
		case SM_SHARED_ALIASED:
			return string("SM_SHARED_ALIASED");
		default:
			return string("???");

	}
}

string CModule::protection_bits_to_rwx (vm_prot_t p)
{
	char returned[4];

	returned[0] = (p & VM_PROT_READ    ? 'r' : '-');
	returned[1] = (p & VM_PROT_WRITE   ? 'w' : '-');
	returned[2] = (p & VM_PROT_EXECUTE ? 'x' : '-');
	returned[3] = '\0';

	return string(returned);
}

string CModule::unparse_inheritance (vm_inherit_t i)
{
	switch (i)
	{
		case VM_INHERIT_SHARE:
			return string("share");
		case VM_INHERIT_COPY:
			return string("copy");
		case VM_INHERIT_NONE:
			return string("none");
		default:
			return string("???");
	}
}

string CModule::behavior_to_text (vm_behavior_t b)
{
	switch (b)
	{
		case VM_BEHAVIOR_DEFAULT: return string("default");
		case VM_BEHAVIOR_RANDOM:  return string("random");
		case VM_BEHAVIOR_SEQUENTIAL: return string("fwd-seq");
		case VM_BEHAVIOR_RSEQNTL: return string("rev-seq");
		case VM_BEHAVIOR_WILLNEED: return string("will-need");
		case VM_BEHAVIOR_DONTNEED: return string("will-need");
		case VM_BEHAVIOR_FREE: return string("free-nowb");
		case VM_BEHAVIOR_ZERO_WIRED_PAGES: return string("zero-wire");
		case VM_BEHAVIOR_REUSABLE: return string("reusable");
		case VM_BEHAVIOR_REUSE: return string("reuse");
		case VM_BEHAVIOR_CAN_REUSE: return string("canreuse");
		default: return string("?");
	}


}
