#include "memorymap.h"

CMemoryMap::CMemoryMap()
{
	m_vModuleList.clear();
	m_nProcessID = -1;
	m_strProcessName.clear();
	m_nDisplayMemLineCount = 3;
}


void CMemoryMap::SetDisplayLineCount(int nDisplayMemLineCount)
{
	m_nDisplayMemLineCount = nDisplayMemLineCount;	
}
	

int CMemoryMap::GetModuleCount()
{
	return m_vModuleList.size();
}

int CMemoryMap::GetProcessID()
{
	return m_nProcessID;
}

string CMemoryMap::GetProcessName()
{
	return m_strProcessName;
}

int CMemoryMap::SetProcessID(string strProcessID)
{
	m_nProcessID = atoi(strProcessID.c_str());
	m_strProcessName = GetProcessNameUsingProcessID(strProcessID);
	
	if( m_strProcessName.empty() == true )
	{
		m_nProcessID = -1;
		return -1;
	}

        // /var/mobile/Applications/B04484A3-C6EF-439C-8556-3DFFB5A0B221/SmartPIB.app/SmartPIB(434)	
	int nPos = m_strProcessName.find_last_of("/\\");
	    nPos = m_strProcessName.substr(0, nPos).find_last_of("/\\");
	m_strHomePath = m_strProcessName.substr(0, nPos+1);
	
	return 1;
}

int CMemoryMap::GetProcessListByName(vector<string>& vProcessList, string strProcessName)
{
	int status = 0;
	int count = 0;
	char line[400];
	vProcessList.clear();

	cout << "+ SEARCH PROCESS LIST OF KEYWORD : " << strProcessName << endl;

	//FILE *fp = popen("ps -ef | grep /mobile/Applications", "r"); // for iOS
	//FILE *fp = popen("ps -ef | grep /mobile/Containers", "r"); // for iOS
	//FILE *fp = popen("ps -ef", "r"); // for OSX
	string strFindCommand("ps -ef | grep ");
	strFindCommand += m_strAppPath;

	FILE *fp = popen(strFindCommand.c_str(), "r"); // for iOS
	memset(line, 0x00, 400);

	while (1)
	{
		if( fgets(line, 400, fp) == NULL )
		{
			if(count == 0)
			{
				cout << "+ can not find Process of " << strProcessName << endl;
				return -1;
			}
			else
				cout << "+ find Process list of "    << strProcessName << endl;
			break;
		}

		string strLine(line);
		//if( strLine.find( strProcessName ) != -1 && strLine.find( string("grep /mobile/Applications") ) == -1  ) 
		//if( strLine.find( strProcessName ) != -1 && strLine.find( string("grep /mobile/Containers") ) == -1  ) 
		string strFindCommand("grep ");
		strFindCommand += m_strAppPath;
		if( strLine.find( strProcessName ) != -1 && strLine.find( strFindCommand ) == -1  ) 
		{
			count++;
			vProcessList.push_back(strLine);
		}
		memset(line, 0x00, 400);
	}
	status = pclose(fp);
	return 0;
}


bool CMemoryMap::LoadModuleList()
{
	// 1. task_for_pid
	mach_port_t task;
	mach_vm_address_t address =0;
	task_for_pid(mach_task_self(), m_nProcessID, &task);

	kern_return_t kret;
	vm_region_basic_info_data_t info;
	mach_vm_size_t size = 0;

	mach_port_t object_name;
	mach_msg_type_number_t count;

	while(1)
	{
		count = VM_REGION_BASIC_INFO_COUNT_64;
		kret = mach_vm_region (task, &address, &size, VM_REGION_BASIC_INFO, (vm_region_info_t) &info, &count, &object_name);

		if (kret != KERN_SUCCESS)
		{
			break;
		}

		if( IsReadWrite( info.protection ) )
		{
			m_vModuleList.push_back( CModule(m_nProcessID, address, size, info, m_nDisplayMemLineCount) );
		}
		address += size;
	}
	return true;
}

string CMemoryMap::GetProcessNameUsingProcessID(string strProcessID)
{
	if(m_nProcessID == -1)	
		return NULL;

	int status = 0;
	int count = 0;
	char line[400];
	char* pLine = NULL;

	//FILE *fp = popen("ps -ef | grep mobile/Applications", "r"); // for iOS
	//FILE *fp = popen("ps -ef | grep mobile/Containers", "r"); // for iOS
	//FILE *fp = popen("ps -ef", "r"); // for OSX
	string strFindCommand("ps -ef | grep ");
	strFindCommand += m_strAppPath;
	FILE *fp = popen(strFindCommand.c_str(), "r");

	while ( fgets(line, 400, fp) != NULL )
	{
		if( ( pLine = strchr(line, '\n') ) != NULL)
			*pLine ='\0';

		if(string(line).size() > 10)
		{
			string strTemp = string(line).substr(5, 6);
			if( strTemp.find( strProcessID ) != -1 )
			{
				pclose(fp);
				return string(line).substr(51); // for iOS
				//return string(line).substr(49); // for OSX
			}
		}

	}
	pclose(fp);
	return string("");
}

vector<CModule> CMemoryMap::GetModuleList()
{
 	return m_vModuleList;
}

void CMemoryMap::ClearModuleList()
{
	m_vModuleList.clear();
}

bool CMemoryMap::IsReadWrite(vm_prot_t protection)
{
	return ( (protection & VM_PROT_READ) && (protection & VM_PROT_WRITE) ); 
	//return ( (protection & VM_PROT_READ) ); 
}

void CMemoryMap::DisplayLoadLibraryList()
{
	// List all mach-o images in a process
	uint32_t i;
	uint32_t ic = _dyld_image_count();
	for (i = 0; i < ic; i++)
	{
		printf ( "[%5d] %p\t%s\n", i, _dyld_get_image_header(i), _dyld_get_image_name(i) );
	}
}


bool CMemoryMap::DisplayAllVMRegionInfo()
{
	int nIndex = 1;
	vector<CModule>::iterator itr;
	for(itr = m_vModuleList.begin(); itr < m_vModuleList.end(); itr++)
	{
		printf("[%4d /%4d] ", nIndex++, (unsigned int)m_vModuleList.size());
		itr->DisplayVMRegionInfo();
	}
	return true;
}


bool CMemoryMap::SearchItem(vector<string> vStrSearchItemList)
{
	vector<string>::iterator  sitr;
	for(sitr = vStrSearchItemList.begin(); sitr < vStrSearchItemList.end(); sitr++)
	{
		printf("[*] START TO SEARCH [%s]\n", sitr->c_str() );
	}

	vector<CModule>::iterator citr;
	for(citr = m_vModuleList.begin(); citr < m_vModuleList.end(); citr++)
	{
		citr->SearchOfMemory(vStrSearchItemList);
	}
	return true;
}


bool CMemoryMap::ReplaceItem(vector<string> vStrReplaceItemList)
{
	int nReplaceCnt = vStrReplaceItemList.size() / 2;
	for(int cnt = 0; cnt < nReplaceCnt; cnt++)
	{
		string strKeyword        = vStrReplaceItemList[cnt*2    ];
		string strReplaceKeyword = vStrReplaceItemList[cnt*2 + 1];

		printf("[*] START TO REPLACE [%s >>> %s]\n", strKeyword.c_str(), strReplaceKeyword.c_str() );
	}

	vector<CModule>::iterator itr;
	for(itr = m_vModuleList.begin(); itr < m_vModuleList.end(); itr++)
	{
		CModule module = *itr;
		itr->ReplaceOfMemory(vStrReplaceItemList);
	}
	return true;
}

string CMemoryMap::GetHomePath()
{
	return m_strHomePath;
}

void CMemoryMap::SetiOSVersion(int niOSVersion)
{
	m_niOSVersion = niOSVersion; 

	if(m_niOSVersion == 8 )
		m_strAppPath = string("/mobile/Containers");
	else
		m_strAppPath = string("/mobile/Applications");
}
