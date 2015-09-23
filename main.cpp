#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach/vm_region.h>
#include <mach-o/loader.h>
#include <mach-o/dyld_images.h>

#include <vector>
#include <iostream>
#include <algorithm>
#include "memorymap.h"
#include "util.h"
#include "packet.h"

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



// #NAME SPCAE DEFINE
using namespace std;

// #DEFINE
#define MAX_STRING_SIZE      100
#define FSA_AMCI_VERSION     "1.2.4"

// #FUNCTION DEFINE
int  DisplayMenu();
void DisplayInfo(vector<string>& vList);
int  ProcessUserTask(int nSelectedMenuNumber);

// #GLOVAL VALUE DEFINE
vector<string>  vStrItemList;
vector<string>  vStrAllModuleList;
CMemoryMap      MemoryMap;

int main(int argc, char **argv)
{
	// Display AMCI Version
	cout << endl << "[*] AMCI Version : " << FSA_AMCI_VERSION << endl;

	// Display iOS Version
	DisplayiOSVersion();
	MemoryMap.SetiOSVersion( GetiOSVersion() );

	// Load "amc_item.txt" 
	DisplayLine(LINE_TYPE_NULL, 1);
	if( LoadItemList(vStrItemList) == true )
	{
		cout <<"[*] LOAD ITEM LIST!" ;
	}

	DisplayLine(LINE_TYPE_NULL, 1);
	while(1)
	{
		DisplayInfo(vStrItemList);

		if ( ProcessUserTask( DisplayMenu() ) == -1 )
			break;
	}

	return 0;
}

int ProcessUserTask(int nSelectedMenuNumber)
{
	char strProcessName[MAX_STRING_SIZE]; 
	char strProcessID[MAX_STRING_SIZE]; 
	char strDummyItem[MAX_STRING_SIZE];
	char*          ptrTemp   = NULL;
	unsigned char* pDumpData = NULL;

	memset(strProcessName, 0x00, MAX_STRING_SIZE);
	memset(strProcessID,   0x00, MAX_STRING_SIZE);
	memset(strDummyItem,   0x00, MAX_STRING_SIZE);

	vector<CModule> vModuleList;
	vector<CModule>::iterator i;

	switch( nSelectedMenuNumber )
	{

		case '1' :
		{
			cout << "  [1]>>>> INPUT PROCESS KEYWORD : " ; 
			cin.getline(strProcessName, MAX_STRING_SIZE);

			DisplayLine(LINE_TYPE_NULL, 2);
			DisplayLine(LINE_TYPE_DASH, 1);

			vector<string>  vStrProcessList;
			if( MemoryMap.GetProcessListByName(vStrProcessList, strProcessName) != -1 )
				DisplayList(vStrProcessList, LIST_TYPE_PROCESS);


			if( vStrProcessList.size() == 1 )
			{
				MemoryMap.SetProcessID( vStrProcessList[0].substr(5, 6) ); 
			} 

			DisplayLine(LINE_TYPE_DASH, 1);
			DisplayLine(LINE_TYPE_NULL, 2);

			vStrProcessList.clear();

			break;
		}

		case '2' :
				cout << "  [2]>>>> INPUT PROCESS ID : " ; 
				cin.getline(strProcessID, MAX_STRING_SIZE);

				DisplayLine(LINE_TYPE_NULL, 1);

				if( MemoryMap.SetProcessID(strProcessID) == -1 )
					cout <<"+ CAN'T FIND PROCESS ID(" << strProcessID << ")!" << endl;		
				
				DisplayLine(LINE_TYPE_DASH, 1);
				DisplayLine(LINE_TYPE_NULL, 2);

				break;


		case '3' :	
				cout << "  [3]>>>> INPUT ITEM for ADD(you can input one or multiple item) : " ; 
				cin.getline(strDummyItem, MAX_STRING_SIZE);

				StringTokenizer(vStrItemList, string(strDummyItem), string(" "));

				DisplayLine(LINE_TYPE_DASH, 1);
				DisplayLine(LINE_TYPE_NULL, 2);

				break;

		case '4' :
		{
			cout << "  [4]>>>> INPUT ITEM NUMBER for DELETE(you can input one item number) : " ; 
			cin.getline(strDummyItem, MAX_STRING_SIZE);


			int nInputNumber = atoi(strDummyItem);
			int nItemCount = vStrItemList.size();
			if( nInputNumber > 0 && nInputNumber <= nItemCount )
				vStrItemList.erase( vStrItemList.begin()+nInputNumber-1 );
			else
				printf("PLEASE ENTER A NUMBER BETWEEN %d to %d NUMBER!\n", 1, nItemCount);

			DisplayLine(LINE_TYPE_DASH, 1);
			DisplayLine(LINE_TYPE_NULL, 2);

			break;
		}

		case '5' :
		{
			// CHECK Search Item
			if(vStrItemList.size() == 0)
			{
				cout << "PLEASE ADD an ITEM by USING the MENU[3]!" << endl;					
				DisplayLine(LINE_TYPE_DASH, 1);
				DisplayLine(LINE_TYPE_NULL, 2);

				break;
			}

			// CHOICE Serach Item Number 
			cout << "  [5]>>>> INPUT ITEM NUMBER(you can input one or multiple item number) : " ; 
			cin.getline(strDummyItem, MAX_STRING_SIZE);

			vector<string> vStrTempList;
			StringTokenizer(vStrTempList, string(strDummyItem), string(" "));

			// MAKE Search Item
			vector<string> vStrSearchList;
			vector<string>::iterator itr;
			for( itr = vStrTempList.begin(); itr < vStrTempList.end(); itr++ )
			{
				string strSelectItemIndex = *itr;
				int    nSelectItemIndex   = atoi( strSelectItemIndex.c_str() ) - 1;

				if( nSelectItemIndex < 0 || nSelectItemIndex >= vStrItemList.size() )
				{
					printf("PLEASE ENTER A NUMBER BETWEEN %d to %d NUMBER!\n", 1, (int)vStrItemList.size());
					return 0;
				}
				vStrSearchList.push_back( vStrItemList[nSelectItemIndex] );
			}

			DisplayLine(LINE_TYPE_NULL, 1);
			DisplayLine(LINE_TYPE_DASH, 1);


			if( MemoryMap.LoadModuleList() == false )
			{
				cout << "FAIL TO READ MEMORY MAP!" << endl;
				cout << "PLEASE FIND THE PROCESS AGAIN by USING the MENU[1], [2]" << endl;
				
				DisplayLine(LINE_TYPE_DASH, 1);
				DisplayLine(LINE_TYPE_NULL, 2);

				break;
			}
			

			printf("[+] START TO SEARCH (TARGET VM REGION COUNT [%d])\n", MemoryMap.GetModuleCount() );
			MemoryMap.SearchItem(vStrSearchList);
			/*
			int nCheckLoopCount = 1;
			int nTotalLoopCount = vModuleList.size();
			for(i = vModuleList.begin(); i !=  vModuleList.end(); i++)
			{
				DisplayLine(LINE_TYPE_DASH, 1);
				printf( "[+] [%d / %d] START DUMP MEMORY at [0x%08x]-[0x%08x] / SIZE[%s]\n", 
						nCheckLoopCount++, 
						nTotalLoopCount, 
						(unsigned int)i->GetStartAddress(), 
						(unsigned int)i->GetEndAddress(), 
						i->GetStrMemorySize().c_str() );    

				i->SearchOfMemory(vStrSearchList); 
				
				DisplayLine(LINE_TYPE_DASH, 1);
				DisplayLine(LINE_TYPE_NULL, 1);
			}
			*/
			printf("[-] END TO SEARCH\n" );
			DisplayLine(LINE_TYPE_DASH, 1);
		  	DisplayLine(LINE_TYPE_NULL, 1);

			MemoryMap.ClearModuleList();	
			vModuleList.clear();
			vStrTempList.clear();
			vStrSearchList.clear();
			break;
		}
		
	
		case '6' :
		{
			if(vStrItemList.size() < 2)
			{
				cout << "PLEASE ADD the TWO or MORE ITEMs by USING the MENU[3]!" << endl;
				DisplayLine(LINE_TYPE_DASH, 1);
				DisplayLine(LINE_TYPE_NULL, 2);

				break;
			}

			cout << "  [6]>>>> INPUT ITEM NUMBER(you can input two or multiple item number) : " ; 
			cin.getline(strDummyItem, MAX_STRING_SIZE);

			vector<string> vStrTempList;
			StringTokenizer(vStrTempList, string(strDummyItem), string(" "));

			if(vStrTempList.size() % 2 == 1)
			{
				cout << vStrTempList.size() << endl;
				cout << "PLEASE ENTER the EVEN NUMBER of ITEMs TO BE EXCHANGED!" << endl;
				
				DisplayLine(LINE_TYPE_DASH, 1);
				DisplayLine(LINE_TYPE_NULL, 2);

				break;
			}

			vector<string> vStrReplaceList;
			vector<string>::iterator itr;
			for( itr = vStrTempList.begin(); itr < vStrTempList.end(); itr++ )
			{
				string strSelectItemIndex = *itr;
				int    nSelectItemIndex   = atoi( strSelectItemIndex.c_str() ) - 1;
				
				if( nSelectItemIndex < 0 || nSelectItemIndex >= vStrItemList.size() )
				{
					printf("PLEASE ENTER A NUMBER BETWEEN %d to %d NUMBER!\n", 1, (int)vStrItemList.size());
					return 0;
				} 
	
				vStrReplaceList.push_back( vStrItemList[nSelectItemIndex] );
			}

			if( MemoryMap.LoadModuleList() == false )
			{
				cout << "FAIL TO READ MEMORY MAP!" << endl;
				cout << "PLEASE FIND THE PROCESS AGAIN by USING the MENU[1], [2]" << endl;
				
				DisplayLine(LINE_TYPE_DASH, 1);
				DisplayLine(LINE_TYPE_NULL, 2);

				break;
			}
			
			DisplayLine(LINE_TYPE_NULL, 1);
			DisplayLine(LINE_TYPE_DASH, 1);

			printf("[+] START TO REPLACE (TARGET VM REGION COUNT [%d])\n", MemoryMap.GetModuleCount() );
			MemoryMap.ReplaceItem(vStrReplaceList);
			printf("[-] END TO REPLACE\n" );

			MemoryMap.ClearModuleList();
			vStrTempList.clear();
			vStrReplaceList.clear();

			break;
		}
	
		case '7':
		{
			// CHECK Search Item
			if(vStrItemList.size() == 0)
			{
				cout << "PLEASE ADD an ITEM by USING the MENU[3]!" << endl;					
				DisplayLine(LINE_TYPE_DASH, 1);
				DisplayLine(LINE_TYPE_NULL, 2);

				break;
			}

			// CHOICE Serach Item Number 
			cout << "  [5]>>>> INPUT ITEM NUMBER(you can input one or multiple item number) : " ; 
			cin.getline(strDummyItem, MAX_STRING_SIZE);

			vector<string> vStrTempList;
			StringTokenizer(vStrTempList, string(strDummyItem), string(" "));

			// MAKE Search Item
			vector<string> vStrSearchList;
			vector<string>::iterator itr;
			for( itr = vStrTempList.begin(); itr < vStrTempList.end(); itr++ )
			{
				string strSelectItemIndex = *itr;
				int    nSelectItemIndex   = atoi( strSelectItemIndex.c_str() ) - 1;

				if( nSelectItemIndex < 0 || nSelectItemIndex >= vStrItemList.size() )
				{
					printf("PLEASE ENTER A NUMBER BETWEEN %d to %d NUMBER!\n", 1, (int)vStrItemList.size());
					return 0;
				}
				vStrSearchList.push_back( vStrItemList[nSelectItemIndex] );
			}

			DisplayLine(LINE_TYPE_NULL, 1);
			DisplayLine(LINE_TYPE_DASH, 1);


			SearchItemInFile(vStrSearchList, MemoryMap.GetHomePath());
			break;
		}

		case 'r':
		{
			if( MemoryMap.LoadModuleList() == false )
			{
				cout << "FAIL TO READ MEMORY MAP!" << endl;
				cout << "PLEASE FIND THE PROCESS AGAIN by USING the MENU[1], [2]" << endl;
				
				DisplayLine(LINE_TYPE_DASH, 1);
				DisplayLine(LINE_TYPE_NULL, 2);

				break;
			}
	
			MemoryMap.DisplayAllVMRegionInfo();
			MemoryMap.ClearModuleList();	
			break;
		}
		
		case 'l':
		{
			MemoryMap.DisplayLoadLibraryList();
			break;
		}
	

		case '8' :
		{
				int nStaticCnt = 0;
				nStaticCnt++;
					
				cout << "  [*]>>>> START DUMP\n" ; 
				DisplayLine(LINE_TYPE_DASH, 1);

				if( MemoryMap.LoadModuleList() == false )
				{
					cout << "FAIL TO READ MEMORY MAP!" << endl;
					cout << "PLEASE FIND THE PROCESS AGAIN by USING the MENU[1], [2]" << endl;

					DisplayLine(LINE_TYPE_DASH, 1);
					DisplayLine(LINE_TYPE_NULL, 2);

					break;
				}

				vModuleList = MemoryMap.GetModuleList();
				string strFolderPath = GetFilePath();

				int nFileCnt   = 1;
				int nModuleCnt = vModuleList.size(); 
				for(i = vModuleList.begin(); i !=  vModuleList.end(); i++)
				{
					pDumpData = (unsigned char*) malloc(i->GetMemorySize()); 
					if(pDumpData == NULL)
					{
						cout << "Memory Alloc Fail for Dump!" << endl;
						break;
					}
					memset(pDumpData, 0x00, i->GetMemorySize());

					i->GetDumpMemory(pDumpData);

					int nResult = SaveToFile(strFolderPath, pDumpData, i->GetMemorySize());
					if(nResult == 0)
						printf(" [+] [%d / %d] DUMP FILE SAVED![%s] \n", nFileCnt, nModuleCnt, i->GetStrMemorySize().c_str() );
					else
						printf(" [!] [%d / %d] DUMP FILE SAVED ERROR![%s] \n", nFileCnt, nModuleCnt, i->GetStrMemorySize().c_str() );

					nFileCnt++;

					free(pDumpData);
				}
				DisplayLine(LINE_TYPE_DASH, 1);
				chmod(strFolderPath.c_str(), 0777);

				MemoryMap.ClearModuleList();
				vModuleList.clear();
				break;
		}

		case 'v' :
		{
			// Display Version
			cout << "[*] AMCI Version : " << FSA_AMCI_VERSION << endl;
			break;
		}

		case 'n' :
		{
			cout << "  [N]>>>> INPUT ITEM NUMBER(you can input one or multiple item number) : " ; 
			cin.getline(strDummyItem, MAX_STRING_SIZE);

			vector<string> vStrTempList;
			StringTokenizer(vStrTempList, string(strDummyItem), string(" "));

			vector<string> vStrSearchList;
			vector<string>::iterator itr;
			for( itr = vStrTempList.begin(); itr < vStrTempList.end(); itr++ )
			{
				string strSelectItemIndex = *itr;
				int    nSelectItemIndex   = atoi( strSelectItemIndex.c_str() ) - 1;

				if( nSelectItemIndex < 0 || nSelectItemIndex >= vStrItemList.size() )
				{
					printf("  [!]PLEASE ENTER A NUMBER BETWEEN %d to %lu NUMBER!\n", 1, vStrItemList.size());
					return 0;
				}
				vStrSearchList.push_back( vStrItemList[nSelectItemIndex] );
			}

			for( itr = vStrSearchList.begin(); itr < vStrSearchList.end(); itr++ )
			{
				cout << "  [*] Search Item [" << *itr << "] in Network" << endl; 
			}
			DisplayLine(LINE_TYPE_DASH, 1);

			CPacket packet(vStrSearchList);
			packet.SelectDevice();
			packet.Sniffing();

			break;
		}


		case 'x' :
		{
			cout << "  [X]>>>> INPUT DISPLAY LINE COUNT : " ; 
			cin.getline(strDummyItem, MAX_STRING_SIZE);

			int nInputNumber = atoi(strDummyItem);
			if( nInputNumber > 0 && nInputNumber <= 100 )
			{
				MemoryMap.SetDisplayLineCount(nInputNumber);
				cout << "  [*]>>>> SET DISPLAY LINE COUNT : " << nInputNumber << endl; 
			}
			else
				printf("  [*]PLEASE ENTER A NUMBER BETWEEN %d to %d NUMBER!\n", 1, 100);
			
			DisplayLine(LINE_TYPE_DASH, 1);
			DisplayLine(LINE_TYPE_NULL, 2);


			break;
		}


		case 'q' :
				return -1;
 
		default :
				DisplayLine(LINE_TYPE_NULL, 1);
				DisplayLine(LINE_TYPE_DASH,  1);
				cout << "+YOU WRITE WRONG NUMBER : " << (char)nSelectedMenuNumber << endl;
			
				break;
	}
return 0;

}

void DisplayInfo(vector<string>& vStrList)
{

	// 1. DISPLAY SET PROCESS INFO
	if(MemoryMap.GetProcessID() != -1)
	{		
		cout << "=====================[PROCESS INFO]==========================" << endl;
		cout << "+ SET PROCESS : " << MemoryMap.GetProcessName() << "(" << MemoryMap.GetProcessID() << ")" << endl;
	}
	else
	{
		cout << "=====================[PROCESS INFO]==========================" << endl;
		cout << "+ PROCESS WAS NOT SELECTED!                                 +" << endl; 
	}
	
	// 2. DISPLAY ITEM INFO
	if(vStrList.size() != 0)
	{
		cout << "=======================[ITEM LIST]===========================" << endl;
		DisplayList(vStrList, LIST_TYPE_ITEM);	
		cout << "=============================================================" << endl;
	}
	else
	{
		cout << "=======================[ITEM LIST]===========================" << endl;
		cout << "+ ITEM WAS NOT ADDED!                                       +" << endl;
		cout << "=============================================================" << endl;
	}
}


int DisplayMenu()
{
	char strInputNumber[MAX_STRING_SIZE];
	memset(strInputNumber, 0x00, MAX_STRING_SIZE);

	cout << "+-----------------------------------------------------------+" << endl;
	cout << "+ [1]. FIND PROCESS ID          + [3]. ADD    ITEM          +" << endl;
	cout << "+ [2]. SET  PROCESS ID          + [4]. DELETE ITEM          +" << endl;
	cout << "+-----------------------------------------------------------+" << endl;
	cout << "+ [5]. SEARCH ITEM(in MEMORY)   + [6]. REPLACE ITEM         +" << endl;
	cout << "+ [7]. SEARCH ITEM(in FILE)     + [8]. DUMP to FILE         +" << endl;
	cout << "+-----------------------------------------------------------+" << endl;
     	cout << "+ [R]. SHOW all VM Region                                   +" << endl;
     	cout << "+ [L]. SHOW all Load Library                                +" << endl;
	cout << "+-----------------------------------------------------------+" << endl;
        cout << "+ [N]. SEARCH ITEM(in NETWORK)                              +" << endl;
	cout << "+-----------------------------------------------------------+" << endl;
	cout << "+ >> SELECT MENU(QUIT is 'q') : ";

	cin.getline(strInputNumber, MAX_STRING_SIZE);
	return strInputNumber[0];
} 

