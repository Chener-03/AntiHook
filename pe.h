#pragma once
#include <windows.h>
#include <vector>
#include<TlHelp32.h>

typedef struct _MODULE_INFO
{
	LPVOID  DllBase;			//DLL����ַ
	DWORD SizeOfImage;		//��С
	WCHAR FullName[260];	//·��
	WCHAR BaseName[64];		//����
	LPVOID MemoryImage;		//�ڴ���ӳ��
	LPVOID DiskImage;		//Ӳ����ӳ��
} MODULE_INFO;

typedef struct _PE_INFO
{
	PIMAGE_NT_HEADERS PeHead;	//peͷ
	PIMAGE_NT_HEADERS32 PeHead32;	//32 peͷ
	LPVOID ExportTableRva;		//��������������ַ
	DWORD ExportSize;			//�������С
	LPVOID ImportTableRva;		//�������������ַ
	DWORD ImportSize;			//
} PE_INFO, * PPE_INFO;

typedef enum _HOOK_TYPE
{
	EatHook,
	IatHook,
	InlineHook
} HOOK_TYPE;

typedef struct _PROCESS_HOOK_INFO
{
	HOOK_TYPE HookType;
	LPVOID OriginalAddress;						//ԭ������ַ
	LPVOID HookAddress;							//���ӵĵ�ַ
	WCHAR HookedApiName[128];					//���ҹ��ĺ�����
	WCHAR HookedModule[64];						//���ҹ���ģ����
	WCHAR HookLocation[260];					//�������ڵ�ģ��
	BYTE  OriByte[30];							//��ʵǰ20�ֽ� �ָ�inline
	LPVOID RecoveryAddr;						//�ָ��ĵ�ַ	  �ָ�iat /eat
	DWORD  eatOffset;							//eat dword ƫ��
} PROCESS_HOOK_INFO, * PPROCESS_HOOK_INFO;













