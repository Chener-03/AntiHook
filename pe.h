#pragma once
#include <windows.h>
#include <vector>
#include<TlHelp32.h>

typedef struct _MODULE_INFO
{
	LPVOID  DllBase;			//DLL基地址
	DWORD SizeOfImage;		//大小
	WCHAR FullName[260];	//路径
	WCHAR BaseName[64];		//名字
	LPVOID MemoryImage;		//内存中映像
	LPVOID DiskImage;		//硬盘中映像
} MODULE_INFO;

typedef struct _PE_INFO
{
	PIMAGE_NT_HEADERS PeHead;	//pe头
	PIMAGE_NT_HEADERS32 PeHead32;	//32 pe头
	LPVOID ExportTableRva;		//导出表相对虚拟地址
	DWORD ExportSize;			//导出表大小
	LPVOID ImportTableRva;		//导入表相对虚拟地址
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
	LPVOID OriginalAddress;						//原函数地址
	LPVOID HookAddress;							//钩子的地址
	WCHAR HookedApiName[128];					//被挂钩的函数名
	WCHAR HookedModule[64];						//被挂钩的模块名
	WCHAR HookLocation[260];					//钩子所在的模块
	BYTE  OriByte[30];							//真实前20字节 恢复inline
	LPVOID RecoveryAddr;						//恢复的地址	  恢复iat /eat
	DWORD  eatOffset;							//eat dword 偏移
} PROCESS_HOOK_INFO, * PPROCESS_HOOK_INFO;













