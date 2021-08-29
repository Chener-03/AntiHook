#pragma once
#include <windows.h>
#include <vector>
#include<TlHelp32.h>
#include <VersionHelpers.h>
#include "pe.h"

class AntiHook final
{
public:
	AntiHook(DWORD pid);

	~AntiHook();

	VOID ScanMain();

	VOID RecoveryHook(PROCESS_HOOK_INFO info);

	std::vector<MODULE_INFO> getModuleInfo()const;

	std::vector<PROCESS_HOOK_INFO> getHookInfo()const;

	

private:
	std::vector<MODULE_INFO> moduleInfo;			//模块列表
	std::vector<MODULE_INFO>::iterator modInfoItr;	//模块迭代器
	std::vector<PROCESS_HOOK_INFO> hookInfo;		//所有hook
	std::vector<PROCESS_HOOK_INFO>::iterator hookItr;
	DWORD pid;
	HANDLE m_hProcess;		
	BOOL m_IsFromIat = 0, m_IsFromEat = 0;
	BOOL isWOW64 = FALSE;
private:
	
	/// <summary>
	/// 加载模块信息
	/// </summary>
	VOID queryModuleInfo();

	/// <summary>
	/// pe加载器
	/// </summary>
	/// <param name="FilePath"></param>
	/// <param name="DllBase"></param>
	/// <param name="Buffer"></param>
	/// <param name="BufferSize"></param>
	VOID peLoad(WCHAR* FilePath, LPVOID DllBase, LPVOID Buffer, DWORD BufferSize);

	/// <summary>
	/// pe解析器
	/// </summary>
	/// <param name="ImageBase"></param>
	/// <param name="Pe"></param>
	BOOL peAnalysis(LPVOID ImageBase, PPE_INFO Pe);

	inline DWORD AlignSize(UINT Size, UINT Align);

	/// <summary>
	/// pe重定位
	/// </summary>
	/// <param name="NewImageBase"></param>
	/// <param name="ExistImageBase"></param>
	VOID baseReloc(LPVOID NewImageBase, LPVOID ExistImageBase);

	PIMAGE_BASE_RELOCATION RelocBlock(ULONG_PTR VA, ULONG SizeOfBlock, PUSHORT NextOffset, INT64 Diff);

	/// <summary>
	/// 读取/释放 当前迭代器指向模块的内存镜像
	/// </summary>
	VOID ReadMemoryImage();
	VOID FreeMemoryImage();

	/// <summary>
	/// 扫描eat和inline
	/// </summary>
	VOID ScanEATHook();

	/// <summary>
	/// 扫描iat
	/// </summary>
	VOID ScanIATHook();

	VOID ScanInlineHook(char* ApiName, LPVOID Address);

	/// <summary>
	/// 是否是全局变量
	/// </summary>
	/// <param name="PeHead"></param>
	/// <param name="Rva"></param>
	/// <returns></returns>
	BOOL IsGlobalVar(PIMAGE_NT_HEADERS PeHead, DWORD Rva);
	BOOL IsGlobalVar32(PIMAGE_NT_HEADERS32 PeHead, DWORD Rva);

	/// <summary>
	/// 函数名重定位
	/// </summary>
	/// <param name="RedirectionName"></param>
	/// <returns></returns>
	LPVOID FileNameRedirection(char* RedirectionName);

	/// <summary>
	/// 取模块信息
	/// </summary>
	/// <param name="DllName"></param>
	/// <param name="iter"></param>
	/// <returns></returns>
	BOOL GetModuleInfomation(WCHAR* DllName, std::vector<MODULE_INFO>::iterator& iter);

	BOOL GetModuleInfomation(LPVOID address, std::vector<MODULE_INFO>::iterator& iter);

	/// <summary>
	/// 原文件取导出
	/// </summary>
	/// <param name="ImageBase"></param>
	/// <param name="Ordinal"></param>
	/// <returns></returns>
	LPVOID GetExportByOrdinal(LPVOID ImageBase, LPVOID Ordinal);

	/// <summary>
	/// 镜像文件取导出
	/// </summary>
	/// <param name="ImageBase"></param>
	/// <param name="ProcName"></param>
	/// <returns></returns>
	LPVOID GetExportByName(LPVOID ImageBase, char* ProcName);

	/// <summary>
	/// 取模块基质
	/// </summary>
	/// <param name="Address"></param>
	/// <param name="ModulePath"></param>
	VOID GetModulePathByAddress(LPVOID Address, WCHAR* ModulePath);

	/// <summary>
	/// 获取函数地址
	/// </summary>
	/// <param name="DllName"></param>
	/// <param name="ApiName"></param>
	/// <param name="RealDllName"></param>
	/// <returns></returns>
	LPVOID GetProcessAddressLocal(char* DllName, char* ApiName, WCHAR* RealDllName);

};

