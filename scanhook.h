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
	std::vector<MODULE_INFO> moduleInfo;			//ģ���б�
	std::vector<MODULE_INFO>::iterator modInfoItr;	//ģ�������
	std::vector<PROCESS_HOOK_INFO> hookInfo;		//����hook
	std::vector<PROCESS_HOOK_INFO>::iterator hookItr;
	DWORD pid;
	HANDLE m_hProcess;		
	BOOL m_IsFromIat = 0, m_IsFromEat = 0;
	BOOL isWOW64 = FALSE;
private:
	
	/// <summary>
	/// ����ģ����Ϣ
	/// </summary>
	VOID queryModuleInfo();

	/// <summary>
	/// pe������
	/// </summary>
	/// <param name="FilePath"></param>
	/// <param name="DllBase"></param>
	/// <param name="Buffer"></param>
	/// <param name="BufferSize"></param>
	VOID peLoad(WCHAR* FilePath, LPVOID DllBase, LPVOID Buffer, DWORD BufferSize);

	/// <summary>
	/// pe������
	/// </summary>
	/// <param name="ImageBase"></param>
	/// <param name="Pe"></param>
	BOOL peAnalysis(LPVOID ImageBase, PPE_INFO Pe);

	inline DWORD AlignSize(UINT Size, UINT Align);

	/// <summary>
	/// pe�ض�λ
	/// </summary>
	/// <param name="NewImageBase"></param>
	/// <param name="ExistImageBase"></param>
	VOID baseReloc(LPVOID NewImageBase, LPVOID ExistImageBase);

	PIMAGE_BASE_RELOCATION RelocBlock(ULONG_PTR VA, ULONG SizeOfBlock, PUSHORT NextOffset, INT64 Diff);

	/// <summary>
	/// ��ȡ/�ͷ� ��ǰ������ָ��ģ����ڴ澵��
	/// </summary>
	VOID ReadMemoryImage();
	VOID FreeMemoryImage();

	/// <summary>
	/// ɨ��eat��inline
	/// </summary>
	VOID ScanEATHook();

	/// <summary>
	/// ɨ��iat
	/// </summary>
	VOID ScanIATHook();

	VOID ScanInlineHook(char* ApiName, LPVOID Address);

	/// <summary>
	/// �Ƿ���ȫ�ֱ���
	/// </summary>
	/// <param name="PeHead"></param>
	/// <param name="Rva"></param>
	/// <returns></returns>
	BOOL IsGlobalVar(PIMAGE_NT_HEADERS PeHead, DWORD Rva);
	BOOL IsGlobalVar32(PIMAGE_NT_HEADERS32 PeHead, DWORD Rva);

	/// <summary>
	/// �������ض�λ
	/// </summary>
	/// <param name="RedirectionName"></param>
	/// <returns></returns>
	LPVOID FileNameRedirection(char* RedirectionName);

	/// <summary>
	/// ȡģ����Ϣ
	/// </summary>
	/// <param name="DllName"></param>
	/// <param name="iter"></param>
	/// <returns></returns>
	BOOL GetModuleInfomation(WCHAR* DllName, std::vector<MODULE_INFO>::iterator& iter);

	BOOL GetModuleInfomation(LPVOID address, std::vector<MODULE_INFO>::iterator& iter);

	/// <summary>
	/// ԭ�ļ�ȡ����
	/// </summary>
	/// <param name="ImageBase"></param>
	/// <param name="Ordinal"></param>
	/// <returns></returns>
	LPVOID GetExportByOrdinal(LPVOID ImageBase, LPVOID Ordinal);

	/// <summary>
	/// �����ļ�ȡ����
	/// </summary>
	/// <param name="ImageBase"></param>
	/// <param name="ProcName"></param>
	/// <returns></returns>
	LPVOID GetExportByName(LPVOID ImageBase, char* ProcName);

	/// <summary>
	/// ȡģ�����
	/// </summary>
	/// <param name="Address"></param>
	/// <param name="ModulePath"></param>
	VOID GetModulePathByAddress(LPVOID Address, WCHAR* ModulePath);

	/// <summary>
	/// ��ȡ������ַ
	/// </summary>
	/// <param name="DllName"></param>
	/// <param name="ApiName"></param>
	/// <param name="RealDllName"></param>
	/// <returns></returns>
	LPVOID GetProcessAddressLocal(char* DllName, char* ApiName, WCHAR* RealDllName);

};

