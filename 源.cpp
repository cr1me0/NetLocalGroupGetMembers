#include <stdio.h>
#include <Windows.h>
#include <lmaccess.h>
#include <Winnetwk.h>

#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "mpr.lib")

int wmain(int argc, wchar_t* argv[]) {
	if (argc != 6) {
		wprintf(L"Usage: %s <domain> <username> <password> <localgroupname> <servername>\n", argv[0]);
		wprintf(L"       %s domain username password administrators \\\\192.168.232.128\n", argv[0]);
		exit(1);
	}

	NETRESOURCE nr;

	LPCTSTR domain = argv[1];
	LPCTSTR username = argv[2];
	LPCTSTR password = argv[3];
	LPCWSTR TargetGroup = argv[4];				// ��������
	LPCWSTR servername = argv[5];				// �Ѿ�����ipc���ӵ�IP
		
	LOCALGROUP_MEMBERS_INFO_2* buff;			// LOCALGROUP_MEMBERS_INFO_2�ṹ������buff��Ż�ȡ������Ϣ
	DWORD dwPrefmaxlen = MAX_PREFERRED_LENGTH;	// ָ���������ݵ���ѡ��󳤶ȣ����ֽ�Ϊ��λ�����ָ��MAX_PREFERRED_LENGTH���ú�������������������ڴ�����
	DWORD dwEntriesread;						// ָ��һ��ֵ��ָ�룬��ֵ����ʵ��ö�ٵ�Ԫ������
	DWORD dwTotalentries;

	memset(&nr, 0, sizeof(NETRESOURCE));

	nr.dwType = RESOURCETYPE_ANY;
	nr.lpLocalName = NULL;
	nr.lpRemoteName = (LPWSTR)servername;
	nr.lpProvider = NULL;

	HANDLE token;
	if (LogonUser(username, domain, password, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, &token)) {
		if (ImpersonateLoggedOnUser(token)) {
			// ���ӵ�IPC$
			DWORD result = WNetAddConnection2(&nr, NULL, NULL, CONNECT_TEMPORARY);

			if (result == NO_ERROR) {
				printf("[+] Connected to IPC$ on %ls\n", servername);

				NetLocalGroupGetMembers(servername, TargetGroup, 2, (LPBYTE*)&buff, dwPrefmaxlen, &dwEntriesread, &dwTotalentries, NULL);
				printf("[+] List of LocalGroupMembers \n");
				for (DWORD i = 0; i < dwEntriesread; i++) {
					wprintf(L"	%s\n", buff[i].lgrmi2_domainandname);
				}

				WNetCancelConnection2(servername, 0, TRUE);

				printf("[+] DisConnected to IPC$ on %ls\n", servername);
			} else {
				printf("[-] Failed to connect to IPC$. Error code: %d\n", result);
			}

			// �ָ������û�������
			RevertToSelf();
		}
		else {
			printf("[-] Impersonation failed.\n");
		}

		CloseHandle(token);
	}
	else {
		printf("[-] LogonUser failed.\n");
	}
}