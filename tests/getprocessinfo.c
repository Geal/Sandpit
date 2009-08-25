#include <stdio.h>
#include <windows.h>
#include <winbase.h>
#include <ntdef.h>
#include <ntsecapi.h>
// ???????????
#include <winnt.h>
#include <sddl.h>
#define MAXSIZE 16384

void format_error();

#define print_error() format_error(__FILE__, __FUNCTION__, __LINE__)

int main(void)
{
	int i;
	char user_name[250];
	DWORD user_num = 250;
	char computer_name[250];
	DWORD computer_num = 250;

	if (!GetComputerName( computer_name, &computer_num))
		printf("%08x\n", GetLastError());
	else
		printf("Computer: %s\n", computer_name);
	
	if (!GetUserName( user_name, &user_num))
		printf("%08x\n", GetLastError());
	else
		printf("User: %s\n", user_name);
		
	HANDLE h_me = GetCurrentProcess();
	
	HANDLE h_token;
	
	/* Use GetKernelObjectSecurity ?*/
	OpenProcessToken( h_me, TOKEN_READ, &h_token);
	
	TOKEN_USER * ptok_usr = (TOKEN_USER *) malloc( MAXSIZE );
	DWORD ret;
	if (!GetTokenInformation (h_token, TokenUser, ptok_usr, MAXSIZE, &ret))
	{
		print_error();
		return;
	}
	
	char * stringsid;
	if (!ConvertSidToStringSidA( ptok_usr->User.Sid, &stringsid))
	{
		print_error();
		return;
	}	
	
	printf("Sid: %s\n",stringsid);
	
	LocalFree(stringsid);

	fflush(stdout);
	getchar();

	TOKEN_GROUPS *ptg;
	// token groups
	ptg = (TOKEN_GROUPS *) malloc( MAXSIZE );
	if ( ! GetTokenInformation( h_token, TokenGroups, ptg, MAXSIZE, &ret ) )
	{
		print_error();
		return;
	}
	else
	{
		if ( ptg->GroupCount == 0 )
			printf( "Token groups: (none)\n" );
		else
		{
			printf( "Token groups:\n" );
			for ( i = 0; i < ptg->GroupCount; ++ i )
			{
				char * strsid;
				if (!ConvertSidToStringSidA( ptg->Groups[i].Sid, &strsid))
				{
					print_error();
					return;
				}	

				printf("Group Sid: %40s",strsid);
				LocalFree(stringsid);

				char name[MAXSIZE];
                char domain[MAXSIZE];
                DWORD i_name=MAXSIZE, i_domain=MAXSIZE;
                SID_NAME_USE snu;
				if(!LookupAccountSidA(NULL, ptg->Groups[i].Sid, name, &i_name,
                                        domain, &i_domain, &snu))
				{
					print_error();

				}	
                else
                {
                    printf("\t %s\\%s\n", domain, name);
                }

			}
		}
	}

	fflush(stdout);
	getchar();
	
	UCHAR privbuf[1000];
	PTOKEN_PRIVILEGES ptgPrivileges = (PTOKEN_PRIVILEGES) privbuf;
	DWORD privilegeNameSize;
	DWORD displayNameSize;
	char privilegeName[500];
	char displayName[500];
	DWORD langId;

	if (!GetTokenInformation (h_token, TokenPrivileges, privbuf, sizeof(privbuf), &ret))
	{
		print_error();
		return;
	}
	
	printf( "Account privileges: \n\n" );
	for( i = 0; i < ptgPrivileges->PrivilegeCount; i ++ )
	{
		privilegeNameSize = sizeof privilegeName;
		displayNameSize = sizeof displayName;
		LookupPrivilegeName( NULL, &ptgPrivileges->Privileges[i].Luid,
			privilegeName, &privilegeNameSize );
		LookupPrivilegeDisplayName( NULL, privilegeName,
			displayName, &displayNameSize, &langId );
		printf( "%40s (%s)\n", displayName, privilegeName );
	}
	fflush(stdout);
	getchar();

	return 0;
}


void format_error( char * file, char * function, int line)
{
		LPVOID lpMsgBuf;
		FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
						NULL, /* lpSource */
						GetLastError(), /*dwMessageId */
						MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), /* dwLanguageId */
						(LPTSTR) &lpMsgBuf,
						0, NULL );
		printf("\nError in %s:%d - %s : %s", file, line, function, lpMsgBuf);
		LocalFree(lpMsgBuf);
        fflush(stdout);
		return;
}
