
//gcc -o tripwire.exe tripwire.cpp -lsapi -lstdc++
#include <windows.h>

#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <stdio.h>
#include <psapi.h>
#include <tchar.h>

bool isProcessIDActive(DWORD processID){

	DWORD aProcesses[1024], cbNeeded, cProcesses;
	unsigned int i;

	if(!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)){
		return FALSE;
	}
	else{
		cProcesses = cbNeeded/sizeof(DWORD);
		for(i = 0; i < cProcesses; i++){
			if(aProcesses[i] != 0){
				if(aProcesses[i] == processID){
					return TRUE;
				}
			}
		}	
	}

	return FALSE;
}


int main(int argc, char* argv[]){

	DWORD pidU = -1;

	if (argc > 1){
		pidU = atoi(argv[1]);
	}

	//DWORD pid =   GetCurrentProcessId();
	//printf("%u",pid);

	
    bool trigger = isProcessIDActive(pidU);

    //printf(trigger ? "TRUE" : "FALSE" );

    if(trigger){
    	printf("Arming tripwire to Process ID: %d\n.", pidU);

    	while(trigger){

    		trigger = isProcessIDActive(pidU);
    		Sleep(1000);
    		printf("PING\n");
    	}
    	printf("PID no longer available, triggering followup.");
    	system("shutdown /r /t 60");

    }
    else{

    	printf("No matching PID to attach tripwire: %d\n", pidU);
    }




	return 0;
}