# BOFMask
This repository contains the code for this blog post: 

BOFMask is a proof-of-concept for masking Cobalt Strike's Beacon payload while executing a Beacon Object File (BOF). Normally, Beacon is left exposed during BOF execution. If some behavior from a user-provided BOF triggers a memory scan by an EDR product, then Beacon will likely be detected in memory. Since Cobalt Strike's 4.7 release, users are able to provide a Sleep Mask to hide Beacon while it is sleeping, which is implemented as a BOF provided by the user. This demonstrates that it is possible to execute a BOF while Beacon is masked.

The actual implementation of this is simple: A setup function, GetBeaconBaseAddress, is used to generate a key and find Beacon's base address. Beacon's base address is located by going up two stack frames to find the return address after the BOF finishes executing. This will be an address within Beacon's .text section, which we can pass in to the VirtualQuery API to get the base address of the .text section. Then, a simple XOR mask is used to hide Beacon, and the memory protection setting changed with the VirtualProtect API.

## Usage
One of the main goals of this code was to enable users to drop it into their existing BOF arsenals, with minimal modifications. To that end, using the BOF mask is fairly simple.

You must call the GetBeaconBaseAddress function from within your BOF entrypoint. You CANNOT call another function from your entrypoint and then call GetBeaconBaseAddress. If "go" is the name of the function that beacon will execute in your BOF, you must call GetBeaconBaseAddress from within "go". 

Once you've called GetBeaconBaseAddress to set everything up, you can toggle the BOF mask with MaskBeacon and UnmaskBeacon. There are two main caveats here: You CANNOT call Beacon API functions while Beacon is masked, and if you do not call MaskBeacon and UnmaskBeacon in the right order then your Beacon WILL DIE! For example, if you call MaskBeacon twice in a row without unmasking, then Beacon will be XOR'd twice and a call to UnmaskBeacon will not fix it. If you call UnmaskBeacon twice then you may get an access violation, as Beacon may not be writable. 

Below is a simple intended use case.
```
void go(char* args, int length){
    //YOUR CODE HERE, YOU MUST CALL ANY ARGUMENT UNPACKING FUNCTIONS BEFORE CALLING MaskBeacon
    GetBeaconBaseAddress();
    //YOU CAN STILL CALL BEACON APIS HERE
    MaskBeacon();

    //YOUR CODE HERE
    //DO NOT CALL ANY BEACON APIS BETWEEN MASKING AND UNMASKING!!!!! IT WILL KILL YOUR BEACON!!!!!

    UnmaskBeacon();
    //YOUR CODE HERE, YOU CAN NOW CALL BEACON APIS AGAIN
}
```
The example.c file contains a simple use case which masks Beacon, calls MessageBoxA to block execution, and then unmasks Beacon. 

## Compiling
This code is intended to be compiled with MINGW. You can compile the example BOF included in this repository like this:
```
x86_64-w64-mingw32-gcc -c example.c -o example.x64.o -masm=intel
```

### Defensive considerations
Detecting BOF execution by Beacon is not a particularly fruitful area to focus on. Ultimately, Beacon Object Files are just position independent code loaded by a few benign API calls (LoadLibraryA/GetProcAddress/VirtualAlloc/etc.). It should be much more productive to focus on preventing the initial Beacon execution, or detecting the subsequent post-exploitation activity. For a BOF to be useful it must generate some activity on the host or network, such as enumerating Active Directory via LDAP or performing credential dumping attacks. 

That said, this technique does leave the executing BOF (and the Sleep Mask BOF, if one is in use) in memory as unbacked RX (or RWX) regions. These are generally a good indicator of malicious activity for threat hunters and memory scanners. However, there are ways for these artifacts to be hidden by a skilled operator. 

Below is a non-comprehensive list of resources that you can use for detecting Cobalt Strike.
*	Cobalt Strike YARA rules - Elastic - https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_CobaltStrike.yar
*	PE-Sieve - Hasherezade - https://github.com/hasherezade/pe-sieve
*	Moneta - Forrest Orr - https://github.com/forrest-orr/moneta
*	Hunt Sleeping Beacons - @thefLinkk - https://github.com/thefLink/Hunt-Sleeping-Beacons
*	BeaconEye - Ceri Coburn - https://github.com/CCob/BeaconEye
*	Cobalt Strike, A Defenders Guide - DFIR Report - https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/
