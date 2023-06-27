#include "bofmask.h"

WINBASEAPI int WINAPI USER32$MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

void go(char* args, int len){
  GetBeaconBaseAddress();
  //You can use Beacon APIs here!
  MaskBeacon();
  //DON'T CALL ANY BEACON APIS HERE!
  USER32$MessageBoxA(NULL, "HI!", "HI!", MB_OK);
  UnmaskBeacon();
  //You can use Beacon APIs again!
}
