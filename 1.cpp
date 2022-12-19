#include <iostream>
#include <string>
#include <windows.h>
using namespace std;

int main() {
	__int64 enc[6] = { 0xD803C1FC098,0x0E20360BC097,0x0FE02A1C00A0,0x0FA0121040CB,0x0F2032104092,0x0D6015884082 };
	for (int i = 0; i < 6; i++) {
		cout << (char)(((enc[i] >> 37) ^ 0xa) % 256);
		cout << (char)(((enc[i] >> 23) ^ 0x14) % 256);
		cout << (char)(((enc[i] >> 14) ^ 0x1E) % 256);
		cout << ((unsigned char)(~enc[i]));
	}
}