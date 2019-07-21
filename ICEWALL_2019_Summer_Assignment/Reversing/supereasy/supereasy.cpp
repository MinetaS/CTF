#include <cstdio>

typedef unsigned __int8 byte;

int main() {
	byte flag[20] = {0x35, 0x3F, 0x32, 0x34, 0x08, 0x23, 0x42, 0x09, 0x5E, 0x20, 0x43, 0x42, 0x05, 0x16, 0x5E, 0x1E, 0x40, 0x5D, 0x5D, 0x0E};

	for (int i=0 ; i<20 ; i++) {
		for (int j=32 ; j<128 ; j++) {
			byte c = (byte)j;

			if ((flag[i] ^ c) == 115) {
				printf("%c", c);
				break;
			}
		}
	}

	return 0;
}