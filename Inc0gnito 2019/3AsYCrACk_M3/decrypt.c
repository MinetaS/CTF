#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
	const char *src = "Cdm+V2^U`7";
	char encrypt[11];

	memset(encrypt, 33, 10);
	encrypt[0] = 'C';
	encrypt[10] = 0;

	for (int i=1 ; i<10 ; i++) {
		while (1) {
			char payload[39];
			char result[11];

			memset(payload, 0, 39);

			strcat(payload, "./3AsYCrACk_M3 ");
			strcat(payload, encrypt);
			strcat(payload, " > output.txt");

			system(payload);

			FILE *out = fopen("output.txt", "r");
			fscanf(out, "answer is %s", result);

			if (result[i] == src[i]) {
				printf("encrypt[%d] = %c\n", i, result[i]);
				break;
			}

			encrypt[i]++;

			if (encrypt[i] == 127) {
				printf("No Solution\n");
				return 0;
			}

			fclose(out);
		}
	}

	printf("The decrypted text is %s\n", encrypt);

	return 0;
}
