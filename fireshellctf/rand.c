#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
	int seed = atoi(argv[1]);
	srand(seed);
	for(int i = 0; i < 100; i++) {
		printf("%d\n", rand());
	}
	return 0;
}
