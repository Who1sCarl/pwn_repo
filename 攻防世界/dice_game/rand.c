#include <stdio.h>

#include <stdlib.h>

int main()

{

        int seed =1;       
	int v2;
        int k;
        srand(seed);

        printf("Random Numbers are:\n");

        for(k = 1;k <= 50; k++){

	v2 = rand() % 6 + 1;
	printf("%d",v2);

        printf(" ");}

        return 0;

}
