#include <stdio.h>

#include <stdlib.h>

int main()

{
       
        int k;

        srand(0);

        printf("Random Numbers are:\n");

        for(k = 1; k <= 10; k++){
        	 printf("%i",rand());
        	 printf("\n");

        }
        return 0;

}

