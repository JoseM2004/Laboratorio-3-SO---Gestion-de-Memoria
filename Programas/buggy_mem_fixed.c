#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {

    int *p = malloc(5 * sizeof(int));
    for (int i = 0; i < 5; i++) /* Corregido: < en vez de <= */
    p[i] = i;

    
    char *q = malloc(100);
    strcpy(q, "hola mundo");
    printf("%s\n", q);
    free(q); /* Corregido: se libera la memoria de q para evitar memory leak */

    
    printf("p[0] = %d\n", p[0]); /* Corregido: se accede a p antes de liberarla */
    free(p);
    
    
    return 0;
}