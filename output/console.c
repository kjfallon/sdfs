#include "console.h"
#include <stdio.h>

/***************************************************************************
 * Print hex representation of bytes                                        *
 *                                                                         *
 ***************************************************************************/
void hexPrint(unsigned char *data, int length) {
    int i;
    for(i = 0; i < length; i++)
        printf("%02x", data[i]);
    printf("\n");
}
