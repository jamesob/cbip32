#include "bip32.h"


int main(int argc, char *argv[]) {
   if (argc != 3) {
       fprintf(stderr, "Usage: %s <seed hex> <path>\n", argv[0]);
       return 1;
   }
   
   bip32_key key;
   char serialized[112];
   
   if (!bip32_derive_from_str(&key, argv[1], argv[2])) {
       fprintf(stderr, "Derivation failed\n");
       return 1;
   }

   size_t out_size;
   if (!bip32_serialize(&key, serialized, &out_size)) {
       fprintf(stderr, "Serialization failed\n");
       return 1;
   }

   printf("%s\n", serialized);
   return 0;
}
