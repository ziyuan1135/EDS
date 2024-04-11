#include"DES.h"

static uint8_t test_plaintext[8] = {0x12, 0x34, 0x56, 0xAB, 0xCD, 0x13, 0x25, 0x36};
static uint8_t test_key[8] = {0xAA, 0xBB, 0x09, 0x18, 0x27, 0x36, 0xCC, 0xDD};
static uint8_t test_ciphertext[8] = {0xC0, 0xB7, 0xA8, 0xD0, 0x5F, 0x3A, 0x82, 0x9C};

int main(int argc, char* argv[]){
    uint8_t plaintext[8];
    uint8_t ciphertext[8];
    uint8_t key[8];
    
    memcpy(plaintext, test_plaintext, sizeof(uint8_t)*8);
    memcpy(key, test_key, sizeof(uint8_t)*8);

    printf("================================================\n");
    printf("Plaintext : ");
    for (int i = 0; i < 8; i++){
        printf("%02X", plaintext[i]);
    }
    DES(plaintext, ciphertext, key);
    printf("\n================================================\n");
    printf("Ciphertext : ");
    for (int i = 0; i < 8; i++){
        printf("%02X", ciphertext[i]);
    }

    if(memcmp(ciphertext, test_ciphertext, sizeof(uint8_t)*8)!=0){
        printf("\nERROR : the encryption does not match the test case\n");
        return -1;
    }
    printf("\n================================================\n");
    return 0;
}