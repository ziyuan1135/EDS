#include"DES.h"

/* This is a project to implementation DES using C language, and it is just for
* self-learning.
*/

/*====================================================================
*============================ function ===============================
*=====================================================================
*/

uint32_t left_rot(uint32_t value, int shift) {
    if ((shift %= 28) == 0)
      return value;
    return ((value << shift) | (value >> (28 - shift))) & mask28bit;
}

uint32_t right_rot(uint32_t value, int shift) {
    if ((shift %= 28) == 0)
      return value;
    return ((value >> shift) | (value << (28 - shift))) & mask28bit;
}

uint8_t PC_1_permutation(uint8_t* key){
    uint8_t res[8];
    for (int j = 0; j < 8; j++){
        uint8_t temp = 0;
        for (int i = j*7; i < (j+1)*7; i++){
            int k_1 = (PC_1[i] >> 3);
            int k_2 = PC_1[i] & 0b111; 
            if (key[k_1] & (1 << ( 8 - k_2)) ){
                temp = (temp << 1) + 1;
            }
            else{
                temp = temp << 1;
            }
        }
        res[j] = temp;
    }
    memcpy(key, res, sizeof(uint8_t)*8);
    return 0;
}

uint8_t PC_2_permutation(uint8_t* key, uint8_t* subkey){
    uint8_t res[8];
    for (int j = 0; j < 8; j++){
        uint8_t temp = 0;
        for (int i = j*6; i < (j+1)*6; i++){
            int k_1 = (PC_2[i] - 1) / 7;
            int k_2 = (PC_2[i] - 1) % 7; 
            if (key[k_1] & (1 << (6 - k_2)) ){
                temp = (temp << 1) + 1;
            }
            else{
                temp = temp << 1;
            }
        }
        res[j] = temp;
    }
    memcpy(subkey, res, sizeof(uint8_t)*8);
    return 0;
}

uint8_t IP_or_IP_inv(uint8_t* plaintext, const int* table){
    uint8_t res[8];
    for (int j = 0; j < 8; j++){
        uint8_t temp = 0;
        for (int i = j*8; i < (j+1)*8; i++){
            int k_1 = (table[i] - 1) / 8;
            int k_2 = (table[i] - 1) % 8; 
            if (plaintext[k_1] & (1 << (7 - k_2)) ){
                temp = (temp << 1) + 1;
            }
            else{
                temp = temp << 1;
            }
        }
        res[j] = temp;
    }
    memcpy(plaintext, res, sizeof(uint8_t)*8);
    return 0;
}

uint8_t Expansion(uint8_t* R, uint8_t* output){
     uint8_t res[8];

    for (int j = 0; j < 8; j++){
        uint8_t temp = 0;
        for (int i = j*6; i < (j+1)*6; i++){
            int k_1 = (E[i] - 1) / 8;
            int k_2 = (E[i] - 1) % 8; 
            if (R[k_1] & (1 << (7 - k_2)) ){
                temp = (temp << 1) + 1;
            }
            else{
                temp = temp << 1;
            }
        }
        res[j] = temp;
    }
    memcpy(output, res, sizeof(uint8_t)*8);
    return 0;
}

uint8_t S_box(uint8_t* xored_R){
    
    for (int i = 0; i < 8; i++){
        int column = (xored_R[i] & 0b011110) >> 1;
        int row = ((xored_R[i] & 0b100000) >> 4) | (xored_R[i] & 0b000001);
        xored_R[i] = S[i][row][column];
    }
    return 0;
}

uint8_t P_perm_and_xored(uint8_t* s_boxed, uint8_t* plaintext){
    uint8_t res[4];
    for (int j = 0; j < 4; j++){
        uint8_t temp = 0;
        for (int i = j*8; i < (j+1)*8; i++){
            int k_1 = (P[i] - 1) / 4;
            int k_2 = (P[i] - 1) % 4; 
            if (s_boxed[k_1] & (1 << (3 - k_2)) ){
                temp = (temp << 1) + 1;
            }
            else{
                temp = temp << 1;
            }
        }
        res[j] = temp ^ plaintext[j];
    }
    memcpy(plaintext, res, sizeof(uint8_t)*4);
    return 0;
}

uint8_t DES(uint8_t* plaintext, uint8_t* ciphertext, uint8_t* key){
    uint8_t subkey[8];
    uint8_t expansion[8];
    uint32_t temp1, temp2;

    memcpy(ciphertext, plaintext, sizeof(uint8_t)*8);
    IP_or_IP_inv(ciphertext, IP);
    PC_1_permutation(key);
    /* 16 round encrypt*/
    for (int j = 0; j < 16; j++){
        /* compute round key */
        memset(subkey, 0, sizeof(subkey));
        memset(&temp1, 0, sizeof(temp1));
        memset(&temp2, 0, sizeof(temp2));
        temp1 = (key[0] << 21) | (key[1] << 14) | (key[2] << 7) | key[3];
        temp2 = (key[4] << 21) | (key[5] << 14) | (key[6] << 7) | key[7];
        temp1 = left_rot(temp1, shift_table[j]);
        temp2 = left_rot(temp2, shift_table[j]);
        for (int i = 0; i < 4; i++){
            key[3 - i] = temp1 & 0b1111111;
            key[7 - i] = temp2 & 0b1111111;
            temp1 = temp1 >> 7;
            temp2 = temp2 >> 7;
        }
        PC_2_permutation(key, subkey);

        /* compute f function */
        Expansion(ciphertext+4, expansion);
        /* XOR operation */
        for (int i = 0; i < 8; i++){
            expansion[i] = expansion[i] ^ subkey[i]; 
        }
        S_box(expansion);
        P_perm_and_xored(expansion, ciphertext);

        /* exchange L and R*/
        if(j != 15){
            for (int i = 0; i < 4; i++){
                ciphertext[i] = ciphertext[i] ^ ciphertext[4 + i];
                ciphertext[4 + i] = ciphertext[i] ^ ciphertext [4 + i];
                ciphertext[i] = ciphertext[i] ^ ciphertext[4 + i];
            } 
        }
/*         printf("round [%d] : ", j+1);
        for (int i = 0; i < 8; i++){
            printf("%02X", ciphertext[i]);
            if(i+1==4){
               printf(" ");
            }
        }
        printf("\n"); */
    }

    IP_or_IP_inv(ciphertext, IP_inv);
/*     printf("\n================================================\n");
    printf("Ciphertext : ");
    for (int i = 0; i < 8; i++){
        printf("%02X", ciphertext[i]);
    } */
    return 0;
}