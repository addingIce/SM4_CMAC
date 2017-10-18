#include <stdio.h>
#include <stdlib.h>
#include <openssl/sms4.h>
#include <openssl/modes.h>

unsigned char MAC[16];
unsigned char MACkey[16];
unsigned char k1[16];
unsigned char k2[16];


void leftshift(int len, unsigned char* add, unsigned char*des)
{
    int i;
    for (i = 0; i < len - 1; i++)
    {
        des[i] = (add[i] << 1) + (add[i + 1] >= 0x80?1:0);
    }
    des[len - 1] = add[len - 1] << 1;
}   //left-shift for 1 bit

void ArrayXor(int len, unsigned char*a1, unsigned char*a2, unsigned char*des)
{
    int i;
    for (i = 0; i < len; i++)
    {
        des[i] = a1[i] ^ a2[i];
    }
}

void LoadMacKey(unsigned char *key)
{
    int i;
    unsigned char plain[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    unsigned char Rb[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87 };
    unsigned char c0[16];
    for (i = 0; i < 16; i++)
    {
        MACkey[i] = key[i];   //  set MAC key
    }
    sms4_key_t mackey;
    sms4_set_encrypt_key(&mackey,MACkey);
    sms4_encrypt(plain,c0,&mackey);
    if (c0[0]<0x80)    //generate k1
    {
        leftshift(16, c0, k1);
    }
    else
    {
        leftshift(16, c0, k1);
        ArrayXor(16, k1, Rb, k1);
    }

    if (k1[0] < 0x80)   //generate k2
    {
        leftshift(16, k1, k2);
    }
    else
    {
        leftshift(16, k1, k2);
        ArrayXor(16, k2, Rb, k2);
    }
}

void GenerateMAC(int len, unsigned char *add, unsigned char *macvalue)
{
    int i,block;
    unsigned char IVtemp[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char Blocktemp[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    sms4_key_t mackey;
    sms4_set_encrypt_key(&mackey,MACkey);

    if (len % 16 == 0 && len!=0)
    {
        block = len / 16;
        for (i = 0; i < block-1; i++)
        {
            ArrayXor(16, &add[i * 16], IVtemp, Blocktemp);
            sms4_encrypt(Blocktemp,IVtemp,&mackey);
        }
        ArrayXor(16, &add[(block-1)*16], IVtemp, Blocktemp);
        ArrayXor(16, Blocktemp, k1, Blocktemp);
        sms4_encrypt(Blocktemp,macvalue,&mackey);
    }
    else
    {
        if (len==0)
        {
            block = 1;
            Blocktemp[0] = 0x80;//padding the first bit with 1
            ArrayXor(16, Blocktemp, k2, Blocktemp);
            sms4_encrypt(Blocktemp,macvalue,&mackey);
        }
        else
        {
            unsigned char remain = len % 16;
            block = len / 16 + 1;
            for (i = 0; i < block - 1; i++)
            {
                ArrayXor(16, &add[i * 16], IVtemp, Blocktemp);
                sms4_encrypt(Blocktemp,IVtemp,&mackey);
            }
            // the last block padding
            for (i = 0; i < remain; i++)
            {
                Blocktemp[i] = add[(block - 1) * 16 + i];
            }
            Blocktemp[remain] = 0x80;
            for (i = remain + 1; i < 16; i++)
            {
                Blocktemp[i] = 0;
            }
            // end of the last block padding

            ArrayXor(16, Blocktemp, k2, Blocktemp);
            ArrayXor(16, Blocktemp, IVtemp, Blocktemp);
            sms4_encrypt(Blocktemp,macvalue,&mackey);
        }

    }
}

int main()
{
    unsigned char In[] = {0x01,0x02,0x03,0x04,0x05,0x06,0x01,0x02,0x03,0x04,0x05,0x06,0x01,0x02,0x03,0x04,0x05,0x06,0x01,0x02,0x03,0x04,0x01,0x02,0x03,0x04,0x05,0x06,0x01,0x02,0x03,0x04,0x05,0x06,0x01,0x02,0x03,0x04};
    unsigned char Userkey[] = {0x01,0x02,0x03,0x04,0x05,0x06,0x01,0x02,0x03,0x04,0x05,0x06,0x01,0x02,0x03,0x04,0x01,0x02,0x03,0x04,0x05,0x06,0x01,0x02,0x03,0x04,0x05,0x06,0x01,0x02,0x03,0x04};

    LoadMacKey(Userkey);
    GenerateMAC(13, In, MAC);
    int i = 0;
    for(i = 0;i<16;i++){
        printf("%x ",MAC[i]);
    }

    return 0;
}
