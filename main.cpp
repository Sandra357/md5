#include <string>
#include <string.h>
#include <iostream>
#include <stdio.h>
#include <cstdlib>
#include <conio.h>
using namespace std;


#ifdef __alpha
typedef unsigned int UINT4;
#else
typedef unsigned long int UINT4;
typedef unsigned long DWORD;
typedef unsigned int UINT;
typedef unsigned long ULONG;
typedef unsigned char UCHAR;
#endif

#define MD5_INIT_STATE_0 0x67452301
#define MD5_INIT_STATE_1 0xefcdab89
#define MD5_INIT_STATE_2 0x98badcfe
#define MD5_INIT_STATE_3 0x10325476

void MD5Init(void);
void MD5Update(unsigned char *bug, unsigned int len);
void MD5Final(char* cReturnStr);
void Transform(UINT4 *buf, UINT4 *in);

unsigned char  m_lpszBuffer[64];
DWORD m_nCount[2];
DWORD m_lMD5[4];

static unsigned char PADDING[64] = {
 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

#define FF(a, b, c, d, x, s, ac) \
 {(a) += F ((b), (c), (d)) + (x) + (UINT4)(ac); \
  (a) = ROTATE_LEFT ((a), (s)); \
  (a) += (b); \
 }





#define GG(a, b, c, d, x, s, ac) \
 {(a) += G ((b), (c), (d)) + (x) + (UINT4)(ac); \
  (a) = ROTATE_LEFT ((a), (s)); \
  (a) += (b); \
 }
#define HH(a, b, c, d, x, s, ac) \
 {(a) += H ((b), (c), (d)) + (x) + (UINT4)(ac); \
  (a) = ROTATE_LEFT ((a), (s)); \
  (a) += (b); \
 }
#define II(a, b, c, d, x, s, ac) \
 {(a) += I ((b), (c), (d)) + (x) + (UINT4)(ac); \
  (a) = ROTATE_LEFT ((a), (s)); \
  (a) += (b); \
 }

void ByteToDWord(DWORD* Output, long* Input, unsigned int nLength){
UINT i=0;
UINT j=0;
for (; j < nLength; i++, j += 4)
{
 Output[i] = (ULONG)Input[j]   |
    (ULONG)Input[j+1] << 8 |
    (ULONG)Input[j+2] << 16 |
    (ULONG)Input[j+3] << 24;
}
}

void DWordToByte(unsigned char* Output, DWORD* Input, unsigned int nLength ){
UINT i = 0;
UINT j = 0;
for (; j < nLength; i++, j += 4)
{
 Output[j] =   (UCHAR)(Input[i] & 0xff);
 Output[j+1] = (UCHAR)((Input[i] >> 8) & 0xff);
 Output[j+2] = (UCHAR)((Input[i] >> 16) & 0xff);
 Output[j+3] = (UCHAR)((Input[i] >> 24) & 0xff);
}
}

void MD5Init (void)
{
 memset(m_lpszBuffer, 0, 64 );
 m_nCount[0] = m_nCount[1] = 0;

m_lMD5[0] = MD5_INIT_STATE_0;
m_lMD5[1] = MD5_INIT_STATE_1;
m_lMD5[2] = MD5_INIT_STATE_2;
m_lMD5[3] = MD5_INIT_STATE_3;
}

void MD5Update (unsigned char *inBuf, unsigned int inLen)
{
 register int i, ii;
 int mdi;
 UINT4 in[16];

 mdi = (int)((m_nCount[0] >> 3) & 0x3F);

 if ((m_nCount[0] + ((UINT4)inLen << 3)) < m_nCount[0])
   m_nCount[1]++;
 m_nCount[0] += ((UINT4)inLen << 3);
 m_nCount[1] += ((UINT4)inLen >> 29);

 while (inLen--) {
   m_lpszBuffer[mdi++] = *inBuf++;

   if (mdi == 0x40) {
     for (i = 0, ii = 0; i < 16; i++, ii += 4)
       in[i] = (((UINT4)m_lpszBuffer[ii+3]) << 24) |
               (((UINT4)m_lpszBuffer[ii+2]) << 16) |
               (((UINT4)m_lpszBuffer[ii+1]) << 8) |
               ((UINT4)m_lpszBuffer[ii]);
     Transform (m_lMD5, in);
     mdi = 0;
   }
 }
}

void MD5Final (char* cReturnStr)
{
unsigned char bits[8];
int nIndex;
unsigned int nPadLen;
const int nMD5Size = 16;
 unsigned char lpszMD5[16];
char temp[2];
int i;

cReturnStr[0]='\0';

DWordToByte( bits, m_nCount, 8 );

nIndex = (int)((m_nCount[0] >> 3) & 0x3f);
nPadLen = (nIndex < 56) ? (56 - nIndex) : (120 - nIndex);
MD5Update (PADDING, nPadLen);

MD5Update (bits, 8);

DWordToByte( lpszMD5, m_lMD5, nMD5Size );

for (i=0; i < nMD5Size; i++)
{

 if (lpszMD5[i] == 0) {
  temp[0] = '0';
  temp[1]='0';
 }
 else if (lpszMD5[i] <= 15)  {
     sprintf(temp,"0%x",lpszMD5[i]);
 }
 else {
     sprintf(temp,"%x",lpszMD5[i]);
 }
   strcat(cReturnStr,temp);
}
lpszMD5[0]='\0';
}

void Transform(register UINT4 *buf,register UINT4 *in)
{
 register UINT4 a = buf[0], b = buf[1], c = buf[2], d = buf[3];
    char bufa [20];
    char bufb [20];
    char bufc [20];
    char bufd [20];

#define S11 7
#define S12 12
#define S13 17
#define S14 22
    cout << "iteration 1:\n";
 FF ( a, b, c, d, in[ 0], S11, 0xD76AA478L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 2:\n";
 FF ( d, a, b, c, in[ 1], S12, 0xE8C7B756L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 3:\n";
 FF ( c, d, a, b, in[ 2], S13, 0x242070DBL);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 4:\n";
 FF ( b, c, d, a, in[ 3], S14, 0xC1BDCEEEL);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 5:\n";
 FF ( a, b, c, d, in[ 4], S11, 0xF57C0FAFL);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 6:\n";
 FF ( d, a, b, c, in[ 5], S12, 0x4787C62AL);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 7:\n";
 FF ( c, d, a, b, in[ 6], S13, 0xA8304613L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 8:\n";
 FF ( b, c, d, a, in[ 7], S14, 0xFD469501L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 9:\n";
 FF ( a, b, c, d, in[ 8], S11, 0x698098D8L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 10:\n";
 FF ( d, a, b, c, in[ 9], S12, 0x8B44F7AFL);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 11:\n";
 FF ( c, d, a, b, in[10], S13, 0xFFFF5BB1L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 12:\n";
 FF ( b, c, d, a, in[11], S14, 0x895CD7BEL);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 13:\n";
 FF ( a, b, c, d, in[12], S11, 0x6B901122L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 14:\n";
 FF ( d, a, b, c, in[13], S12, 0xFD987193L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 15:\n";
 FF ( c, d, a, b, in[14], S13, 0xA679438EL);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 16:\n";
 FF ( b, c, d, a, in[15], S14, 0x49B40821L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

#define S21 5
#define S22 9
#define S23 14
#define S24 20

 cout << "iteration 17:\n";
 GG ( a, b, c, d, in[ 1], S21, 0xF61E2562L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 18:\n";
 GG ( d, a, b, c, in[ 6], S22, 0xC040B340L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 19:\n";
 GG ( c, d, a, b, in[11], S23, 0x265E5A51L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 20:\n";
 GG ( b, c, d, a, in[ 0], S24, 0xE9B6C7AAL);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 21:\n";
 GG ( a, b, c, d, in[ 5], S21, 0xD62F105DL);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 22:\n";
 GG ( d, a, b, c, in[10], S22, 0x02441453L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 23:\n";
 GG ( c, d, a, b, in[15], S23, 0xD8A1E681L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 24:\n";
 GG ( b, c, d, a, in[ 4], S24, 0xE7D3FBC8L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 25:\n";
 GG ( a, b, c, d, in[ 9], S21, 0x21E1CDE6L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 26:\n";
 GG ( d, a, b, c, in[14], S22, 0xC33707D6L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 27:\n";
 GG ( c, d, a, b, in[ 3], S23, 0xF4D50D87L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 28:\n";
 GG ( b, c, d, a, in[ 8], S24, 0x455A14EDL);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 29:\n";
 GG ( a, b, c, d, in[13], S21, 0xA9E3E905L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 30:\n";
 GG ( d, a, b, c, in[ 2], S22, 0xFCEFA3F8L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 31:\n";
 GG ( c, d, a, b, in[ 7], S23, 0x676F02D9L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 32:\n";
 GG ( b, c, d, a, in[12], S24, 0x8D2A4C8AL);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

#define S31 4
#define S32 11
#define S33 16
#define S34 23

 cout << "iteration 33:\n";
 HH ( a, b, c, d, in[ 5], S31, 0xFFFA3942L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 34:\n";
 HH ( d, a, b, c, in[ 8], S32, 0x8771F681L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 35:\n";
 HH ( c, d, a, b, in[11], S33, 0x6D9D6122L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 36:\n";
 HH ( b, c, d, a, in[14], S34, 0xFDE5380CL);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 37:\n";
 HH ( a, b, c, d, in[ 1], S31, 0xA4BEEA44L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 38:\n";
 HH ( d, a, b, c, in[ 4], S32, 0x4BDECFA9L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 39:\n";
 HH ( c, d, a, b, in[ 7], S33, 0xF6BB4B60L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 40:\n";
 HH ( b, c, d, a, in[10], S34, 0xBEBFBC70L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 41:\n";
 HH ( a, b, c, d, in[13], S31, 0x289B7EC6L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 42:\n";
 HH ( d, a, b, c, in[ 0], S32, 0xEAA127FAL);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 43:\n";
 HH ( c, d, a, b, in[ 3], S33, 0xD4EF3085L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 44:\n";
 HH ( b, c, d, a, in[ 6], S34, 0x04881D05L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 45:\n";
 HH ( a, b, c, d, in[ 9], S31, 0xD9D4D039L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 46:\n";
 HH ( d, a, b, c, in[12], S32, 0xE6DB99E5L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 47:\n";
 HH ( c, d, a, b, in[15], S33, 0x1FA27CF8L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 48:\n";
 HH ( b, c, d, a, in[ 2], S34, 0xC4AC5665L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

#define S41 6
#define S42 10
#define S43 15
#define S44 21

 cout << "iteration 49:\n";
 II ( a, b, c, d, in[ 0], S41, 0xF4292244L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 50:\n";
 II ( d, a, b, c, in[ 7], S42, 0x432AFF97L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 51:\n";
 II ( c, d, a, b, in[14], S43, 0xAB9423A7L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 52:\n";
 II ( b, c, d, a, in[ 5], S44, 0xFC93A039L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 53:\n";
 II ( a, b, c, d, in[12], S41, 0x655B59C3L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 54:\n";
 II ( d, a, b, c, in[ 3], S42, 0x8F0CCC92L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 55:\n";
 II ( c, d, a, b, in[10], S43, 0xFFEFF47DL);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 56:\n";
 II ( b, c, d, a, in[ 1], S44, 0x85845DD1L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 57:\n";
 II ( a, b, c, d, in[ 8], S41, 0x6FA87E4FL);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 58:\n";
 II ( d, a, b, c, in[15], S42, 0xFE2CE6E0L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 59:\n";
 II ( c, d, a, b, in[ 6], S43, 0xA3014314L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 60:\n";
 II ( b, c, d, a, in[13], S44, 0x4E0811A1L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 61:\n";
 II ( a, b, c, d, in[ 4], S41, 0xF7537E82L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 62:\n";
 II ( d, a, b, c, in[11], S42, 0xBD3AF235L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 63:\n";
 II ( c, d, a, b, in[ 2], S43, 0x2AD7D2BBL);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";

 cout << "iteration 64:\n";
 II ( b, c, d, a, in[ 9], S44, 0xEB86D391L);
 itoa (a, bufa, 16);
 itoa (b, bufb, 16);
 itoa (c, bufc, 16);
 itoa (d, bufd, 16);
 cout << "a = " << bufa << "\n";
 cout << "b = " << bufb << "\n";
 cout << "c = " << bufc << "\n";
 cout << "d = " << bufd << "\n";
 //cout << "a = " << a << "\n";

 buf[0] += a;
 itoa (buf[0], bufa, 16);
 cout << "bufa: " << bufa << "\n";
 buf[1] += b;
 itoa (buf[1], bufa, 16);
 cout << "bufb: " << bufa << "\n";
 buf[2] += c;
 itoa (buf[2], bufa, 16);
 cout << "bufc: " << bufa << "\n";
 buf[3] += d;
 itoa (buf[3], bufa, 16);
 cout << "bufd: " << bufa << "\n";
}

void GetMD5(char* pBuf, UINT nLength,char* cReturnStr){
MD5Init();
MD5Update((unsigned char *)pBuf, nLength);
MD5Final(cReturnStr);
}

int main ()
{
    //char in[] = "MD5 was proposed by Ron Rivest in 1992.";
    string in;
    //char* str;
    char out[50] = {'\0'};
    //string out;

    cout << "Enter your words\n";
    cin >> in;

    //char *str = new char[in.size()+1];
    //strcpy(str, in.c_str());

    //char* strout = new char[30];
    //GetMD5(in, strlen(in), out);
    GetMD5(&in[0], strlen(&in[0]), out);
    //string out(strout);
    cout << out;
    //delete(str);
    //delete(strout);

    while (getch() != (const char) 13);
    return 0;

}
