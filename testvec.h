#ifndef _TESTVEC_H_
#define _TESTVEC_H_

#include <stdint.h>

static uint8_t P256_private_key[] =
{
    0XDC, 0x51, 0XD3, 0x86, 0X6A, 0x15, 0XBA, 0XCD,
    0XE3, 0X3D, 0x96, 0XF9, 0x92, 0XFC, 0XA9, 0X9D,
    0XA7, 0XE6, 0XEF, 0x09, 0x34, 0XE7, 0x09, 0x75,
    0x59, 0XC2, 0X7F, 0x16, 0x14, 0XC8, 0X8A, 0X7F
};

static uint8_t P256_public_key_x[] =
{
    0x24, 0x42, 0XA5, 0XCC, 0X0E, 0XCD, 0x01, 0X5F,
    0XA3, 0XCA, 0x31, 0XDC, 0X8E, 0X2B, 0XBC, 0x70,
    0XBF, 0x42, 0XD6, 0X0C, 0XBC, 0XA2, 0x00, 0x85,
    0XE0, 0x82, 0X2C, 0XB0, 0x42, 0x35, 0XE9, 0x70
};

static uint8_t P256_public_key_y[] =
{
    0X6F, 0XC9, 0X8B, 0XD7, 0XE5, 0x02, 0x11, 0XA4,
    0XA2, 0x71, 0x02, 0XFA, 0x35, 0x49, 0XDF, 0x79,
    0XEB, 0XCB, 0X4B, 0XF2, 0x46, 0XB8, 0x09, 0x45,
    0XCD, 0XDF, 0XE7, 0XD5, 0x09, 0XBB, 0XFD, 0X7D
};

static uint8_t P256_hash[] =
{
    0XBA, 0x78, 0x16, 0XBF, 0X8F, 0x01, 0XCF, 0XEA,
    0x41, 0x41, 0x40, 0XDE, 0X5D, 0XAE, 0x22, 0x23,
    0XB0, 0x03, 0x61, 0XA3, 0x96, 0x17, 0X7A, 0X9C,
    0XB4, 0x10, 0XFF, 0x61, 0XF2, 0x00, 0x15, 0XAD
};

static uint8_t P256_k[] =
{
    0X9E, 0x56, 0XF5, 0x09, 0x19, 0x67, 0x84, 0XD9,
    0x63, 0XD1, 0XC0, 0XA4, 0x01, 0x51, 0X0E, 0XE7,
    0XAD, 0XA3, 0XDC, 0XC5, 0XDE, 0XE0, 0X4B, 0x15,
    0X4B, 0XF6, 0X1A, 0XF1, 0XD5, 0XA6, 0XDE, 0XCE
};

static uint8_t P256_r[] =
{
    0XCB, 0x28, 0XE0, 0x99, 0X9B, 0X9C, 0x77, 0x15,
    0XFD, 0X0A, 0x80, 0XD8, 0XE4, 0X7A, 0x77, 0x07,
    0x97, 0x16, 0XCB, 0XBF, 0x91, 0X7D, 0XD7, 0X2E,
    0x97, 0x56, 0X6E, 0XA1, 0XC0, 0x66, 0x95, 0X7C
};

static uint8_t P256_s[] =
{
    0x86, 0XFA, 0X3B, 0XB4, 0XE2, 0X6C, 0XAD, 0X5B,
    0XF9, 0X0B, 0X7F, 0x81, 0x89, 0x92, 0x56, 0XCE,
    0x75, 0x94, 0XBB, 0X1E, 0XA0, 0XC8, 0x92, 0x12,
    0x74, 0X8B, 0XFF, 0X3B, 0X3D, 0X5B, 0x03, 0x15
};

#endif  // _TESTVEC_H_