/*
 * Copyright (c) 2014 Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright notice,
 *       this list of conditions and the following disclaimer in the documentation
 *       and/or other materials provided with the distribution.
 *     * Neither the name of Intel Corporation nor the names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
*/


#ifndef IAESNI_H__
#define IAESNI_H__

#include <stdlib.h>

#define AES_CPUID_BIT (1<<25)

//indicates input param
#define _AES_IN

//indicates output param
#define _AES_OUT

//indicates input/output param - based on context
#define _AES_INOUT

typedef unsigned char UCHAR;

#define INLINE inline

#ifndef bool
#define bool BOOL
#endif
//test if the processor actually supports the above functions
//executing one the functions below without processor support will cause UD fault
//bool check_for_aes_instructions(void);

#if (__cplusplus)
extern "C" {
#endif
    int check_for_aes_instructions(void);

#define ALIGN16 __attribute__((aligned (16)))

#define DEFINE_ROUND_KEYS \
    UCHAR __attribute__ ((aligned (16))) _expandedKey[16*16];\
    UCHAR *expandedKey = _expandedKey;

// encryption functions
// plainText is pointer to input stream
// cipherText is pointer to buffer to be filled with encrypted (cipher text) data
// key is pointer to enc key (sizes are 16 bytes for AES-128, 24 bytes for AES-192, 32 for AES-256)
// numBlocks is number of 16 bytes blocks to process - note that encryption is done on full 16 byte blocks
void intel_AES_enc128(_AES_IN UCHAR *plainText, _AES_OUT UCHAR *cipherText, _AES_IN UCHAR *key, _AES_IN size_t numBlocks);
void intel_AES_enc192(_AES_IN UCHAR *plainText, _AES_OUT UCHAR *cipherText, _AES_IN UCHAR *key, _AES_IN size_t numBlocks);
void intel_AES_enc256(_AES_IN UCHAR *plainText, _AES_OUT UCHAR *cipherText, _AES_IN UCHAR *key, _AES_IN size_t numBlocks);


void intel_AES_enc128_CBC(_AES_IN UCHAR *plainText, _AES_OUT UCHAR *cipherText, _AES_IN UCHAR *key,
        _AES_IN size_t numBlocks, _AES_IN UCHAR *iv);
void intel_AES_enc192_CBC(_AES_IN UCHAR *plainText, _AES_OUT UCHAR *cipherText, _AES_IN UCHAR *key,
        _AES_IN size_t numBlocks, _AES_IN UCHAR *iv);
void intel_AES_enc256_CBC(_AES_IN UCHAR *plainText, _AES_OUT UCHAR *cipherText, _AES_IN UCHAR *key,
        _AES_IN size_t numBlocks, _AES_IN UCHAR *iv);

// decryption functions
// cipherText is pointer to encrypted stream
// plainText is pointer to buffer to be filled with original (plain text) data
// key is pointer to enc key (sizes are 16 bytes for AES-128, 24 bytes for AES-192, 32 for AES-256)
// numBlocks is number of 16 bytes blocks to process - note that decryption is done of full 16 byte blocks
void intel_AES_dec128_CBC(_AES_IN UCHAR *cipherText, _AES_OUT UCHAR *plainText, _AES_IN UCHAR *key,
        _AES_IN size_t numBlocks, _AES_IN UCHAR *iv);
void intel_AES_dec192_CBC(_AES_IN UCHAR *cipherText, _AES_OUT UCHAR *plainText, _AES_IN UCHAR *key,
        _AES_IN size_t numBlocks, _AES_IN UCHAR *iv);
void intel_AES_dec256_CBC(_AES_IN UCHAR *cipherText, _AES_OUT UCHAR *plainText, _AES_IN UCHAR *key,
        _AES_IN size_t numBlocks, _AES_IN UCHAR *iv);

#if (__cplusplus)
}
#endif

#endif



