/*
 * Copyright (c) 2014 Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
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

#ifndef _INTEL_AES_ASM_INTERFACE_H__
#define _INTEL_AES_ASM_INTERFACE_H__

#include "iaesni.h"

//structure to pass aes processing data to asm level functions
typedef struct _sAesData {
    _AES_IN     UCHAR   *in_block;
    _AES_OUT    UCHAR   *out_block;
    _AES_IN     UCHAR   *expanded_key;
    _AES_INOUT  UCHAR   *iv;    // for CBC mode
    _AES_IN     size_t  length; // length in bytes
} sAesData;

#if (__cplusplus)
extern "C"
{
#endif

    void iEncExpandKey256(const _AES_IN UCHAR *key, _AES_OUT UCHAR *expanded_key);
    void iEncExpandKey192(const _AES_IN UCHAR *key, _AES_OUT UCHAR *expanded_key);
    void iEncExpandKey128(const _AES_IN UCHAR *key, _AES_OUT UCHAR *expanded_key);

    void iDecExpandKey256(const UCHAR *key, _AES_OUT UCHAR *expanded_key);
    void iDecExpandKey192(const UCHAR *key, _AES_OUT UCHAR *expanded_key);
    void iDecExpandKey128(const UCHAR *key, _AES_OUT UCHAR *expanded_key);


    void iEnc128_CBC(sAesData *data);
    void iDec128_CBC(sAesData *data);
    void iEnc256_CBC(sAesData *data);
    void iDec256_CBC(sAesData *data);
    void iEnc192_CBC(sAesData *data);
    void iDec192_CBC(sAesData *data);

#if (__cplusplus)
}
#endif

#endif

