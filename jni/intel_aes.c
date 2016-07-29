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

#if (__cplusplus)
extern "C" {
#endif

#include "iaesni.h"
#include "iaes_asm_interface.h"

#if (__cplusplus)
}
#endif

#include <stdio.h>
#include <string.h>

#include <wmmintrin.h>

void iDecExpandKey128(const UCHAR *key, _AES_OUT UCHAR *expanded_key)
{
    UCHAR ALIGN16 tempKey[16*11];
    __m128i *Key_Schedule = (__m128i*)expanded_key;
    __m128i *Temp_Key_Schedule = (__m128i*)tempKey;
    iEncExpandKey128(key, tempKey);
    Key_Schedule[10] = Temp_Key_Schedule[0];
    Key_Schedule[9] = _mm_aesimc_si128(Temp_Key_Schedule[1]);
    Key_Schedule[8] = _mm_aesimc_si128(Temp_Key_Schedule[2]);
    Key_Schedule[7] = _mm_aesimc_si128(Temp_Key_Schedule[3]);
    Key_Schedule[6] = _mm_aesimc_si128(Temp_Key_Schedule[4]);
    Key_Schedule[5] = _mm_aesimc_si128(Temp_Key_Schedule[5]);
    Key_Schedule[4] = _mm_aesimc_si128(Temp_Key_Schedule[6]);
    Key_Schedule[3] = _mm_aesimc_si128(Temp_Key_Schedule[7]);
    Key_Schedule[2] = _mm_aesimc_si128(Temp_Key_Schedule[8]);
    Key_Schedule[1] = _mm_aesimc_si128(Temp_Key_Schedule[9]);
	Key_Schedule[0] = Temp_Key_Schedule[10];
}

void iDecExpandKey192(const UCHAR *key, _AES_OUT UCHAR *expanded_key)
{
    UCHAR ALIGN16 tempKey[16*13];
    __m128i *Key_Schedule = (__m128i*)expanded_key;
    __m128i *Temp_Key_Schedule = (__m128i*)tempKey;
    iEncExpandKey192(key, tempKey);
    Key_Schedule[12] = Temp_Key_Schedule[0];
    Key_Schedule[11] = _mm_aesimc_si128(Temp_Key_Schedule[1]);
    Key_Schedule[10] = _mm_aesimc_si128(Temp_Key_Schedule[2]);
    Key_Schedule[9] = _mm_aesimc_si128(Temp_Key_Schedule[3]);
    Key_Schedule[8] = _mm_aesimc_si128(Temp_Key_Schedule[4]);
    Key_Schedule[7] = _mm_aesimc_si128(Temp_Key_Schedule[5]);
    Key_Schedule[6] = _mm_aesimc_si128(Temp_Key_Schedule[6]);
    Key_Schedule[5] = _mm_aesimc_si128(Temp_Key_Schedule[7]);
    Key_Schedule[4] = _mm_aesimc_si128(Temp_Key_Schedule[8]);
    Key_Schedule[3] = _mm_aesimc_si128(Temp_Key_Schedule[9]);
    Key_Schedule[2] = _mm_aesimc_si128(Temp_Key_Schedule[10]);
    Key_Schedule[1] = _mm_aesimc_si128(Temp_Key_Schedule[11]);
    Key_Schedule[0] = Temp_Key_Schedule[12];
}

void iDecExpandKey256(const UCHAR *key, _AES_OUT UCHAR *expanded_key)
{
    UCHAR ALIGN16 tempKey[16*15];
    __m128i *Key_Schedule = (__m128i*)expanded_key;
    __m128i *Temp_Key_Schedule = (__m128i*)tempKey;
    iEncExpandKey256(key, tempKey);
    Key_Schedule[14] = Temp_Key_Schedule[0];
    Key_Schedule[13] = _mm_aesimc_si128(Temp_Key_Schedule[1]);
    Key_Schedule[12] = _mm_aesimc_si128(Temp_Key_Schedule[2]);
    Key_Schedule[11] = _mm_aesimc_si128(Temp_Key_Schedule[3]);
    Key_Schedule[10] = _mm_aesimc_si128(Temp_Key_Schedule[4]);
    Key_Schedule[9] = _mm_aesimc_si128(Temp_Key_Schedule[5]);
    Key_Schedule[8] = _mm_aesimc_si128(Temp_Key_Schedule[6]);
    Key_Schedule[7] = _mm_aesimc_si128(Temp_Key_Schedule[7]);
    Key_Schedule[6] = _mm_aesimc_si128(Temp_Key_Schedule[8]);
    Key_Schedule[5] = _mm_aesimc_si128(Temp_Key_Schedule[9]);
    Key_Schedule[4] = _mm_aesimc_si128(Temp_Key_Schedule[10]);
    Key_Schedule[3] = _mm_aesimc_si128(Temp_Key_Schedule[11]);
    Key_Schedule[2] = _mm_aesimc_si128(Temp_Key_Schedule[12]);
    Key_Schedule[1] = _mm_aesimc_si128(Temp_Key_Schedule[13]);
    Key_Schedule[0] = Temp_Key_Schedule[14];
}

void iDec128_CBC(sAesData *data)
{
    __m128i feedback0,feedback1, data0, data1, lastIn0, lastIn1;
    unsigned int i,j, remainder, numBlocks;
    UCHAR ALIGN16 remBuf[16];

    numBlocks = data->length >> 4;
    feedback0 =_mm_loadu_si128 ((__m128i*)data->iv);
    feedback1 = _mm_loadu_si128 ((__m128i*)data->in_block);
    for(i=0; i < ((numBlocks >> 1) << 1); i+=2)
    {
        lastIn0 = _mm_loadu_si128 (((__m128i*)data->in_block)+i);
        lastIn1 = _mm_loadu_si128 (((__m128i*)data->in_block)+i+1);
        data0 = _mm_xor_si128 (lastIn0,((__m128i*)data->expanded_key)[0]);
        data1 = _mm_xor_si128 (lastIn1,((__m128i*)data->expanded_key)[0]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[1]);
        data1 = _mm_aesdec_si128 (data1,((__m128i*)data->expanded_key)[1]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[2]);
        data1 = _mm_aesdec_si128 (data1,((__m128i*)data->expanded_key)[2]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[3]);
        data1 = _mm_aesdec_si128 (data1,((__m128i*)data->expanded_key)[3]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[4]);
        data1 = _mm_aesdec_si128 (data1,((__m128i*)data->expanded_key)[4]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[5]);
        data1 = _mm_aesdec_si128 (data1,((__m128i*)data->expanded_key)[5]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[6]);
        data1 = _mm_aesdec_si128 (data1,((__m128i*)data->expanded_key)[6]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[7]);
        data1 = _mm_aesdec_si128 (data1,((__m128i*)data->expanded_key)[7]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[8]);
        data1 = _mm_aesdec_si128 (data1,((__m128i*)data->expanded_key)[8]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[9]);
        data1 = _mm_aesdec_si128 (data1,((__m128i*)data->expanded_key)[9]);
        data0 = _mm_aesdeclast_si128 (data0,((__m128i*)data->expanded_key)[10]);
        data1 = _mm_aesdeclast_si128 (data1,( (__m128i*)data->expanded_key)[10]);
        data0 = _mm_xor_si128 (data0,feedback0);
        data1 = _mm_xor_si128 (data1,feedback1);
        _mm_storeu_si128 (((__m128i*)data->out_block)+i,data0);
        _mm_storeu_si128 (((__m128i*)data->out_block)+i+1,data1);
        feedback0 = _mm_loadu_si128 (((__m128i*)data->in_block)+i+1);
        if(i + 2 < numBlocks)
            feedback1 = _mm_loadu_si128 (((__m128i*)data->in_block)+i+2);
    }
    if(numBlocks & 1)
    {
        lastIn0 = _mm_loadu_si128 (((__m128i*)data->in_block)+numBlocks-1);
        data0 = _mm_xor_si128 (lastIn0,((__m128i*)data->expanded_key)[0]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[1]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[2]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[3]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[4]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[5]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[6]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[7]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[8]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[9]);
        data0 = _mm_aesdeclast_si128 (data0, ((__m128i*)data->expanded_key)[10]);
        data0 = _mm_xor_si128 (data0, feedback0);
        _mm_storeu_si128 (((__m128i*)data->out_block)+numBlocks-1, data0);
        feedback0 = lastIn0;
    }

/* copy any remaining bytes < 16 byte blocksize as a zero padded full aes block. */
    remainder = data->length & 0xF;
    if(remainder)
    {
        data0 = _mm_setzero_si128();
        _mm_store_si128((__m128i*)remBuf, data0);
        memcpy(remBuf, data->in_block+data->length-remainder, remainder);
        lastIn0 = _mm_load_si128 ((__m128i*)remBuf);
        data0 = _mm_xor_si128 (lastIn0, ((__m128i*)data->expanded_key)[0]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[1]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[2]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[3]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[4]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[5]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[6]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[7]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[8]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[9]);
        data0 = _mm_aesdeclast_si128 (data0, ((__m128i*)data->expanded_key)[10]);
        data0 = _mm_xor_si128 (data0, feedback0);
        _mm_store_si128 ((__m128i*)(remBuf), data0);
        memcpy(data->out_block+data->length-remainder, remBuf, remainder);
    }
}

void iDec192_CBC(sAesData *data)
{
    __m128i feedback0,feedback1, data0, data1, lastIn0, lastIn1;
    unsigned int i,j, remainder, numBlocks;
    UCHAR ALIGN16 remBuf[16];

    numBlocks = data->length >> 4;
    feedback0 =_mm_loadu_si128 ((__m128i*)data->iv);
    feedback1 = _mm_loadu_si128 ((__m128i*)data->in_block);
    for(i=0; i < ((numBlocks >> 1) << 1); i+=2)
    {
        lastIn0 = _mm_loadu_si128 (((__m128i*)data->in_block)+i);
        lastIn1 = _mm_loadu_si128 (((__m128i*)data->in_block)+i+1);
        data0 = _mm_xor_si128 (lastIn0,((__m128i*)data->expanded_key)[0]);
        data1 = _mm_xor_si128 (lastIn1,((__m128i*)data->expanded_key)[0]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[1]);
        data1 = _mm_aesdec_si128 (data1,((__m128i*)data->expanded_key)[1]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[2]);
        data1 = _mm_aesdec_si128 (data1,((__m128i*)data->expanded_key)[2]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[3]);
        data1 = _mm_aesdec_si128 (data1,((__m128i*)data->expanded_key)[3]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[4]);
        data1 = _mm_aesdec_si128 (data1,((__m128i*)data->expanded_key)[4]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[5]);
        data1 = _mm_aesdec_si128 (data1,((__m128i*)data->expanded_key)[5]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[6]);
        data1 = _mm_aesdec_si128 (data1,((__m128i*)data->expanded_key)[6]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[7]);
        data1 = _mm_aesdec_si128 (data1,((__m128i*)data->expanded_key)[7]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[8]);
        data1 = _mm_aesdec_si128 (data1,((__m128i*)data->expanded_key)[8]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[9]);
        data1 = _mm_aesdec_si128 (data1,((__m128i*)data->expanded_key)[9]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[10]);
        data1 = _mm_aesdec_si128 (data1,((__m128i*)data->expanded_key)[10]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[11]);
        data1 = _mm_aesdec_si128 (data1,((__m128i*)data->expanded_key)[11]);
        data0 = _mm_aesdeclast_si128 (data0,((__m128i*)data->expanded_key)[12]);
        data1 = _mm_aesdeclast_si128 (data1,( (__m128i*)data->expanded_key)[12]);
        data0 = _mm_xor_si128 (data0,feedback0);
        data1 = _mm_xor_si128 (data1,feedback1);
        _mm_storeu_si128 (((__m128i*)data->out_block)+i,data0);
        _mm_storeu_si128 (((__m128i*)data->out_block)+i+1,data1);
        feedback0 = _mm_loadu_si128 (((__m128i*)data->in_block)+i+1);
        if(i + 2 < numBlocks)
            feedback1 = _mm_loadu_si128 (((__m128i*)data->in_block)+i+2);
    }
    if(numBlocks & 1)
    {
        lastIn0 = _mm_loadu_si128 (((__m128i*)data->in_block)+numBlocks-1);
        data0 = _mm_xor_si128 (lastIn0,((__m128i*)data->expanded_key)[0]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[1]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[2]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[3]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[4]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[5]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[6]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[7]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[8]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[9]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[10]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[11]);
        data0 = _mm_aesdeclast_si128 (data0, ((__m128i*)data->expanded_key)[12]);
        data0 = _mm_xor_si128 (data0, feedback0);
        _mm_storeu_si128 (((__m128i*)data->out_block)+numBlocks-1, data0);
        feedback0 = lastIn0;
    }

/* copy any remaining bytes < 16 byte blocksize as a zero padded full aes block. */
    remainder = data->length & 0xF;
    if(remainder)
    {
        data0 = _mm_setzero_si128();
        _mm_store_si128((__m128i*)remBuf, data0);
        memcpy(remBuf, data->in_block+data->length-remainder, remainder);
        lastIn0 = _mm_load_si128 ((__m128i*)remBuf);
        data0 = _mm_xor_si128 (lastIn0, ((__m128i*)data->expanded_key)[0]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[1]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[2]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[3]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[4]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[5]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[6]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[7]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[8]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[9]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[10]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[11]);
        data0 = _mm_aesdeclast_si128 (data0, ((__m128i*)data->expanded_key)[12]);
        data0 = _mm_xor_si128 (data0, feedback0);
        _mm_store_si128 ((__m128i*)(remBuf), data0);
        memcpy(data->out_block+data->length-remainder, remBuf, remainder);
    }
}

void iDec256_CBC(sAesData *data)
{
    __m128i feedback0,feedback1, data0, data1, lastIn0, lastIn1;
    unsigned int i,j, remainder, numBlocks;
    UCHAR ALIGN16 remBuf[16];

    numBlocks = data->length >> 4;
    feedback0 =_mm_loadu_si128 ((__m128i*)data->iv);
    feedback1 = _mm_loadu_si128 ((__m128i*)data->in_block);
    for(i=0; i < ((numBlocks >> 1) << 1); i+=2)
    {
        lastIn0 = _mm_loadu_si128 (((__m128i*)data->in_block)+i);
        lastIn1 = _mm_loadu_si128 (((__m128i*)data->in_block)+i+1);
        data0 = _mm_xor_si128 (lastIn0,((__m128i*)data->expanded_key)[0]);
        data1 = _mm_xor_si128 (lastIn1,((__m128i*)data->expanded_key)[0]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[1]);
        data1 = _mm_aesdec_si128 (data1,((__m128i*)data->expanded_key)[1]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[2]);
        data1 = _mm_aesdec_si128 (data1,((__m128i*)data->expanded_key)[2]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[3]);
        data1 = _mm_aesdec_si128 (data1,((__m128i*)data->expanded_key)[3]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[4]);
        data1 = _mm_aesdec_si128 (data1,((__m128i*)data->expanded_key)[4]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[5]);
        data1 = _mm_aesdec_si128 (data1,((__m128i*)data->expanded_key)[5]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[6]);
        data1 = _mm_aesdec_si128 (data1,((__m128i*)data->expanded_key)[6]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[7]);
        data1 = _mm_aesdec_si128 (data1,((__m128i*)data->expanded_key)[7]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[8]);
        data1 = _mm_aesdec_si128 (data1,((__m128i*)data->expanded_key)[8]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[9]);
        data1 = _mm_aesdec_si128 (data1,((__m128i*)data->expanded_key)[9]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[10]);
        data1 = _mm_aesdec_si128 (data1,((__m128i*)data->expanded_key)[10]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[11]);
        data1 = _mm_aesdec_si128 (data1,((__m128i*)data->expanded_key)[11]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[12]);
        data1 = _mm_aesdec_si128 (data1,((__m128i*)data->expanded_key)[12]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[13]);
        data1 = _mm_aesdec_si128 (data1,((__m128i*)data->expanded_key)[13]);
        data0 = _mm_aesdeclast_si128 (data0,((__m128i*)data->expanded_key)[14]);
        data1 = _mm_aesdeclast_si128 (data1,( (__m128i*)data->expanded_key)[14]);
        data0 = _mm_xor_si128 (data0,feedback0);
        data1 = _mm_xor_si128 (data1,feedback1);
        _mm_storeu_si128 (((__m128i*)data->out_block)+i,data0);
        _mm_storeu_si128 (((__m128i*)data->out_block)+i+1,data1);
        feedback0 = _mm_loadu_si128 (((__m128i*)data->in_block)+i+1);
        if(i + 2 < numBlocks)
            feedback1 = _mm_loadu_si128 (((__m128i*)data->in_block)+i+2);
    }
    if(numBlocks & 1)
    {
        lastIn0 = _mm_loadu_si128 (((__m128i*)data->in_block)+numBlocks-1);
        data0 = _mm_xor_si128 (lastIn0,((__m128i*)data->expanded_key)[0]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[1]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[2]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[3]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[4]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[5]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[6]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[7]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[8]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[9]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[10]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[11]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[12]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[13]);
        data0 = _mm_aesdeclast_si128 (data0, ((__m128i*)data->expanded_key)[14]);
        data0 = _mm_xor_si128 (data0, feedback0);
        _mm_storeu_si128 (((__m128i*)data->out_block)+numBlocks-1, data0);
        feedback0 = lastIn0;
    }

/* copy any remaining bytes < 16 byte blocksize as a zero padded full aes block. */
    remainder = data->length & 0xF;
    if(remainder)
    {
        data0 = _mm_setzero_si128();
        _mm_store_si128((__m128i*)remBuf, data0);
        memcpy(remBuf, data->in_block+data->length-remainder, remainder);
        lastIn0 = _mm_load_si128 ((__m128i*)remBuf);
        data0 = _mm_xor_si128 (lastIn0, ((__m128i*)data->expanded_key)[0]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[1]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[2]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[3]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[4]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[5]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[6]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[7]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[8]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[9]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[10]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[11]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[12]);
        data0 = _mm_aesdec_si128 (data0,((__m128i*)data->expanded_key)[13]);
        data0 = _mm_aesdeclast_si128 (data0, ((__m128i*)data->expanded_key)[14]);
        data0 = _mm_xor_si128 (data0, feedback0);
        _mm_store_si128 ((__m128i*)(remBuf), data0);
        memcpy(data->out_block+data->length-remainder, remBuf, remainder);
    }
}

INLINE __m128i AES_128_ASSIST (__m128i temp1, __m128i temp2)
{
    __m128i temp3;
    temp2 = _mm_shuffle_epi32 (temp2 ,0xff);
    temp3 = _mm_slli_si128 (temp1, 0x4);
    temp1 = _mm_xor_si128 (temp1, temp3);
    temp3 = _mm_slli_si128 (temp3, 0x4);
    temp1 = _mm_xor_si128 (temp1, temp3);
    temp3 = _mm_slli_si128 (temp3, 0x4);
    temp1 = _mm_xor_si128 (temp1, temp3);
    temp1 = _mm_xor_si128 (temp1, temp2);
    return temp1;
}

void iEncExpandKey128(const _AES_IN UCHAR *key, _AES_OUT UCHAR *expanded_key)
{
    __m128i temp1, temp2;
    __m128i *Key_Schedule = (__m128i*)expanded_key;
    temp1 = _mm_loadu_si128((__m128i*)key);
    Key_Schedule[0] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1 ,0x1);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[1] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x2);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[2] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x4);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[3] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x8);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[4] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x10);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[5] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x20);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[6] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x40);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[7] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x80);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[8] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x1b);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[9] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x36);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[10] = temp1;
}

INLINE void KEY_192_ASSIST(__m128i* temp1, __m128i * temp2, __m128i * temp3)
{
    __m128i temp4;
    *temp2 = _mm_shuffle_epi32 (*temp2, 0x55);
    temp4 = _mm_slli_si128 (*temp1, 0x4);
    *temp1 = _mm_xor_si128 (*temp1, temp4);
    temp4 = _mm_slli_si128 (temp4, 0x4);
    *temp1 = _mm_xor_si128 (*temp1, temp4);
    temp4 = _mm_slli_si128 (temp4, 0x4);
    *temp1 = _mm_xor_si128 (*temp1, temp4);
    *temp1 = _mm_xor_si128 (*temp1, *temp2);
    *temp2 = _mm_shuffle_epi32(*temp1, 0xff);
    temp4 = _mm_slli_si128 (*temp3, 0x4);
    *temp3 = _mm_xor_si128 (*temp3, temp4);
    *temp3 = _mm_xor_si128 (*temp3, *temp2);
}

void iEncExpandKey192(const _AES_IN UCHAR *key, _AES_OUT UCHAR *expanded_key)
{
    __m128i temp1, temp2, temp3, temp4;
    __m128i *Key_Schedule = (__m128i*)expanded_key;
    temp1 = _mm_loadu_si128((__m128i*)key);
    temp3 = _mm_loadu_si128((__m128i*)(key+16));
    Key_Schedule[0]=temp1;
    Key_Schedule[1]=temp3;
    temp2=_mm_aeskeygenassist_si128 (temp3,0x1);
    KEY_192_ASSIST(&temp1, &temp2, &temp3);
    Key_Schedule[1] = (__m128i)_mm_shuffle_pd((__m128d)Key_Schedule[1],
    (__m128d)temp1,0);
    Key_Schedule[2] = (__m128i)_mm_shuffle_pd((__m128d)temp1,(__m128d)temp3,1);
    temp2=_mm_aeskeygenassist_si128 (temp3,0x2);
    KEY_192_ASSIST(&temp1, &temp2, &temp3);
    Key_Schedule[3]=temp1;
    Key_Schedule[4]=temp3;
    temp2=_mm_aeskeygenassist_si128 (temp3,0x4);
    KEY_192_ASSIST(&temp1, &temp2, &temp3);
    Key_Schedule[4] = (__m128i)_mm_shuffle_pd((__m128d)Key_Schedule[4],
    (__m128d)temp1,0);
    Key_Schedule[5] = (__m128i)_mm_shuffle_pd((__m128d)temp1,(__m128d)temp3,1);
    temp2=_mm_aeskeygenassist_si128 (temp3,0x8);
    KEY_192_ASSIST(&temp1, &temp2, &temp3);
    Key_Schedule[6]=temp1;
    Key_Schedule[7]=temp3;
    temp2=_mm_aeskeygenassist_si128 (temp3,0x10);
    KEY_192_ASSIST(&temp1, &temp2, &temp3);
    Key_Schedule[7] = (__m128i)_mm_shuffle_pd((__m128d)Key_Schedule[7],
    (__m128d)temp1,0);
    Key_Schedule[8] = (__m128i)_mm_shuffle_pd((__m128d)temp1,(__m128d)temp3,1);
    temp2=_mm_aeskeygenassist_si128 (temp3,0x20);
    KEY_192_ASSIST(&temp1, &temp2, &temp3);
    Key_Schedule[9]=temp1;
    Key_Schedule[10]=temp3;
    temp2=_mm_aeskeygenassist_si128 (temp3,0x40);
    KEY_192_ASSIST(&temp1, &temp2, &temp3);
    Key_Schedule[10] = (__m128i)_mm_shuffle_pd((__m128d)Key_Schedule[10],
    (__m128d)temp1,0);
    Key_Schedule[11] = (__m128i)_mm_shuffle_pd((__m128d)temp1,(__m128d)temp3,1);
    temp2=_mm_aeskeygenassist_si128 (temp3,0x80);
    KEY_192_ASSIST(&temp1, &temp2, &temp3);
    Key_Schedule[12]=temp1;
}

INLINE void KEY_256_ASSIST_1(__m128i* temp1, __m128i * temp2)
{
    __m128i temp4;
    *temp2 = _mm_shuffle_epi32(*temp2, 0xff);
    temp4 = _mm_slli_si128 (*temp1, 0x4);
    *temp1 = _mm_xor_si128 (*temp1, temp4);
    temp4 = _mm_slli_si128 (temp4, 0x4);
    *temp1 = _mm_xor_si128 (*temp1, temp4);
    temp4 = _mm_slli_si128 (temp4, 0x4);
    *temp1 = _mm_xor_si128 (*temp1, temp4);
    *temp1 = _mm_xor_si128 (*temp1, *temp2);
}

INLINE void KEY_256_ASSIST_2(__m128i* temp1, __m128i * temp3)
{
    __m128i temp2,temp4;
    temp4 = _mm_aeskeygenassist_si128 (*temp1, 0x0);
    temp2 = _mm_shuffle_epi32(temp4, 0xaa);
    temp4 = _mm_slli_si128 (*temp3, 0x4);
    *temp3 = _mm_xor_si128 (*temp3, temp4);
    temp4 = _mm_slli_si128 (temp4, 0x4);
    *temp3 = _mm_xor_si128 (*temp3, temp4);
    temp4 = _mm_slli_si128 (temp4, 0x4);
    *temp3 = _mm_xor_si128 (*temp3, temp4);
    *temp3 = _mm_xor_si128 (*temp3, temp2);
}

void iEncExpandKey256 (const unsigned char *key, unsigned char *expanded_key)
{
    __m128i temp1, temp2, temp3;
    __m128i *Key_Schedule = (__m128i*)expanded_key;
    temp1 = _mm_loadu_si128((__m128i*)key);
    temp3 = _mm_loadu_si128((__m128i*)(key+16));
    Key_Schedule[0] = temp1;
    Key_Schedule[1] = temp3;
    temp2 = _mm_aeskeygenassist_si128 (temp3,0x01);
    KEY_256_ASSIST_1(&temp1, &temp2);
    Key_Schedule[2]=temp1;
    KEY_256_ASSIST_2(&temp1, &temp3);
    Key_Schedule[3]=temp3;
    temp2 = _mm_aeskeygenassist_si128 (temp3,0x02);
    KEY_256_ASSIST_1(&temp1, &temp2);
    Key_Schedule[4]=temp1;
    KEY_256_ASSIST_2(&temp1, &temp3);
    Key_Schedule[5]=temp3;
    temp2 = _mm_aeskeygenassist_si128 (temp3,0x04);
    KEY_256_ASSIST_1(&temp1, &temp2);
    Key_Schedule[6]=temp1;
    KEY_256_ASSIST_2(&temp1, &temp3);
    Key_Schedule[7]=temp3;
    temp2 = _mm_aeskeygenassist_si128 (temp3,0x08);
    KEY_256_ASSIST_1(&temp1, &temp2);
    Key_Schedule[8]=temp1;
    KEY_256_ASSIST_2(&temp1, &temp3);
    Key_Schedule[9]=temp3;
    temp2 = _mm_aeskeygenassist_si128 (temp3,0x10);
    KEY_256_ASSIST_1(&temp1, &temp2);
    Key_Schedule[10]=temp1;
    KEY_256_ASSIST_2(&temp1, &temp3);
    Key_Schedule[11]=temp3;
    temp2 = _mm_aeskeygenassist_si128 (temp3,0x20);
    KEY_256_ASSIST_1(&temp1, &temp2);
    Key_Schedule[12]=temp1;
    KEY_256_ASSIST_2(&temp1, &temp3);
    Key_Schedule[13]=temp3;
    temp2 = _mm_aeskeygenassist_si128 (temp3,0x40);
    KEY_256_ASSIST_1(&temp1, &temp2);
    Key_Schedule[14]=temp1;
}

void iEnc128_CBC(sAesData *data)
{
    __m128i feedback, tmp;
    unsigned int i,j, remainder, numBlocks;
    UCHAR ALIGN16 remBuf[16];

    numBlocks = data->length >> 4;
    feedback =_mm_loadu_si128 ((__m128i*)data->iv);

    for(i=0; i < numBlocks; i++)
    {
        tmp = _mm_loadu_si128 (((__m128i*)data->in_block)+i);
        feedback = _mm_xor_si128 (tmp,feedback);
        feedback = _mm_xor_si128 (feedback,((__m128i*)data->expanded_key)[0]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[1]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[2]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[3]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[4]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[5]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[6]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[7]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[8]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[9]);
        feedback = _mm_aesenclast_si128 (feedback, ((__m128i*)data->expanded_key)[10]);
        _mm_storeu_si128 (((__m128i*)data->out_block)+i, feedback);
    }

/* copy any remaining bytes < 16 byte blocksize as a zero padded full aes block. */
    remainder = data->length & 0xF;
    if(remainder)
    {
        tmp = _mm_setzero_si128();
        _mm_store_si128((__m128i*)remBuf, tmp);
        memcpy(remBuf, data->in_block+data->length-remainder, remainder);
        tmp = _mm_loadu_si128 ((__m128i*)remBuf);
        feedback = _mm_xor_si128 (tmp, feedback);
        feedback = _mm_xor_si128 (feedback, ((__m128i*)data->expanded_key)[0]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[1]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[2]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[3]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[4]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[5]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[6]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[7]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[8]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[9]);
        feedback = _mm_aesenclast_si128 (feedback, ((__m128i*)data->expanded_key)[10]);
        _mm_store_si128 ((__m128i*)(remBuf), feedback);
        memcpy(data->out_block+data->length-remainder, remBuf, remainder);
    }
}

void iEnc192_CBC(sAesData *data)
{
    __m128i feedback, tmp;
    unsigned int i,j, remainder, numBlocks;
    UCHAR ALIGN16 remBuf[16];

    numBlocks = data->length >> 4;
    feedback =_mm_loadu_si128 ((__m128i*)data->iv);

    for(i=0; i < numBlocks; i++)
    {
        tmp = _mm_loadu_si128 (((__m128i*)data->in_block)+i);
        feedback = _mm_xor_si128 (tmp,feedback);
        feedback = _mm_xor_si128 (feedback,((__m128i*)data->expanded_key)[0]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[1]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[2]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[3]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[4]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[5]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[6]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[7]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[8]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[9]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[10]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[11]);
        feedback = _mm_aesenclast_si128 (feedback, ((__m128i*)data->expanded_key)[12]);
        _mm_storeu_si128 (((__m128i*)data->out_block)+i, feedback);
    }

/* copy any remaining bytes < 16 byte blocksize as a zero padded full aes block. */
    remainder = data->length & 0xF;
    if(remainder)
    {
        tmp = _mm_setzero_si128();
        _mm_store_si128((__m128i*)remBuf, tmp);
        memcpy(remBuf, data->in_block+data->length-remainder, remainder);
        tmp = _mm_loadu_si128 ((__m128i*)remBuf);
        feedback = _mm_xor_si128 (tmp, feedback);
        feedback = _mm_xor_si128 (feedback, ((__m128i*)data->expanded_key)[0]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[1]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[2]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[3]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[4]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[5]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[6]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[7]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[8]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[9]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[10]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[11]);
        feedback = _mm_aesenclast_si128 (feedback, ((__m128i*)data->expanded_key)[12]);
        _mm_store_si128 ((__m128i*)(remBuf), feedback);
        memcpy(data->out_block+data->length-remainder, remBuf, remainder);
    }
}

void iEnc256_CBC(sAesData *data)
{
    __m128i feedback, tmp;
    unsigned int i,j, remainder, numBlocks;
    UCHAR ALIGN16 remBuf[16];

    numBlocks = data->length >> 4;
    feedback =_mm_loadu_si128 ((__m128i*)data->iv);

    for(i=0; i < numBlocks; i++)
    {
        tmp = _mm_loadu_si128 (((__m128i*)data->in_block)+i);
        feedback = _mm_xor_si128 (tmp,feedback);
        feedback = _mm_xor_si128 (feedback,((__m128i*)data->expanded_key)[0]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[1]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[2]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[3]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[4]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[5]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[6]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[7]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[8]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[9]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[10]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[11]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[12]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[13]);
        feedback = _mm_aesenclast_si128 (feedback, ((__m128i*)data->expanded_key)[14]);
        _mm_storeu_si128 (((__m128i*)data->out_block)+i, feedback);
    }

/* copy any remaining bytes < 16 byte blocksize as a zero padded full aes block. */
    remainder = data->length & 0xF;
    if(remainder)
    {
        tmp = _mm_setzero_si128();
        _mm_store_si128((__m128i*)remBuf, tmp);
        memcpy(remBuf, data->in_block+data->length-remainder, remainder);
        tmp = _mm_loadu_si128 ((__m128i*)remBuf);
        feedback = _mm_xor_si128 (tmp, feedback);
        feedback = _mm_xor_si128 (feedback, ((__m128i*)data->expanded_key)[0]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[1]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[2]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[3]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[4]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[5]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[6]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[7]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[8]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[9]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[10]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[11]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[12]);
        feedback = _mm_aesenc_si128 (feedback,((__m128i*)data->expanded_key)[13]);
        feedback = _mm_aesenclast_si128 (feedback, ((__m128i*)data->expanded_key)[14]);
        _mm_store_si128 ((__m128i*)(remBuf), feedback);
        memcpy(data->out_block+data->length-remainder, remBuf, remainder);
    }
}

void intel_AES_enc128_CBC(UCHAR *plainText,UCHAR *cipherText,UCHAR *key,size_t length,UCHAR *iv)
{
    DEFINE_ROUND_KEYS
    sAesData aesData;
    aesData.in_block = plainText;
    aesData.out_block = cipherText;
    aesData.expanded_key = expandedKey;
    aesData.length = length;
    aesData.iv = iv;

    iEncExpandKey128(key,expandedKey);
    iEnc128_CBC(&aesData);
}

void intel_AES_enc192_CBC(UCHAR *plainText,UCHAR *cipherText,UCHAR *key,size_t length,UCHAR *iv)
{
    DEFINE_ROUND_KEYS
    sAesData aesData;
    aesData.in_block = plainText;
    aesData.out_block = cipherText;
    aesData.expanded_key = expandedKey;
    aesData.length = length;
    aesData.iv = iv;

    iEncExpandKey192(key,expandedKey);
    iEnc192_CBC(&aesData);
}

void intel_AES_enc256_CBC(UCHAR *plainText,UCHAR *cipherText,UCHAR *key,size_t length,UCHAR *iv)
{
    DEFINE_ROUND_KEYS
    sAesData aesData;
    aesData.in_block = plainText;
    aesData.out_block = cipherText;
    aesData.expanded_key = expandedKey;
    aesData.length = length;
    aesData.iv = iv;

    iEncExpandKey256(key,expandedKey);
    iEnc256_CBC(&aesData);
}

void intel_AES_dec128_CBC(UCHAR *cipherText,UCHAR *plainText,UCHAR *key,size_t length,UCHAR *iv)
{
    DEFINE_ROUND_KEYS
    sAesData aesData;
    aesData.in_block = cipherText;
    aesData.out_block = plainText;
    aesData.expanded_key = expandedKey;
    aesData.length = length;
    aesData.iv = iv;

    iDecExpandKey128(key,expandedKey);
    iDec128_CBC(&aesData);
}

void intel_AES_dec192_CBC(UCHAR *cipherText,UCHAR *plainText,UCHAR *key,size_t length,UCHAR *iv)
{
    DEFINE_ROUND_KEYS
    sAesData aesData;
    aesData.in_block = cipherText;
    aesData.out_block = plainText;
    aesData.expanded_key = expandedKey;
    aesData.length = length;
    aesData.iv = iv;

    iDecExpandKey192(key,expandedKey);
    iDec192_CBC(&aesData);
}

void intel_AES_dec256_CBC(UCHAR *cipherText,UCHAR *plainText,UCHAR *key,size_t length,UCHAR *iv)
{
    DEFINE_ROUND_KEYS
    sAesData aesData;
    aesData.in_block = cipherText;
    aesData.out_block = plainText;
    aesData.expanded_key = expandedKey;
    aesData.length = length;
    aesData.iv = iv;

    iDecExpandKey256(key,expandedKey);
    iDec256_CBC(&aesData);
}


#ifdef __i386__

/* 32 bit version of cpuid must correctly handle ebx due to use of -fPIC */
static void __cpuid(unsigned int where[4], unsigned int leaf) {
    asm volatile(
    "mov %%ebx, %%edi;"
    "cpuid;"
    "xchgl %%ebx, %%edi;"
    :"=a"(*where),"=D"(*(where+1)), "=c"(*(where+2)),"=d"(*(where+3)):"a"(leaf));
  return;
}

#else

static void __cpuid(unsigned int where[4], unsigned int leaf) {
    asm volatile("cpuid":"=a"(*where),"=b"(*(where+1)), "=c"(*(where+2)),"=d"(*(where+3)):"a"(leaf));
    return;
}

#endif

/*
 * check_for_aes_instructions()
 *   return 1 if AES-NI is supported and 0 if it is not
 */

int check_for_aes_instructions()
{
  unsigned int cpuid_results[4];

  __cpuid(cpuid_results,0);

  if (cpuid_results[0] < 1)
    return 0;
/*
 *      MSB         LSB
 * EBX = 'u' 'n' 'e' 'G'
 * EDX = 'I' 'e' 'n' 'i'
 * ECX = 'l' 'e' 't' 'n'
 */

  if (memcmp((unsigned char *)&cpuid_results[1], "Genu", 4) != 0 ||
    memcmp((unsigned char *)&cpuid_results[3], "ineI", 4) != 0 ||
    memcmp((unsigned char *)&cpuid_results[2], "ntel", 4) != 0)
    return 0;

  __cpuid(cpuid_results,1);

  if (cpuid_results[2] & AES_CPUID_BIT)
    return 1;

  return 0;
}
