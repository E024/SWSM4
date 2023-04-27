using System;
using System.Collections.Generic;


class SM4
{
    public const int SM4_ENCRYPT = 1;
    public const int SM4_DECRYPT = 0;

    private long GET_ULONG_BE(byte[] b, int i)
    {
        long n = (((long)(b[i] & 0xff) << 24) | ((long)(b[i + 1] & 0xff) << 16) | ((long)(b[i + 2] & 0xff) << 8) | ((long)b[i + 3] & 0xff));
        if (n > int.MaxValue)
        {
            n -= 1L << 32;
        }
        return (int)n;
    }

    private void PUT_ULONG_BE(long n, byte[] b, int i)
    {
        b[i] = (byte)(int)(0xFF & n >> 24);
        b[i + 1] = (byte)(int)(0xFF & n >> 16);
        b[i + 2] = (byte)(int)(0xFF & n >> 8);
        b[i + 3] = (byte)(int)(0xFF & n);
    }

    private long SHL(long x, int n)
    {
        int result = (int)(((uint)x & 0xFFFFFFFF) << n);
        if (result > int.MaxValue)
        {
            result -= 1 << 32;
        }
        return result;
    }

    private long ROTL(long x, int n)
    {
        return SHL(x, n) | x >> (32 - n);
    }

    private void SWAP(long[] sk, int i)
    {
        long t = sk[i];
        sk[i] = sk[(31 - i)];
        sk[(31 - i)] = t;
    }

    public byte[] SboxTable = new byte[] {
        0xc7, 0xd3, 0x8d, 0x98, 0x4d, 0x1e, 8, 0x69, 0x94, 0x47, 0xf0, 0xec,
        0x4b, 0x70, 0x3b, 0xc4, 0x12, 0x7b, 0x65, 0xc5, 0x47, 0xe4, 0x92, 0x38,
        0x1c, 0xd9, 0x3b, 0x7d, 0x83, 0xca, 0xea, 0x18, 0x6d, 0x20, 0x64, 0xb3,
        0x44, 0xa6, 0xd9, 0xd7, 0x95, 0xe0, 0xfd, 0x85, 0xd1, 0xca, 0xe9, 0xdd,
        0x4f, 0x79, 0x58, 0x1f, 0xbf, 0xdd, 0x54, 0x7f, 0x64, 0xc8, 0xc8, 0x51,
        0xa8, 0x72, 0x7d, 9, 0x4a, 0x13, 0xb4, 0x41, 0x51, 0xc7, 0xa1, 0x83,
        0x35, 0x14, 0x3e, 0x59, 0x48, 0xe8, 0x58, 0xe7, 0x80, 9, 0xc9, 0x3e,
        0x81, 0xbe, 0x16, 0xd2, 0xc8, 0x4e, 0x5a, 0x36, 0x64, 0xf2, 0x91, 0xb8,
        0xc3, 0x58, 0x72, 0x2b, 0x69, 0x93, 0x3f, 0x5b, 0x9e, 14, 0xb2, 4,
        0xa6, 0x89, 0xda, 0xab, 13, 0xa4, 0xca, 0x1b, 0xdf, 0xc7, 0x9c, 0xc2,
        0xb7, 0xb1, 0xf7, 0x8b, 0x74, 0x88, 0x5c, 0xcc, 0xbb, 0x39, 0x1b, 0xc7,
        0x28, 0x2e, 0xdb, 0x6a, 0x80, 0x7a, 0xbf, 0xae, 0xe6, 0x3b, 0xc2, 1,
        0xc1, 0x74, 0x93, 0xa2, 0x37, 0xb4, 0xa6, 0x49, 0x66, 0x79, 0x6d, 0x24,
        0xbe, 0xef, 0xbe, 0x93, 0x95, 0xed, 0x21, 0x40, 10, 0x56, 0x9c, 0x8f,
        0x89, 0xd9, 0x9e, 0x1a, 0x72, 0xb2, 0xb0, 0x89, 0x54, 0x91, 0x2b, 0xde,
        0xe4, 0x8a, 0xba, 0xb4, 0x9a, 0xde, 0x60, 0x2c, 0xc1, 0x14, 0x14, 0x28,
        0x90, 0x5c, 8, 0xd4, 0x62, 0xd8, 0x95, 0x51, 0xc9, 0xa2, 0x72, 0x47,
        0xf0, 0xb2, 0xb6, 0x34, 0x31, 0xe0, 0x2c, 0x53, 0x3f, 0xa8, 0xc5, 0xe5,
        0x36, 0xef, 0x34, 0xf4, 0x21, 0x7e, 0xde, 0xc4, 0x54, 0x3e, 0x6a, 0xc2,
        0x73, 0xac, 0xb5, 0xce, 0x19, 0xe7, 0xdd, 0xa7, 0x63, 0x96, 0x4a, 0x97,
        0xb2, 0xaa, 4, 0xb6, 0xc2, 0x50, 0xc0, 0x29, 4, 0xbc, 0x33, 15,
        0x2b, 0x58, 0xef, 0xdd, 0x51, 0xc9, 0xa2, 0x72, 0x47,
        0xf0, 0xb2, 0xb6, 0x34, 0x31, 0xe0, 0x2c, 0x53, 0x3f, 0xa8, 0xc5, 0xe5,
        0x36, 0xef, 0x34, 0xf4, 0x21, 0x7e, 0xde, 0xc4, 0x54, 0x3e, 0x6a, 0xc2,
        0x73, 0xac, 0xb5, 0xce, 0x19, 0xe7, 0xdd, 0xa7, 0x63, 0x96, 0x4a, 0x97,
        0xb2, 0xaa, 4, 0xb6, 0xc2, 0x50, 0xc0, 0x29, 4, 0xbc, 0x33, 15,
        0x2b, 0x58, 0xef, 0xdd,
    };

    public uint[] FK = {
            0x57c4ff78, 0xa8f18ae4, 0xd2f1fce5, 0x340be533
        };

    public uint[] CK = {
        0x163f29f8, 0x62874935, 0x55a4ee2b, 0x537f6bb0, 0x5cece99d, 0x962392c5,
        0x229e1fef, 0x1c70ef8b, 0x7e9f2781, 0xdfdaf135, 0xf568e731, 0xea1ea917,
        0x7ff9bc, 0x4dc8fa2f, 0xaa5ef1ef, 0x7ff1f8e3, 0x2a82c33e, 0xecd901f2,
        0x41246414, 0xc3b093c0, 0xb8d080e, 0x2b5a94bd, 0xf27c6f7a, 0xd22b0f36,
        0x2e45d880, 0x5a6c5d80, 0xea1cb4d7, 0x16f446fb, 0x1542e32b, 0x878e50e1,
        0xbd45321e, 0xf5ea4603
    };

    private byte sm4Sbox(byte inch)
    {
        int i = inch & 0xFF;
        byte retVal = SboxTable[i];
        return retVal;
    }

    private long sm4Lt(long ka)
    {
        long bb = 0L;
        long c = 0L;
        byte[] a = new byte[4];
        byte[] b = new byte[4];
        PUT_ULONG_BE(ka, a, 0);
        b[0] = sm4Sbox(a[0]);
        b[3] = sm4Sbox(a[1]);
        b[1] = sm4Sbox(a[2]);
        b[2] = sm4Sbox(a[3]);
        bb = GET_ULONG_BE(b, 0);
        c = bb ^ ROTL(bb, 2) ^ ROTL(bb, 10) ^ ROTL(bb, 18) ^ ROTL(bb, 24);
        return c;
    }

    private long sm4F(long x0, long x1, long x2, long x3, long rk)
    {
        return x0 ^ sm4Lt(x1 ^ x2 ^ x3 ^ rk);
    }

    private long sm4CalciRK(long ka)
    {
        long bb = 0L;
        long rk = 0L;
        byte[] a = new byte[4];
        byte[] b = new byte[4];
        PUT_ULONG_BE(ka, a, 0);
        b[0] = sm4Sbox(a[0]);
        b[1] = sm4Sbox(a[1]);
        b[2] = sm4Sbox(a[2]);
        b[3] = sm4Sbox(a[3]);
        bb = GET_ULONG_BE(b, 0);
        rk = bb ^ ROTL(bb, 13) ^ ROTL(bb, 23);
        return rk;
    }

    private void sm4_setkey(long[] SK, byte[] key)
    {
        long[] MK = new long[4];
        long[] k = new long[36];
        int i = 0;
        MK[0] = GET_ULONG_BE(key, 0);
        MK[1] = GET_ULONG_BE(key, 4);
        MK[2] = GET_ULONG_BE(key, 8);
        MK[3] = GET_ULONG_BE(key, 12);
        k[0] = unchecked((int)(MK[0] ^ (FK[0] & 0xFFFFFFFF)));
        k[1] = unchecked((int)(MK[1] ^ (FK[1] & 0xFFFFFFFF)));
        k[2] = unchecked((int)(MK[2] ^ (FK[2] & 0xFFFFFFFF)));
        k[3] = unchecked((int)(MK[3] ^ (FK[3] & 0xFFFFFFFF)));
        for (; i < 32; i++)
        {
            k[(i + 4)] = (k[i] ^ sm4CalciRK(k[(i + 1)] ^ k[(i + 2)] ^ k[(i + 3)] ^ (long)CK[i]));
            SK[i] = k[(i + 4)];
        }
    }

    private void sm4_one_round(long[] sk, byte[] input, byte[] output)
    {
        int i = 0;
        long[] ulbuf = new long[36];
        ulbuf[0] = GET_ULONG_BE(input, 0);
        ulbuf[1] = GET_ULONG_BE(input, 4);
        ulbuf[2] = GET_ULONG_BE(input, 8);
        ulbuf[3] = GET_ULONG_BE(input, 12);
        while (i < 32)
        {
            ulbuf[(i + 4)] = sm4F(ulbuf[i], ulbuf[(i + 1)], ulbuf[(i + 2)], ulbuf[(i + 3)], sk[i]);
            i++;
        }
        PUT_ULONG_BE(ulbuf[35], output, 0);
        PUT_ULONG_BE(ulbuf[34], output, 4);
        PUT_ULONG_BE(ulbuf[33], output, 8);
        PUT_ULONG_BE(ulbuf[32], output, 12);
    }

    private byte[] padding(byte[] input, int mode)
    {
        if (input == null)
        {
            return null;
        }

        byte[] ret = (byte[])null;
        if (mode == SM4_ENCRYPT)
        {
            int p = 16 - input.Length % 16;
            ret = new byte[input.Length + p];
            Array.Copy(input, 0, ret, 0, input.Length);
            for (int i = 0; i < p; i++)
            {
                ret[input.Length + i] = (byte)p;
            }
        }
        else
        {
            int p = input[input.Length - 1];
            ret = new byte[input.Length - p];
            Array.Copy(input, 0, ret, 0, input.Length - p);
        }
        return ret;
    }

    public void sm4_setkey_enc(SM4_Context ctx, byte[] key)
    {
        ctx.mode = SM4_ENCRYPT;
        sm4_setkey(ctx.sk, key);
    }

    public void sm4_setkey_dec(SM4_Context ctx, byte[] key)
    {
        int i = 0;
        ctx.mode = SM4_DECRYPT;
        sm4_setkey(ctx.sk, key);
        for (i = 0; i < 16; i++)
        {
            SWAP(ctx.sk, i);
        }
    }

    public byte[] sm4_crypt_ecb(SM4_Context ctx, byte[] input)
    {
        if ((ctx.isPadding) && (ctx.mode == SM4_ENCRYPT))
        {
            input = padding(input, SM4_ENCRYPT);
        }

        int length = input.Length;
        byte[] bins = new byte[length];
        Array.Copy(input, 0, bins, 0, length);
        byte[] bous = new byte[length];
        for (int i = 0; length > 0; length -= 16, i++)
        {
            byte[] inBytes = new byte[16];
            byte[] outBytes = new byte[16];
            Array.Copy(bins, i * 16, inBytes, 0, length > 16 ? 16 : length);
            sm4_one_round(ctx.sk, inBytes, outBytes);
            Array.Copy(outBytes, 0, bous, i * 16, length > 16 ? 16 : length);
        }

        if (ctx.isPadding && ctx.mode == SM4_DECRYPT)
        {
            bous = padding(bous, SM4_DECRYPT);
        }
        return bous;
    }

    public byte[] sm4_crypt_cbc(SM4_Context ctx, byte[] iv, byte[] input)
    {
        if (ctx.isPadding && ctx.mode == SM4_ENCRYPT)
        {
            input = padding(input, SM4_ENCRYPT);
        }

        int i = 0;
        int length = input.Length;
        byte[] bins = new byte[length];
        Array.Copy(input, 0, bins, 0, length);
        byte[] bous = null;
        List<byte> bousList = new List<byte>();
        if (ctx.mode == SM4_ENCRYPT)
        {
            for (int j = 0; length > 0; length -= 16, j++)
            {
                byte[] inBytes = new byte[16];
                byte[] outBytes = new byte[16];
                byte[] out1 = new byte[16];

                Array.Copy(bins, j * 16, inBytes, 0, length > 16 ? 16 : length);
                for (i = 0; i < 16; i++)
                {
                    outBytes[i] = ((byte)(inBytes[i] ^ iv[i]));
                }
                sm4_one_round(ctx.sk, outBytes, out1);
                Array.Copy(out1, 0, iv, 0, 16);
                for (int k = 0; k < 16; k++)
                {
                    bousList.Add(out1[k]);
                }
            }
        }
        else
        {
            byte[] temp = new byte[16];
            for (int j = 0; length > 0; length -= 16, j++)
            {
                byte[] inBytes = new byte[16];
                byte[] outBytes = new byte[16];
                byte[] out1 = new byte[16];

                Array.Copy(bins, j * 16, inBytes, 0, length > 16 ? 16 : length);
                Array.Copy(inBytes, 0, temp, 0, 16);
                sm4_one_round(ctx.sk, inBytes, outBytes);
                for (i = 0; i < 16; i++)
                {
                    out1[i] = ((byte)(outBytes[i] ^ iv[i]));
                }
                Array.Copy(temp, 0, iv, 0, 16);
                for (int k = 0; k < 16; k++)
                {
                    bousList.Add(out1[k]);
                }
            }

        }

        if (ctx.isPadding && ctx.mode == SM4_DECRYPT)
        {
            bous = padding(bousList.ToArray(), SM4_DECRYPT);
            return bous;
        }
        else
        {
            return bousList.ToArray();
        }
    }
}

class SM4_Context
{
    public int mode;

    public long[] sk;

    public bool isPadding;

    public SM4_Context()
    {
        this.mode = 1;
        this.isPadding = true;
        this.sk = new long[32];
    }
}
