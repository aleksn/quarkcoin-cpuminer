#include "cpuminer-config.h"
#include "miner.h"

#include <string.h>
#include <stdint.h>

#include "blake.c"
#include "bmw.c"
#include "groestl.c"
#include "jh.c"
#include "keccak.c"
#include "skein.c"
#include "jh_sse2_opt64.h"
#include "grso.h"

/*define data alignment for different C compilers*/
#if defined(__GNUC__)
      #define DATA_ALIGN16(x) x __attribute__ ((aligned(16)))
#else
      #define DATA_ALIGN16(x) __declspec(align(16)) x
#endif

void quarkhash(void *state, const void *input)
{
    DATA_ALIGN16(sph_blake512_context     ctx_blake);
    DATA_ALIGN16(sph_bmw512_context       ctx_bmw);
    DATA_ALIGN16(sph_groestl512_context   ctx_groestl);
    DATA_ALIGN16(sph_jh512_context        ctx_jh);
    DATA_ALIGN16(sph_keccak512_context    ctx_keccak);
    DATA_ALIGN16(sph_skein512_context     ctx_skein);
    DATA_ALIGN16(jhState sts_jh);
    DATA_ALIGN16(grsoState sts_grs);

    uint32_t mask = 8;
    uint32_t zero = 0;

	//these uint512 in the c++ source of the client are backed by an array of uint32
    DATA_ALIGN16(uint32_t hash[16]);
	
	
    sph_blake512_init(&ctx_blake);
    sph_blake512 (&ctx_blake, input, 80);
    sph_blake512_close (&ctx_blake, hash);	 //0
	
    sph_bmw512_init(&ctx_bmw);
    sph_bmw512 (&ctx_bmw, hash, 64);    //0
    sph_bmw512_close(&ctx_bmw, hash);   //1


    if ((hash[0] & mask) != zero)   //1
    {
        grsoInit(&sts_grs);
        grsoUpdate(&sts_grs, (char*)hash, 64);
        grsoFinal(&sts_grs, (char*)hash);
    }
    else
    {
        sph_skein512_init(&ctx_skein);
        sph_skein512 (&ctx_skein, hash, 64); //1
        sph_skein512_close(&ctx_skein, hash); //2
    }

    grsoInit(&sts_grs);
    grsoUpdate(&sts_grs, (char*)hash, 64);
    grsoFinal(&sts_grs, (char*)hash);

    jhInit(&sts_jh, 512);
    jhUpdate(&sts_jh, (char*)hash, 64*8);
    jhFinal(&sts_jh, (char*)hash);

    if ((hash[0] & mask) != zero) //4
    {
        sph_blake512_init(&ctx_blake);
        sph_blake512 (&ctx_blake, hash, 64); //
        sph_blake512_close(&ctx_blake, hash); //5
    }
    else
    {
        sph_bmw512_init(&ctx_bmw);
        sph_bmw512 (&ctx_bmw, hash, 64); //4
        sph_bmw512_close(&ctx_bmw, hash);   //5
    }

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak,hash, 64); //5
    sph_keccak512_close(&ctx_keccak, hash); //6

    sph_skein512_init(&ctx_skein);
    sph_skein512 (&ctx_skein, hash, 64); //6
    sph_skein512_close(&ctx_skein, hash); //7

    if ((hash[0] & mask) != zero) //7
    {
        sph_keccak512_init(&ctx_keccak);
        sph_keccak512 (&ctx_keccak, hash, 64); //
        sph_keccak512_close(&ctx_keccak, hash); //8
    }
    else
    {
        jhInit(&sts_jh, 512);
        jhUpdate(&sts_jh, (char*)hash, 64*8);
        jhFinal(&sts_jh, (char*)hash);

    }

    memcpy(state, hash, 32);
	
}

int scanhash_quark(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce, unsigned long *hashes_done)
{
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];

	uint32_t hash64[8] __attribute__((aligned(32)));
	uint32_t endiandata[32];
	
	//char testdata[] = {"\x70\x00\x00\x00\x5d\x38\x5b\xa1\x14\xd0\x79\x97\x0b\x29\xa9\x41\x8f\xd0\x54\x9e\x7d\x68\xa9\x5c\x7f\x16\x86\x21\xa3\x14\x20\x10\x00\x00\x00\x00\x57\x85\x86\xd1\x49\xfd\x07\xb2\x2f\x3a\x8a\x34\x7c\x51\x6d\xe7\x05\x2f\x03\x4d\x2b\x76\xff\x68\xe0\xd6\xec\xff\x9b\x77\xa4\x54\x89\xe3\xfd\x51\x17\x32\x01\x1d\xf0\x73\x10\x00"};
	
	//we need bigendian data...
	//lessons learned: do NOT endianchange directly in pdata, this will all proof-of-works be considered as stale from minerd.... 
	int kk=0;
	for (; kk < 32; kk++)
	{
		be32enc(&endiandata[kk], ((uint32_t*)pdata)[kk]);
	};

//	if (opt_debug) 
//	{
//		applog(LOG_DEBUG, "Thr: %02d, firstN: %08x, maxN: %08x, ToDo: %d", thr_id, first_nonce, max_nonce, max_nonce-first_nonce);
//	}
	
	
	
	
	do {
	
		pdata[19] = ++n;
		be32enc(&endiandata[19], n); 
		quarkhash(hash64, &endiandata);
        if (((hash64[7]&0xFFFFFF00)==0) && 
				fulltest(hash64, ptarget)) {
            *hashes_done = n - first_nonce + 1;
			return true;
		}
	} while (n < max_nonce && !work_restart[thr_id].restart);
	
	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}
