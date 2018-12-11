/* 
Wrapper for zlib.  182095
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include "comp_wrapper.h"

#define LOG_ERROR(fmt,args...) printf("[%s][%s:%s:%d] "fmt"\n","error",__FILE__,__func__,__LINE__, ##args);
#if 0
#define LOG_DEBUG(fmt,args...) printf("[%s][%s:%s:%d] "fmt"\n","debug",__FILE__,__func__,__LINE__, ##args);
#else
#define LOG_DEBUG(fmt,args...)
#endif

/*
extern int zlib_param_level;
extern int zlib_param_windowBits;
extern int zlib_param_memLevel;
extern int zlib_param_strategy;
extern int g_log_level;
*/

void COMP_CTX_ERR_load_COMP_strings(void)
{
}

static int __zlib_method_init(struct WRAPPER_COMP_CTX *ctx)
{
	int err;

	int  deflate_level = Z_BEST_SPEED;
    int  deflate_method = Z_DEFLATED;
    int  deflate_windowBits = MAX_WBITS; //15
    int  deflate_memLevel = MAX_MEM_LEVEL-1; //8
    int  deflate_strategy = Z_DEFAULT_STRATEGY; //0  , Z_FIXED 4
    /*
	if(zlib_param_level >= -1 && zlib_param_level <=Z_BEST_COMPRESSION)
	{
		deflate_level = zlib_param_level;//L
	}
	if(zlib_param_windowBits >= 10 && zlib_param_windowBits <= MAX_WBITS)
	{
		deflate_windowBits = zlib_param_windowBits; //W
	}
	if(zlib_param_memLevel >= 4 && zlib_param_memLevel <= MAX_MEM_LEVEL)
	{
		deflate_memLevel = zlib_param_memLevel; //M
	}
	if(zlib_param_strategy >= 0 && zlib_param_strategy <= Z_FIXED)
	{
		deflate_strategy = zlib_param_strategy;//S
	}
    */

	ctx->istream.zalloc = Z_NULL;
	ctx->istream.zfree = Z_NULL;
	ctx->istream.opaque = Z_NULL;
	ctx->istream.next_in = Z_NULL;
	ctx->istream.next_out = Z_NULL;
	ctx->istream.avail_in = 0;
	ctx->istream.avail_out = 0;
	err = inflateInit2(&ctx->istream,MAX_WBITS);
	if (err != Z_OK)
	{
		LOG_ERROR("err = %d ", err);
		return err;
	}
	
	ctx->ostream.zalloc = Z_NULL;
	ctx->ostream.zfree = Z_NULL;
	ctx->ostream.opaque = Z_NULL;
	ctx->ostream.next_in = Z_NULL;
	ctx->ostream.next_out = Z_NULL;
	ctx->ostream.avail_in = 0;
	ctx->ostream.avail_out = 0;
	
	err = deflateInit2(&ctx->ostream,deflate_level, deflate_method, deflate_windowBits, deflate_memLevel,
                         deflate_strategy);
	if (err != Z_OK)
	{
		LOG_ERROR("err = %d deflate_cfg=[%d,%d,%d,%d,%d]", err,
			deflate_level, deflate_method, deflate_windowBits, deflate_memLevel,deflate_strategy);
		inflateEnd(&ctx->istream);
		return err;
	}
	else
	{
		LOG_DEBUG( "deflate_cfg=[%d,%d,%d,%d,%d]",
			deflate_level, deflate_method, deflate_windowBits, deflate_memLevel,deflate_strategy);
	}
	
	return 0;
}

static void __zlib_method_finish(struct WRAPPER_COMP_CTX *ctx)
{
	inflateEnd(&ctx->istream);
	deflateEnd(&ctx->ostream);
}

static int __zlib_method_compress_block(struct WRAPPER_COMP_CTX *ctx, unsigned char *out,
	unsigned int olen, unsigned char *in, unsigned int ilen)
{
	int err = Z_OK;

	ctx->ostream.next_in = in;
	ctx->ostream.avail_in = ilen;
	ctx->ostream.next_out = out;
	ctx->ostream.avail_out = olen;
	if (ilen > 0)
	{
		err = deflate(&ctx->ostream, Z_SYNC_FLUSH);
	}
	
	if (err != Z_OK)
	{
		LOG_ERROR( "err = %d ", err);
		return -1;
	}
	
	LOG_DEBUG("compress(%4u)->%4u %s",
		ilen,olen - ctx->ostream.avail_out,
		(ilen != olen - ctx->ostream.avail_out)?"zlib":"clear");
	return olen - ctx->ostream.avail_out;
}

static int __zlib_method_expand_block(struct WRAPPER_COMP_CTX *ctx, unsigned char *out,
	unsigned int olen, unsigned char *in, unsigned int ilen)
{
	int err = Z_OK;

	ctx->istream.next_in = in;
	ctx->istream.avail_in = ilen;
	ctx->istream.next_out = out;
	ctx->istream.avail_out = olen;
	if (ilen > 0)
	{
		err = inflate(&ctx->istream, Z_SYNC_FLUSH);
	}
	
	if (err != Z_OK)
	{
		LOG_ERROR("err = %d ", err);
		if(err > 0)
		{
			return 0-err;
		}
		return err;
	}
	
	return olen - ctx->istream.avail_out;
}




static struct WRAPPER_COMP_METHOD zlib_method_wrapper = {
	0,
	"zlib",
	__zlib_method_init,
	__zlib_method_finish,
	__zlib_method_compress_block,
	__zlib_method_expand_block
	};

struct WRAPPER_COMP_METHOD *wrapper_comp_zlib(void)
{
	return(&zlib_method_wrapper);
}

static int __zstd_method_init(struct WRAPPER_COMP_CTX *ctx)
{	
	return 0;
}

static void __zstd_method_finish(struct WRAPPER_COMP_CTX *ctx)
{
	
}

static int __zstd_method_compress_block(struct WRAPPER_COMP_CTX *ctx, unsigned char *out,
	unsigned int olen, unsigned char *in, unsigned int ilen)
{
	int compressionLevel = 0;
      return (int)ZSTD_compress( out, (size_t) olen,(const unsigned char*) in, (size_t) ilen,compressionLevel);
}

static int __zstd_method_expand_block(struct WRAPPER_COMP_CTX *ctx, unsigned char *out,
	unsigned int olen, unsigned char *in, unsigned int ilen)
{
      return (int) ZSTD_decompress( out, (size_t) olen,  (const unsigned char*) in, (size_t) ilen);
}

static struct WRAPPER_COMP_METHOD zstd_method_wrapper = {
	0,
	"zstd",
	__zstd_method_init,
	__zstd_method_finish,
	__zstd_method_compress_block,
	__zstd_method_expand_block
	};

struct WRAPPER_COMP_METHOD *wrapper_comp_zstd(void)
{
	return(&zstd_method_wrapper);
}

struct WRAPPER_COMP_CTX *wrapper_comp_ctx_new(struct WRAPPER_COMP_METHOD *meth)
{
	struct WRAPPER_COMP_CTX *ret = NULL;
	if( NULL == meth)
	{
        return NULL;
	}

	if ((ret=(struct WRAPPER_COMP_CTX *)calloc(1, sizeof(struct WRAPPER_COMP_CTX))) == NULL)
	{
        LOG_ERROR("Failed to alocate memory");
        return(NULL);
	}
      
    // memset_s(ret,sizeof(struct WRAPPER_COMP_CTX), 0,sizeof(struct WRAPPER_COMP_CTX));
    ret->meth=meth;
    //ret->meth=&zlib_method_wrapper;
	
    if ((ret->meth->init != NULL) && ret->meth->init(ret))
	{
        LOG_ERROR("Failed to init");
        free(ret);
	}
	
    return ret;
}

void wrapper_comp_ctx_free(struct WRAPPER_COMP_CTX *ctx)
{
	if(ctx == NULL)
	{
		return;
	}
	if (ctx->meth->finish != NULL)
	{
		ctx->meth->finish(ctx);
	}
	free(ctx);
}

int wrapper_comp_compress_block(struct WRAPPER_COMP_CTX *ctx, unsigned char *out, int olen,
	     unsigned char *in, int ilen)
{
	int ret;
	if (ctx->meth->compress == NULL)
		{
		LOG_ERROR("NULL compressor");
		return(-1);
		}
	ret=ctx->meth->compress(ctx,out,olen,in,ilen);
	if (ret > 0)
		{
		ctx->compress_in+=ilen;
		ctx->compress_out+=ret;
		}
	return(ret);
}

int wrapper_comp_expand_block(struct WRAPPER_COMP_CTX *ctx, unsigned char *out, int olen,
	     unsigned char *in, int ilen)
{
	int ret;

	if (ctx->meth->expand == NULL)
		{
		LOG_ERROR("NULL expander");
		return(-1);
		}
	ret=ctx->meth->expand(ctx,out,olen,in,ilen);
	if (ret > 0)
		{
		ctx->expand_in+=ilen;
		ctx->expand_out+=ret;
		}
	return(ret);
}


