/*
Wrapper for zlib.  182095
*/
#ifndef __COMP_WRAPPER_H__
#define __COMP_WRAPPER_H__
#include <zlib.h>
#include "zstd.h"

struct WRAPPER_COMP_METHOD;

typedef struct WRAPPER_COMP_CTX
{
	struct WRAPPER_COMP_METHOD  *meth;
	unsigned long compress_in;
	unsigned long compress_out;
	unsigned long expand_in;
	unsigned long expand_out;
	z_stream istream;
	z_stream ostream;
}WRAPPER_COMP_CTX_T;

typedef struct WRAPPER_COMP_METHOD
{
	int type;		/* NID for compression library */
	const char *name;	/* A text string to identify the library */
	int (*init)(struct WRAPPER_COMP_CTX *ctx);
	void (*finish)(struct WRAPPER_COMP_CTX *ctx);
	int (*compress)(struct WRAPPER_COMP_CTX *ctx,
			unsigned char *out, unsigned int olen,
			unsigned char *in, unsigned int ilen);
	int (*expand)(struct WRAPPER_COMP_CTX *ctx,
			  unsigned char *out, unsigned int olen,
			  unsigned char *in, unsigned int ilen);
} WRAPPER_COMP_METHOD_T;

struct WRAPPER_COMP_METHOD *wrapper_comp_zlib(void);
struct WRAPPER_COMP_METHOD *wrapper_comp_zstd(void);
struct WRAPPER_COMP_CTX *wrapper_comp_ctx_new(struct WRAPPER_COMP_METHOD *meth);
void wrapper_comp_ctx_free(struct WRAPPER_COMP_CTX *ctx);
int wrapper_comp_compress_block(struct WRAPPER_COMP_CTX *ctx, unsigned char *out, int olen,
	     unsigned char *in, int ilen);
int wrapper_comp_expand_block(struct WRAPPER_COMP_CTX *ctx, unsigned char *out, int olen,
	     unsigned char *in, int ilen);
void COMP_CTX_ERR_load_COMP_strings(void);

#endif /* __COMP_WRAPPER_H__ */
