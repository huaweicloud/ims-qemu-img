/*
Wrapper for zlib.  182095
*/

#ifndef __COMP_WRAPPER_DEF_H__
#define __COMP_WRAPPER_DEF_H__

/* 182095
	Wrapper for the compression algorithms : on zlib by now
*/

#define COMP_METHOD	struct WRAPPER_COMP_METHOD
#define COMP_CTX	struct WRAPPER_COMP_CTX
#define ERR_load_COMP_strings COMP_CTX_ERR_load_COMP_strings
#define COMP_zlib wrapper_comp_zlib
#define COMP_zstd wrapper_comp_zstd
#define COMP_CTX_new wrapper_comp_ctx_new
#define COMP_CTX_free  wrapper_comp_ctx_free
#define COMP_compress_block wrapper_comp_compress_block
#define COMP_expand_block wrapper_comp_expand_block

#endif /* __COMP_WRAPPER_DEF_H__ */
