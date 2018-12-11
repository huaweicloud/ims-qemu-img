/*
 * Block driver for Connectix / Microsoft Virtual PC images
 *
 * Copyright (c) 2005 Alex Beregszaszi
 * Copyright (c) 2009 Kevin Wolf <kwolf@suse.de>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "qemu-common.h"
#include "block/block_int.h"
#include "qemu/module.h"
//#include "migration/migration.h"
#include <openssl/comp.h>
#include <stdio.h>
#include <stdlib.h>
#if defined(CONFIG_UUID)
#include <uuid/uuid.h>
#endif

/**************************************************************/

#define VHD_SECTOR_SIZE  512

#define VHD_SECTOR_SHIFT   9

#define FOOTER_SIZE 4096

#define ZVHD_DATA_PREFIX_LEN 12

#define ZVHD_COOKIE_LEN 7

#define ZVHD_COOKIE "stream"

#define ZVHD_DATA_PREFIX "hwstream bg"

#define ZVHD_DATA_POSTFIX "end"

#define ZVHD_DATA_POSTFIX_LEN 4

#define HD_RESERVED        0x00000002 /* NOTE: must always be set        */

#define GEOM_ENCODE(_c, _h, _s) (((_c) << 16) | ((_h) << 8) | (_s))

/* Version field in hd_ftr */
#define HD_FF_VERSION      0x00010000

#define VHD_VERSION(major, minor)  (((major) << 16) | ((minor) & 0x0000FFFF))

#define IMAGE_BLOCK_SHIFT 21

#define IMAGE_SECTOR_SHIFT 9

#define IMAGE_SHIFT_PER_BLOCK (IMAGE_BLOCK_SHIFT - IMAGE_SECTOR_SHIFT)

#define IMAGE_BLOCK_SIZE ((uint32_t)1<<IMAGE_BLOCK_SHIFT)

#define BLOCK_SIZE_SECTOR 4096

#define BLOCK_G_SHIFT 30

#define BLOCK_G_SIZE ((uint32_t)1<<BLOCK_G_SHIFT)

#define BLOCK_4M_SIZE 4194304

/* VHD uses an epoch of 12:00AM, Jan 1, 2000. This is the Unix timestamp for
 * the start of the VHD epoch. */
#define VHD_EPOCH_START 946684800

//#define VHD_MAX_SECTORS       (65535LL * 255 * 255)
//#define VHD_MAX_GEOMETRY      (65535LL *  16 * 255)

enum LOG_LEVEL
{
    LOG_FATAL = 0,
	LOG_ERR,
	LOG_INFO,
	LOG_WARN,
	LOG_DEBUG,
};

#define FREE(m) \
    if ((m))\
    {\
       free((m));\
       m = NULL;\
    }

struct ZVHD_FOOTER {
  char          cookie[8];       /* Identifies original creator of the disk      */
  uint32_t    features;        /* Feature Support -- see below                 */
  uint32_t    ff_version;      /* (major,minor) version of disk file           */
  uint64_t    data_offset;     /* Abs. offset from SOF to next structure       */
  uint32_t    timestamp;       /* Creation time.  secs since 1/1/2000GMT       */
  char          crtr_app[4];     /* Creator application                          */
  uint32_t    crtr_ver;        /* Creator version (major,minor)                */
  uint32_t    crtr_os;         /* Creator host OS                              */
  uint64_t    orig_size;       /* Size at creation (bytes)                     */
  uint64_t    curr_size;       /* Current size of disk (bytes)                 */
  uint32_t    geometry;        /* Disk geometry                                */
  uint32_t    type;            /* Disk type                                    */
  uint32_t    checksum;        /* 1's comp sum of this struct.                 */
  uuid_t       uuid;            /* Unique disk ID, used for naming parents      */
  char          saved;           /* one-bit -- is this disk/VM in a saved state? */
  char          hidden;          /* tapdisk-specific field: is this vdi hidden?  */
  char          align_64;        /* For xcopy, data block align by 64KB          */
  char          reserved[425];   /* padding                                      */
};

typedef struct ZVHD_DATA zvhd_data_t;

typedef struct ZVHD_FOOTER pvhd_footer_t;

typedef struct ZVHD_CONTEXT
{
    int fd;
    uint32_t flags;
    uint64_t sectors;
    uint64_t fpos;
    uint32_t blk_size;
    uint64_t cur_offset;
    pvhd_footer_t *footer;
    char *footer_buf;
    zvhd_data_t *data_buf;
    char *buf;
    char *zero_buf;
    uint32_t curr_buf_size;
    COMP_CTX *ctx;
    uint32_t ver;   //0--old 1--new
    uint32_t end_flag; //0--not end   1--end of data
}zvhd_context_t;

struct ZVHD_DATA
{
    char prefix[ZVHD_DATA_PREFIX_LEN];
    uint32_t size;
    uint32_t curr_blk;
    char reservered[28];
};

int logging  = 0;

FILE *LOGFH = NULL;

void logprintf(const char *format, ...);

static int zvhd_read(BlockDriverState *bs, int64_t sector_num,
                    uint8_t *buf, int nb_sectors);

static void zvhd_clear_data(uint8_t *buf, int total_size);

static int zvhd_get_more_data(BlockDriverState *bs, zvhd_context_t *zvhd , int *total_size);

static int check_zvhd_data_end(const uint8_t *buf, int count);

static int check_zvhd_data_start(const uint8_t *buf);

typedef struct BDRVZVHDState {
    CoMutex lock;
    zvhd_context_t *zvhd_context_buffer;
    uint64_t free_data_block_offset;
} BDRVZVHDState;

static uint32_t pvhd_checksum_footer(pvhd_footer_t *footer)
{
    int i;
    unsigned char *blob;
    uint32_t checksum, tmp;

    checksum         = 0;
    tmp              = footer->checksum;
    footer->checksum = 0;

    blob = (unsigned char *)footer;
    for (i = 0; i < sizeof(pvhd_footer_t); i++)
        checksum += (uint32_t)blob[i];

    footer->checksum = tmp;
    return ~checksum;
}

static int is_not_zero(const uint8_t *buf, int len)
{
    int i;
    long d0, d1, d2, d3;
    const long * const data = (const long *) buf;

    len /= (int)sizeof(long);

    for(i = 0; i < len; i += 4) {
        d0 = data[i + 0];
        d1 = data[i + 1];
        d2 = data[i + 2];
        d3 = data[i + 3];
        if (d0 || d1 || d2 || d3) {
            return 1;
        }
    }
    return 0;
}

static uint64_t psecs_round_up(uint64_t bytes)
{
    return ((bytes + (VHD_SECTOR_SIZE - 1)) >> VHD_SECTOR_SHIFT);
}

static uint64_t psecs_round_up_no_zero(uint64_t bytes)
{
    return (psecs_round_up(bytes) ? : 1);
}

/*
 * nabbed from vhd specs.
 */
static uint32_t pvhd_chs(uint64_t size)
{
    uint32_t secs, cylinders, heads, spt, cth;

    secs = psecs_round_up_no_zero(size);

    if (secs > 65535 * 16 * 255)
        secs = 65535 * 16 * 255;

    if (secs >= 65535 * 16 * 63) {
        spt   = 255;
        cth   = secs / spt;
        heads = 16;
    } else {
        spt   = 17;
        cth   = secs / spt;
        heads = (cth + 1023) / 1024;

        if (heads < 4)
            heads = 4;

        if (cth >= (heads * 1024) || heads > 16) {
            spt   = 31;
            cth   = secs / spt;
            heads = 16;
        }

        if (cth >= heads * 1024) {
            spt   = 63;
            cth   = secs / spt;
            heads = 16;
        }
    }

    cylinders = cth / heads;

    return GEOM_ENCODE(cylinders, heads, spt);
}

static uint32_t pvhd_time(time_t time)
{
    return (uint32_t)(time - VHD_EPOCH_START);
}

void logprintf(const char *format, ...)
{
    va_list ap;    
    char buf[27] = {0}, *eol = NULL;
    time_t t;
    FILE *file = NULL;
    
    //lint -e1055
    va_start(ap, format);
    //lint +e1055

    if (logging)
    {
        file = LOGFH;
    }
    else
    {
        file = stdout;
    }

    t = time(NULL);
    if (ctime_r(&t, buf))
    {
        eol = strchr(buf, '\n');
        if (eol)
        {
            *eol = '\0';
        }

        fprintf(file, (const char*)"[%s] ", buf);
    }

    (void)vfprintf(file, format, ap);
    fflush(file);
    //lint -e1055
    va_end(ap);
    //lint +e1055

}

static coroutine_fn int zvhd_co_read(BlockDriverState *bs, int64_t sector_num,
                                    uint8_t *buf, int nb_sectors)
{
    int ret;
    BDRVZVHDState *s = bs->opaque;
    qemu_co_mutex_lock(&s->lock);
    ret = zvhd_read(bs, sector_num, buf, nb_sectors);
    qemu_co_mutex_unlock(&s->lock);
    return ret;
}

static int check_zvhd_data_start(const uint8_t *buf)
{
    char tmpbuf[ZVHD_DATA_PREFIX_LEN+1] = {0};
    pvhd_footer_t *footer = NULL;

    if (memcmp(((zvhd_data_t *)buf)->prefix,ZVHD_DATA_PREFIX,ZVHD_DATA_PREFIX_LEN))
    {
        footer = (pvhd_footer_t *)buf;
        if (memcmp(footer->cookie, ZVHD_COOKIE,ZVHD_COOKIE_LEN-1) ==0)
        {
            return -1;
        }

        memcpy(tmpbuf,((zvhd_data_t *)buf)->prefix,ZVHD_DATA_PREFIX_LEN);
        return -EINVAL;
    }

    return 0;
}

static int check_zvhd_data_end(const uint8_t *buf,int count)
{
    const char * tmp = NULL;
    char tmpbuf[ZVHD_DATA_POSTFIX_LEN+1] = {0};

    tmp = (char *)buf + count - ZVHD_DATA_POSTFIX_LEN;

    if (memcmp(tmp,ZVHD_DATA_POSTFIX,ZVHD_DATA_POSTFIX_LEN))
    {
	    memcpy(tmpbuf,tmp,ZVHD_DATA_POSTFIX_LEN);
	    //logprintf(LOG_ERR,"check postfix failed,current postfix is %s\n",tmpbuf);
        return -EINVAL;
    }

    return 0;
}

static int zvhd_get_more_data(BlockDriverState *bs,zvhd_context_t *zvhd ,int *total_size)
{
    int size =0;
    int msize = 0;
    int ret = 0;

    size = ((zvhd_data_t *)zvhd->buf)->size;

    if ((size + sizeof(zvhd_data_t) + ZVHD_DATA_POSTFIX_LEN) <= FOOTER_SIZE)
    {

        if (check_zvhd_data_end((uint8_t *)zvhd->buf,FOOTER_SIZE))
        {
            return -EINVAL;
        }
    }else
    {
        msize = (size + sizeof(zvhd_data_t) + ZVHD_DATA_POSTFIX_LEN - 1) / FOOTER_SIZE * FOOTER_SIZE;

        ret = bdrv_pread(bs->file, zvhd->cur_offset, zvhd->buf+FOOTER_SIZE, msize);
        if (ret < 0) 
       {
            return ret;
        }

        zvhd->cur_offset = zvhd->cur_offset + msize;

        if (check_zvhd_data_end((uint8_t *)zvhd->buf,msize + FOOTER_SIZE))
        {
            return -EINVAL;
        }
    }
    *total_size = msize + FOOTER_SIZE;
    return 0;
}


static int zvhd_read(BlockDriverState *bs, int64_t sector_num,
                    uint8_t *buf, int nb_sectors)
{
    BDRVZVHDState *s = bs->opaque;
    zvhd_context_t *zvhd = s->zvhd_context_buffer;
    int total_size = nb_sectors << 9;
    int ret = 0;
    int begin_block = sector_num / BLOCK_SIZE_SECTOR;
    if (1 == zvhd->end_flag)
    {
        zvhd_clear_data(buf, total_size);
        return 0;
    }

    //has got data last time
    if(memcmp(zvhd->data_buf->prefix,ZVHD_DATA_PREFIX,ZVHD_DATA_PREFIX_LEN) == 0)
    {
        if(begin_block < zvhd->data_buf->curr_blk)
        {
            zvhd_clear_data(buf, total_size);
            return 0;
        }
        else if(begin_block == zvhd->data_buf->curr_blk)
        {
            memcpy(buf, zvhd->buf+sizeof(zvhd_data_t), total_size);
            zvhd_clear_data((uint8_t *)zvhd->buf, zvhd->curr_buf_size);
            return 0;
        }
        else
        {
            return -EINVAL;
        }
    }

    ret = bdrv_pread(bs->file, zvhd->cur_offset, zvhd->buf, FOOTER_SIZE);
    if (ret < 0) 
    {
        return ret;
    }
    zvhd->cur_offset = zvhd->cur_offset + FOOTER_SIZE;

    ret = check_zvhd_data_start((uint8_t *)zvhd->buf);
    if (ret)
    {
        //arrive at the end of zvhd file
        if(-1 == ret)
        {
            zvhd->end_flag = 1;
            zvhd_clear_data(buf, total_size);
            return 0;
        }
        return -EINVAL;
    }

    ret = zvhd_get_more_data(bs, zvhd, (int *)&zvhd->curr_buf_size);
    if(ret)
    {
        return ret;
    }

     if (0 != zvhd->data_buf->size)
    {
        ret = COMP_expand_block(zvhd->ctx,(unsigned char *)buf,total_size,(unsigned char *)zvhd->buf + sizeof(zvhd_data_t),zvhd->data_buf->size);
        if (ret < 0)
        {
            ERR_load_COMP_strings();
            //logprintf(LOG_ERR,"expand data failed,ret is %d\n",ret);
            return ret;
        }
        //logprintf(LOG_DEBUG,"decompress size is %d\n",ret);
        if (ret != total_size)
        {
    	     //logprintf(LOG_ERR,"expand size is not correct,ret is %d\n",ret);
            return -EIO;
        }
    }
    else
    {
        //logprintf(LOG_ERR, "data's size is 0 \n");
        return -EIO;
    }

    if(begin_block == zvhd->data_buf->curr_blk)
    {
        zvhd_clear_data((uint8_t *)zvhd->buf,zvhd->curr_buf_size);
        //logprintf(LOG_DEBUG, "current block[%u] is equal to [%u]\n", begin_block, zvhd->data_buf->curr_blk);
    }
    else
    {
        memset(zvhd->buf+sizeof(zvhd_data_t), 0, (zvhd->curr_buf_size -sizeof(zvhd_data_t))?:total_size);
        memcpy(zvhd->buf+sizeof(zvhd_data_t), buf, total_size);
        zvhd_clear_data(buf, total_size);
        zvhd->curr_buf_size = total_size + sizeof(zvhd_data_t);
        //logprintf(LOG_DEBUG, "current block[%u] is not equal to [%u]\n", begin_block, zvhd->data_buf->curr_blk);
    }
    
    return 0;
}


static int zvhd_validate_footer(pvhd_footer_t *footer)
{
    uint32_t checksum;

    //csize = sizeof(footer->cookie);
    //@pome

    if (memcmp(footer->cookie, ZVHD_COOKIE,ZVHD_COOKIE_LEN-1) !=0) {
        char buf[9];
        memcpy(buf, footer->cookie, 8);
        buf[8]= '\0';
        return -EINVAL;
    }

    checksum = pvhd_checksum_footer(footer);
    if (checksum != footer->checksum) {

        if (footer->hidden &&
            !strncmp(footer->crtr_app, "tap", 3) &&
            (footer->crtr_ver == VHD_VERSION(0, 1) ||
             footer->crtr_ver == VHD_VERSION(1, 1))) {
            char tmp = footer->hidden;
            footer->hidden = 0;
            checksum = pvhd_checksum_footer(footer);
            footer->hidden = tmp;

            if (checksum == footer->checksum)
                return 0;
        }

        return -EINVAL;
    }

    return 0;
}


static int zvhd_open(BlockDriverState *bs, QDict *options, int flags,
                    Error **errp)
{
    BDRVZVHDState *s = bs->opaque;
    zvhd_context_t *zvhd = NULL;
    int ret = 0;
    
    s->zvhd_context_buffer = (void *)calloc(1,sizeof(zvhd_context_t));
    if (NULL == s->zvhd_context_buffer )
    {
        ret = -1;
        goto fail;
    }

    zvhd = s->zvhd_context_buffer;
    zvhd->fpos = 0;
    
    ret = posix_memalign((void **)&zvhd->buf,FOOTER_SIZE,FOOTER_SIZE+BLOCK_4M_SIZE);
    if (ret != 0)
    {
        FREE(s->zvhd_context_buffer);
        goto fail;
    }
    
    memset(zvhd->buf, 0, FOOTER_SIZE+BLOCK_4M_SIZE);
    ret = posix_memalign((void **)&zvhd->footer_buf,FOOTER_SIZE,FOOTER_SIZE);
    if (ret != 0)
    {
        FREE(zvhd->buf);
        FREE(s->zvhd_context_buffer);
        goto fail;
    }
    
    ret = bdrv_pread(bs->file, 0, zvhd->footer_buf, FOOTER_SIZE);
    if (ret < 0) {
        FREE(zvhd->buf);
        FREE(zvhd->footer_buf);
        FREE(s->zvhd_context_buffer);
        goto fail;
    }

    zvhd->cur_offset = FOOTER_SIZE;
    zvhd->footer = (pvhd_footer_t *)zvhd->footer_buf;
    
    ret = zvhd_validate_footer(zvhd->footer);
    if (ret)
    {
        FREE(zvhd->buf);
        FREE(zvhd->footer_buf);
        FREE(s->zvhd_context_buffer);
        
        ret = -1;
        goto fail;
    }

    bs->total_sectors = (zvhd->footer->curr_size) >>VHD_SECTOR_SHIFT;

    if(zvhd->footer->crtr_ver == VHD_VERSION(1,4))
    {
        zvhd->ver = 1;
    }
    else
    {
        zvhd->ver = 0;
    }

    zvhd->sectors = zvhd->footer->orig_size >> 9;

    zvhd->data_buf = (zvhd_data_t *)zvhd->buf;
    zvhd->ctx = COMP_CTX_new(COMP_zlib());
    if (!zvhd->ctx)
    {
        FREE(zvhd->buf);
        FREE(zvhd->footer_buf);
        FREE(s->zvhd_context_buffer);
        ret = -1;
        goto fail;
    }

    ret = posix_memalign((void **)&zvhd->zero_buf ,FOOTER_SIZE,IMAGE_BLOCK_SIZE);
    if (ret != 0)
    {
        FREE(zvhd->buf);
        FREE(zvhd->footer_buf);
        FREE(s->zvhd_context_buffer);
        goto fail;
    }
    
    memset(zvhd->zero_buf ,0,IMAGE_BLOCK_SIZE); 

    qemu_co_mutex_init(&s->lock);
    
    return 0;

fail:
//    qemu_vfree(s->pagetable);
//#ifdef CACHE
//    g_free(s->pageentry_u8);
//#endif
    return ret;
}

static void zvhd_clear_data(uint8_t *buf,int total_size)
{
    memset(buf,0,total_size);
}

static int zvhd_write(BlockDriverState *bs, int64_t sector_num,
    const uint8_t *buf, int nb_sectors)
{
    BDRVZVHDState *s = bs->opaque;
    zvhd_context_t *zvhd = s->zvhd_context_buffer;
    int total_size = nb_sectors << 9;
    int ret = 0;
    int postfix_offset = 0;

    //int begin_index = (sector_num % BLOCK_SIZE_SECTOR) << 9;
    int begin_block = sector_num / BLOCK_SIZE_SECTOR;
    memcpy(zvhd->zero_buf,buf,total_size);
    
    
    memcpy(zvhd->data_buf->prefix,ZVHD_DATA_PREFIX,ZVHD_DATA_PREFIX_LEN - 1);
    //zero will not come here
    if (is_not_zero((uint8_t *)buf,total_size))
    {
        ret = COMP_compress_block(zvhd->ctx,(unsigned char *)zvhd->buf+FOOTER_SIZE,BLOCK_4M_SIZE,(unsigned char *)zvhd->zero_buf,IMAGE_BLOCK_SIZE);
        if (ret < 0)
        {
            ERR_load_COMP_strings();
            return -1;
        }

        if (ret >= BLOCK_4M_SIZE)
        {
            return -ENOMEM;
        }
        else
        {
            zvhd->data_buf->size = ret;
            zvhd->data_buf->curr_blk = begin_block;
            memmove(zvhd->buf+sizeof(zvhd_data_t),zvhd->buf+FOOTER_SIZE,ret);
        }
     

        zvhd->curr_buf_size = (sizeof(zvhd_data_t) + zvhd->data_buf->size + ZVHD_DATA_POSTFIX_LEN + BLOCK_SIZE_SECTOR - 1) / BLOCK_SIZE_SECTOR * BLOCK_SIZE_SECTOR;
        postfix_offset = zvhd->curr_buf_size - ZVHD_DATA_POSTFIX_LEN;
        memcpy(zvhd->buf + postfix_offset,ZVHD_DATA_POSTFIX,ZVHD_DATA_POSTFIX_LEN);

        ret = bdrv_pwrite_sync(bs->file, zvhd->cur_offset, zvhd->buf,zvhd->curr_buf_size);
        if (ret < 0) {
            return -1;
        }
    
        zvhd->cur_offset = zvhd->cur_offset + zvhd->curr_buf_size;
        
        zvhd_clear_data((uint8_t *)zvhd->buf,zvhd->curr_buf_size);
        zvhd_clear_data((uint8_t *)zvhd->zero_buf,IMAGE_BLOCK_SIZE);
        
    }

    //when write end,rewrite the footer
    if ((sector_num + nb_sectors) >= zvhd->sectors)
    {
        ret = bdrv_pwrite_sync(bs->file, zvhd->cur_offset, zvhd->footer_buf,FOOTER_SIZE);
         if (ret < 0) {
             return -1;
         }
     }
    
    return 0;
}

static coroutine_fn int zvhd_co_write(BlockDriverState *bs, int64_t sector_num,
                                     const uint8_t *buf, int nb_sectors)
{
    int ret;
    BDRVZVHDState *s = bs->opaque;
    qemu_co_mutex_lock(&s->lock);
    ret = zvhd_write(bs, sector_num, buf, nb_sectors);
    qemu_co_mutex_unlock(&s->lock);
    return ret;
}

static void zvhdinitializefooter(zvhd_context_t *ctx, int type, uint64_t size)
{
    memset(ctx->footer, 0, sizeof(pvhd_footer_t));
    memcpy(ctx->footer->cookie, ZVHD_COOKIE, strlen(ZVHD_COOKIE));
    ctx->footer->features     = HD_RESERVED;
    ctx->footer->ff_version   = HD_FF_VERSION;
    ctx->footer->timestamp    = pvhd_time(time(NULL));
    ctx->footer->crtr_ver     = VHD_VERSION(1,4);  //zvhd new version, old version is VHD_VERSION(1,3)
    ctx->footer->crtr_os      = 0x00000000;
    ctx->footer->orig_size    = size;
    ctx->footer->curr_size    = (size + BLOCK_G_SIZE -1)/BLOCK_G_SIZE*BLOCK_G_SIZE;
    ctx->footer->geometry     = pvhd_chs(size);
    ctx->footer->type         = type;
    ctx->footer->saved        = 0;
    ctx->footer->data_offset  = 0xFFFFFFFFFFFFFFFFULL;
    strncpy(ctx->footer->crtr_app, "tap",sizeof(ctx->footer->crtr_app) - 1);
    uuid_generate(ctx->footer->uuid);
    ctx->footer->checksum = pvhd_checksum_footer(ctx->footer);
}


static int zvhd_create(const char *filename, QemuOpts *opts, Error **errp)
{
    int64_t total_size;
    int ret = -EIO;
    Error *local_err = NULL;
    BlockDriverState *bs = NULL;

    zvhd_context_t g_zvhd;

    /* Read out options */
    total_size = ROUND_UP(qemu_opt_get_size_del(opts, BLOCK_OPT_SIZE, 0),
                          BDRV_SECTOR_SIZE);

    ret = bdrv_create_file(filename, opts, &local_err);
    if (ret < 0) {
        error_propagate(errp, local_err);
        goto out;
    }
    ret = bdrv_open(&bs, filename, NULL, NULL, BDRV_O_RDWR | BDRV_O_PROTOCOL,
                    NULL, &local_err);
    if (ret < 0) {
        error_propagate(errp, local_err);
        goto out;
    }

    ret = posix_memalign((void **)&g_zvhd.footer_buf,FOOTER_SIZE,FOOTER_SIZE);
    if (ret){
        goto out;
    }
    g_zvhd.footer = (pvhd_footer_t *)g_zvhd.footer_buf;
    zvhdinitializefooter(&g_zvhd,4,total_size);

    ret = bdrv_pwrite_sync(bs, 0, g_zvhd.footer_buf, FOOTER_SIZE);
    
    FREE(g_zvhd.footer_buf);
    
out:
    bdrv_unref(bs);
    return ret;
}

static int zvhd_has_zero_init(BlockDriverState *bs)
{
    //BDRVZVHDState *s = bs->opaque;

    return 0;
}

static void zvhd_close(BlockDriverState *bs)
{
    BDRVZVHDState *s = bs->opaque;
    zvhd_context_t *zvhd = s->zvhd_context_buffer;
    FREE(zvhd->zero_buf);
    FREE(zvhd->footer_buf);
    FREE(zvhd->buf);
    FREE(zvhd);
}

static int zvhd_get_info(BlockDriverState *bs, BlockDriverInfo *bdi)
{
    //BDRVZVHDState *s = (BDRVZVHDState *)bs->opaque;

    //bdi->unallocated_blocks_are_zero = true;
    return 1;
}

static QemuOptsList zvhd_create_opts = {
    .name = "zvhd-create-opts",
    .head = QTAILQ_HEAD_INITIALIZER(zvhd_create_opts.head),
    .desc = {
        {
            .name = BLOCK_OPT_SIZE,
            .type = QEMU_OPT_SIZE,
            .help = "Virtual disk size"
        },
        { /* end of list */ }
    }
};

static int zvhd_probe(const uint8_t *buf, int buf_size, const char *filename)
{
    if (buf_size >= ZVHD_COOKIE_LEN && !strncmp((char *)buf, ZVHD_COOKIE, ZVHD_COOKIE_LEN - 1))
	return 100;
    return 0;
}

static BlockDriver bdrv_zvhd= {
    .format_name       = "zvhd",
    .instance_size       = sizeof(BDRVZVHDState),
    .bdrv_probe             = zvhd_probe,
    .bdrv_read            = zvhd_co_read,
    .bdrv_open              = zvhd_open,
    .bdrv_close             = zvhd_close,
    .bdrv_create            = zvhd_create,
    .bdrv_write                 = zvhd_co_write,
    .bdrv_get_info          = zvhd_get_info,
    .bdrv_has_zero_init     = zvhd_has_zero_init,
    .create_opts            = &zvhd_create_opts,
};

static void bdrv_zvhd_init(void)
{
    bdrv_register(&bdrv_zvhd);
}

block_init(bdrv_zvhd_init);
