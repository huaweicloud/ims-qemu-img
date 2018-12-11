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
#define USE_COMP_WRAPPER
#ifdef USE_COMP_WRAPPER
#include "comp_wrapper_def.h"
#include "comp_wrapper.h"
#else
#include <openssl/comp.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#if defined(CONFIG_UUID)
#include <uuid/uuid.h>
#endif

#define ZVHD2_READ_WITH_INDEX
#define COULD_BE_READ_AS_ZVHD_ 0

#if COULD_BE_READ_AS_ZVHD_
#undef USE_FRAME_COMPRESSION
#undef ZVHD2_READ_WITH_INDEX
#else
#define USE_FRAME_COMPRESSION
#endif

#define INDEX_ZERO_BLK   0  // 1:index contains zero blocks  0:index does not contains zero blocks

/**************************************************************/

#define VHD_SECTOR_SIZE  512

#define VHD_SECTOR_SHIFT   9

#define BLOCK_SHIFT  (12) // 12:4KB

#define BLOCK_SIZE  (1 << BLOCK_SHIFT)

#define FOOTER_SIZE BLOCK_SIZE

#define ZVHD2_DATA_PREFIX_LEN 12

#define ZVHD2_COOKIE_LEN 7

#if COULD_BE_READ_AS_ZVHD_
#define ZVHD2_COOKIE "stream"
#else
#define ZVHD2_COOKIE "z2strm" //z2 stream
#endif

#define ZVHD2_DATA_PREFIX "hwstream bg"

#define ZVHD2_DATA_POSTFIX "end"

#define ZVHD2_DATA_POSTFIX_LEN 4
#define HD_RESERVED        0x00000002 /* NOTE: must always be set        */

#define GEOM_ENCODE(_c, _h, _s) (((_c) << 16) | ((_h) << 8) | (_s))

/* Version field in hd_ftr */
#define HD_FF_VERSION      0x00010000

#define VHD_VERSION(major, minor)  (((major) << 16) | ((minor) & 0x0000FFFF))

#define MIN_IMAGE_BLOCK_SHIFT ( 20 )  // 1MB
#define MAX_IMAGE_BLOCK_SHIFT ( 25 ) // 32MB


#if COULD_BE_READ_AS_ZVHD_     // zvhd does support other block size
#define IMAGE_BLOCK_SHIFT 21
#else
#define IMAGE_BLOCK_SHIFT ( 21 ) // 20:1MB 21:2MB:default 22:4MB 23:8MB 24:16MB 25:32MB
#endif

#define IMAGE_SECTOR_SHIFT 9

#define IMAGE_SHIFT_PER_BLOCK (IMAGE_BLOCK_SHIFT - IMAGE_SECTOR_SHIFT)

#define IMAGE_BLOCK_SIZE ((uint32_t)1<<IMAGE_BLOCK_SHIFT)

#define BLOCK_SIZE_SECTOR 4096

#define BLOCK_G_SHIFT 30

#define BLOCK_G_SIZE ((uint32_t)1<<BLOCK_G_SHIFT)

//#define ZVHD2_SEGMENT_SIZE    (256*1024) //MB

#define ZVHD2_INDEX_SEG_SIZE           ( 512*1024 ) //2097152:2MB 512KB~
#define BLOCKS_PER_BYPE                (8)

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
const void * log_level_str[] = {"fatal","error","info","warn","debug"};

#define FREE(m) \
    if ((m))\
    {\
       free((m));\
       m = NULL;\
    }

struct ZVHD2_FOOTER {
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
  char          zvhd2_version;  // 424 remains
  
  uint32_t     block_size;       // 420 remains
  uint32_t     max_blk_num;      // 416 remains
  
  uint64_t     index_lba;        // 408 remains
  uint64_t     bitmap_lba;       // 400 remains
  uint32_t     index_size;       // 396 remains
  uint32_t     bitmap_size;      // 392 remains
  uint32_t     index_seg_size;    // 388 remains    
  uint32_t     bitmap_seg_size;  // 384 remains
  uint32_t     index_seg_num;    // 380 remains    
  uint32_t     bitmap_seg_num;  // 376 remains
  uint32_t     non_zero_blk_num;   // 372 remains
  char          index_contains_zero_blk;            // 371 remains
  char          compress_method;            // 370 remains
  
  
  char          reserved[370];   /* padding                                      */
};

typedef struct ZVHD2_DATA zvhd2_data_t;

typedef struct ZVHD2_FOOTER zvhd2_footer_t;

typedef struct ZVHD2_INDEX_ENTRY
{
    uint64_t blk_offset;  // the lba address of the block in zvhd2 file
    uint32_t blk_num;
    uint32_t blk_disk_size; 
}zvhd2_index_entry_t;

typedef struct ZVHD2_INDEX_STORE
{
    unsigned char * store_buffer;
    uint64_t tmp_file_offset;   // if index_file_offset is not zero : it is the offset in index tmp file, 
                                // the content of store_buffer is stored at this offset.
    int  status; // 0:allocated, 1:filling, 2:fill from file
    int32_t non_zero_first;              
    int32_t non_zero_last;
    uint32_t  non_zero_blk_base;    //blk_num in disk : all non
    uint32_t non_zero_blk_count;
    uint32_t seg_idx;
}zvhd2_index_store_t;

enum INDEX_STORE_STATUS
{
    INDEX_STORE_STATUS_ALLOCATED = 0,
    INDEX_STORE_STATUS_FILLING,
    INDEX_STORE_STATUS_FILLED
};

typedef struct ZVHD2_INDEX
{   
    zvhd2_index_store_t * index_segs;
    uint32_t index_segs_num;
    uint32_t index_seg_size; // should be aligned with 4KB

    uint32_t blk_num_per_seg;
    uint32_t max_segs_num;
    uint32_t segs_num;
    zvhd2_index_store_t * bm_segs;
    uint32_t bm_segs_num;
    uint32_t bm_seg_size; // should be aligned with 4KB

    int index_tmp_file_fd;    
    unsigned char * index_buffer;
    unsigned char * bm_buffer;
}zvhd2_index_t;

typedef struct ZVHD2_CONTEXT
{
    int fd;
    uint32_t flags;
    uint64_t sectors;
    uint64_t fpos;
    uint32_t blk_size;
    uint32_t max_blk_num;
    uint64_t cur_offset;
    zvhd2_footer_t *footer;
    char *footer_buf;
    zvhd2_data_t *data_buf;
    char *buf;
    uint32_t buf_size;
    char *zero_buf;
    uint32_t curr_buf_size;
    COMP_CTX *ctx;
    uint32_t ver;   //0--old 1--new
    uint32_t end_flag; //0--not end   1--end of data
    zvhd2_index_t  zvhd2_index;
}zvhd2_context_t;

struct ZVHD2_DATA  //48B
{
    char prefix[ZVHD2_DATA_PREFIX_LEN];  //12B
    uint32_t size;                       // 4B
    uint32_t curr_blk;                   // 4B     
    uint8_t compressed;                  // 1B
    uint8_t reserved3[3];                // 3B
    uint32_t orig_size;                  // 4B
    char reservered[20];                 // 20B
};

enum COMPRESS_METHOD
{
    COMPRESS_METHOD_ZLIB = 0,
    COMPRESS_METHOD_ZSTD
};

#define  DEFAULT_COMPRESS_METHOD COMPRESS_METHOD_ZSTD

#ifdef   C_COMPRESS_METHOD_ZLIB
#undef DEFAULT_COMPRESS_METHOD
#define  DEFAULT_COMPRESS_METHOD COMPRESS_METHOD_ZLIB
#endif  

#ifdef   C_COMPRESS_METHOD_ZSTD
#undef DEFAULT_COMPRESS_METHOD
#define  DEFAULT_COMPRESS_METHOD COMPRESS_METHOD_ZSTD
#endif

void __zvhd2_logprintf(int level, const char *format, ...);

#define LOG(LEVEL,fmt,args...) __zvhd2_logprintf(LEVEL,"[%s][%s:%s:%d] "fmt,log_level_str[LEVEL],__FILE__,__func__,__LINE__, ##args);
#define LOG_FATAL(fmt,args...) LOG(LOG_FATAL,fmt,##args);
#define LOG_ERROR(fmt,args...) LOG(LOG_ERR,fmt,##args);
#define LOG_INFO(fmt,args...) LOG(LOG_INFO,fmt,##args);
#define LOG_WARN(fmt,args...) LOG(LOG_WARN,fmt,##args);
#if 0
#define LOG_DEBUG(fmt,args...) LOG(LOG_DEBUG,fmt,##args);
#else
#define LOG_DEBUG(fmt,args...)
#endif

#ifndef ZVHD2_READ_WITH_INDEX
static int zvhd2_get_more_data(BlockDriverState *bs, zvhd2_context_t *zvhd2 , uint32_t *total_size);
static int check_zvhd2_data_end(const char *buf, int count);
static int check_zvhd2_data_start(const char *buf);
static int zvhd2_read(BlockDriverState *bs, int64_t sector_num,
                    uint8_t *buf, int nb_sectors);
#endif
static int zvhd2_read_with_index(BlockDriverState *bs, int64_t sector_num,
                    uint8_t *buf, int nb_sectors);
static int zvhd2_read_with_indexbm(BlockDriverState *bs, int64_t sector_num,
                    uint8_t *buf, int nb_sectors);

static void zvhd2_clear_data(uint8_t *buf, int total_size);

int __zvhd2_index_initiliaze(zvhd2_index_t * zvhd2_index, uint32_t max_blk_num, uint32_t blk_size, int read_only);
int __zvhd2_index_finalize(zvhd2_index_t * zvhd2_index);
zvhd2_index_store_t * __zvhd2_index_get_store(zvhd2_index_t * zvhd2_index, uint64_t index_seg_idx);
int __zvhd2_index_set(zvhd2_index_t * zvhd2_index, uint32_t cur_blk, uint64_t blk_offset, uint32_t blk_num,uint32_t blk_disk_size);
int __zvhd2_index_get(zvhd2_index_t * zvhd2_index, uint32_t cur_blk, uint64_t * blk_offset, uint32_t * blk_num,uint32_t * blk_disk_size);
zvhd2_index_store_t * __zvhd2_bm_get_store(zvhd2_index_t * zvhd2_index, int bm_seg_idx);
int __zvhd2_bm_set(zvhd2_index_t * zvhd2_index, zvhd2_index_store_t * bm_store, uint32_t blk_num);
uint32_t __count_and_find_non_zero(unsigned char *bitmap, uint32_t start, uint32_t bitcnt, int32_t *first, int32_t *last); 
int  __zvhd2_bm_get_index_num(zvhd2_index_t * zvhd2_index, uint32_t blk_num, uint32_t *index_block_num) ;
int __zvhd2_bm_read(BlockDriverState *bs, uint32_t blk_num, uint8_t *bm_value, uint32_t *index_block_num );
int __zvhd2_read_initiliaze_bm(BlockDriverState *bs);
int __zvhd2_index_read(BlockDriverState *bs, uint32_t blk_num, uint64_t *blk_offset, uint32_t *blk_disk_size);
int __zvhd2_index_debug(zvhd2_index_store_t * idx_store , uint32_t blk_count);

typedef struct BDRVZVHD2State {
    CoMutex lock;
    zvhd2_context_t *zvhd2_context_buffer;
    uint64_t free_data_block_offset;
} BDRVZVHD2State;

static struct WRAPPER_COMP_METHOD * __get_comp_method_wrapper(zvhd2_context_t *ctx)
{
    if(COMPRESS_METHOD_ZSTD == ctx->footer->compress_method)
    {
        return COMP_zstd();
    }
    else if(COMPRESS_METHOD_ZLIB == ctx->footer->compress_method)
    {
        return COMP_zlib();
    }
    return NULL;
}

static uint32_t pvhd_checksum_footer(zvhd2_footer_t *footer)
{
    int i;
    unsigned char *blob;
    uint32_t checksum, tmp;

    checksum         = 0;
    tmp              = footer->checksum;
    footer->checksum = 0;

    blob = (unsigned char *)footer;
    for (i = 0; i < sizeof(zvhd2_footer_t); i++)
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

void __zvhd2_logprintf(int level, const char *format, ...)
{
    va_list ap;    
    char buf[27] = {0}, *eol = NULL;
    time_t t;
    FILE *file = NULL;
    
    //lint -e1055
    va_start(ap, format);
    //lint +e1055

    file = stdout;

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
 
static coroutine_fn int zvhd2_co_read(BlockDriverState *bs, int64_t sector_num,
                                    uint8_t *buf, int nb_sectors)
{
    int ret;
    BDRVZVHD2State *s = bs->opaque;
    zvhd2_context_t *zvhd2 = s->zvhd2_context_buffer;
    qemu_co_mutex_lock(&s->lock);

#ifdef ZVHD2_READ_WITH_INDEX
    if(zvhd2->footer->index_contains_zero_blk)
    {
        ret = zvhd2_read_with_index(bs, sector_num, buf, nb_sectors);
    }
    else
    {
        ret = zvhd2_read_with_indexbm(bs, sector_num, buf, nb_sectors);
    }
#else
    ret = zvhd2_read(bs, sector_num, buf, nb_sectors);
#endif
    qemu_co_mutex_unlock(&s->lock);
    return ret;
}

#ifndef ZVHD2_READ_WITH_INDEX
static int check_zvhd2_data_start(const char *buf)
{
    char tmpbuf[ZVHD2_DATA_PREFIX_LEN+1] = {0};
    zvhd2_footer_t *footer = NULL;

    if (memcmp(((zvhd2_data_t *)buf)->prefix,ZVHD2_DATA_PREFIX,ZVHD2_DATA_PREFIX_LEN))
    {
        footer = (zvhd2_footer_t *)buf;
        if (memcmp(footer->cookie, ZVHD2_COOKIE,ZVHD2_COOKIE_LEN-1) ==0)
        {
            return -1;
        }

        memcpy(tmpbuf,((zvhd2_data_t *)buf)->prefix,ZVHD2_DATA_PREFIX_LEN);
        return -EINVAL;
    }

    return 0;
}

static int check_zvhd2_data_end(const char *buf,int count)
{
    const char * tmp = NULL;
    char tmpbuf[ZVHD2_DATA_POSTFIX_LEN+1] = {0};

    tmp = buf + count - ZVHD2_DATA_POSTFIX_LEN;

    if (memcmp(tmp,ZVHD2_DATA_POSTFIX,ZVHD2_DATA_POSTFIX_LEN))
    {
        memcpy(tmpbuf,tmp,ZVHD2_DATA_POSTFIX_LEN);
        LOG_ERROR("check postfix failed,current postfix is %s\n",tmpbuf);
        return -EINVAL;
    }

    return 0;
}

static int zvhd2_get_more_data(BlockDriverState *bs,zvhd2_context_t *zvhd2 ,uint32_t *total_size)
{
    int size =0;
    int msize = 0;
    int ret = 0;

    size = ((zvhd2_data_t *)zvhd2->buf)->size;

    if ((size + sizeof(zvhd2_data_t) + ZVHD2_DATA_POSTFIX_LEN) <= FOOTER_SIZE)
    {

        if (check_zvhd2_data_end(zvhd2->buf,FOOTER_SIZE))
        {
            return -EINVAL;
        }
    }else
    {
        msize = (size + sizeof(zvhd2_data_t) + ZVHD2_DATA_POSTFIX_LEN - 1) / BLOCK_SIZE * BLOCK_SIZE;

        ret = bdrv_pread(bs->file, zvhd2->cur_offset, zvhd2->buf+FOOTER_SIZE, msize);
        if (ret < 0) 
       {
            return ret;
        }

        zvhd2->cur_offset = zvhd2->cur_offset + msize;

        if (check_zvhd2_data_end(zvhd2->buf,msize + FOOTER_SIZE))
        {
            return -EINVAL;
        }
    }
    *total_size = msize + FOOTER_SIZE;
    return 0;
}

static int zvhd2_read(BlockDriverState *bs, int64_t sector_num,
                    uint8_t *buf, int nb_sectors)
{
    BDRVZVHD2State *s = bs->opaque;
    zvhd2_context_t *zvhd2 = s->zvhd2_context_buffer;
    int total_size = nb_sectors << 9;
    int ret = 0;
    int begin_block = sector_num / BLOCK_SIZE_SECTOR;
    //LOG_DEBUG("will read block %d size %d\n",begin_block, total_size);
    if (1 == zvhd2->end_flag)
    {
        zvhd2_clear_data(buf, total_size);
        return 0;
    }

    //has got data last time
    if(memcmp(zvhd2->data_buf->prefix,ZVHD2_DATA_PREFIX,ZVHD2_DATA_PREFIX_LEN) == 0)
    {
        if(begin_block < zvhd2->data_buf->curr_blk)
        {
            zvhd2_clear_data(buf, total_size);
            return 0;
        }
        else if(begin_block == zvhd2->data_buf->curr_blk)
        {
            memcpy(buf, zvhd2->buf+sizeof(zvhd2_data_t), total_size);
            zvhd2_clear_data((uint8_t *)zvhd2->buf, zvhd2->curr_buf_size);
            return 0;
        }
        else
        {
            return -EINVAL;
        }
    }

    ret = bdrv_pread(bs->file, zvhd2->cur_offset, zvhd2->buf, FOOTER_SIZE);
    if (ret < 0) 
    {
        return ret;
    }
    zvhd2->cur_offset = zvhd2->cur_offset + FOOTER_SIZE;

    ret = check_zvhd2_data_start(zvhd2->buf);
    if (ret)
    {
        //arrive at the end of zvhd2 file
        if(-1 == ret)
        {
            zvhd2->end_flag = 1;
            zvhd2_clear_data(buf, total_size);
            return 0;
        }
        return -EINVAL;
    }

    ret = zvhd2_get_more_data(bs, zvhd2, &zvhd2->curr_buf_size);
    if(ret)
    {
        return ret;
    }

     if (0 != zvhd2->data_buf->size)
    {
#ifdef USE_FRAME_COMPRESSION
        COMP_CTX_free(zvhd2->ctx);
        zvhd2->ctx = COMP_CTX_new(__get_comp_method_wrapper(zvhd2));
#endif
        ret = COMP_expand_block(zvhd2->ctx,(unsigned char *)buf,total_size,(unsigned char *)zvhd2->buf + sizeof(zvhd2_data_t),zvhd2->data_buf->size);
        if (ret < 0)
        {
            ERR_load_COMP_strings();
            LOG_ERROR("expand data failed,ret is %d\n",ret);
            return ret;
        }
        if (ret != total_size)
        {
             LOG_ERROR("expand size is not correct,ret is %d\n",ret);
            return -EIO;
        }
    }
    else
    {
        LOG_ERROR("data's size is 0 \n");
        return -EIO;
    }

    if(begin_block == zvhd2->data_buf->curr_blk)
    {
        LOG_DEBUG("decompress size is %d, block [%u] from [%u] \n", ret,  zvhd2->data_buf->curr_blk, begin_block);
        zvhd2_clear_data((uint8_t *)zvhd2->buf,zvhd2->curr_buf_size);
    }
    else
    {
        memset(zvhd2->buf+sizeof(zvhd2_data_t), 0, (zvhd2->curr_buf_size -sizeof(zvhd2_data_t))?:total_size);
        memcpy(zvhd2->buf+sizeof(zvhd2_data_t), buf, total_size);
        zvhd2_clear_data(buf, total_size);
        zvhd2->curr_buf_size = total_size + sizeof(zvhd2_data_t);
        LOG_DEBUG( "decompress size is %d, block [%u] from [%u] \n", ret,  zvhd2->data_buf->curr_blk, begin_block);
    }
    
    return 0;
}
#endif

static int zvhd2_validate_footer(zvhd2_footer_t *footer)
{
    uint32_t checksum;

    //csize = sizeof(footer->cookie);
    //@pome

    if (memcmp(footer->cookie, ZVHD2_COOKIE,ZVHD2_COOKIE_LEN-1) !=0) {
        char buf[9];
        memcpy(buf, footer->cookie, 8);
        buf[8]= '\0';
        LOG_ERROR("Wrong footer cookie %s !=%s\n",  buf, ZVHD2_COOKIE);
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
        LOG_ERROR("Wrong checksum %u != %u (from file)\n", checksum, footer->checksum);
        return -EINVAL;
    }

    return 0;
}

int __zvhd2_index_initiliaze(zvhd2_index_t * zvhd2_index, uint32_t max_blk_num, uint32_t blk_size, int read_only)
{
    int ret = 0;
    uint64_t test_4K_blocks = 0;
    zvhd2_index->index_seg_size = ZVHD2_INDEX_SEG_SIZE;
    
    test_4K_blocks = zvhd2_index->index_seg_size;
    test_4K_blocks = (test_4K_blocks << BLOCK_SHIFT) >> BLOCK_SHIFT;
    if(test_4K_blocks != zvhd2_index->index_seg_size)
    {
        LOG_ERROR("ZVHD2_INDEX_SEG_SIZE=%d, is not aligned with %d\n",ZVHD2_INDEX_SEG_SIZE,BLOCK_SIZE);
        LOG_ERROR("ZVHD2_INDEX_SEG_SIZE=%llu, is not aligned with %d\n",test_4K_blocks,zvhd2_index->index_seg_size);
        return -1;
    }
    
    zvhd2_index->blk_num_per_seg = (zvhd2_index->index_seg_size/sizeof(zvhd2_index_entry_t));
    if(zvhd2_index->blk_num_per_seg*sizeof(zvhd2_index_entry_t) != zvhd2_index->index_seg_size)
    {
        LOG_ERROR("ZVHD2_INDEX_SEG_SIZE=%d, is not aligned with index entry\n",ZVHD2_INDEX_SEG_SIZE);
        return -1;
    }
    
    zvhd2_index->max_segs_num = (max_blk_num + zvhd2_index->blk_num_per_seg -1)/zvhd2_index->blk_num_per_seg;
    zvhd2_index->segs_num = 0;    
    zvhd2_index->bm_seg_size = zvhd2_index->blk_num_per_seg/BLOCKS_PER_BYPE; 
    test_4K_blocks = zvhd2_index->bm_seg_size ;
    test_4K_blocks = (test_4K_blocks<< BLOCK_SHIFT) >> BLOCK_SHIFT;
    if(test_4K_blocks != zvhd2_index->bm_seg_size)
    {
        LOG_ERROR("ZVHD2_INDEX_SEG_SIZE=%d, is not aligned with %d for bitmap seg size %d\n",
                ZVHD2_INDEX_SEG_SIZE,BLOCK_SIZE,zvhd2_index->bm_seg_size);
        return -1;
    }
    zvhd2_index->index_segs = NULL;  
    zvhd2_index->bm_segs = NULL;    
    
    zvhd2_index->index_tmp_file_fd = -1;     
    
    LOG_DEBUG( "index info : max_segs_num=%u blk_num_per_seg=%u\n", zvhd2_index->max_segs_num, zvhd2_index->blk_num_per_seg);
    LOG_DEBUG( "index info : index_seg_size=%u bm_seg_size=%u\n", zvhd2_index->index_seg_size,zvhd2_index->bm_seg_size);   

    if (read_only) {
    }
    
    
    zvhd2_index->index_segs = (zvhd2_index_store_t *)calloc(zvhd2_index->max_segs_num,sizeof(zvhd2_index_store_t));
    if(NULL == zvhd2_index->index_segs)
    {
        return -ENOMEM;
    }
    zvhd2_index->bm_segs = (zvhd2_index_store_t *)calloc(zvhd2_index->max_segs_num,sizeof(zvhd2_index_store_t));
    if(NULL == zvhd2_index->bm_segs)
    {
        free(zvhd2_index->index_segs);
        return -ENOMEM;
    }

    ret = posix_memalign((void **)&zvhd2_index->index_buffer,BLOCK_SIZE,zvhd2_index->index_seg_size);
    if (ret != 0)
    {
        free(zvhd2_index->bm_segs);
        free(zvhd2_index->index_segs);
        return ret;
    }

    ret = posix_memalign((void **)&zvhd2_index->bm_buffer,BLOCK_SIZE,zvhd2_index->bm_seg_size);
    if (ret != 0)
    {
        free(zvhd2_index->index_buffer);
        free(zvhd2_index->bm_segs);
        free(zvhd2_index->index_segs);
        return ret;
    }
    zvhd2_index->index_segs[0].store_buffer = zvhd2_index->index_buffer;   
    zvhd2_index->index_segs[0].status = INDEX_STORE_STATUS_ALLOCATED;
    zvhd2_index->index_segs_num = 1;
    zvhd2_index->bm_segs[0].store_buffer = zvhd2_index->bm_buffer;    
    zvhd2_index->bm_segs[0].status = INDEX_STORE_STATUS_ALLOCATED;
    zvhd2_index->bm_segs_num = 1;

    int i = 0;
    for(i= 0;i < zvhd2_index->max_segs_num;i++)
    {
        zvhd2_index_store_t * index_store = zvhd2_index->index_segs+i;
        zvhd2_index_store_t * bm_store = zvhd2_index->bm_segs+i;
        LOG_DEBUG("index %d : %p,%p \n", i,index_store,index_store->store_buffer);
        LOG_DEBUG("bm %d : %p,%p \n", i,bm_store,bm_store->store_buffer);
    }

    if (read_only) {
        //return 0;
    }

    return 0;
}

int __zvhd2_index_finalize(zvhd2_index_t * zvhd2_index)
{
    int i = 0;
    
    for(i = 0;i < zvhd2_index->max_segs_num;i++)
    {
        zvhd2_index_store_t * index_store = zvhd2_index->index_segs+i;
        zvhd2_index_store_t * bm_store = zvhd2_index->bm_segs+i;
        LOG_DEBUG("index %d : %p,%p \n", i,index_store,index_store==NULL?NULL:index_store->store_buffer);
        LOG_DEBUG("bm %d : %p,%p \n", i,bm_store,bm_store==NULL?NULL:bm_store->store_buffer);
    }

    for( i=0;i<zvhd2_index->max_segs_num;i++)
    {
         zvhd2_index_store_t * index_store = zvhd2_index->index_segs+i;
         if(NULL != index_store->store_buffer)
         {
             free(index_store->store_buffer);
             index_store->store_buffer = NULL;
         }
    }
    free(zvhd2_index->index_segs);
    zvhd2_index->index_segs = NULL;

    for( i=0;i<zvhd2_index->max_segs_num;i++)
    {
         zvhd2_index_store_t * bm_store = zvhd2_index->bm_segs+i;
         if(NULL != bm_store->store_buffer)
         {
             free(bm_store->store_buffer);
             bm_store->store_buffer = NULL;
         }
    }
    free(zvhd2_index->bm_segs);
    zvhd2_index->bm_segs = NULL;

    return 0;
}

zvhd2_index_store_t * __zvhd2_index_get_store(zvhd2_index_t * zvhd2_index, uint64_t index_seg_idx)
{
    if(index_seg_idx >= zvhd2_index->max_segs_num)
    {
        LOG_ERROR(" index_seg_idx is out of the reserved scope\n");
        return NULL;
    }

    zvhd2_index_store_t * idx_store = zvhd2_index->index_segs + index_seg_idx;
    if(idx_store->store_buffer)
    {
        return idx_store;
    }

    idx_store->store_buffer = calloc(1, zvhd2_index->index_seg_size);
    if(NULL == idx_store->store_buffer)
    {
        LOG_ERROR(" allocate memory failed for index store buffer\n")
        return NULL;
    }
    
    zvhd2_index->index_segs_num ++;
    idx_store->non_zero_blk_count = 0;
    idx_store->status = INDEX_STORE_STATUS_ALLOCATED;

    return idx_store;    
}

int __zvhd2_index_set(zvhd2_index_t * zvhd2_index, uint32_t cur_blk, uint64_t blk_offset, uint32_t blk_num,uint32_t blk_disk_size)
{   
    int ret = 0;
    int index_seg_idx =   cur_blk/zvhd2_index->blk_num_per_seg;
    zvhd2_index_store_t * idx_store = __zvhd2_index_get_store(zvhd2_index, index_seg_idx);
    if(NULL == idx_store)
    {
        LOG_ERROR(" index idx is out of the reserved scope cur_blk=%u, index_seg_idx=%d\n",cur_blk, index_seg_idx);
        return -EINVAL;
    }
    
    int entry_idx = cur_blk % zvhd2_index->blk_num_per_seg;
    zvhd2_index_entry_t * idx_entry = ((zvhd2_index_entry_t*)idx_store->store_buffer) + entry_idx;

    idx_entry->blk_offset = blk_offset;
    idx_entry->blk_num = blk_num;
    idx_entry->blk_disk_size = blk_disk_size;
    

    idx_store->non_zero_blk_count ++;
    idx_store->status = INDEX_STORE_STATUS_FILLING;
    LOG_DEBUG(" cur_blk=%u, real_blk_num=%u  index_seg_idx=%d entry_idx:%d nz=%u\n",cur_blk, blk_num,  index_seg_idx,entry_idx,idx_store->non_zero_blk_count);
    return ret;
}

int __zvhd2_index_get(zvhd2_index_t * zvhd2_index, uint32_t cur_blk, uint64_t * blk_offset, uint32_t * blk_num,uint32_t * blk_disk_size)
{   
    int ret = 0;
    int index_seg_idx =   cur_blk/zvhd2_index->blk_num_per_seg;
    zvhd2_index_store_t * idx_store = __zvhd2_index_get_store(zvhd2_index, index_seg_idx);
    if(NULL == idx_store)
    {
        LOG_ERROR(" index idx is out of the reserved scope\n")
        return -EINVAL;
    }
    
    int entry_idx = cur_blk % zvhd2_index->blk_num_per_seg;
    zvhd2_index_entry_t * idx_entry = ((zvhd2_index_entry_t*)idx_store->store_buffer) + entry_idx;

    *blk_offset = idx_entry->blk_offset;
    *blk_num = idx_entry->blk_num;
    *blk_disk_size = idx_entry->blk_disk_size;

    return ret;
}

zvhd2_index_store_t * __zvhd2_bm_get_store(zvhd2_index_t * zvhd2_index, int bm_seg_idx)
{
    if(bm_seg_idx >= zvhd2_index->max_segs_num)
    {
        LOG_ERROR(" index_seg_idx is out of the reserved scope %d >= %u\n",bm_seg_idx, zvhd2_index->max_segs_num);
        return NULL;
    }

    zvhd2_index_store_t * idx_store = zvhd2_index->bm_segs + bm_seg_idx;
    if(idx_store->store_buffer)
    {
        return idx_store;
    }

    idx_store->store_buffer = calloc(1, zvhd2_index->bm_seg_size);
    if(NULL == idx_store->store_buffer)
    {
        LOG_ERROR(" allocate memory failed for index store buffer\n")
        return NULL;
    }

    zvhd2_index->bm_segs_num ++;
    idx_store->non_zero_blk_count = 0;
    idx_store->status = INDEX_STORE_STATUS_ALLOCATED;

    return idx_store;    
}

int __zvhd2_bm_set(zvhd2_index_t * zvhd2_index, zvhd2_index_store_t * bm_store, uint32_t blk_num)
{          
    int entry_idx = blk_num % zvhd2_index->blk_num_per_seg;    
    if(bm_store->store_buffer[entry_idx/BLOCKS_PER_BYPE] != 0)
    {
        LOG_DEBUG("%u 0x%x  0x%x\n", entry_idx, bm_store->store_buffer[entry_idx/BLOCKS_PER_BYPE], 1 << (entry_idx%BLOCKS_PER_BYPE));
    }
    bm_store->store_buffer[entry_idx/BLOCKS_PER_BYPE] |=  1 << (entry_idx%BLOCKS_PER_BYPE);
    LOG_DEBUG("%u 0x%x  blk_num=%u\n", entry_idx, bm_store->store_buffer[entry_idx/BLOCKS_PER_BYPE],blk_num);
    bm_store->non_zero_blk_count ++;
    return 0;
}

uint32_t __count_and_find_non_zero(unsigned char *bitmap, uint32_t start, uint32_t bitcnt, int32_t *first, int32_t *last) 
{
    int32_t i;
    uint32_t count = 0;
    assert(first);
    assert(last);
    *first = -1;
    *last = -1;//LOG_DEBUG("0x%x 0x%x \n", bitmap[0],bitmap[1]);
    for(i = start; i < bitcnt; i++)
    {
        //if(bitmap[i/BLOCKS_PER_BYPE] != 0)
        //    LOG_DEBUG("%u 0x%x \n", i, bitmap[i/BLOCKS_PER_BYPE]);
        if(((bitmap[i/BLOCKS_PER_BYPE] >> i%BLOCKS_PER_BYPE) & 1) == 1)
        {
            
            if(*first < 0)
            {
                *first = i;
            }
            *last = i;
            count++;
            LOG_DEBUG("%u 0x%x count=%u first=%d last=%d \n", i, bitmap[i/BLOCKS_PER_BYPE],count,*first,*last);
        }
    }
    return count;
}

int  __zvhd2_bm_get_index_num(zvhd2_index_t * zvhd2_index, uint32_t blk_num, uint32_t *index_block_num) 
{
   int bm_seg_idx =   blk_num/zvhd2_index->blk_num_per_seg;    
   zvhd2_index_store_t * bm_store = __zvhd2_bm_get_store(zvhd2_index, bm_seg_idx);
   if(NULL == bm_store )
   {
        LOG_ERROR("bm_store is NULL for blk_num %u, seg %d\n", blk_num, bm_seg_idx);
        return -EINVAL;
   }
    
    if(bm_store->status != INDEX_STORE_STATUS_FILLED)
    {
        LOG_ERROR("bm_store is not filled for blk_num %u, seg %d\n", blk_num, bm_seg_idx);
        return -EINVAL;
    }
    
    uint32_t  seg_ofset = blk_num%zvhd2_index->blk_num_per_seg;
    if(bm_store->non_zero_first < 0 || seg_ofset > bm_store->non_zero_last)
    {
        LOG_ERROR("there is no nz_item in this seg %d for blk %d \n", bm_seg_idx, blk_num);
        return -EINVAL;
    }

    uint32_t start = bm_store->non_zero_first;
    uint32_t bitcnt = seg_ofset+1;
    int32_t first =-1;
    int32_t last = -1;
    
    uint32_t count = __count_and_find_non_zero(bm_store->store_buffer, start, bitcnt, &first, &last);
    *index_block_num = bm_store->non_zero_blk_base+count-1;  

    LOG_DEBUG("blk_num %u -> %u @seg %d,%u : count=(%u,%d,%d) base=%u  \n",*index_block_num, blk_num,
                                bm_store->seg_idx,seg_ofset,count,first,last,bm_store->non_zero_blk_base);

    return 0;
}

int __zvhd2_bm_read(BlockDriverState *bs, uint32_t blk_num, uint8_t *bm_value, uint32_t *index_block_num )
{   
    BDRVZVHD2State *s = bs->opaque;
    zvhd2_context_t *zvhd2 = s->zvhd2_context_buffer;
    zvhd2_index_t * zvhd2_index = &(zvhd2->zvhd2_index);
    int ret = 0;
    int bm_seg_idx =   blk_num/zvhd2_index->blk_num_per_seg;
    
    zvhd2_index_store_t * bm_store = __zvhd2_bm_get_store(zvhd2_index, bm_seg_idx);
    if(NULL == bm_store)
    {
        LOG_ERROR(" bm idx is out of the reserved scope\n")
        return -EINVAL;
    }
    
    if(INDEX_STORE_STATUS_FILLED != bm_store->status)
    {
        uint64_t  offset = zvhd2->footer->bitmap_lba + bm_seg_idx*zvhd2_index->bm_seg_size;
        memset(bm_store->store_buffer,0, zvhd2_index->bm_seg_size);
        bm_store->seg_idx = bm_seg_idx;
        ret = bdrv_pread(bs->file, offset , bm_store->store_buffer, zvhd2_index->bm_seg_size);
        if(ret == zvhd2_index->bm_seg_size)
        {
            bm_store->non_zero_blk_count = __count_and_find_non_zero(bm_store->store_buffer, 0, zvhd2_index->bm_seg_size*BLOCKS_PER_BYPE,
                                    &bm_store->non_zero_first, &bm_store->non_zero_last);
            bm_store->status = INDEX_STORE_STATUS_FILLED;
            LOG_DEBUG("seg %d : lba (%llu,%u) base_blk %u count (%u,%d,%d)\n",bm_store->seg_idx, offset, zvhd2_index->bm_seg_size, bm_store->non_zero_blk_base,
                    bm_store->non_zero_blk_count,bm_store->non_zero_first,bm_store->non_zero_last);
        }
        else
        {
            LOG_ERROR(" failed to read bitmap data ret=%d \n",ret)
            return -EINVAL;
        }
    }

    if(INDEX_STORE_STATUS_FILLED != bm_store->status)
    {
        LOG_ERROR(" failed to fill bitmap data\n")
        return -EINVAL;
    }

    int entry_idx = blk_num % zvhd2_index->blk_num_per_seg;
    *bm_value =  (bm_store->store_buffer[entry_idx/BLOCKS_PER_BYPE] >> (entry_idx%BLOCKS_PER_BYPE)) & 1;

    if(! (*bm_value) )
    {
        return 0;
    }

    LOG_DEBUG("blk %u is not zero, seg %d, entry %d\n", blk_num, bm_seg_idx, entry_idx );

    if(!zvhd2->footer->index_contains_zero_blk && NULL != index_block_num)
    {
        ret =  __zvhd2_bm_get_index_num(zvhd2_index, blk_num, index_block_num); 
        return ret;
    }

    return 0;
}

int __zvhd2_read_initiliaze_bm(BlockDriverState *bs)
{
    BDRVZVHD2State *s = bs->opaque;
    zvhd2_context_t *zvhd2 = s->zvhd2_context_buffer;
    zvhd2_index_t * zvhd2_index = &(zvhd2->zvhd2_index);
    int ret = 0;

    uint8_t  bm_value = 0;
    int i = 0;
    zvhd2_index_store_t * bm_store = NULL;
    for(i=0;i<zvhd2_index->max_segs_num;i++)
    {
        ret = __zvhd2_bm_read(bs, i*zvhd2_index->blk_num_per_seg, &bm_value,NULL);
        if(ret)
        {
            return ret;
        }
        bm_store = __zvhd2_bm_get_store(zvhd2_index, i);
        if(i>0)
        {
            zvhd2_index_store_t * bm_store_prev = __zvhd2_bm_get_store(zvhd2_index, i-1);
            bm_store->non_zero_blk_base = bm_store_prev->non_zero_blk_base + bm_store_prev->non_zero_blk_count;
        }
        else
        {
            bm_store->non_zero_blk_base = 0;
        }
    }

    for(i=0;i<zvhd2_index->max_segs_num;i++)
    {
        bm_store = __zvhd2_bm_get_store(zvhd2_index, i);
        LOG_DEBUG("seg %d : lba (%llu,%u) base_blk %u count (%u,%d,%d)\n",bm_store->seg_idx, zvhd2->footer->bitmap_lba + i*zvhd2_index->bm_seg_size, zvhd2_index->bm_seg_size, bm_store->non_zero_blk_base,
                    bm_store->non_zero_blk_count,bm_store->non_zero_first,bm_store->non_zero_last);
    }
    
    return 0;
}

int __zvhd2_index_read(BlockDriverState *bs, uint32_t blk_num, uint64_t *blk_offset, uint32_t *blk_disk_size)
{   
    BDRVZVHD2State *s = bs->opaque;
    zvhd2_context_t *zvhd2 = s->zvhd2_context_buffer;
    zvhd2_index_t * zvhd2_index = &(zvhd2->zvhd2_index);
    int ret = 0;
    int index_seg_idx =   blk_num/zvhd2_index->blk_num_per_seg;

    zvhd2_index_store_t * idx_store = __zvhd2_index_get_store(zvhd2_index, index_seg_idx);
    if(NULL == idx_store)
    {
        LOG_ERROR(" index idx is out of the reserved scope\n")
        return -EINVAL;
    }
    
    if(INDEX_STORE_STATUS_FILLED != idx_store->status)
    {
        uint64_t  offset = zvhd2->footer->index_lba + index_seg_idx*zvhd2_index->index_seg_size;
        ret = bdrv_pread(bs->file, offset , idx_store->store_buffer, zvhd2_index->index_seg_size);
        if(ret == zvhd2_index->index_seg_size)
        {
            idx_store->status = INDEX_STORE_STATUS_FILLED;
        }
        else
        {
            LOG_ERROR(" failed to read index data ret=%d \n",ret)
            return -EINVAL;
        }
    }

    if(INDEX_STORE_STATUS_FILLED != idx_store->status)
    {
        LOG_ERROR(" failed to fill index data\n")
        return -EINVAL;
    }
    
    int entry_idx = blk_num % zvhd2_index->blk_num_per_seg;
    zvhd2_index_entry_t * idx_entry = ((zvhd2_index_entry_t*)idx_store->store_buffer) + entry_idx;

    if(idx_entry->blk_offset == 0)
    {
        *blk_offset = 0;
        *blk_disk_size = 0;
        return 0;
    }
    else if(blk_num != idx_entry->blk_num && zvhd2->footer->index_contains_zero_blk)    
    {
        LOG_ERROR(" wrong blk_num required %u, but get %u\n", blk_num, idx_entry->blk_num)
        return -EINVAL;
    }

    *blk_offset = idx_entry->blk_offset;
    *blk_disk_size = idx_entry->blk_disk_size;
    return 0;
}

int __zvhd2_index_debug(zvhd2_index_store_t * idx_store , uint32_t blk_count)
{   
    int ret = 0;
    if(NULL == idx_store)
    {
        LOG_ERROR(" index idx is out of the reserved scope\n")
        return -EINVAL;
    }
    
    int entry_idx = 0;
    for(entry_idx=0;entry_idx<blk_count;entry_idx++)
    {
        zvhd2_index_entry_t * idx_entry = ((zvhd2_index_entry_t*)idx_store->store_buffer) + entry_idx;
        if(idx_entry->blk_offset != 0 && idx_entry->blk_disk_size != 0)
        {
            LOG_DEBUG("index entry %d: offset %llu, size %d,  real_blk_num[%u]  \n",
                                entry_idx,idx_entry->blk_offset, idx_entry->blk_disk_size, idx_entry->blk_num);
        }
    }
    return ret;
}

static int zvhd2_read_with_index(BlockDriverState *bs, int64_t sector_num,
                    uint8_t *buf, int nb_sectors)
{
    BDRVZVHD2State *s = bs->opaque;
    zvhd2_context_t *zvhd2 = s->zvhd2_context_buffer;
    int total_size = nb_sectors << 9;
    int ret = 0;
    int begin_block = sector_num / BLOCK_SIZE_SECTOR;

    uint64_t blk_offset = 0;
    uint32_t blk_disk_size  = 0;
    //LOG_DEBUG("will read block %u \n",begin_block);
    ret = __zvhd2_index_read(bs, begin_block, &blk_offset, &blk_disk_size);
    if(ret)
    {
        LOG_ERROR("error ret=%d, read block %u : %llu,%u\n",ret,begin_block,blk_offset, blk_disk_size);
        return ret;
    }

    if (blk_offset == 0 || blk_disk_size == 0)  // a zero block
    {
        //LOG_DEBUG("read block %u : %llu,%u\n",begin_block,blk_offset, blk_disk_size);
        zvhd2_clear_data(buf, total_size);
        return 0;
    }

    ret = bdrv_pread(bs->file, blk_offset, zvhd2->buf, blk_disk_size);
    if (ret < 0) 
    {
        return ret;
    }
    LOG_DEBUG("read block : size=%u, offset=%llu,write_size=%u, block[%u %u]\n",zvhd2->data_buf->size,blk_offset, blk_disk_size,begin_block,zvhd2->data_buf->curr_blk);

    if (0 != zvhd2->data_buf->size)
    {
#ifdef USE_FRAME_COMPRESSION
        COMP_CTX_free(zvhd2->ctx);
        zvhd2->ctx = COMP_CTX_new(__get_comp_method_wrapper(zvhd2));
#endif
        ret = COMP_expand_block(zvhd2->ctx,(unsigned char *)buf,total_size,(unsigned char *)zvhd2->buf + sizeof(zvhd2_data_t),zvhd2->data_buf->size);
        if (ret < 0)
        {
            ERR_load_COMP_strings();
            LOG_ERROR("expand data failed,ret is %d\n",ret);
            return ret;
        }
        if (ret != total_size)
        {
             LOG_ERROR("expand size is not correct,ret is %d\n",ret);
            return -EIO;
        }
    }
    else
    {
        LOG_ERROR( "data's size is 0 \n");
        return -EIO;
    }

    LOG_DEBUG("decompress size is %d, block [%u] from [%u] \n", ret,  zvhd2->data_buf->curr_blk, begin_block);
    /*
    if(begin_block == zvhd2->data_buf->curr_blk)
    {
        zvhd2_clear_data((uint8_t *)zvhd2->buf,zvhd2->curr_buf_size);
        LOG_DEBUG( "decompress size is %d, block [%u] from [%u] \n", ret,  zvhd2->data_buf->curr_blk, begin_block);
    }
    else
    {
        memset(zvhd2->buf+sizeof(zvhd2_data_t), 0, (zvhd2->curr_buf_size -sizeof(zvhd2_data_t))?:total_size);
        memcpy(zvhd2->buf+sizeof(zvhd2_data_t), buf, total_size);
        zvhd2_clear_data(buf, total_size);
        zvhd2->curr_buf_size = total_size + sizeof(zvhd2_data_t);
        LOG_DEBUG( "decompress size is %d, block [%u] from [%u] \n", ret,  zvhd2->data_buf->curr_blk, begin_block);
    }
   */
    
    return 0;
}

/*
void debug_buffer(unsigned char *buffer,  uint32_t len, uint32_t id)
{
    char tmp_file_path[1024];
    snprintf(tmp_file_path,1023, "/tmp/will_be_deleted_%u_%u.mem.qemu", id,len);
    FILE *outfile = fopen(tmp_file_path, "w");
    if(outfile== NULL)
    {
        return;
    }

    fseek(outfile, 0, SEEK_SET);
    size_t w_size = fwrite(buffer, 1, len, outfile);
    fclose(outfile);
    LOG_INFO("_debug_mem_buffer saved to %s\n", tmp_file_path);
}
*/

static int zvhd2_read_with_indexbm(BlockDriverState *bs, int64_t sector_num,
                    uint8_t *buf, int nb_sectors)
{
    BDRVZVHD2State *s = bs->opaque;
    zvhd2_context_t *zvhd2 = s->zvhd2_context_buffer;
    int total_size = nb_sectors << 9;
    int ret = 0;
    uint32_t block_num = sector_num / BLOCK_SIZE_SECTOR;

    uint64_t blk_offset = 0;
    uint32_t blk_disk_size  = 0;
    uint8_t  bm_value = 0;
    
    if(block_num%10240 == 0)
    {
        LOG_DEBUG("will read block %u \n",block_num);
    }

    if(!zvhd2->footer->index_contains_zero_blk)
    {
        ret = __zvhd2_bm_read(bs, block_num, &bm_value,&block_num);
        if(ret)
        {
            LOG_ERROR("error ret=%d, bm read block %u \n",ret,block_num);
            return ret;
        }
        if(!bm_value)  // a zero block
        {
            //LOG_DEBUG("read block %u : %llu,%u\n",begin_block,blk_offset, blk_disk_size);
            zvhd2_clear_data(buf, total_size);
            return 0;
        }
    }

    ret = __zvhd2_index_read(bs, block_num, &blk_offset, &blk_disk_size);
    if(ret)
    {
        LOG_ERROR("error ret=%d, read block %u : %llu,%u\n",ret,block_num,blk_offset, blk_disk_size);
        return ret;
    }

    if (blk_offset == 0 || blk_disk_size == 0)  // a zero block
    {
        //LOG_DEBUG("read block %u : %llu,%u\n",begin_block,blk_offset, blk_disk_size);
        zvhd2_clear_data(buf, total_size);
        return 0;
    }

    ret = bdrv_pread(bs->file, blk_offset, zvhd2->buf, blk_disk_size);
    if (ret < 0) 
    {
        return ret;
    }
    LOG_DEBUG("read block : size=%u, offset=%llu,read_size=%u, block[%u %u]\n",zvhd2->data_buf->size,blk_offset, blk_disk_size,block_num,zvhd2->data_buf->curr_blk);

    if (0 != zvhd2->data_buf->size)
    {
#ifdef USE_FRAME_COMPRESSION
        COMP_CTX_free(zvhd2->ctx);
        zvhd2->ctx = COMP_CTX_new(__get_comp_method_wrapper(zvhd2));
#endif
        //debug_buffer((unsigned char *)zvhd2->buf + sizeof(zvhd2_data_t),zvhd2->data_buf->size, zvhd2->data_buf->curr_blk);
        ret = COMP_expand_block(zvhd2->ctx,(unsigned char *)buf,total_size,(unsigned char *)zvhd2->buf + sizeof(zvhd2_data_t),zvhd2->data_buf->size);
        if (ret < 0)
        {
            ERR_load_COMP_strings();
            LOG_ERROR("expand data failed,ret is %d\n",ret);
            return ret;
        }
        if (ret != total_size)
        {
             LOG_ERROR("expand size is not correct,ret is %d\n",ret);
            return -EIO;
        }
    }
    else
    {
        LOG_ERROR( "data's size is 0 \n");
        return -EIO;
    }

    LOG_DEBUG( "decompress size is %d, block [%u] from [%u] \n", ret,  zvhd2->data_buf->curr_blk, block_num);

/*    if(block_num == zvhd2->data_buf->curr_blk && zvhd2->footer->index_contains_zero_blk)
    {
        zvhd2_clear_data((uint8_t *)zvhd2->buf,zvhd2->curr_buf_size);
        LOG_DEBUG( "decompress size is %d, block [%u] from [%u] \n", ret,  zvhd2->data_buf->curr_blk, block_num);
    }
    else
    {
        memset(zvhd2->buf+sizeof(zvhd2_data_t), 0, (zvhd2->curr_buf_size -sizeof(zvhd2_data_t))?:total_size);
        memcpy(zvhd2->buf+sizeof(zvhd2_data_t), buf, total_size);
        zvhd2_clear_data(buf, total_size);
        zvhd2->curr_buf_size = total_size + sizeof(zvhd2_data_t);
        LOG_DEBUG( "decompress size is %d, block [%u] from [%u] \n", ret,  zvhd2->data_buf->curr_blk, block_num);
    }
   */ 
    return 0;
}

static int zvhd2_open(BlockDriverState *bs, QDict *options, int flags,
                    Error **errp)
{
    BDRVZVHD2State *s = bs->opaque;
    zvhd2_context_t *zvhd2 = NULL;
    int ret = 0;
    
    s->zvhd2_context_buffer = (void *)calloc(1,sizeof(zvhd2_context_t));
    if (NULL == s->zvhd2_context_buffer )
    {
        ret = -1;
        goto fail;
    }

    zvhd2 = s->zvhd2_context_buffer;
    zvhd2->fpos = 0;
    
    ret = posix_memalign((void **)&zvhd2->footer_buf,BLOCK_SIZE,FOOTER_SIZE);
    if (ret != 0)
    {
        FREE(s->zvhd2_context_buffer);
        goto fail;
    }

    ret = bdrv_pread(bs->file, 0, zvhd2->footer_buf, FOOTER_SIZE);
    if(ret == FOOTER_SIZE)
    {
        zvhd2->cur_offset = FOOTER_SIZE;
        zvhd2->footer = (zvhd2_footer_t *)zvhd2->footer_buf;
    }
    
    if(bs->read_only && zvhd2->footer->zvhd2_version && (ret == FOOTER_SIZE))
    {
        int64_t real_file_size =  bdrv_getlength(bs->file);
        ret = bdrv_pread(bs->file, real_file_size-FOOTER_SIZE, zvhd2->footer_buf, FOOTER_SIZE);
        LOG_DEBUG("read index footer ret=%d file_size=%d inde_footer_lba=%llu\n",ret,real_file_size,real_file_size-FOOTER_SIZE);
        LOG_DEBUG("index_contains_zero_blk=%d\n",zvhd2->footer->index_contains_zero_blk);
        LOG_DEBUG("index lba=%d size=%u seg_num=%u seg_size=%u\n",zvhd2->footer->index_lba,zvhd2->footer->index_size,zvhd2->footer->index_seg_num,zvhd2->footer->index_seg_size);
        LOG_DEBUG("bitmap lba=%d size=%u seg_num=%u seg_size=%u\n",zvhd2->footer->bitmap_lba,zvhd2->footer->bitmap_size,zvhd2->footer->bitmap_seg_num,zvhd2->footer->bitmap_seg_size);
    }

    if (ret != FOOTER_SIZE) 
    {
        FREE(zvhd2->footer_buf);
        FREE(s->zvhd2_context_buffer);
        goto fail;
    }    
    
    ret = zvhd2_validate_footer(zvhd2->footer);
    if (ret)
    {
        LOG_ERROR("validate footer failed\n");
        FREE(zvhd2->footer_buf);
        FREE(s->zvhd2_context_buffer);
        
        ret = -1;
        goto fail;
    }

    zvhd2->blk_size = zvhd2->footer->block_size;
    zvhd2->max_blk_num = zvhd2->footer->max_blk_num;

    int cluster_bits = ffs(zvhd2->blk_size) - 1;
    if ((1 << cluster_bits) != zvhd2->blk_size)
    {
        LOG_ERROR( "Cluster size %lu is not a power of two", zvhd2->blk_size);
        ret = -1;
        goto fail;
    }
    else if (cluster_bits < MIN_IMAGE_BLOCK_SHIFT || cluster_bits > MAX_IMAGE_BLOCK_SHIFT)
    {
        LOG_ERROR( "Cluster size must be a power of two between %d MB and %d MB", 
                    1 << (MIN_IMAGE_BLOCK_SHIFT-20), 1 << (MIN_IMAGE_BLOCK_SHIFT - 20));
        ret = -1;
        goto fail;
    }
    LOG_DEBUG("block size  :  %u %d\n", zvhd2->blk_size, cluster_bits);
    if(zvhd2->footer->zvhd2_version > 0)
    {
        LOG_DEBUG( "index info : index_lba=%llu index_size=%u index_contains_zero_blk=%d \n", zvhd2->footer->index_lba, zvhd2->footer->index_size, zvhd2->footer->index_contains_zero_blk);
        LOG_DEBUG( "index info : bitmap_lba=%llu bitmap_size=%u\n", zvhd2->footer->bitmap_lba, zvhd2->footer->bitmap_size);
        LOG_DEBUG( "index info : non_zero_blk_num=%u max_blk_num=%u\n", zvhd2->footer->non_zero_blk_num, zvhd2->footer->max_blk_num);
    }
    
    zvhd2->buf_size = zvhd2->blk_size*2 + (zvhd2->blk_size/1000) + 128;
    zvhd2->buf_size = ROUND_UP(zvhd2->buf_size, BLOCK_SIZE);
    ret = posix_memalign((void **)&zvhd2->buf,BLOCK_SIZE,FOOTER_SIZE+zvhd2->buf_size);
    if (ret != 0)
    {
        FREE(zvhd2->footer_buf);
        FREE(s->zvhd2_context_buffer);
        goto fail;
    }
    memset(zvhd2->buf, 0, FOOTER_SIZE+zvhd2->buf_size);
    
    LOG_DEBUG("size=%llu\n", zvhd2->footer->curr_size);
    bs->total_sectors = (zvhd2->footer->curr_size) >>VHD_SECTOR_SHIFT;
    LOG_DEBUG("sectors=%d\n", bs->total_sectors);

    if(zvhd2->footer->crtr_ver == VHD_VERSION(1,4))
    {
        zvhd2->ver = 1;
    }
    else
    {
        zvhd2->ver = 0;
    }

    LOG_DEBUG("orig_size=%llu\n", zvhd2->footer->orig_size);
    LOG_INFO("compress_method=%u\n", zvhd2->footer->compress_method);
    zvhd2->sectors = zvhd2->footer->orig_size >> 9;
    //bs->total_sectors = zvhd2->sectors;
    LOG_DEBUG("sectors=%d\n", bs->total_sectors);


    ret = __zvhd2_index_initiliaze(&(zvhd2->zvhd2_index), 
                        zvhd2->max_blk_num, zvhd2->blk_size, bs->read_only);
    if( (!ret) && bs->read_only && zvhd2->footer->zvhd2_version > 0)
    {
        ret = __zvhd2_read_initiliaze_bm(bs);
    }
     if (ret != 0)
    {
        FREE(zvhd2->buf);
        FREE(zvhd2->footer_buf);
        FREE(s->zvhd2_context_buffer);
        goto fail;
    }

    


    zvhd2->data_buf = (zvhd2_data_t *)zvhd2->buf;
    zvhd2->ctx = COMP_CTX_new(__get_comp_method_wrapper(zvhd2));
    if (!zvhd2->ctx)
    {
        FREE(zvhd2->buf);
        FREE(zvhd2->footer_buf);
        FREE(s->zvhd2_context_buffer);
        ret = -1;
        goto fail;
    }
    LOG_DEBUG("zlib context size=%lu %lu\n", sizeof(zvhd2->ctx),sizeof(*(void **)zvhd2->ctx));

    ret = posix_memalign((void **)&zvhd2->zero_buf ,BLOCK_SIZE,zvhd2->blk_size);
    if (ret != 0)
    {
        FREE(zvhd2->buf);
        FREE(zvhd2->footer_buf);
        FREE(s->zvhd2_context_buffer);
        goto fail;
    }
    
    memset(zvhd2->zero_buf ,0,zvhd2->blk_size); 

    qemu_co_mutex_init(&s->lock);
    
    return 0;

fail:
//    qemu_vfree(s->pagetable);
//#ifdef CACHE
//    g_free(s->pageentry_u8);
//#endif
    return ret;
}

static void zvhd2_clear_data(uint8_t *buf,int total_size)
{
    memset(buf,0,total_size);
}

static int zvhd2_write_index(BlockDriverState *bs, int64_t sector_num,int nb_sectors)
{
    int ret = 0;
    BDRVZVHD2State *s = bs->opaque;
    zvhd2_context_t *zvhd2 = s->zvhd2_context_buffer;
    zvhd2_index_t *zvhd2_index = &(zvhd2->zvhd2_index);
    
    zvhd2->footer->index_lba = zvhd2->cur_offset;
    zvhd2->footer->index_size = 0;
    zvhd2->footer->index_seg_num = 0;
    zvhd2->footer->index_seg_size = zvhd2_index->index_seg_size;

    uint32_t blk_count = 0;
    uint32_t total_blk_count = zvhd2->footer->non_zero_blk_num;
    if(zvhd2->footer->index_contains_zero_blk)
    {
        total_blk_count = zvhd2->footer->max_blk_num;
    }

    while(blk_count < total_blk_count)
    {
        int index_seg_idx =   blk_count/zvhd2_index->blk_num_per_seg;
        zvhd2_index_store_t * idx_store = __zvhd2_index_get_store(zvhd2_index, index_seg_idx);
        if (NULL == idx_store) 
        {
            return -1;
        }
        
        if(total_blk_count - blk_count > zvhd2_index->blk_num_per_seg)
        {
            ret = bdrv_pwrite_sync(bs->file, zvhd2->cur_offset, idx_store->store_buffer,zvhd2_index->index_seg_size);
            __zvhd2_index_debug(idx_store,zvhd2_index->blk_num_per_seg);
            blk_count +=  zvhd2_index->blk_num_per_seg;
        }
        else
        {
            ret = bdrv_pwrite_sync(bs->file, zvhd2->cur_offset, idx_store->store_buffer,zvhd2_index->index_seg_size);
            __zvhd2_index_debug(idx_store,total_blk_count - blk_count);
            blk_count =  total_blk_count;
        }
        
        if (ret < 0) 
        {
            return -1;
        }
        
        zvhd2->footer->index_size += zvhd2_index->index_seg_size;
        zvhd2->footer->index_seg_num++;

        zvhd2->cur_offset = zvhd2->cur_offset + zvhd2_index->index_seg_size;
        
    }

    LOG_DEBUG("done write index lba=%llu size=%u nonzero_num=%u \n", zvhd2->footer->index_lba, zvhd2->footer->index_size,
                    zvhd2->footer->non_zero_blk_num);
    return ret;
}

static int zvhd2_write_bitmap(BlockDriverState *bs, int64_t sector_num,int nb_sectors)
{
    int ret = 0;
    BDRVZVHD2State *s = bs->opaque;
    zvhd2_context_t *zvhd2 = s->zvhd2_context_buffer;
    zvhd2_index_t *zvhd2_index = &(zvhd2->zvhd2_index);

    zvhd2->footer->bitmap_lba = zvhd2->cur_offset;
    zvhd2->footer->bitmap_seg_size = zvhd2_index->bm_seg_size;
    zvhd2->footer->bitmap_size = 0;
    zvhd2->footer->bitmap_seg_num = 0;

    uint32_t i = 0;  
    zvhd2_index_store_t * bm_store = __zvhd2_bm_get_store(zvhd2_index, 0);
    if (NULL == bm_store) 
    {
        return -1;
    }    

    uint32_t total_blk_count = zvhd2->footer->max_blk_num;
    uint32_t  blk_num = 0;
    uint32_t blk_count = 0;

    uint64_t  blk_offset = 0;
    uint32_t  blk_disk_size = 0;

    if(!zvhd2->footer->index_contains_zero_blk)
    {
        total_blk_count = zvhd2->footer->non_zero_blk_num;
    }

    for(i=0; i<zvhd2_index->max_segs_num; i++)
    {
        memset(bm_store->store_buffer, 0, zvhd2_index->bm_seg_size);
        while(blk_count < total_blk_count )
        {
            // find non zero blocks
            if(blk_offset <= 0)
            {
                ret = __zvhd2_index_get(zvhd2_index, blk_count, &blk_offset, &blk_num,&blk_disk_size);
                if(ret)
                {
                    return -1;
                }
            }

            // check whether it is in segment i
            if(blk_num >= (i+1)*zvhd2_index->blk_num_per_seg )
            {
                break;
            }
            else if(blk_offset > 0) //none zero block
            {
                LOG_DEBUG(" blk_count=%u, real_blk_num=%u lba(%llu,%u) \n",blk_count, blk_num,blk_offset,blk_disk_size);
                __zvhd2_bm_set(zvhd2_index, bm_store, blk_num);
                blk_offset = 0;
                blk_disk_size = 0;
                blk_count++;                
            }
            else
            {
                blk_count++;
            }
         }

        // write bitmap segment i        
        ret = bdrv_pwrite_sync(bs->file, zvhd2->cur_offset, bm_store->store_buffer,zvhd2_index->bm_seg_size);
        if (ret < 0) 
        {
            LOG_ERROR("write segment %d failed, at %llu size %u, ret=%d \n", i, zvhd2->cur_offset, zvhd2_index->bm_seg_size,ret);
            return -1;
        }
        
        bm_store->non_zero_blk_count = __count_and_find_non_zero(bm_store->store_buffer, 0, zvhd2_index->bm_seg_size*BLOCKS_PER_BYPE,
                                &bm_store->non_zero_first, &bm_store->non_zero_last);
        LOG_DEBUG("doing write bitmap seg %d : lba (%llu,%u) base_blk %u count (%u,%d,%d)\n",zvhd2->footer->bitmap_seg_num, zvhd2->cur_offset, zvhd2_index->bm_seg_size, bm_store->non_zero_blk_base,
                bm_store->non_zero_blk_count,bm_store->non_zero_first,bm_store->non_zero_last);


        zvhd2->footer->bitmap_size += zvhd2_index->bm_seg_size;
        zvhd2->footer->bitmap_seg_num ++;
        LOG_DEBUG("doing write bitmap lba=%llu size=%u (%u)  [%u, %u)\n", zvhd2->footer->bitmap_lba, zvhd2_index->bm_seg_size,
                zvhd2->footer->bitmap_size,(i)*zvhd2_index->blk_num_per_seg,(i+1)*zvhd2_index->blk_num_per_seg);
        
        zvhd2->cur_offset = zvhd2->cur_offset + zvhd2_index->bm_seg_size;
        LOG_DEBUG("doing total_blk_count=%u blk_count=%u \n", total_blk_count,blk_count  );


    }

    LOG_DEBUG("done write bitmap lba=%llu size=%u nz_num=%u  blk_num_per_seg=%u seg_num=%u\n", zvhd2->footer->bitmap_lba, zvhd2->footer->bitmap_size,
                    zvhd2->footer->non_zero_blk_num,zvhd2_index->blk_num_per_seg,zvhd2->footer->bitmap_seg_num);
    return ret;
}

static int zvhd2_write_index_footer(BlockDriverState *bs)
{
    int ret = 0;
    BDRVZVHD2State *s = bs->opaque;
    zvhd2_context_t *zvhd2 = s->zvhd2_context_buffer;

    zvhd2->footer->checksum = 0;
    zvhd2->footer->checksum = pvhd_checksum_footer(zvhd2->footer);
    ret = bdrv_pwrite_sync(bs->file, zvhd2->cur_offset, zvhd2->footer_buf,FOOTER_SIZE);
    if (ret < 0) 
    {
         return -1;
    }
    
    LOG_DEBUG("done file size :  %llu %llu \n", zvhd2->cur_offset, zvhd2->cur_offset+FOOTER_SIZE);
    zvhd2->cur_offset = zvhd2->cur_offset + FOOTER_SIZE;

    return ret;
}

static int zvhd2_write(BlockDriverState *bs, int64_t sector_num,
    const uint8_t *buf, int nb_sectors)
{
    BDRVZVHD2State *s = bs->opaque;
    zvhd2_context_t *zvhd2 = s->zvhd2_context_buffer;
    int total_size = nb_sectors << 9;
    int ret = 0;
    int postfix_offset = 0;
    uint32_t cur_blk = 0;

    //int begin_index = (sector_num % BLOCK_SIZE_SECTOR) << 9;
    int begin_block = sector_num / BLOCK_SIZE_SECTOR;
    memcpy(zvhd2->zero_buf,buf,total_size);
    
    if(begin_block%10240 == 0)
    {
        LOG_DEBUG("write sector %llu, sectors %d,  block %d, \n", sector_num, nb_sectors, begin_block);
    }
    memcpy(zvhd2->data_buf->prefix,ZVHD2_DATA_PREFIX,ZVHD2_DATA_PREFIX_LEN - 1);
    //zero will not come here
    if (is_not_zero((uint8_t *)buf,total_size))
    {
#ifdef USE_FRAME_COMPRESSION
        COMP_CTX_free(zvhd2->ctx);
        zvhd2->ctx = COMP_CTX_new(__get_comp_method_wrapper(zvhd2));
#endif
        ret = COMP_compress_block(zvhd2->ctx,(unsigned char *)zvhd2->buf+FOOTER_SIZE,zvhd2->buf_size,(unsigned char *)zvhd2->zero_buf,zvhd2->blk_size);
        if (ret < 0)
        {
            ERR_load_COMP_strings();
            return -1;
        }

        if (ret >= zvhd2->buf_size)
        {
            LOG_ERROR( "Out of buffer size : %d >= %d src_size=%d\n", ret, zvhd2->buf_size,zvhd2->blk_size );
            return -ENOMEM;
        }
        else
        {
            zvhd2->data_buf->size = ret;
            zvhd2->data_buf->curr_blk = begin_block;
            memmove(zvhd2->buf+sizeof(zvhd2_data_t),zvhd2->buf+FOOTER_SIZE,ret);
        }     

        zvhd2->curr_buf_size = (sizeof(zvhd2_data_t) + zvhd2->data_buf->size + ZVHD2_DATA_POSTFIX_LEN + BLOCK_SIZE_SECTOR - 1) / BLOCK_SIZE_SECTOR * BLOCK_SIZE_SECTOR;
        postfix_offset = zvhd2->curr_buf_size - ZVHD2_DATA_POSTFIX_LEN;
        memcpy(zvhd2->buf + postfix_offset,ZVHD2_DATA_POSTFIX,ZVHD2_DATA_POSTFIX_LEN);

        ret = bdrv_pwrite_sync(bs->file, zvhd2->cur_offset, zvhd2->buf,zvhd2->curr_buf_size);
        if (ret < 0) {
            LOG_ERROR("compress size is %d, write offset %llu, size %d, block[%u] \n",zvhd2->data_buf->size, zvhd2->cur_offset, zvhd2->curr_buf_size, zvhd2->data_buf->curr_blk);
            return -1;
        }
        LOG_DEBUG("compress size is %d, write offset %llu, size %d,  real_blk_no[%u], no[%u]  \n",zvhd2->data_buf->size, zvhd2->cur_offset, zvhd2->curr_buf_size, zvhd2->data_buf->curr_blk,zvhd2->footer->non_zero_blk_num);

        if(zvhd2->footer->index_contains_zero_blk)
        {
            cur_blk = zvhd2->data_buf->curr_blk;
        }
        else
        {
            cur_blk = zvhd2->footer->non_zero_blk_num;
        }

        ret = __zvhd2_index_set(&(zvhd2->zvhd2_index), cur_blk,
                    zvhd2->cur_offset, zvhd2->data_buf->curr_blk, zvhd2->curr_buf_size);
        if (ret) {
            LOG_ERROR("record index info failed: offset %llu, size %d, block[%u] \n", zvhd2->cur_offset, zvhd2->curr_buf_size, zvhd2->data_buf->curr_blk);
            return -1;
        }

        zvhd2->footer->non_zero_blk_num += 1;
        
        zvhd2->cur_offset = zvhd2->cur_offset + zvhd2->curr_buf_size;
        
        zvhd2_clear_data((uint8_t *)zvhd2->buf,zvhd2->curr_buf_size);
        zvhd2_clear_data((uint8_t *)zvhd2->zero_buf,zvhd2->blk_size);
        
    }

    //when write end,rewrite the footer
    if ((sector_num + nb_sectors) >= zvhd2->sectors)
    {
        ret = bdrv_pwrite_sync(bs->file, zvhd2->cur_offset, zvhd2->footer_buf,FOOTER_SIZE);
         if (ret < 0) {
             return -1;
         }
        zvhd2->cur_offset = zvhd2->cur_offset + FOOTER_SIZE;

        ret = zvhd2_write_index(bs,sector_num,nb_sectors);
        if(ret)
        {
            LOG_ERROR("write index info failed ret=%d\n", ret);
            return ret;
        }
        ret = zvhd2_write_bitmap(bs,sector_num,nb_sectors);
        if(ret)
        {
            LOG_ERROR("write bitmap info failed ret=%d\n", ret);
            return ret;
        }

        ret = zvhd2_write_index_footer(bs);
        if(ret)
        {
            LOG_ERROR("write index footer failed ret=%d\n", ret);
            return ret;
        }
    
        

     }
    
    return 0;
}

static coroutine_fn int zvhd2_co_write(BlockDriverState *bs, int64_t sector_num,
                                     const uint8_t *buf, int nb_sectors)
{
    int ret;
    BDRVZVHD2State *s = bs->opaque;
    qemu_co_mutex_lock(&s->lock);
    ret = zvhd2_write(bs, sector_num, buf, nb_sectors);
    qemu_co_mutex_unlock(&s->lock);
    return ret;
}

static void zvhd2initializefooter(zvhd2_context_t *ctx, int type, uint64_t size, uint64 block_size)
{
    memset(ctx->footer, 0, sizeof(zvhd2_footer_t));
    memcpy(ctx->footer->cookie, ZVHD2_COOKIE, strlen(ZVHD2_COOKIE));
    ctx->footer->features     = HD_RESERVED;
    ctx->footer->ff_version   = HD_FF_VERSION;
    ctx->footer->timestamp    = pvhd_time(time(NULL));
    ctx->footer->crtr_ver     = VHD_VERSION(1,4);  //zvhd2 new version, old version is VHD_VERSION(1,3)
    ctx->footer->crtr_os      = 0x00000000;
    ctx->footer->orig_size    = size;
    ctx->footer->curr_size    = (size + BLOCK_G_SIZE -1)/BLOCK_G_SIZE*BLOCK_G_SIZE;
    ctx->footer->geometry     = pvhd_chs(size);
    ctx->footer->type         = type;
    ctx->footer->saved        = 0;
    ctx->footer->data_offset  = 0xFFFFFFFFFFFFFFFFULL;
#if COULD_BE_READ_AS_ZVHD_
    ctx->footer->zvhd2_version = 0;
#else
    ctx->footer->zvhd2_version = 1;
#endif    
    
    ctx->footer->block_size = block_size;
    ctx->footer->max_blk_num = (size+block_size-1)/block_size;

    ctx->footer->index_lba = 0;
    ctx->footer->bitmap_lba = 0;
    ctx->footer->index_size = 0;
    ctx->footer->bitmap_size = 0;
    
    ctx->footer->index_seg_size = 0;
    ctx->footer->bitmap_seg_size = 0;
    ctx->footer->index_seg_num = 0;
    ctx->footer->bitmap_seg_num = 0;

    ctx->footer->non_zero_blk_num = 0;
    ctx->footer->index_contains_zero_blk = INDEX_ZERO_BLK;

    ctx->footer->compress_method = DEFAULT_COMPRESS_METHOD;
    
    strncpy(ctx->footer->crtr_app, "tap",sizeof(ctx->footer->crtr_app) - 1);
    uuid_generate(ctx->footer->uuid);
    ctx->footer->checksum = pvhd_checksum_footer(ctx->footer);
}


static int zvhd2_create(const char *filename, QemuOpts *opts, Error **errp)
{
    int64_t total_size;
    int ret = -EIO;
    Error *local_err = NULL;
    BlockDriverState *bs = NULL;
    size_t block_size = IMAGE_BLOCK_SIZE;
    int cluster_bits;
    

    zvhd2_context_t zvhd2_cxt;

    total_size = ROUND_UP(qemu_opt_get_size_del(opts, BLOCK_OPT_SIZE, 0),BDRV_SECTOR_SIZE);
    //block_size = qemu_opt_get_size_del(opts,BLOCK_OPT_CLUSTER_SIZE, block_size);
    cluster_bits = ffs(block_size) - 1;
    LOG_DEBUG( "block size setting :  %lu %d\n", block_size, cluster_bits);
    if ((1 << cluster_bits) != block_size)
    {
        error_setg(errp, "Cluster size %lu is not a power of two", block_size);
        return -EINVAL;
    }
    else if (cluster_bits < MIN_IMAGE_BLOCK_SHIFT || cluster_bits > MAX_IMAGE_BLOCK_SHIFT)
    {
        error_setg(errp, "Cluster size must be a power of two between %d MB and %d MB", 
                    1 << (MIN_IMAGE_BLOCK_SHIFT-20), 1 << (MIN_IMAGE_BLOCK_SHIFT - 20));
        return -EINVAL;
    }
    block_size = IMAGE_BLOCK_SIZE;

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

    ret = posix_memalign((void **)&zvhd2_cxt.footer_buf,FOOTER_SIZE,FOOTER_SIZE);
    if (ret){
        goto out;
    }
    zvhd2_cxt.footer = (zvhd2_footer_t *)zvhd2_cxt.footer_buf;
    zvhd2initializefooter(&zvhd2_cxt,4,total_size,block_size);

    ret = bdrv_pwrite_sync(bs, 0, zvhd2_cxt.footer_buf, FOOTER_SIZE);
    
    FREE(zvhd2_cxt.footer_buf);
    
out:
    bdrv_unref(bs);
    return ret;
}

static int zvhd2_has_zero_init(BlockDriverState *bs)
{
    //BDRVZVHD2State *s = bs->opaque;

    return 0;
}

static void zvhd2_close(BlockDriverState *bs)
{
    BDRVZVHD2State *s = bs->opaque;
    zvhd2_context_t *zvhd2 = s->zvhd2_context_buffer;
    __zvhd2_index_finalize(&(zvhd2->zvhd2_index));
    COMP_CTX_free(zvhd2->ctx);
    FREE(zvhd2->zero_buf);
    FREE(zvhd2->footer_buf);
    FREE(zvhd2->buf);
    FREE(zvhd2);
}

static int zvhd2_get_info(BlockDriverState *bs, BlockDriverInfo *bdi)
{
    BDRVZVHD2State *s = bs->opaque;
    zvhd2_context_t *zvhd2 = s->zvhd2_context_buffer;

    //bdi->unallocated_blocks_are_zero = true;
    
    bdi->cluster_size = zvhd2->blk_size;
    return 1;
}

static QemuOptsList zvhd2_create_opts = {
    .name = "zvhd2-create-opts",
    .head = QTAILQ_HEAD_INITIALIZER(zvhd2_create_opts.head),
    .desc = {
        {
            .name = BLOCK_OPT_SIZE,
            .type = QEMU_OPT_SIZE,
            .help = "Virtual disk size"
        },
        { /* end of list */ }
    }
};

static int zvhd2_probe(const uint8_t *buf, int buf_size, const char *filename)
{
    if (buf_size >= ZVHD2_COOKIE_LEN && !strncmp((char *)buf, ZVHD2_COOKIE, ZVHD2_COOKIE_LEN - 1))
    {
        return 100;
    }
    return 0;
}

static BlockDriver bdrv_zvhd2= {
    .format_name       = "zvhd2",
    .instance_size       = sizeof(BDRVZVHD2State),
    .bdrv_probe             = zvhd2_probe,
    .bdrv_read            = zvhd2_co_read,
    .bdrv_open              = zvhd2_open,
    .bdrv_close             = zvhd2_close,
    .bdrv_create            = zvhd2_create,
    .bdrv_write                 = zvhd2_co_write,
    .bdrv_get_info          = zvhd2_get_info,
    .bdrv_has_zero_init     = zvhd2_has_zero_init,
    .create_opts            = &zvhd2_create_opts,
};

static void bdrv_zvhd2_init(void)
{
    bdrv_register(&bdrv_zvhd2);
}

block_init(bdrv_zvhd2_init);
