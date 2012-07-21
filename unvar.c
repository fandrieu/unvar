/*
 * Copyright (C) 2009-2012 fand
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

/*
 * .var backup archive decompressor using QuickLZ 1.4.x
 */

// Remember to define QLZ_COMPRESSION_LEVEL and QLZ_STREAMING_MODE to the same values for the compressor and decompressor
// ...guessed values for var files:
#define QLZ_COMPRESSION_LEVEL 2
#define QLZ_STREAMING_BUFFER 0

// no checksum support, better be safe..
#define QLZ_MEMORY_SAFE

#include <stdio.h>
#include <stdlib.h>

#include "quicklz.h"

//#if QLZ_STREAMING_BUFFER == 0
//    #error Define QLZ_STREAMING_BUFFER to a non-zero value for this demo
//#endif

static const char *progname = NULL;
static unsigned long long total_in = 0;
static unsigned long long total_out = 0;
static int opt_debug = 0;
static int opt_writezero = 0;

/* magic file header for .var files */
static const unsigned char magic[8] =
    { 0x2d, 0x5e, 0x70, 0x3c, 0x99, 0x72, 0x6a, 0xb8 };


/*************************************************************************
// file IO
**************************************************************************/

unsigned int xread(FILE *fp, void *buf, size_t len, int allow_eof)
{
    unsigned int l;

    l = fread(buf, 1, len, fp);
    if (l > len)
    {
        fprintf(stderr, "\nsomething's wrong with your C library !!!\n");
        exit(1);
    }
    if (l != len && !allow_eof)
    {
        fprintf(stderr, "\nread error - premature end of file\n");
        exit(1);
    }
    total_in += (unsigned long long) l;
    return l;
}


unsigned int xwrite(FILE *fp, void *buf, size_t len)
{
    if (fp != NULL && fwrite(buf, len, 1, fp) != 1)
    {
        fprintf(stderr, "\nwrite error  (disk full ?)\n");
        exit(1);
    }
    total_out += (unsigned long long) len;
    return len;
}

int xgetc(FILE *fp)
{
    unsigned char c;
    xread(fp, &c, 1, 0);
    return c;
}

/* read little endian 32-bit integers */

unsigned long xread32(FILE *fp)
{
    unsigned char b[4];
    unsigned long v;

    xread(fp, b, 4, 0);
    //v  = (unsigned long) b;
    v  = (unsigned long) b[0] <<  0;
    v |= (unsigned long) b[1] <<  8;
    v |= (unsigned long) b[2] << 16;
    v |= (unsigned long) b[3] << 24;
    return v;
}

/* read little endian 64-bit integers */

unsigned long long xread64(FILE *fp)
{
    unsigned char b[8];
    unsigned long long v;

    xread(fp, b, 8, 0);
    //v  = (unsigned long) b;
    v  = (unsigned long long) b[0] <<  0;
    v |= (unsigned long long) b[1] <<  8;
    v |= (unsigned long long) b[2] << 16;
    v |= (unsigned long long) b[3] << 24;
    v |= (unsigned long long) b[4] << 32;
    v |= (unsigned long long) b[5] << 40;
    v |= (unsigned long long) b[6] << 48;
    v |= (unsigned long long) b[7] << 56;
    return v;
}


/* skip some bytes */
unsigned int xskip(FILE *fp, unsigned long long len)
{
    total_in += (unsigned long long) len;
    return fseeko64(fp, len, SEEK_CUR);
}
unsigned int xskipout(FILE *fo, unsigned long long len)
{
    total_out += (unsigned long long) len;
    if (fo == NULL)
        return 1;
    return fseeko64(fo, len, SEEK_CUR);
}

/* write zero blocks */
int xwrite_empty_blocks(FILE *fo, unsigned long block_size, unsigned long num, char *buf)
{
    if (opt_writezero)
    {
        unsigned long i;
        //normal: write all zeroes
        memset(buf, 0, block_size);
        for (i=0; i<num; i++)
        {
            xwrite(fo, buf, block_size);
        }
    }
    else
    {
        //sparse: skip n-1 bytes and write 0 to the last one
        unsigned long long total = (unsigned long long) block_size * num - 1;
        if (opt_debug>0)
            printf("@%llu skipping %lu blocks = %llu bytes\n", fo==NULL?0:ftello64(fo), num, total);
        char last = 0;
        xskipout(fo, total);
        xwrite(fo, &last, 1);
    }
    return 1;
}

/*************************************************************************
// compress / test
//
// basic test: compress a file in random length blocks
**************************************************************************/

int tst_comp(FILE *ifile, FILE *ofile, int opt_verbose)
{
    char *file_data, *compressed, *scratch;
    size_t d, c;
    unsigned int len;

    // allocate source buffer
    fseek(ifile, 0, SEEK_END);
    len = ftell(ifile);
    fseek(ifile, 0, SEEK_SET);

    file_data = (char*) malloc(len);

    // allocate "uncompressed size" + 400 bytes for the destination buffer where 
    // "uncompressed size" = 10000 in worst case in this sample demo
    compressed = (char*) malloc(len + 400); 

    // allocate and initially zero out the scratch buffer. After this, make sure it is
    // preserved across calls and never modified manually
    scratch = (char*) malloc(QLZ_SCRATCH_COMPRESS);
    memset(scratch, 0, QLZ_SCRATCH_COMPRESS); 

    // test: compress the file in random sized packets
    //while((d = fread(file_data, 1, rand() % len + 1, ifile)) != 0)
    
    // compress fixed sized packets
    while((d = fread(file_data, 1, len, ifile)) != 0)
    {
        c = qlz_compress(file_data, compressed, d, scratch);
        printf("%u bytes compressed into %u\n", (unsigned int)d, (unsigned int)c);

        // the buffer "compressed" now contains c bytes which we could have sent directly to a 
        // decompressing site for decompression
        fwrite(compressed, c, 1, ofile);
    }
    return 0;
}

/*************************************************************************
// decompress / test
//
// basic test: decompress one raw block from a file
**************************************************************************/

int tst_decomp(FILE *ifile, FILE *ofile, int opt_verbose)
{
    char *src, *dst, *scratch;
    unsigned int len;
    unsigned int l;

    // allocate source buffer
    fseek(ifile, 0, SEEK_END);
    len = ftell(ifile);
    fseek(ifile, 0, SEEK_SET);
    src = (char*) malloc(len);

    // read file and allocate destination buffer
    l = fread(src, 1, len, ifile);
    len = qlz_size_decompressed(src);
    if (opt_verbose)
        printf("%s: uncomp block len: %d\n", progname, len);
    dst = (char*) malloc(len);

    // QLZ_SCRATCH_DECOMPRESS is defined in the beginning of the quicklz.h file
    scratch = (char*) malloc(QLZ_SCRATCH_DECOMPRESS);

    // decompress and write result
    len = qlz_decompress(src, dst, scratch);
    if (opt_verbose)
        printf("%s: decompd len: %d\n", progname, len);
    fwrite(dst, len, 1, ofile);
    return 0;
}

/*************************************************************************
// decompress / var
**************************************************************************/

//debug
int str_to_hexstr(char *str, char *newstr)
{
    unsigned int tr = 0;
    char *cpold = str;
    char *cpnew = newstr; 
    //while(tr<strlen(str)) {
    while(tr<16) {
        sprintf(cpnew, "%02x", (unsigned char)(*cpold++));
        cpnew+=2;
        tr++;
    }
    *(cpnew) = '\0';
    return 1;
}


/*
    VAR file header
*/
typedef struct {
    unsigned int version_1;
    unsigned int version_2;
    unsigned int len;
    unsigned long flags;
    unsigned long long size;
    unsigned long block_size;
    char uuid [ 16 ];
    char chk [ 16 ];
    unsigned long tr1;
    unsigned long tr2;
} var_header;


int var_read_header(FILE *fi, var_header *header)
{
    //read header
    header->version_1 = xread32(fi);
    header->flags = xread32(fi);
    header->version_2 = xread32(fi);
    header->len = xread32(fi);
    //skip to uuid = 32 x 2
    xskip(fi, 8);
    //read UUID
    xread(fi, header->uuid, 16, 1);
    //empty?
    xskip(fi, 16);
    
    //skip text header, to first block
    xskip(fi, header->len);
    //TODO: parse text header, at least file_size / block_size
    header->size = 0;    
    header->block_size = 0x40000;
    return 1;
}

int var_read_footer_start(FILE *fi, var_header *header)
{
    //read footer start
    
    //skip empty
    xskip(fi, 8);
    
    //read those
    header->tr1 = xread32(fi);
    header->tr2 = xread32(fi);
    
    //skip empty
    xskip(fi, 8);

    //read chk
    xread(fi, header->chk, 16, 1);

    //skip to first map entry
    xskip(fi, 0x48);
    
    return 1;
}


int var_read_footer_end(FILE *fi)
{
    //read footer end
    int i;
    char chk [ 16 ];
    char file_chk_str [ 33 ];
    unsigned long tmp1;
    unsigned long tmp2;
    unsigned long tmp3;
    
    for (i = 0; i<4; i++) {
		//read chk
		xread(fi, chk, 16, 1);

		//skip empty
		xskip(fi, 16*3);
		
		//debug...
        str_to_hexstr(chk, file_chk_str);
        printf("%s: footer chk %d: %s\n", progname, i, file_chk_str);
	}
	
    //read those
    tmp1 = xread32(fi);
    tmp2 = xread32(fi); //64....
    tmp3 = xread32(fi);
	
	//debug...
	printf("%s: footer info %lu / %lu / %lu\n",
		progname, tmp1, tmp2, tmp3);
    
    //should be the end of file...
    
    return 1;
}


/*
    VAR block header
*/
typedef struct {
    unsigned long num;
    unsigned long in_len;
    unsigned long out_len;
    unsigned long method;
    char chk [16];
    unsigned long long pos;
} var_block_header;

int var_read_block_header(FILE *fi, var_block_header *header)
{
    // read block number
    header->num = xread32(fi);
    //TOFIX: 64 bit num ??
    xread32(fi);
    
    // read compressed size
    header->in_len = xread32(fi);

    // read uncompressed size
    header->out_len = xread32(fi);
    // empty / 64 ?
    xread32(fi);
    
    // read block method ?
    header->method = xread32(fi);
    
    // read block chk
    xread(fi, header->chk, 16, 1);
    
    // empty
    xskip(fi, 56);
    
    // read block pos
    header->pos = xread64(fi);

    //TOFIX: use block_pos ?
    xskip(fi, 8);
    
    return 1;
}


/*
    QLZ block header
*/
typedef struct {
    char type;    
    unsigned long in_len;
    unsigned long out_len;
} qlz_block_header;

int var_read_qlz_block_header(FILE *fi, qlz_block_header *header)
{
    // read the QLZ block marker
    // it's 4b (& 4a for uncompressed) with QLZ_COMPRESSION_LEVEL 2
    header->type = xgetc(fi);

    // read qlz block uncompressed & compressed size
    header->in_len = xread32(fi);
    header->out_len = xread32(fi);
    return 1;
}



/*
    VAR file decompress
*/
int var_decompress(FILE *fi, FILE *fo, int verbose)
{
    int r = 0;
    char *in_buf = NULL;
    char *out_buf = NULL;
    char *scratch = NULL;
    unsigned char m [ sizeof(magic) ];
    unsigned int block_size;
    unsigned long checksum;
    
    //VAR ext
    var_header file;    
    char file_chk_str [ 33 ];

    //VAR ext block
    var_block_header block;
    qlz_block_header qlz_block;
    unsigned long new_len;
    unsigned long block_next_num;
    unsigned long block_count;
    unsigned long block_empty;
    unsigned long long block_real_pos;
    unsigned long block_last_nonzero;
    
    total_in = total_out = 0;
    block_count = block_empty = 0;
    block_next_num = block_last_nonzero = 0;

/*
 * Step 1: check magic header, read flags & block size, init checksum
 */
    if (xread(fi, m, sizeof(magic),1) != sizeof(magic) ||
        memcmp(m, magic, sizeof(magic)) != 0)
    {
        printf("%s: header error - this file is not a .var\n", progname);
        r = 1;
        goto err;
    }
    //read header
    var_read_header(fi, &file);
    block_size = file.block_size;

    if (block_size < 1024 || block_size > 8*1024*1024L)
    {
        printf("%s: header error - invalid block size %u\n",
                progname, block_size);
        r = 3;
        goto err;
    }
    if (verbose > 0)
        printf("%s: block size %u\n",
                progname, block_size);
    
    //header debug
    if (verbose > 0)
    {
        str_to_hexstr(file.uuid, file_chk_str);
        printf("%s: version_1 %u, version_2 %u, header_len %u, header_end x%llx\n\tfile_flags %lx, file_uuid %s\n",
                progname, file.version_1, file.version_2, file.len, ftello64(fi), file.flags, file_chk_str);
    }

    //init checksum
    //TODO: VAR checksums...md5 ?
    checksum = 0;
    //checksum = adler((unsigned char *)src[thread_id], QLZ_SIZE_COMPRESSED(src[thread_id]), 0x00010000);

/*
 * Step 2: allocate buffer for in-place decompression
 */
    // QLZ uses one input & one ouput buffer + a scratch one
    // The decompressed length can be obtained with "qlz_size_decompressed(src)"
    // but we use the fixed block size and reuse the same buffers for all blocks
    //out_len = qlz_size_decompressed(in);    
    if (opt_debug > 0)
        printf("%s: allocate 2 x %d\n", progname, block_size);
    in_buf = (char*) malloc(block_size);
    out_buf = (char*) malloc(block_size);
    scratch = (char*) malloc(QLZ_SCRATCH_DECOMPRESS);
    if (in_buf == NULL || out_buf == NULL || scratch == NULL)
    {
        printf("%s: out of memory\n", progname);
        r = 4;
        goto err;
    }
    
/*
 * Step 3: process blocks
 */
    for (;;)
    {
        
        /*
            Parse the VAR block header
        */

        block_real_pos = ftello64(fi);
        
        var_read_block_header(fi, &block);

        //NOTE: files can have no data blocks at all (all zero disk...)
        //if (block_next_num > 0 && block.num == 0) {
		if (block.in_len == 0) {
            // file end
            if (verbose > 0)
                printf("%s: last block at %llx\n",\
                    progname, block_real_pos);
            
            break;
        }
        
        // block header debug
        if (opt_debug > 0) {
            str_to_hexstr(block.chk, file_chk_str);
            printf("%s: reading block\t%lu, pos\t%llu\tin/out: %lu/%lu\ncheck: %s\n",\
                progname, block.num, ftello64(fi), block.in_len, block.out_len, file_chk_str);
        }

        if (block.num != block_next_num)
        {
            if (block.num < block_next_num)
            {
                printf("%s: block number error - expected >= %lu / got %lu (x%llx)\n",\
                    progname, block_next_num, block.num, block_real_pos);
                r = 5;
                goto err;
            }
            // bloc_num >  block_next_num actually means empty blocks...
            block_next_num = block.num - block_next_num;
            if (opt_debug > 0)
                printf("%s: writing %ld empty blocks\n", progname, block_next_num);
            
            xwrite_empty_blocks(fo, block_size, block_next_num, out_buf);
            
            //record empty blocks + reset next_num
            block_empty += block_next_num;
            block_next_num = block.num;
        }
        block_next_num += 1;
        
        // sanity check of the size values
        if (block.in_len-9 > block_size || block.out_len > block_size ||
            block.in_len == 0 || block.in_len-9 > block.out_len)
        {
            printf("%s: block size error - data corrupted\n", progname);
            printf("%s: len in / out:  %lu /  %lu\n",
                    progname, block.in_len, block.out_len);
            r = 6;
            goto err;
        }

        //check block pos
        //NOTE: this this doesn't seem to be the set in v5 files...
        if (block.pos && block.pos != block_real_pos)
        {
            printf("%s: block position error - expected %llu / got %llu\n",\
                progname, block_real_pos, block.pos);
            r = 7;
            goto err;
        }

        
        /*
            Parse the QLZ header
            actually we don't need to (it's part of a standard QLZ block),
            it's just for additionale checks,
            but we need to rewind after that...
        */
        
        var_read_qlz_block_header(fi, &qlz_block);
        if (qlz_block.type != 0x4b && qlz_block.type != 0x4a)
        {
            printf("%s: block flag error - expected 4b/4a / got %x\n",\
                progname, (int)qlz_block.type);
            r = 8;
            goto err;
        }

        // read qlz block uncompressed & compressed size
        // it should be the same as in the VAR header
        if (qlz_block.out_len != block.out_len || qlz_block.in_len != block.in_len)
        {
            printf("%s: block qlz len error - in %lu/%lu, out %lu/%lu\n",\
                progname, block.in_len, qlz_block.in_len, block.out_len, qlz_block.out_len);
            r = 9;
            goto err;
        }

        /*
            Read & decompress the QLZ block
        */
        block_count++;
        
/*
//Debug: dump block cheksum
str_to_hexstr(block_chk, file_chk_str);
printf("%s: block check: %s\n", progname, file_chk_str);
*/

        // rewind at the begining of the QLZ block / header
        // 1 x QLZ marker + 4 x comp size + 4 x uncomp size
        xskip(fi, -9);
        //debug
        if (opt_debug > 0)
            printf("QLZ block start x%llx\n", ftello64(fi));
        
        if (opt_debug > 1)
        {
            // skip the block
            xskip(fi, block.in_len);
        }
        else
        {

            // read the compressed block in "in_buf"
            xread(fi, in_buf, block.in_len, 0);
            
            //TODO: compressed cheksum ??
            //checksum = adler(checksum, out, block.out_len);
            //printf("chk adlr %p\n", checksum);
            
            //real decompress

            // debug
            //xwrite(fo, in, block.in_len);
            
            //todo: clean scratch buffer (if QLZ_STREAMING_BUFFER > 0)
            //memset(scratch_buf, 0, QLZ_SCRATCH_DECOMPRESS);

            // decompress
            //NOTE: define QLZ_MEMORY_SAFE to get checks...
            new_len = qlz_decompress(in_buf, out_buf, scratch);

            if (opt_debug > 0)
                printf("%s: decomp len: %lu / %lu\n", progname, new_len, block.out_len);

            if (new_len != block.out_len)
            {
                printf("%s: compressed data violation\n", progname);
                r = 10;
                goto err;
            }
            
            // write decompressed block
            xwrite(fo, out_buf, block.out_len);
            
            // update checksum
            //if (flags & 1)
            //	checksum = qlz_adler32(checksum, out, block.out_len);
        }

        if (opt_debug > 0)
            printf("QLZ block end x%llx\n", ftello64(fi));

        //debug
        if (opt_debug > 1)
        {
            if(block_next_num>1)
            {
                printf("bail, pos x%llx\n", ftello64(fi));
                goto err;
            }
        }
        
    }

/*
 * Step 4: process footer
 */

    /*
    // read and verify checksum
    if (flags & 1)
    {
        unsigned long c = xread32(fi);
        if (c != checksum)
        {
            printf("%s: checksum error - data corrupted\n", progname);
            r = 10;
            goto err;
        }
    }
    */
    
    //read footer start
    var_read_footer_start(fi, &file);

    //footer debug
    if (verbose > 0)
    {
        str_to_hexstr(file.chk, file_chk_str);
        printf("%s: footer: tr1 %lu, tr2 %lu, pos %llx, check %s\n",
                progname, file.tr1, file.tr2, ftello64(fi), file_chk_str);
    }


/*
 * Step 5: process blocks map
 */
//TODO: check // blocks...
    
    block_next_num = 0;
    block_last_nonzero = -1;
    for(;;)
    {
        var_read_block_header(fi, &block);
        
        //FIXME: files can have no data blocks at all (all zero disk...)
        if (block_next_num > 0 && block.num == 0) {
		//if (block.num == 0) {
            // file end
            if (verbose > 0)
                printf("%s: last map entry (total %lu blocks) at %llx\n",\
                    progname, block_next_num, ftello64(fi));
            
            //write last empty blocks
            block_next_num = block_next_num - 1 - block_last_nonzero;
            if (opt_debug > 0)
                printf("%s: writing %ld trailing empty blocks\n", progname, block_next_num);
            
            xwrite_empty_blocks(fo, block_size, block_next_num, out_buf);
            
            block_empty += block_next_num;
            
            //end
            break;
        }
        
        if (block.num != block_next_num)
        {
            printf("%s: map block number error - expected >= %lu / got %lu (x%llx)\n",\
                progname, block_next_num, block.num, ftello64(fi));
            r = 11;
            goto err;
        }
        block_next_num += 1;
        
        //TODO check // real last block processed
        if (block.in_len > 0)
            block_last_nonzero = block.num;

//debug
//if (block.out_len != block_size)
if (block.out_len != 0x40000)
    printf("%s:different block_size: %lu\n", progname, block.out_len);

        // block map debug
        if (opt_debug > 0)
            printf("%s: reading map\t%lu, in/out: %lu/%lu, end @ x%llx\n",\
                progname, block.num, block.in_len, block.out_len, ftello64(fi));
    }
    
    //read footer end
    var_read_footer_end(fi);
    
    if (verbose > 0)
        printf("%s: blocks decomp / empty / total: %lu / %lu / %lu\n",\
            progname, block_count, block_empty, block_count + block_empty);

    r = 0;
err:
    free(in_buf);
    free(out_buf);
    free(scratch);
    return r;
}


/*************************************************************************
// main
**************************************************************************/

static void usage(void)
{
	printf("var backup archive decompressor\n");
	printf("\nusage:\n");
    printf("\t%s [-d]  input-file output-file  (var decompress)\n", progname);
    printf("\t%s -t    input-file              (var test)\n", progname);
    printf("\noptions:\n");
    printf("\t-b          var block size\n");
    printf("\t-Z          don't write sparse file / write all zeros\n");
    printf("\t-v          be more verbose\n");
    printf("\t--debug     output a lot of debug info\n");
    printf("\ntests:\n");
    printf("\t%s -k    input-file output-file  (block compress)\n", progname);
    printf("\t%s -x    input-file output-file  (block decompress)\n", progname);
    exit(1);
}


/* open input file */
static FILE *xopen_fi(const char *name)
{
    FILE *fp;

    fp = fopen64(name, "rb");
    if (fp == NULL)
    {
        printf("%s: cannot open input file %s\n", progname, name);
        exit(1);
    }
    return fp;
}


/* open output file */
static FILE *xopen_fo(const char *name)
{
    FILE *fp;

#if 1
    /* this is an example program, so make sure we don't overwrite a file */
    fp = fopen64(name, "rb");
    if (fp != NULL)
    {
        printf("%s: file %s already exists -- not overwritten\n", progname, name);
        fclose(fp); fp = NULL;
        exit(1);
    }
#endif
    fp = fopen64(name, "wb");
    if (fp == NULL)
    {
        printf("%s: cannot open output file %s\n", progname, name);
        exit(1);
    }
    return fp;
}


/* close file */
static void xclose(FILE *fp)
{
    if (fp)
    {
        int err;
        err = ferror(fp);
        if (fclose(fp) != 0)
            err = 1;
        if (err)
        {
            printf("%s: error while closing file\n", progname);
            exit(1);
        }
    }
}


/*************************************************************************
//
**************************************************************************/

int main(int argc, char* argv[])
{
    int i = 1;
    int r = 0;
    FILE *ifile = NULL;
    FILE *ofile = NULL;
    int opt_var_decompress = 0;
    int opt_var_test = 0;
    int opt_verbose = 0;
    int opt_block_compress = 0;
    int opt_block_decompress = 0;
    const char *in_name = NULL;
    const char *out_name = NULL;
    unsigned int opt_block_size = 0x4000;
    const char *s;

/*
 * Step 1: init
 */

    progname = argv[0];
    for (s = progname; *s; s++)
        if ((*s == '/' || *s == '\\') && s[1])
            progname = s + 1;
#if 0
    printf("QLZ test\n");
#endif

/*
 * Step 2: get options
 */

    while (i < argc && argv[i][0] == '-')
    {
        if (strcmp(argv[i],"-d") == 0)
            opt_var_decompress = 1;
        else if (strcmp(argv[i],"-t") == 0)
            opt_var_test = 1;
        else if (strcmp(argv[i],"-v") == 0)
            opt_verbose = 9;
        else if (strcmp(argv[i],"-k") == 0)
            opt_block_compress = 1;
        else if (strcmp(argv[i],"-x") == 0)
            opt_block_decompress = 1;
        else if (argv[i][1] == 'b' && argv[i][2])
        {
            long b = atol(&argv[i][2]);
            if (b >= 1024L && b <= 8*1024*1024L)
                opt_block_size = (unsigned int) b;
            else
            {
                printf("%s: invalid block_size in option `%s'.\n", progname, argv[i]);
                usage();
            }
        }
        else if (strcmp(argv[i],"--debug") == 0)
            opt_debug += 1;
        else if (strcmp(argv[i],"-Z") == 0)
            opt_writezero = 1;
        else
            usage();
        i++;
    }
    if (opt_debug > 0)
        printf("prog %s, test %d, decomp, %d\n",\
            progname, opt_var_test, opt_var_decompress);
    if (opt_var_test && i >= argc)
        usage();
    if (!opt_var_test && i + 2 != argc)
        usage();

/*
 * Step 3: process file
 */

    if (!opt_var_test)
    {
        in_name = argv[i++];
        out_name = argv[i++];
        ifile = xopen_fi(in_name);
        ofile = xopen_fo(out_name);
        
        if (opt_block_compress)
        {
            r = tst_comp(ifile, ofile, opt_verbose);
        }
        else if (opt_block_decompress)
        {
            r = tst_decomp(ifile, ofile, opt_verbose);
        }
        else if (opt_var_decompress)
        {
            r = var_decompress(ifile, ofile, opt_verbose);
            if (r == 0)
                printf("%s: decompressed %llu into %llu bytes\n",
                        progname, total_in, total_out);
        } else {
            printf("%s: nothing to do\n", progname);
        }
        
        xclose(ifile);
        xclose(ofile);
    }
    else /* opt_var_test */
    {
        in_name = argv[i++];
        ifile = xopen_fi(in_name);
        
        r = var_decompress(ifile, NULL, opt_verbose);
        if (r == 0)
            printf("%s: %s tested ok (%llu -> %llu bytes)\n",
                    progname, in_name, total_in, total_out);
        
        xclose(ifile);
    }
    
    ifile = NULL;
    ofile = NULL;
    return r;
}
    

/*
vi:ts=4:et
*/
