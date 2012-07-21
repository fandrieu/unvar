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
 * .var backup archive decompressor
 * 
 * based on
 *  - QuickLZ 1.4.1               http://www.quicklz.com/
 *  - L. Peter Deutsch's md5      ghost@aladdin.com
 */

/*
//TODO: force linking against en old glibc => to run on esx
#define GLIBC_COMPAT_SYMBOL(FFF) __asm__(".symver " #FFF "," #FFF "@GLIBC_2.2.5");
GLIBC_COMPAT_SYMBOL(fread)
*/

// Remember to define QLZ_COMPRESSION_LEVEL and QLZ_STREAMING_MODE to the same values for the compressor and decompressor
// ...guessed values for var files:
#define QLZ_COMPRESSION_LEVEL 2
#define QLZ_STREAMING_BUFFER 0

// no compressed checksum, better be safe..
#define QLZ_MEMORY_SAFE

#include <stdio.h>
#include <stdlib.h>

#include "quicklz.h"

#include "md5.h"

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

/* casted tell */
long long unsigned int xtell(FILE *f)
{
    return (long long unsigned int) ftello64(f);
}

/* write zero blocks */
int xwrite_empty_blocks(FILE *fo, unsigned long block_size, unsigned long num, char *buf)
{
    if (num<1)
        return 1;

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
            printf("@%llu skipping %lu %lub blocks = %llu bytes\n",\
				fo==NULL?0:xtell(fo), num, block_size, total);
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

    // allocate source buffer
    fseek(ifile, 0, SEEK_END);
    len = ftell(ifile);
    fseek(ifile, 0, SEEK_SET);
    src = (char*) malloc(len);

    // read file and allocate destination buffer
    len = fread(src, 1, len, ifile);
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
// md5 / test
//
// basic test: compute a file's md5
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


int tst_md5(FILE *ifile, md5_byte_t *digest)
{
    char *file_data;
    unsigned int len;
    md5_state_t state;

    // allocate source buffer
    fseek(ifile, 0, SEEK_END);
    len = ftell(ifile);
    fseek(ifile, 0, SEEK_SET);

    file_data = (char*) malloc(len);

    // read file
    len = fread(file_data, 1, len, ifile);
    
    // compute md5
	md5_init(&state);
	md5_append(&state, (const md5_byte_t *)file_data, len);
	md5_finish(&state, digest);
    
    return 0;
}

/*************************************************************************
// decompress / var
**************************************************************************/

/*
    VAR file header
*/
typedef struct {
    //header
    unsigned int version;
    unsigned int bin_len;
    unsigned int txt_len;
    unsigned long flags;
    unsigned long long size;
    unsigned long block_size;
    char uuid [ 16 ];
    //map
    unsigned long map_len;
    unsigned long map_len2;
    char map_chk [ 16 ];
    //footer
    char chks [4][16];
    unsigned long foot1;
    unsigned long foot2;
    unsigned long foot3;
} var_header;


int var_read_header(FILE *fi, var_header *header)
{
    //read header
    header->version = xread32(fi);
    header->flags = xread32(fi);
    header->bin_len = xread32(fi);
    header->txt_len = xread32(fi);
    //skip to uuid = 32 x 2
    xskip(fi, 8);
    //read UUID
    xread(fi, header->uuid, 16, 1);
    //empty?
    xskip(fi, 16);
    
    //skip text header, to first block
    xskip(fi, header->txt_len);
    //TODO: parse text header, at least file_size / block_size
    header->size = 0;    
    header->block_size = 0x40000;
    return 1;
}

int var_read_map_header(FILE *fi, var_header *header)
{
    //read footer start
    
    //skip empty
    xskip(fi, 8);
    
    //read len ?
    header->map_len = xread32(fi);
    header->map_len2 = xread32(fi);
    
    //skip empty
    xskip(fi, 8);

    //read map chk
    xread(fi, header->map_chk, 16, 1);

    //skip to first map entry
    xskip(fi, 0x48);
    
    return 1;
}


int var_read_footer(FILE *fi, var_header *header)
{
    //read footer
    int i;

    //read 4 different checksums: (md5 16 bytes)
    //bin header - txt header - map - footer
    for (i = 0; i<4; i++) {
        //read chk
        xread(fi, header->chks[i], 16, 1);
        xskip(fi, 16*3);
    }

    //read those
    header->foot1 = xread32(fi);
    header->foot2 = xread32(fi); //64....
    header->foot3 = xread32(fi);
	
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

    TEMP checksum tool...
*/
int file_check_part(FILE *fi, unsigned long len, char *value)
{
    md5_state_t md5_state;
    md5_byte_t md5_digest[16];
    char tmp_buf[1024];
    unsigned long len_done;
    unsigned long len_todo = len;
    
    md5_init(&md5_state);
    while (len_todo > 0) {
        len_done = fread(tmp_buf, 1, (len_todo>1024)?1024:len_todo, fi);
        md5_append(&md5_state, (const md5_byte_t *)tmp_buf, len_done);
        len_todo -= len_done;
    }
    md5_finish(&md5_state, md5_digest);
    
    return memcmp(value, md5_digest, 16);
}


/*
    VAR file decompress
*/
int var_decompress(FILE *fi, FILE *fo, int verbose)
{
    int r = 0;
	int ok;
    char *in_buf = NULL;
    char *out_buf = NULL;
    char *scratch = NULL;
    unsigned char m [ sizeof(magic) ];
    unsigned int block_size;
    md5_state_t md5_state;
    md5_byte_t md5_digest[16];
    static const char *const block_salt = ":lzo:";
    
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
 * Step 1: check magic header, read flags & block size
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
        printf("%s: version %u, bin_len %u, txt_len %u, header_end x%llx\n\tfile_flags %lx, file_uuid %s\n",
                progname, file.version, file.bin_len, file.txt_len, xtell(fi), file.flags, file_chk_str);
    }

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

        block_real_pos = xtell(fi);
        
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
            printf("%s: reading block\t%lu, pos\t%llu\tin/out: %lu/%lu\n",\
                progname, block.num, xtell(fi), block.in_len, block.out_len); 
            str_to_hexstr(block.chk, file_chk_str);
            printf("%s: checksum: %s\n", progname, file_chk_str);
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
            
            xwrite_empty_blocks(fo, block.out_len, block_next_num, out_buf);
            
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

        // rewind at the begining of the QLZ block / header
        // 1 x QLZ marker + 4 x comp size + 4 x uncomp size
        xskip(fi, -9);
        
        if (opt_debug > 1)
        {
            // skip the block
            xskip(fi, block.in_len);
        }
        else
        {

            // read the compressed block in "in_buf"
            xread(fi, in_buf, block.in_len, 0);
            
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

            //check block checksum
            md5_init(&md5_state);
            md5_append(&md5_state, (const md5_byte_t *)block_salt, 5);
            md5_append(&md5_state, (const md5_byte_t *)out_buf, block.out_len);
            md5_finish(&md5_state, md5_digest);
            if (opt_debug > 0)
            {
                str_to_hexstr((char *)md5_digest, file_chk_str);
                printf("%s: verified: %s\n", progname, file_chk_str);
            }
            if (memcmp(block.chk, md5_digest, 16) != 0)
            {
                printf("%s: checksum error - block %lu corrupted\n", progname, block.num);
                r = 11;
                goto err;
            }
        }

        //debug
        if (opt_debug > 1)
        {
            if(block_next_num>1)
            {
                printf("bail, pos x%llx\n", xtell(fi));
                goto err;
            }
        }
        
    }

/*
 * Step 4: process map / index
 */
    
    //read map header
    var_read_map_header(fi, &file);

    //debug
    if (verbose > 0)
    {
        str_to_hexstr(file.map_chk, file_chk_str);
        printf("%s: map: len %lu, len2 %lu, pos %llx, check %s\n",
                progname, file.map_len, file.map_len2, xtell(fi), file_chk_str);
    }

	
	//read all before parsing to verify...
	//TODO: compute while reading blocks ? anyway it's useless...
	if (opt_debug>0)
	{
		ok = file_check_part(fi, file.map_len, file.map_chk);
		fseeko64(fi, -1 * file.map_len, SEEK_CUR);
		printf("%s: map checksum %s\n", progname, (ok==0)?"OK":"ERROR");
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
                    progname, block_next_num, xtell(fi));
            
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
                progname, block_next_num, block.num, xtell(fi));
            r = 12;
            goto err;
        }
        block_next_num += 1;
        block_size = block.out_len; //store previous block size
        
        //TODO check // real last block processed
        if (block.in_len > 0)
            block_last_nonzero = block.num;

//debug
//if (block.out_len != block_size)
if (block.out_len > 0x40000)
    printf("%s: WARNING: block_size too large: %lu\n", progname, block.out_len);

        // block map debug
        if (opt_debug > 0)
            printf("%s: reading map\t%lu, in/out: %lu/%lu, end @ x%llx\n",\
                progname, block.num, block.in_len, block.out_len, xtell(fi));
    }

    //read footer
    var_read_footer(fi, &file);
    //should be the end of file...

	//debug...
    if (verbose > 0)
    {   
        const char *const chk_names[4] = {"bin", "txt", "map", "foot"};
        int i;
        for (i = 0; i<4; i++) {
            str_to_hexstr(file.chks[i], file_chk_str);
            printf("%s: %s chk: %s\n", progname, chk_names[i], file_chk_str);
        }
        printf("%s: footer info %lu / %lu / %lu\n",
            progname, file.foot1, file.foot2, file.foot3);
    }
    
    //TODO: check those md5 before reading the file...
    //...but that implies reading the file end first
    if (opt_debug > 0)
    {
        //chk 0: bin header: from start for bin_len
        fseeko64(fi, 0, SEEK_SET);
        ok = file_check_part(fi, file.bin_len, file.chks[0]);
        printf("%s: binary header checksum %s\n", progname, (ok==0)?"OK":"ERROR");

        //chk 1: txt header: from bin header for txt_len
        ok = file_check_part(fi, file.txt_len, file.chks[1]);
        printf("%s: text header checksum %s\n", progname, (ok==0)?"OK":"ERROR");
        
        //chk 2: map dupe: full map...
        ok = memcmp(file.map_chk, file.chks[2], 16);
        printf("%s: map dupe checksum %s\n", progname, (ok==0)?"OK":"ERROR");
        
        //chk 3: footer: last 12 bytes
        fseeko64(fi, -12, SEEK_END);
        ok = file_check_part(fi, 12, file.chks[3]);
        printf("%s: footer checksum %s\n", progname, (ok==0)?"OK":"ERROR");
    }



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
    printf("\t-Z          don't write sparse file / write all zeros\n");
    printf("\t-v          be more verbose\n");
    printf("\t--debug     output a lot of debug info\n");
    printf("\ntests:\n");
    printf("\t%s -k    input-file output-file  (block compress)\n", progname);
    printf("\t%s -x    input-file output-file  (block decompress)\n", progname);
    printf("\t%s -h    input-file              (file md5)\n", progname);
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
    int opt_file_md5 = 0;
    const char *in_name = NULL;
    const char *out_name = NULL;
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
        else if (strcmp(argv[i],"-h") == 0)
            opt_file_md5 = 1;
        else if (strcmp(argv[i],"--debug") == 0)
            opt_debug += 1;
        else if (strcmp(argv[i],"-Z") == 0)
            opt_writezero = 1;
        else
            usage();
        i++;
    }
    if (opt_var_test && i >= argc)
        usage();
    if (!opt_var_test && !opt_file_md5 && i + 2 != argc)
        usage();

/*
 * Step 3: process file
 */

    if (!opt_var_test && !opt_file_md5)
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
    else /* opt_var_test || opt_file_md5 */
    {
        in_name = argv[i++];
        ifile = xopen_fi(in_name);
        
        if (opt_file_md5)
        {
            md5_byte_t digest[16];
            char hex_output[16*2 + 1];
            
            tst_md5(ifile, digest);
            
            str_to_hexstr((char *)digest, hex_output);
            printf("%s  %s\n", hex_output, in_name);
        }
        else /* opt_var_test */
        {
            r = var_decompress(ifile, NULL, opt_verbose);
            if (r == 0)
                printf("%s: %s tested ok (%llu -> %llu bytes)\n",
                        progname, in_name, total_in, total_out);
        }

        xclose(ifile);
    }
    
    ifile = NULL;
    ofile = NULL;
    return r;
}
    

/*
vi:ts=4:et
*/
