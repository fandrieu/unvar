#!/usr/bin/python2

import pyquicklz

import os
import re
import sys
import struct

import hashlib


def xread32(f):
    return struct.unpack('<L', f.read(4))[0]
    
def xread64(f):
    return struct.unpack('<Q', f.read(8))[0]
    
def xskip(f, len):
    return f.seek(len, os.SEEK_CUR)

def xread(f, len):
    return f.read(len)
    
def xreadchk(f):
    return f.read(16)
    #FCK...
    #return struct.unpack('>QQ', f.read(16))

def str_to_hexstr(s):
    return ''.join([ '%02x' % ord(x) for x in s ])
    
    
class VarHeader():
    def __init__(self, fi):
        'read header'
        self.version_1 = xread32(fi)
        self.flags = xread32(fi)
        self.version_2 = xread32(fi)
        self.len = xread32(fi)
        # skip to uuid = 32 x 2
        xskip(fi, 8)
        # read UUID
        #self.uuid = xread(fi, 16)
        self.uuid = xreadchk(fi)
        # empty?
        xskip(fi, 16)
        
        print "len x%x @ x%x" % (self.len, fi.tell())

        if False:
            #TODO: parse text header, at least file_size / block_size
            self.size = 0
            self.block_size = 0x40000

            # skip text header, to first block
            xskip(fi, self.len)
        
        else:
            #NEW: text header parse
            self.size = 0
            self.block_size = 0x40000
            self.compress = 'lzo'
            self.hash = 'md5'

            text = fi.read(self.len)
            for part in text[:-1].split('\n'):
                key, val = part.split('=')
                if key == 'blocksize':
                    self.block_size = int(val)
                elif key == 'file1':
                    self.size = int(val)
                elif key == 'translators':
                    self.compres = val
                elif key == 'translators':
                    self.hash = val
                else:
                    print "Unknown text header:", key, val


class VarBlockHeader():
    def __init__(self, fi):
        'read block header'
        # read block number
        self.num = xread32(fi)
        #TOFIX: 64 bit num ??
        xread32(fi)
        
        # read compressed size
        self.in_len = xread32(fi)

        # read uncompressed size
        self.out_len = xread32(fi)
        # empty / 64 ?
        xread32(fi)
        
        # read block method ?
        self.method = xread32(fi)
        
        # read block chk
        self.chk = xreadchk(fi)
        
        # empty
        xskip(fi, 56)
        
        # read block pos
        self.pos = xread64(fi)

        # TOFIX: use block_pos ?
        xskip(fi, 8)



class VarFooterStart:
    def __init__(self, fi):
        'read map header'
        #read footer start
        
        #skip empty
        xskip(fi, 8)
        
        #read those
        self.tr1 = xread32(fi)
        self.tr2 = xread32(fi)
        
        #skip empty
        xskip(fi, 8)

        #read chk
        self.chk = xreadchk(fi)

        #skip to first map entry
        xskip(fi, 0x48)

class VarFooterEnd():
    def __init__(self, fi):
        #read footer end
        self.chks = []
        for i in range(4):
            #read chk
            chk = xreadchk(fi)

            #skip empty
            xskip(fi, 16*3)
            
            #debug...
            self.chks.append(chk)
            print "footer chk %d: %s" % (i, str_to_hexstr(chk))
        
        #read those
        tmp1 = xread32(fi)
        tmp2 = xread32(fi) #64....
        tmp3 = xread32(fi)
        
        #debug...
        print "footer info %x / %x / %x" %\
            (tmp1, tmp2, tmp3)
        
        #should be the end of file...


def var_decompress(nin, nout=None, verbose=1):
    opt_debug = 1
    
    fi = open(nin, 'rb')
    
    #
    # Step 1: check magic header, read flags & block size, init checksum
    #
    magic = fi.read(8)
    if not magic == '\x2d\x5e\x70\x3c\x99\x72\x6a\xb8':
        raise ValueError('header error - this file is a .var')
        
    header = VarHeader(fi)
    print "version_1 %u, version_2 %u, header_len %u, header_end x%x\n\tfile_flags %x, file_uuid %s" %\
            (header.version_1, header.version_2, header.len, fi.tell(), header.flags, str_to_hexstr(header.uuid))
    
    #
    # Step 3: process blocks
    #
    total_in = 0
    total_out = 0
    block_count = 0
    block_empty = 0
    block_next_num = 0
    block_last_nonzero = 0
    block_size = header.block_size
    while True:
        
        #
        #  Parse the VAR block header
        #

        block_real_pos = fi.tell()
        
        block = VarBlockHeader(fi)
        
        #NOTE: files can have no data blocks at all (all zero disk...)
        #if block_next_num > 0 and block.num == 0:
        if block.in_len == 0:
            # file end
            if verbose > 0:
                print "last block at %x" % block_real_pos
            break
        
        # block header debug
        if opt_debug > 0:
            print "reading block\t%u, pos\t%u\tin/out: %u/%u\ncheck: %s"%\
                (block.num, fi.tell(), block.in_len, block.out_len, str_to_hexstr(block.chk))

        if block.num != block_next_num:
            if block.num < block_next_num:
                msg = "block number error - expected >= %u / got %u (x%x)" %\
                    (block_next_num, block.num, block_real_pos)
                r = 5
                raise ValueError(msg)
                
            # bloc_num >  block_next_num actually means empty blocks...
            block_next_num = block.num - block_next_num
            if opt_debug > 0:
                print "writing %d empty blocks" % block_next_num
            
            #xwrite_empty_blocks(fo, block_size, block_next_num, out_buf);
            
            # record empty blocks + reset next_num
            block_empty += block_next_num
            block_next_num = block.num
        
        block_next_num += 1

        # sanity check of the size values
        if block.in_len-9 > block_size or block.out_len > block_size or\
            block.in_len == 0 or block.in_len-9 > block.out_len:
            msg = "block size error - data corrupted\n"
            msg += "len in / out:  %u /  %u" %\
                (block.in_len, block.out_len)
            r = 6
            raise ValueError(msg)

        # check block pos
        #NOTE: this this doesn't seem to be the set in v5 files...
        if block.pos and not block.pos == block_real_pos:
            msg = "block position error - expected %u / got %u"%\
                (block_real_pos, block.pos)
            r = 7
            raise ValueError(msg)
        
        #MISSING: QLZ header checking...
        
        #
        #    Read & decompress the QLZ block
        #
        block_count += 1
        
        if opt_debug > 1:
            # skip the block
            xskip(fi, block.in_len)

        else:

            # read the compressed block in "in_buf"
            in_buf = fi.read(block.in_len)
            
            #real decompress
            #PY FIXME: new_len = decompres...
            out_buf = pyquicklz.decompress(in_buf, block.out_len)
            new_len = len(out_buf)

            if opt_debug > 0:
                print "decomp len: %d / %d" % (block_size, block_size)

            if not new_len == block.out_len:
                msg = "compressed data violation\n"
                r = 10
                raise ValueError(msg)

            # write decompressed block
            #xwrite(fo, out_buf, block.out_len);

            # check block checksum
            tmp_chk = hashlib.md5(':lzo:')
            tmp_chk.update(out_buf)
            if opt_debug > 0:
                print "verified: %s" % tmp_chk.hexdigest()

            if not block.chk == tmp_chk.digest():
                msg = "checksum error - block %u corrupted" % block.num
                r = 11
                raise ValueError(msg)
        
    #
    # Step 4: process footer
    #

    # read and verify checksum
    # ....
    
    #read footer start
    file = VarFooterStart(fi)

    #footer debug
    if verbose > 0:
        print "footer: tr1 %x, tr2 %x, pos %x, check %s" %\
                (file.tr1, file.tr2, fi.tell(), str_to_hexstr(file.chk))


    #
    # Step 5: process blocks map
    #
    #TODO: check // blocks...
    
    #DEBUG MD5: "MAP" check: footer check = md5 from <here> to map end
    tmp_data = fi.read(file.tr1)
    xskip(fi, -1 * file.tr1)
    tmp_chk = hashlib.md5(tmp_data)
    print "verified MAP check:", tmp_chk.hexdigest(),
    if tmp_chk.digest() == file.chk:
        print "OK"
    else:
        print "\nERROR: MAP checksum KO"
    
    
    block_next_num = 0
    block_last_nonzero = -1
    while True:
        block = VarBlockHeader(fi)
        
        #FIXME: files can have no data blocks at all (all zero disk...)
        if block_next_num > 0 and block.num == 0:
        #if block.num == 0:
            # file end
            if verbose > 0:
                print "last map entry (total %u blocks) at %x" %\
                    (block_next_num, fi.tell())
            
            #write last empty blocks
            block_next_num = block_next_num - 1 - block_last_nonzero
            if opt_debug > 0:
                print "writing %d trailing empty blocks" % block_next_num
            
            #MISSING...
            #xwrite_empty_blocks(fo, block_size, block_next_num, out_buf);
            
            block_empty += block_next_num
            
            #end
            break
        
        if not block.num == block_next_num:
            msg = "map block number error - expected >= %u / got %u (x%x)" %\
                (block_next_num, block.num, fi.tell())
            r = 11
            raise ValueError(msg)
        
        block_next_num += 1
        
        #TODO check // real last block processed
        if block.in_len > 0:
            block_last_nonzero = block.num

        #debug...
        #if block.out_len != block_size:
        if block.out_len != 0x40000:
            print "different block_size: %u" % block.out_len

        # block map debug
        if opt_debug > 0:
            print "reading map\t%u, in/out: %u/%u, end @ x%x\ncheck: %s" %\
                (block.num, block.in_len, block.out_len, fi.tell(), str_to_hexstr(block.chk))
    
    #read footer end
    footer = VarFooterEnd(fi)
    
    
    #DEBUG MD5: "BINHEADER" check: footer chk 0 = md5 of the "binary" header
    fi.seek(0, os.SEEK_SET)
    tmp_data = fi.read(header.version_2)        #0x40 or this ???
    tmp_chk = hashlib.md5(tmp_data)
    print "verified BINHEADER check:", tmp_chk.hexdigest(),
    if tmp_chk.digest() == footer.chks[0]:
        print "OK"
    else:
        print "\nERROR: BINHEADER checksum KO"
        
    #DEBUG MD5: "TEXTHEADER" check: footer chk 1 = md5 of the "text" header
    fi.seek(header.version_2, os.SEEK_SET)
    tmp_data = fi.read(header.len)
    tmp_chk = hashlib.md5(tmp_data)
    print "verified TEXTHEADER check:", tmp_chk.hexdigest(),
    if tmp_chk.digest() == footer.chks[1]:
        print "OK"
    else:
        print "\nERROR: TEXTHEADER checksum KO"

    #DEBUG MD5: "MAP" check: footer chk 2 = idem footer.chk
    if footer.chks[2] == file.chk:
        print "verified MAP DUPE check: OK"
    else:
        print "ERROR: MAP DUPE checksum KO"        
    
    #DEBUG MD5: "END" check: footer chk 3 = md5 of the last 3 32b values
    fi.seek(-12, os.SEEK_END)
    tmp_data = fi.read(12)
    tmp_chk = hashlib.md5(tmp_data)
    print "verified END check:", tmp_chk.hexdigest(),
    if tmp_chk.digest() == footer.chks[3]:
        print "OK"
    else:
        print "\nERROR: END checksum KO"
    
    if verbose > 0:
        print "blocks decomp / empty / total: %u / %u / %u" %\
            (block_count, block_empty, block_count + block_empty)



def main():
    if len(sys.argv) < 2:
        print "usage: %s <file>" % sys.argv[0]
        sys.exit(1)
    n = sys.argv[1]
    var_decompress(n)

if __name__ == "__main__":
    sys.exit(main())
