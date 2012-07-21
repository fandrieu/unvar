#!/usr/bin/python2

import ctypes
qlzlib = ctypes.CDLL("./quicklz.so")

#FIXME:
scratch_size = 67600
scratch = ctypes.create_string_buffer(scratch_size)


def size_decompressed(source):
    return qlzlib.qlz_size_decompressed(ctypes.c_char_p(source))

def size_compressed(source):
    return qlzlib.qlz_size_compressed(ctypes.c_char_p(source))

def decompress(source, size=0x40000):
    dest = ctypes.create_string_buffer(size)
    new_size = qlzlib.qlz_decompress(ctypes.c_char_p(source), dest, scratch)
    return dest[:new_size]

def compress(source):
    size = len(source)
    dest = ctypes.create_string_buffer(size)
    qlzlib.qlz_decompress(ctypes.c_char_p(source), dest, size, scratch)
    return dest


if __name__ == '__main__':
    #TODO: test ?
    f = open(file, 'rb')
    content = f.read()
    f.close()
    f = open(file + '.out', 'wb')
    f.write(decompress(content))
    f.close()
