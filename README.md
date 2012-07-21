unvar & unvar.py
================

"var" backup archive decompressor based on QuickLZ 1.4
------------------------------------------------------

This is an expiremental attempt at a standalone unpacker for the ".var"
archive format implemented by some VM backup solutions.

The main motivation for this project is to have a last-resort,
run-anywhere tool for disaster recovery.

- - -

It can handle "lzo" compressed archives, which actually use the QuickLZ
algorithm, and as such is based on the GPL'd version of QuickLZ v1.4.

The format itself is a pretty straightforward concatenation of QuickLZ
data blocks with additional metadata and a global index.

While the format is suited for mounting and online decompression, this
tool only aims at offline extracting.

- - -

There's also a python2 version that relies on the quicklz binary library
and a simple ctypes python wrapper.
It's a separated implementation that can be used instead of the C unvar.

- - -

**WARNING** THIS IS EXPERIMENTAL SOFTWARE AND SHOULDN'T BE USED FOR
            ANYTHING BUT TESTING. IT COMES WITH ABSOLUTELY NO WARRANTY.

**WARNING** WHILE INDIVIDUAL DATA BLOCKS AND ARCHIVE METADATA ARE
            CHEKSUMED THERE IS NO WHOLE OUTPUT FILE VERIFICATION.
            AS SUCH GENERATED FILES SHOULD BE CONSIDERED UNRELIABLE
            UNLESS OTHERWISE VERIFIED.
