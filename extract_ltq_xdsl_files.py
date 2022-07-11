#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-2.0-or-later

# Copyright (C) 2022 Andrew I MacIntyre <andymac@pcug.org.au>

# Extract Lantiq xDSL files from decompressed firmware images
#
# Recognised xDSL device files:
# - Lantiq VRX200 (VR9)
# - Lantiq VRX300 (VR10)
# - Lantiq VRX500 (VR11)
#
# Known source firmware images
# - Draytek Vigor 130 (VR9, v3.8.4.1 - requires decompression first)
# - Draytek Vigor 2760-Delight (VR9, v3.8.9.5 - requires decompression first)
# - Draytek Vigor 2762 (VR10, v3.9.6.3 - requires decompression first)
# - Draytek Vigor 165 (VR11, v4.4.1 - requires decompression first)
# - Draytek Vigor 2765 (VR11, v4.4.1 - requires decompression first)
#
# Lantiq VR9, VR10 & VR11 xDSL driver files have been found to have the
# following structure:
# - a little endian long containing the total length of the file - 8 bytes
# - one of two constant byte sequences which can be used to detect the
#   start of the file, starting with the 4th byte of the file:
#   = a 32 byte sequence which appears to be present in all non-G.vector 
#     capable files; or
#   = a 78 byte sequence which appears to be present in all G.vector
#     capable files
# - the bulk of executable code and data comprising the file
# - a 16 byte closing sequence common to all recognised files
#
# Note:
#
# 1) Your use of this script is entirely your (the user's)
# responsibility and at your own risk.
#
# 2) The Draytek images identified above are copyrighted and the embedded
# components are licensed only for use on the devices for which the
# original images are intended.  Your use of this script gives you the
# means to extract material to use for your personal purposes but gives
# you no right to redistribute (i.e. give copies to others or make
# publicly available) files produced by this script.
#
# 3) For the pattern recognition to work the source files must be in
# decompressed form.  For this reason this script won't find xDSL files
# embedded in SquashFS filesystem images, though it can be used to
# determine the Lantiq file version of xDSL files extracted from other
# sources (but see also Martin Blumenstingl's ltq-xdsl-fw-info.sh script
# mentioned in the Credits for this purpose).
#
# 4) The simple pattern recognition approach implemented in this script
# doesn't make any guarantees as to the integrity of the output file(s).
# While I have attempted to verify it's output using known good source
# data there will be risks that what is output may be incomplete or
# invalid and potentially place any device you use output files in at
# risk of failure.
#
# 5) The above noted Draytek images contain 2-4 complete xDSL files and
# don't appear to contain any binary difference files.  Some xDSL files
# are present in multiple images for devices with the same chipset.
#
# Credits:
# - Martin Blumenstingl's respository documenting where to find and
#   how to extract various Lantiq VRX200 (VR9) xDSL files provided the
#   example files from which the recognition technique was developed
#   (see https://xdarklight.github.io/lantiq-xdsl-firmware-info/)
# - the version string extraction is derived from the method used by
#   Martin Blumenstingl's ltq-xdsl-fw-info.sh script
#   (see https://github.com/xdarklight/lantiq-xdsl-firmware-info)

import os
import sys
import struct



### constants

# common strings
NULL = b'\x00'
UNDERSCORE = b'_'
EMPTY = ''

# target strings
XDSL_TYPE = ('A', 'B')
XDSL_START_A = b'\x00\x00\x00\x00\x0a\x00\x00\x00\x68\x24\x00\x00\x00\x00\xff\xff' \
               b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
XDSL_START_B = b'\x00\x00\x00\x00\x0b\x00\x00\x00\x68\x24\x00\x00\x00\x00\xff\xff' \
               b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
               b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
               b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
               b'\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x00\x00'

XDSL_END =     b'\x0b\x46\x42\x3e\x0c\x47\x43\x3f\x0d\x48\x44\x40\x0e\x49\x45\x41'

XDSL_VERSION = b'\x40\x28\x23\x29'

# runtime help
USAGE_STR = """
usage:  %s <source_file> [-l]

where:
  -l - (optional) list version numbers of files found but don't extract them
""" % sys.argv[0]



### helper routines

# write a message on standard output
def logln(msg):
    sys.stdout.write('%s\n' % msg)
    sys.stdout.flush()


# return version number strings from a Lantiq xDSL file
# - there should be two, each of 6 characters separated by full stop
#   characters;  each string is null terminated
# - return as a combined string for use in a file name
# - some older files have the VDSL version prefixed with "V_"
#   which will be preserved
def xdsl_versions(xdsl_bytes):
    srch_offset = 0
    vers_offs_s = len(XDSL_VERSION)
    versions = []
    for i in (0, 1):
        vmark_idx = xdsl_bytes.find(XDSL_VERSION, srch_offset)
        if vmark_idx < 0:
            break
        srch_offset = vmark_idx + vers_offs_s
        term_idx = xdsl_bytes.find(NULL, srch_offset)
        if term_idx - srch_offset > 13:
            break
        versions.append(xdsl_bytes[srch_offset: term_idx])
        srch_offset = term_idx + 1

    if len(versions) == 2:
        version_str = versions[0] + UNDERSCORE + versions[1]
        return version_str.decode('ascii')
    else:
        return EMPTY



### main routine

def extract_xdsl_files(src_file, list_only=False):

    # read the source
    try:
        src_bytes = bytearray(open(src_file, 'rb').read())
    except (OSError, IOError):
        logln('%s: error reading file' % src_file)
        sys.exit(1)
    src_length = len(src_bytes)
    if list_only:
        logln('source file: %s' % src_file)

    # try and find the starting string
    hit_count = 0
    xdsl_end_len = len(XDSL_END)
    for xdsl_type, xdsl_start_marker in enumerate((XDSL_START_A, XDSL_START_B)):
        search_offset = 0
        xdsl_start_len = len(xdsl_start_marker)
        xdsl_type = XDSL_TYPE[xdsl_type]
        while True:
            offset = src_bytes.find(xdsl_start_marker, search_offset)
            if offset > search_offset + 3:

                # check for the file length which is a little endian long
                # immediately preceding the start marker which is also
                # the first 4 bytes of the file; the value found doesn't
                # account for itself or the first 4 bytes of the start
                # marker (which are all NULLs)
                xdsl_length = struct.unpack_from('<L', src_bytes, offset - 4)[0] + 4
                xdsl_end = offset + xdsl_length
                if xdsl_end <= src_length:

                    # check for an end marker finishing at the specified size
                    if src_bytes[xdsl_end - xdsl_end_len: xdsl_end] == XDSL_END:

                        # looks like a hit
                        hit_count += 1
                        hit_s = offset - 4
                        hit_l = xdsl_length + 4
                        logln('[%d]  xDSL file with type %s start marker found:' % (hit_count, xdsl_type))
                        logln('     offset:  0x%x' % hit_s)
                        logln('     length:  %d bytes' % hit_l)
                        xdsl_bytes = src_bytes[hit_s: hit_s + hit_l]

                        # extract version string
                        version_str = xdsl_versions(xdsl_bytes)
                        if version_str:
                            logln('     version: %s' % version_str)
                            xdsl_file = 'xcpe_%s.bin' % version_str
                        else:
                            logln('     version: none identified!')
                            xdsl_file = '%s-dsl_%s.%d.bin' % (src_file, xdsl_type, hit_count)

                        # save xDSL file bytes to a file if it doesn't already exist
                        if not list_only:
                            if not os.path.exists(xdsl_file):
                                open(xdsl_file, 'wb').write(xdsl_bytes)
                            else:
                                logln('     %s: file already exists - skipping!' % xdsl_file)

                        # any others to be found?
                        search_offset = xdsl_end

                    else:
                        # any others to be found?
                        search_offset += offset + xdsl_start_len

                else:
                    # anything returned would be truncated
                    logln('[%d]  xDSL file with type %s start marker found at 0x%x' % (hit_count + 1, xdsl_type, offset))
                    logln('     but apparent length extends beyond end of image!')
                    break

            else:
                break

    if not hit_count:
        logln('! no xDSL files found')



### run as script

if __name__ == '__main__':
    try:
        list_opt = sys.argv[2]
        if list_opt != '-l':
            raise ValueError('"%s": option not recognised' % list_opt)
    except IndexError:
        list_opt = False
    except ValueError as e:
        logln(e.args[0])
        logln(USAGE_STR)
        sys.exit(1)
    try:
        extract_xdsl_files(sys.argv[1], list_opt)
    except IndexError:
        logln(USAGE_STR)
        sys.exit(1)
