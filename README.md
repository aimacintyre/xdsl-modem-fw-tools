# xdsl-modem-fw-tools
Utilities for working with/modifying firmware images for xDSL modems

Most xDSL modems have xDSL chipset firmware files that are loaded into the
chipset from the host filesystem during initialisation.  These chipset firmware
files are sometimes specifically tuned for use with the xDSL equipment of
specific service providers or equipment vendors, and may not work as well
in another environment.  However the modem owner in many cases isn't able to
change the xDSL chipset firmware unless the modem vendor supplies alternative
device firmware images that users can install on (aka "flash to") the device.

The tools in this collection provide support for:
- extracting Lantiq xDSL chipset firmware files from decompressed manufacturer device firmware images
- extracting and decompressing firmware images from Draytek device firmware files

## Dependencies
Python 2.7 or 3.x (3.8 tested)

Development and testing is on Linux but the tools should work on Windows
and MacOS too.  No third party Python libraries/modules are required but some
Python packagers delight in breaking Python's standard library up into separately
installable components so beware...

## Extracting Lantiq xDSL chipset firmware files from uncompressed firmware images
Modem manufacturer firmware images are in compressed form to save space in device
flash memory.  The vast majority of these use SquashFS filesystems and tools
like [binwalk](https://github.com/ReFirmLabs/binwalk) can be used to extract
xDSL chipset firmware files from them.  There are however some device firmware
files that when decompressed contain xDSL chipset firmware files in uncompressed form.

The `extract_ltq_xdsl_files.py` script will scan firmware images and extract
any embedded Lantiq xDSL chipset firmware files it can identify.

### Usage
```
extract_ltq_xdsl_files.py <fw_image_file_name> [-l]
```

By default the script scans the target firmware image and extracts any Lantiq
xDSL chipset firmware files identified to the current working directory.
Extracted files will be named using the template `xcpe_<VDSL_version>_<ADSL_version>.bin`.
Existing files with matching names won't be overwritten.  The optional `-l`
argument restricts operation to listing any detected files without extracting
them.

The script can identify chipset firmware files for the following Lantiq xDSL
chipsets:
- VR9/VRX200 (VDSL version starts with 5)
- VR10/VRX300 (VDSL version starts with 7)
- VR11/VRX500 (VDSL version starts with 8)

### Note
1. Your use of this script is entirely your (the user's) responsibility
   and at your own risk.
2. Your use of this script gives you the means to extract material to use
   for your personal purposes but gives you no right to redistribute
   (i.e. give copies to others or make publicly available) any files produced
   by it.
3. For the pattern recognition to work the source files must be in
   decompressed form.  For this reason this script won't find xDSL files
   embedded in SquashFS filesystem images, though it can be used to
   determine the Lantiq file version of xDSL files extracted from other
   sources (but see also Martin Blumenstingl's `ltq-xdsl-fw-info.sh` script
   referenced in the [Credits](#Credits) section below for this purpose).
4. The simple pattern recognition approach implemented in this script
   doesn't make any guarantees as to the integrity of the output file(s).
   While I have attempted to verify it's output using known good source
   data there will be risks that what is output may be incomplete or
   invalid and potentially place any device you use output files in at
   risk of failure.

## Extracting and decompressing firmware images from DrayTek device firmware files
Draytek (https://www.draytek.com/) has manufactured a number of modems
based on Lantiq xDSL chipsets, such as:
- Vigor 130 (VR9)
- Vigor 2760-Delight (VR9)
- Vigor 2762 (VR10)
- Vigor 165 (VR11)
- Vigor 2765 (VR11)

Firmware images for these devices appear to be like Linux initramfs
images, compressed using a proprietry compression algorithm.  The compressed
firmware image flashed to the device incorporates a decompression routine
which has been reverse engineered (see Credits below) and reimplemented in
the `extract_dtv_fw.py` script to enable extracting the firmware image in
decompressed form.

### Usage
```
extract_dtv_fw.py <fw_image_file> [-fw|-fs]
```

The script supports an optional argument with two values:
- `-fw` (extract operating system firmware image; the default behaviour)
- `-fs` (extract the user interface filesystem)

The extracted file will be saved in the same directory as the source file
with an appended *.fw* or *.fs* to match the extraction option.

### Note
1. The Draytek images identified above are copyrighted.  Your use of this script
   gives you the means to extract material to use for your personal purposes but
   gives you no right to redistribute (i.e. give copies to others or make 
   publicly available) files produced by it.
2. Draytek firmware update packages usually contain 2 variants of each firmware with
   the extensions `.all` and `.rst` - the actual operating system image is the same
   in both files so it makes no difference which is chosen.
3. Draytek Lantiq modem images usually contain 2-4 complete xDSL files and
   don't appear to contain any binary difference files.  Some xDSL files
   are present in multiple images for devices with the same xDSL chipset.
4. While this script can extract the DrayOS user interface filesystem image, this image
   is of curiosity value only in the context of these tools.  For those interested in
   the contents of this image it appears to be in [Portable File System](https://sourceforge.net/projects/pfs/)
   format; Draytools (see Note 5 and the [Credits](#Credits) section below)
   appears to have some support for investigating this information.
5. Draytools (see the [Credits](#Credits) section below) only supports older Draytek
   firmware files that use LZO compression, however the file structure still appears
   to be very similar so it seems likely to me that Draytools could be successfully
   adapted to use the decompression engine in the `extract_dtv_fw.py` script rather
   than the LZO decompressor to support more recent firmware files.

## Credits
I stand on the shoulders of those who've gone before me... the tools in this repository
wouldn't exist without access to the following resources:
- Martin Blumenstingl's respository documenting where to find and
  how to extract various Lantiq VRX200 (VR9) xDSL files from OEM device firmware files provided the 
  example files from which the recognition technique was developed
  (see https://xdarklight.github.io/lantiq-xdsl-firmware-info/)
- The version string extraction in the `extract_ltq_xdsl_files.py` script
  is derived from the method used by Martin Blumenstingl's `ltq-xdsl-fw-info.sh` script
  (see https://github.com/xdarklight/lantiq-xdsl-firmware-info)
- The `extract_dtv_fw.py` script implements the decompression routine described in
  https://github.com/yath/vigor165/blob/main/decompress/decompress.S
  as part of the process of extracting the executable firmware image
  (and the user interface file system) from Draytek modem/router firmware
  files.  Many thanks to yath for this work!
- The Draytek firmware file structure was understood with information
  from the Draytools project (https://github.com/ammonium/draytools - now
  removed; I used the fork at https://github.com/krolinventions/draytools).

## Legal
Copyright (C) 2022 Andrew I MacIntyre

The licence applicable to each script is specified by the [SPDX](https://spdx.dev/)
[licence identifier](https://spdx/dev/licenses/) at the beginning of the script.
