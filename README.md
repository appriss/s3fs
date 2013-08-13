s3fs
====

This project is a clone from the s3fs project at http://code.google.com/p/s3fs/ version 1.71.
To build this project run configure, make, make install. For more information on s3fs visit
the main project page at http://code.google.com/p/s3fs.

Additions added to s3fs version 1.71

1. Implemented mknod function to support special files and block devices.
	(Note* this was committed upstream in revision r460 and is in release 1.72)

UPDATES:

This project has been updated to upstream release 1.72

1. Implemented encryption of temporary files that hit the disk. This feature is enabled using the -o encrypt_tmp_files option. Setting this option also enables the nomultipart flag.


