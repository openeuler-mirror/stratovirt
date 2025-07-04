# stratovirt-img

stratovirt-img is an offline tool for virtual disks.

Usage:

```shell
stratovirt-img command [command options]
```

Command parameters:

- img_path: the path for image.
- fmt: disk format.
- img_size: size for image, the unit can be K, M, G or none for bytes.
- options is a comma separated list of format specific options in a name=value format.

Following commands are supported now:

## Create

Create virtual disk with different format.
Command syntax:

```shell
create [-f fmt] [-o options] img_path img_size
```

Sample Configuration：

```shell
stratovirt-img create -f raw img_path img_size
stratovirt-img create -f qcow2 -o cluster-size=65536 img_path img_size
```

Note: 1. The cluster size can be only be set for `qcow2` or default to 65536. 2. Disk format is default to raw.

## Info

Query the information of virtual disk.

Sample Configuration：

```shell
stratovirt-img info img_path
```

## Check

Check if there are some mistakes on the image and choose to fix.
Command syntax:

```shell
check [-r {leaks|all}] [-no_print_error] [-f fmt] img_path
```

- -r:  `leaks` means only the leaked cluster will be fixed, `all` means all repairable mistake will be fixed.
- -no_print_error: do not print detailed error messages.

Sample Configuration：

```shell
stratovirt-img check img_path
```

Note: The command of check is not supported by raw format.

## Resize

Change the virtual size of the disk.
- `+size`means increase from old size, while `size` means resize to new size.

Command syntax:

```shell
resize [-f fmt] img_path [+]size
```

Sample Configuration：

```shell
stratovirt-img resize -f qcow2 img_path +size
stratovirt-img resize -f raw img_path +size
```

Note: Shrink operation is not supported now.

## Snapshot

Operating internal snapshot for disk, it is only supported by qcow2.
Command syntax:

```shell
snapshot [-l | -a snapshot_name | -c snapshot_name | -d snapshot_name | -r old_snapshot_name new_snapshot_name] img_path
```

- -a snapshot_name: applies a snapshot (revert disk to saved state).
- -c snapshot_name: creates a snapshot.
- -d snapshot_name: deletes a snapshot.
- -l: lists all snapshots in the given image.
- -r old_snapshot_name new_snapshot_name: change the name from 'old_Snapshot_name' to 'new_Snapshot_name'.

Sample Configuration：

```shell
stratovirt-img snapshot -c snapshot_name img_path
stratovirt-img snapshot -a snapshot_name img_path
stratovirt-img snapshot -d snapshot_name img_path
stratovirt-img snapshot -l img_path
stratovirt-img snapshot -r old_snapshot_name new_snapshot_name img_path
```

Note: The internal snapshot is not supported by raw.

## Convert

Convert the disk image to a new disk image using new format.
Command syntax:

```shell
convert [ -f input_fmt | -O output_fmt | -S sparse_size ] input_filename output_filename
```

- -f fmt: Input image format.
- -O output_fmt: Output image format.
- -S sparse_size: the consecutive number of bytes that must contain only zeroes to create a sparse image during conversion. Unit: sector(512 bytes). Default is 8.
- input_filename: name of the input file using *input_fmt* image format.
- output_filename: name of the output file using *output_fmt* image format.

Sample Configuration：

```shell
stratovirt-img convert -f qcow2 -O raw qcow2_img_path raw_img_path
```

Note: Only qcow2 image to raw image conversion is supported currently.
