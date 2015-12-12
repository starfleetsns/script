#!/bin/bash

parted -a optimal --script /dev/sda -- mklabel msdos
parted -a optimal --script /dev/sda -- mkpart primary ext4 1 16GB
parted -a optimal --script /dev/sda -- mkpart extended 16GB 100%
parted -a optimal --script /dev/sda -- mkpart logical linux-swap 16GB 20GB
parted -a optimal --script /dev/sda -- mkpart logical ext4 20GB 36GB
parted -a optimal --script /dev/sda -- mkpart logical ext4 36GB 100%

mkfs.ext4 -L emergency /dev/sda1
mkswap -L swap /dev/sda5
mkfs.ext4 -L localdata /dev/sda6
mkfs.ext4 -L localscratch /dev/sda7




