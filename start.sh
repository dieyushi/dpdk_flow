#!/bin/sh

modprobe uio_pci_generic
modprobe uio
insmod x86_64-native-linuxapp-gcc/kmod/igb_uio.ko

tools/dpdk_nic_bind.py --bind=igb_uio 0000:02:01.0
tools/dpdk_nic_bind.py --bind=igb_uio 0000:02:06.0

mkdir -p /mnt/huge
mount -t hugetlbfs nodev /mnt/huge
echo 128 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages

