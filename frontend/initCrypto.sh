#!/bin/bash

/sbin/rmmod ./virtio_crypto.ko
/sbin/insmod ./virtio_crypto.ko
./crypto_dev_nodes.sh 2&>  /dev/null
