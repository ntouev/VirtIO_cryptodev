# VirtIO-cryptodev

## Description
This repository contains the development of a **driver for Cryptographic Accelerators**, in virtual environments (QEMU).

The project is devided into three sections:
* Implementation of a simple **unencrypted chat** between two peers using [BSD sockets](https://en.wikipedia.org/wiki/Berkeley_sockets).

* Implementation of a simple **encrypted chat** between two peers using [BSD sockets](https://en.wikipedia.org/wiki/Berkeley_sockets) and [cryptodev module](http://cryptodev-linux.org/documentation.html).

* Implementation of a **paravirtualized driver** in the Linux kernel for virtual environments (frontend) and of **virtual Cryptographic hardware** in Qemu-3.0.0 (backend). Combined they can support the access of Cryptographic Accelerators from Virtual environments in QEMU.

## Usage

### Unencrypted chat-Encrypted chat

Compile with:
```console
$ make
```

and run the **server** with:

```console
$ ./server
```
***OR***
```console
$ ./crypto-server
```

In a different terminal run the **client**.
```console
$ ./client 127.0.0.1 35001
```
***OR***
```console
$ ./crypto-client 127.0.0.1 35001
```

**In both situations testing the traffic can be done with:**
```console
$ sudo tcpdump -A -i lo tcp -nnn -XXX -vvv
```

*In the encrypted chat the original data sent shouldn't be understood.*

### Driver
*(The host machine should have the [cryptodev module](http://cryptodev-linux.org/documentation.html) loaded!)*

* Clone or download the repository.

* Download Qemu-3.0.0 source code.

* Apply the patch running inside the *Qemu-3.0.0/* directory

```console
$ patch -p1 < <path to qemu-3.0.0_helpcode.patch>/qemu-3.0.0_helpcode.patch
```

* Replace the source code of Qemu-3.0.0 in the associated files, with the code given in this repository under *backend/* directory.

* Boot the VM  
(*some changes in the boot up script of qemu should be implemented:  **-device virtio-cryptodev-pci** flag should be added in order to add this pci device in qemu)*

* Inside the VM, compile the frontend driver and add the module into the kernel running

```console
$ chmod +x initCrypto.sh
$ ./initCrypto.sh
```
This will also add 32 Nodes,named ***cryptodevX ( X = [0,32] )***, under the */dev* directory that could be used for accessing the hardware.

### Testing the driver
You can test the driver running a simple encryption-decryption test with

```console
$ ./test_crypto
```
OR *(for forked processes accessing the driver)*

```console
$ ./test_fork_crypto
```
OR with the [encrypted-chat](https://github.com/ntouev/VirtIO_cryptodev/tree/master/encrypted-chat).
