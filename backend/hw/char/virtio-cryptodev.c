/*
 * Virtio Cryptodev Device
 *
 * Implementation of virtio-cryptodev qemu backend device.
 *
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
 * Konstantinos Papazafeiropoulos <kpapazaf@cslab.ece.ntua.gr>
 *
 * Implementation of vq_handle_output():
 *
 * Gouliamou Maria-Ethel
 * Ntouros Evangelos
 *
 */

#include "qemu/osdep.h"
#include "qemu/iov.h"
#include "hw/qdev.h"
#include "hw/virtio/virtio.h"
#include "standard-headers/linux/virtio_ids.h"
#include "hw/virtio/virtio-cryptodev.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <crypto/cryptodev.h>

static uint64_t get_features(VirtIODevice *vdev, uint64_t features,
                             Error **errp)
{
    DEBUG_IN();
    return features;
}

static void get_config(VirtIODevice *vdev, uint8_t *config_data)
{
    DEBUG_IN();
}

static void set_config(VirtIODevice *vdev, const uint8_t *config_data)
{
    DEBUG_IN();
}

static void set_status(VirtIODevice *vdev, uint8_t status)
{
    DEBUG_IN();
}

static void vser_reset(VirtIODevice *vdev)
{
    DEBUG_IN();
}

static void vq_handle_output(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtQueueElement *elem;
    unsigned int *syscall_type, *ioctl_type;
    unsigned char *key;
    //unsigned char *output_msg, *input_msg,
    long *host_ret;
    struct session_op *sess;
    struct crypt_op *cryp;
    uint32_t *ses;
    unsigned char *src, *dst, *iv;
    //uint16_t *op;

    //fd_ptr should be heap allocated WHY??
    int *fd_ptr, *fd_ptr_to_close;

    DEBUG_IN();

    elem = virtqueue_pop(vq, sizeof(VirtQueueElement));
    if (!elem) {
        DEBUG("No item to pop from VQ :(");
        return;
    }

    DEBUG("I have got an item from VQ :)");

    syscall_type = elem->out_sg[0].iov_base;
    switch (*syscall_type) {
    case VIRTIO_CRYPTODEV_SYSCALL_TYPE_OPEN:
        DEBUG("VIRTIO_CRYPTODEV_SYSCALL_TYPE_OPEN");
        fd_ptr = elem->in_sg[0].iov_base;
        *fd_ptr = open(CRYPTODEV_FILENAME, O_RDWR);
        if (*fd_ptr < 0) {
            DEBUG("File does not exist");
        }
        printf("Opened /dev/crypto file with fd = %d\n", *fd_ptr);
        break;

    //better error check is needed
    case VIRTIO_CRYPTODEV_SYSCALL_TYPE_CLOSE:
        DEBUG("VIRTIO_CRYPTODEV_SYSCALL_TYPE_CLOSE");
        //fd_ptr could be used. No actual reason why fd_ptr_to_close is used
        fd_ptr_to_close = elem->out_sg[1].iov_base;
        if (close(*fd_ptr_to_close) < 0) {
            DEBUG("close() error");
        }
        else {
            printf("Closed /dev/crypto file with fd = %d\n", *fd_ptr_to_close);
        }
        break;

    case VIRTIO_CRYPTODEV_SYSCALL_TYPE_IOCTL:
        DEBUG("VIRTIO_CRYPTODEV_SYSCALL_TYPE_IOCTL");
        fd_ptr = elem->out_sg[1].iov_base;
        ioctl_type = elem->out_sg[2].iov_base;
        switch (*ioctl_type) {
        case VIRTIO_CRYPTODEV_IOCTL_CIOCGSESSION:
            DEBUG("Entering CIOCGSESSION");
            key = elem->out_sg[3].iov_base;
            sess = elem->in_sg[0].iov_base;
            host_ret = elem->in_sg[1].iov_base;

            sess->key = key;
            *host_ret = ioctl(*fd_ptr, CIOCGSESSION, sess);
            if (*host_ret)
                perror("ioctl(CIOCGSESSION)");

            printf("The key is:\n");
            for(int i=0; i< sess->keylen;i++) {
                printf("%x", *(sess->key + i));
            }
            printf("\n");
            DEBUG("Leaving CIOCGSESSION");
            break;

        case VIRTIO_CRYPTODEV_IOCTL_CIOCFSESSION:
            DEBUG("Entering CIOCFSESSION");
            ses = elem->out_sg[3].iov_base;
            host_ret = elem->in_sg[0].iov_base;

            *host_ret = ioctl(*fd_ptr, CIOCFSESSION, ses);
            if (*host_ret)
                perror("ioctl(CIOCFSESSION)");

            DEBUG("Leaving CIOCFSESSION");
            break;

        case VIRTIO_CRYPTODEV_IOCTL_CIOCCRYPT:
            DEBUG("Entering CIOCCRYPT");
            cryp = elem->out_sg[3].iov_base;
            src = elem->out_sg[4].iov_base;
            iv = elem->out_sg[5].iov_base;
            host_ret = elem->in_sg[0].iov_base;
            dst = elem->in_sg[1].iov_base;

            cryp->src = src;
            cryp->dst = dst;
            cryp->iv = iv;
            *host_ret = ioctl(*fd_ptr, CIOCCRYPT, cryp);
            if (*host_ret)
                perror("ioctl(CIOCCRYPT)");

            printf("\n");
            DEBUG("Leaving CIOCCRYPT");
            break;

        default:
            DEBUG("Unsupported ioctl command!");
            break;
        }

        break;

    default:
        DEBUG("Unknown syscall_type");
        break;
    }

    //push the data in the VirtIO ring buffer
    virtqueue_push(vq, elem, 0);
    //notifies the frontend driver that the work is done via interrupt
    //bare in mind that qemu (backend) is the hardware of the VM.
    //here is not needed because frontend ckecks if the work is done
    //looking the two pointers in the ring buffer. In order to apply this
    //method of checking (using the interrupt), you should change the interrupt
    //handler (function vq_has_data() in file crypto-module.c).
    virtio_notify(vdev, vq);
    g_free(elem);
}

static void virtio_cryptodev_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);

    DEBUG_IN();

    virtio_init(vdev, "virtio-cryptodev", VIRTIO_ID_CRYPTODEV, 0);
    virtio_add_queue(vdev, 128, vq_handle_output);
}

static void virtio_cryptodev_unrealize(DeviceState *dev, Error **errp)
{
    DEBUG_IN();
}

static Property virtio_cryptodev_properties[] = {
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_cryptodev_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *k = VIRTIO_DEVICE_CLASS(klass);

    DEBUG_IN();
    dc->props = virtio_cryptodev_properties;
    set_bit(DEVICE_CATEGORY_INPUT, dc->categories);

    k->realize = virtio_cryptodev_realize;
    k->unrealize = virtio_cryptodev_unrealize;
    k->get_features = get_features;
    k->get_config = get_config;
    k->set_config = set_config;
    k->set_status = set_status;
    k->reset = vser_reset;
}

static const TypeInfo virtio_cryptodev_info = {
    .name          = TYPE_VIRTIO_CRYPTODEV,
    .parent        = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtCryptodev),
    .class_init    = virtio_cryptodev_class_init,
};

static void virtio_cryptodev_register_types(void)
{
    type_register_static(&virtio_cryptodev_info);
}

type_init(virtio_cryptodev_register_types)
