# SPDX-License-Identifier: MIT
#
# Copyright (C) 2020 BayLibre SAS
# Author: Bartosz Golaszewski <bgolaszewski@baylibre.com>
#
# This bbclass allows creating of dm-verity protected partition images. It
# generates a device image file with dm-verity hash data appended at the end
# plus the corresponding .env file containing additional information needed
# to mount the image such as the root hash in the form of ell variables. To
# assure data integrity, the root hash must be stored in a trusted location
# or cryptographically signed and verified.
#
# Usage:
#     DM_VERITY_IMAGE = "core-image-full-cmdline" # or other image
#     DM_VERITY_IMAGE_TYPE = "ext4" # or ext2, ext3 & btrfs
#     IMAGE_CLASSES += "dm-verity-img"
#
# The resulting image can then be used to implement the device mapper block
# integrity checking on the target device.

# Define the location where the DM_VERITY_IMAGE specific dm-verity root hash
# is stored where it can be installed into associated initramfs rootfs.
STAGING_VERITY_DIR ?= "${TMPDIR}/work-shared/${MACHINE}/dm-verity"

# Define the data block size to use in veritysetup.
DM_VERITY_IMAGE_DATA_BLOCK_SIZE ?= "1024"

# Process the output from veritysetup and generate the corresponding .env
# file. The output from veritysetup is not very machine-friendly so we need to
# convert it to some better format. Let's drop the first line (doesn't contain
# any useful info) and feed the rest to a script.
process_verity() {
    local ENV="${STAGING_VERITY_DIR}/${IMAGE_BASENAME}.$TYPE.verity.env"
    local ROOT_HASH_FILE="${STAGING_VERITY_DIR}/${IMAGE_BASENAME}.$TYPE.verity.roothash"
    install -d ${STAGING_VERITY_DIR}
    rm -f $ENV

    # Each line contains a key and a value string delimited by ':'. Read the
    # two parts into separate variables and process them separately. For the
    # key part: convert the names to upper case and replace spaces with
    # underscores to create correct shell variable names. For the value part:
    # just trim all white-spaces.
    IFS=":"
    while read KEY VAL; do
        printf '%s=%s\n' \
            "$(echo "$KEY" | tr '[:lower:]' '[:upper:]' | sed 's/ /_/g')" \
            "$(echo "$VAL" | tr -d ' \t')" >> $ENV
        local "$(echo "$KEY" | tr '[:lower:]' '[:upper:]' | sed 's/ /_/g')"="$(echo "$VAL" | tr -d ' \t')"
    done

    # Add partition size
    echo "DATA_SIZE=$SIZE" >> $ENV

    # Append root hash signature to verity superblock
    if [ -n "${DM_VERITY_KEY}" ]; then
        if [ ! -n "${DM_VERITY_CERT}" ]; then
            DM_VERITY_CERT=${DM_VERITY_KEY}
        fi

        echo -n ${ROOT_HASH} > ${ROOT_HASH_FILE}

        openssl smime -sign -nocerts -noattr -binary -in ${ROOT_HASH_FILE} \
                -inkey ${DM_VERITY_KEY} -signer ${DM_VERITY_CERT} \
                -outform der -out ${ROOT_HASH_FILE}.sig

        # Append signature to verity superblock (into allocated hash block)
        local SIGSIZE=$(stat --printf="%s" ${ROOT_HASH_FILE}.sig)
        local SIGBLOCK=$(expr ${SIZE} + 512)

        # Verity superblock lives in first hash block, but only occupies
        # 512 bytes, check if we have enough space for root hash signature
        if [ $(expr $SIGSIZE + 2 + 512) -gt ${HASH_BLOCK_SIZE} ]; then
            bberror "Root hash signature does not fit into verity superblock"
        fi

        # Convert to hex
        SIGSIZE=$(printf '%04x' ${SIGSIZE})
        # Convert to little endian (__le16) (e.g. 042f to 2f04)
        SIGSIZE=$(echo $SIGSIZE | grep -o .. | tac | tr -d "\n")
        # Write into binary format
        echo -n ${SIGSIZE} | xxd -p -r > ${ROOT_HASH_FILE}.sig_size
        # Generate sig_size+sig binary blob
        cat ${ROOT_HASH_FILE}.sig_size ${ROOT_HASH_FILE}.sig > ${ROOT_HASH_FILE}.sig.blob
        # Inject blob to verity block
        dd if=${ROOT_HASH_FILE}.sig.blob of=${OUTPUT} seek=${SIGBLOCK} bs=1 conv=notrunc
    fi
}

verity_setup() {
    local TYPE=$1
    local INPUT=${IMAGE_NAME}${IMAGE_NAME_SUFFIX}.$TYPE
    local SIZE=$(stat --printf="%s" $INPUT)
    local OUTPUT=$INPUT.verity

    cp -a $INPUT $OUTPUT

    # Yocto 'sometimes' generates ext files larger (a few kb)
    # than the actual ext filesystem, ensure that ext filesystem
    # uses the full available space so that the dm verity hash tree
    # is correctly appended right after the ext filesystem.
    resize2fs $OUTPUT

    # Let's drop the first line of output (doesn't contain any useful info)
    # and feed the rest to another function.
    veritysetup --data-block-size=${DM_VERITY_IMAGE_DATA_BLOCK_SIZE} --hash-offset=$SIZE format $OUTPUT $OUTPUT | tail -n +2 | process_verity
}

VERITY_TYPES = "ext2.verity ext3.verity ext4.verity btrfs.verity ext4.verity.gz"
IMAGE_TYPES += "${VERITY_TYPES}"
CONVERSIONTYPES += "verity"
CONVERSION_CMD:verity = "verity_setup ${type}"
CONVERSION_DEPENDS_verity = "cryptsetup-native openssl-native xxd-native e2fsprogs-native"

python __anonymous() {
    verity_image = d.getVar('DM_VERITY_IMAGE')
    verity_type = d.getVar('DM_VERITY_IMAGE_TYPE')
    image_fstypes = d.getVar('IMAGE_FSTYPES')
    pn = d.getVar('PN')

    if not verity_image or not verity_type:
        return

    if verity_image != pn:
        return # This doesn't concern this image

    if len(verity_type.split()) is not 1:
        bb.fatal('DM_VERITY_IMAGE_TYPE must contain exactly one type')

    d.appendVar('IMAGE_FSTYPES', ' %s.verity' % verity_type)

    # If we're using wic: we'll have to use partition images and not the rootfs
    # source plugin so add the appropriate dependency.
    if 'wic' in image_fstypes:
        dep = ' %s:do_image_%s' % (pn, verity_type)
        d.appendVarFlag('do_image_wic', 'depends', dep)
}
