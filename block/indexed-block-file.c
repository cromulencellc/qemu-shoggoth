/*
 * Rapid Analysis QEMU System Emulator
 *
 * Copyright (c) 2020 Cromulence LLC
 *
 * Distribution Statement A
 *
 * Approved for Public Release, Distribution Unlimited
 *
 * Authors:
 *  Joseph Walker
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 * 
 * The creation of this code was funded by the US Government.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "block/qdict.h"
#include "block/indexed-block-file.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qstring.h"
#include "qapi/qobject-input-visitor.h"
#include "qapi/qapi-visit-block-core.h"
#include "qemu/option.h"
#include "block/block_int.h"
#include "sysemu/block-backend.h"
#include "cromulence/inlines.h"

static QemuOptsList ibf_create_opts = {
    .name = "ibf",
    .head = QTAILQ_HEAD_INITIALIZER(ibf_create_opts.head),
    .desc = {
        {
            .name = BLOCK_OPT_FILE_PATH,
            .type = QEMU_OPT_STRING,
            .help = "The path to the indexed file."
        },
        { /* end of list */ }
    },
};

static QemuOptsList ibf_runtime_opts = {
    .name = "ibf",
    .head = QTAILQ_HEAD_INITIALIZER(ibf_runtime_opts.head),
    .desc = {
        {
            .name = "filename",
            .type = QEMU_OPT_STRING,
            .help = "File name of the image",
        },
        { /* end of list */ }
    },
};   

typedef struct IBFTransactionPacket {
    uint8_t *data;
    uint64_t size;
    SHA1_HASH_TYPE *hash;
} IBFTransactionPacket;

static void ibf_if_read(void *opaque, FILE *fp, size_t read_size_hint, SHA1_HASH_TYPE *hash)
{
    IBFTransactionPacket *p = opaque;
    p->size = read_size_hint;
    p->data = g_new(uint8_t, read_size_hint);

    fread_checked(p->data, p->size, fp);
}
    
static void ibf_if_write(void *opaque, FILE *fp) 
{
    IBFTransactionPacket *p = opaque;
    fwrite(p->data, p->size, 1, fp);
}

static void ibf_calculate_hash(void *opaque, SHA1_HASH_TYPE *hash) 
{
    IBFTransactionPacket *p = opaque;
    memcpy(*hash, p->hash, sizeof(SHA1_HASH_TYPE));
}

static void create_file_visitor(IFVisitor *visitor, void *opaque)
{
    visitor->opaque         = opaque;
    visitor->if_read        = ibf_if_read;
    visitor->if_write       = ibf_if_write; 
    visitor->calculate_hash = ibf_calculate_hash;
}

static int ibf_file_open(BlockDriverState *bs, QDict *options, int flags, Error **errp)
{
    int ret = -EINVAL;
    QemuOpts *opts = NULL;
    Error *local_err = NULL;
    const char *file_name = NULL;

    // Prepare to parse args.
    opts = qemu_opts_create(&ibf_runtime_opts, NULL, 0, errp);
    if (opts)
    {

        // Parse the dictionary for args
        qemu_opts_absorb_qdict(opts, options, &local_err);
        if(!local_err)
        {

            file_name = qemu_opt_get(opts, "filename");

            // Verify that we have a file name.
            if (file_name)
            {
                // Grab the device state
                BDRVIBFState *ibfs = bs->opaque;
                
                // Attempt to open the file
                ibfs->idx_file = indexed_file_new(file_name);

                // Verify that we had success.
                if (ibfs->idx_file)
                {
                    // success
                    ret = 0;
                }
                else
                {
                    // There was an error opening the file.
                    error_setg(errp, "There was a problem opening the file: %s\n", file_name);            
                }
                
            }
            else
            {
                // There was no file name.
                error_setg(errp, "No file name supplied\n");
            }
        }
        else
        {
            // Merge the error over to the I/O param
            // This function call frees local error - so thats done
            error_propagate(errp, local_err);
        }

        // Free the opts
        qemu_opts_del(opts);
    }
    
    // All done
    return ret;
}

static void ibf_close(BlockDriverState *bs)
{
    BDRVIBFState *ibfs = bs->opaque;

    // Freeing the file will close it.
    object_unref(OBJECT(ibfs->idx_file));

}

static int64_t ibf_getlength(BlockDriverState *bs)
{
    BDRVIBFState *ibfs = bs->opaque;
    IndexedFileClass *ibfs_class = INDEXED_FILE_GET_CLASS(ibfs->idx_file);
    return ibfs_class->get_length(ibfs->idx_file);
}

static int coroutine_fn 
ibf_co_create(BlockdevCreateOptions *opts, Error **errp) 
{
    int ret = -EINVAL;
    
    // First, try to create a file 
    // Then verify that we found success.   
    IndexedFile *file = indexed_file_new(opts->u.ibf.filename);
    if (file)
    {
        // All we needed to do was create a file
        // we can close it now.
        object_unref(OBJECT(file));
        ret = 0;
    }
    else
    {
        // There was an error, we should report.
        error_setg(errp, "There was a problem creating the file: %s\n", opts->u.ibf.filename);
    }
    
    return ret;
}

static int coroutine_fn 
ibf_co_create_opts(const char *filename, QemuOpts *opts, Error **errp) 
{
    int ret;
    Visitor *v;
    QDict *qdict;
    Error *local_err = NULL;
    BlockdevCreateOptions *create_options = NULL;

    // Convert opts to dictionary
    qdict = qemu_opts_to_qdict_filtered(opts, NULL, bdrv_ibf.create_opts, true);

    // Add some of our values to it
    qdict_put_str(qdict, "driver", "ibf");
    qdict_put_str(qdict, "filename", filename);

    // Create a visitor to search for data
    v = qobject_input_visitor_new_flat_confused(qdict, errp);
        
    // Verify that we have a visitor.
    if (v)
    {
        // Find block dev creation information.
        visit_type_BlockdevCreateOptions(v, NULL, &create_options, &local_err);
        visit_free(v);
    
        // Check to see if we have an error
        if (!local_err)
        {
            // If there are no errors so far, we can 
            // actually create the file.
            ret = ibf_co_create(create_options, errp);
        }
        else
        {   
            // Propagate the error and free memory.
            error_propagate(errp, local_err); 
            ret = -EINVAL;
        }
    }
    else
    {
        // Error value
        ret = -EINVAL;
    }
    
    return ret;
}


static int ibf_dump_state(BlockDriverState *bs, BlockDriverState *target_bs, SHA1_HASH_TYPE hash)
{
    if (target_bs->drv->bdrv_receive_dump)
    {
        BDRVIBFState *ibfs = bs->opaque;
        IndexedFile *idxf = ibfs->idx_file;
        IndexedFileClass *idxf_class = INDEXED_FILE_GET_CLASS(idxf);
        IBFTransactionPacket tp;
        IFVisitor visitor;
    
        // We want to create a visitor with
        // empty data.
        tp.data = NULL;
        tp.size = 0;
        tp.hash = (SHA1_HASH_TYPE *)&hash;
        create_file_visitor(&visitor, &tp);
    
        // Attempt to load a hash and make sure that the data is loaded
        if (idxf_class->load_from_hash(idxf, &visitor, hash) && tp.data)
        {
            // pass the data along to the target drive
            target_bs->drv->bdrv_receive_dump(target_bs, tp.data, tp.size, hash);
        }
        // TODO free buffer
        
    }
    return 0;
}

static int ibf_receive_dump(BlockDriverState *bs, uint8_t *data, size_t data_len, SHA1_HASH_TYPE hash)
{
    BDRVIBFState *ibfs = bs->opaque;
    IndexedFile *idxf = ibfs->idx_file;
    IndexedFileClass *idxf_class = INDEXED_FILE_GET_CLASS(idxf);
    IBFTransactionPacket tp;
    IFVisitor visitor;
    
    // We want to create a visitor that
    // has been packed with the data and size
    tp.data = data;
    tp.size = data_len;
    tp.hash = (SHA1_HASH_TYPE *)&hash;
    create_file_visitor(&visitor, &tp);
    
    // We will tell the file to write now
    idxf_class->write_data(idxf, &visitor, NULL, NULL);

    return 0;
}

BlockDriver bdrv_ibf = {
    .format_name             = "ibf",
    .protocol_name           = "ibf",
    .instance_size           = sizeof(BDRVIBFState),
    .create_opts             = &ibf_create_opts,    

    .bdrv_file_open           = ibf_file_open,
    .bdrv_close               = ibf_close,
    .bdrv_getlength           = ibf_getlength, 

    .bdrv_co_create           = ibf_co_create,
    .bdrv_co_create_opts      = ibf_co_create_opts,

    .bdrv_dump_state          = ibf_dump_state,
    .bdrv_receive_dump        = ibf_receive_dump,
};

static void bdrv_ibf_init(void)
{
    bdrv_register(&bdrv_ibf);
}

block_init(bdrv_ibf_init);