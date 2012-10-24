/*
 *  linux/fs/ext2/file.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/file.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  ext2 fs regular file handling primitives
 *
 *  64-bit file support on 64-bit platforms by Jakub Jelinek
 * 	(jj@sunsite.ms.mff.cuni.cz)
 */

#include <linux/time.h>
#include "ext2.h"
#include "xattr.h"
#include "acl.h"
#include <asm/uaccess.h>

/*
 * Called when filp is released. This happens when all file descriptors
 * for a single struct file are closed. Note that different open() calls
 * for the same file yield different struct file structures.
 */
static int ext2_release_file (struct inode * inode, struct file * filp)
{
	if (filp->f_mode & FMODE_WRITE) {
		mutex_lock(&EXT2_I(inode)->truncate_mutex);
		ext2_discard_reservation(inode);
		mutex_unlock(&EXT2_I(inode)->truncate_mutex);
	}
	return 0;
}

/* 
 * ===  FUNCTION  ==============================================================
 *         Name:  do_encrypted_sync_write
 *
 *  Description:  Wrapper for do_sync_write. Takes same params, and when
 *                encryption key is not set, it defaults to just being a
 *                passthrough method anyway.
 *
 *                If the file being written to is under the root folder named by
 *                EXT3301_ENCRYPT_DIR, then this method takes the current buffer
 *                and encrypts each element of it.
 * 
 *      Version:  0.0.1
 *       Params:  struct file *filp
 *                const char __user *buf
 *                size_t len
 *                loff_t *ppos
 *      Returns:  ssize_t number of bytes written
 *        Usage:  do_encrypted_sync_write( struct file *filp,
 *                    const char __user *buf, size_t len, loff_t *ppos )
 *      Outputs:  N/A

 *        Notes:  
 * =============================================================================
 */
ssize_t do_encrypted_sync_write(struct file *filp, const char __user *buf,
        size_t len, loff_t *ppos)
{
    int i;
    mm_segment_t old_fs;
    ssize_t retval;
    struct dentry *parent, *second_last;
    char *newbuf = kmalloc(len, GFP_NOFS);
    int encrypting = 0;

    memset(newbuf, 0, len);
    memcpy(newbuf, buf, len - 1);

    // If we can't get the name, we can't tell whether it's the /encrypt directory
    // so just pass through
    if (filp != NULL && filp->f_dentry != NULL && &filp->f_dentry->d_name != NULL) {
        
        second_last = NULL;
        parent = filp->f_dentry->d_parent;
        while (parent != NULL) {
            if (strncmp(parent->d_name.name, "/", 2) == 0) {
                if (second_last != NULL &&
                    strncmp(second_last->d_name.name, EXT3301_ENCRYPT_DIR,
                        strlen(EXT3301_ENCRYPT_DIR) + 1) == 0) {
                    // The file is in the encrypt directory, work your magic
                    for ( i = 0; i < len; i++ )
                        newbuf[i] = buf[i] ^ ext3301_enc_key; // Simple encryption
                    newbuf[len] = 0;
                    encrypting = 1;
                }
                // We're at the root of parents, break out
                break;
            }

            // Next parent
            second_last = parent;
            parent = parent->d_parent;
        }
        
    }

    if (encrypting) {
        // Switch to kernel space before trying to write. Avoids EFAULT
        old_fs = get_fs();
        set_fs(KERNEL_DS);
        retval = do_sync_write(filp, newbuf, len, ppos);
        set_fs(old_fs);
    } else
        retval = do_sync_write(filp, buf, len, ppos);

    kfree(newbuf);

    return retval;
}

/* 
 * ===  FUNCTION  ==============================================================
 *         Name:  do_encrypted_sync_read
 *
 *  Description:  Wrapper for do_sync_read. Takes same params, and when
 *                encryption key is not set, it defaults to just being a
 *                passthrough method anyway.
 *
 *                If the file being read from is under the root folder named by
 *                EXT3301_ENCRYPT_DIR, then this method takes the current buffer
 *                and encrypts each element of it.
 * 
 *      Version:  0.0.1
 *       Params:  struct file *filp
 *                char __user *buf
 *                size_t len
 *                loff_t *ppos
 *      Returns:  ssize_t number of bytes written
 *        Usage:  do_encrypted_sync_read( struct file *filp, char __user *buf,
 *                    size_t len, loff_t *ppos )
 *      Outputs:  N/A

 *        Notes:  
 * =============================================================================
 */
ssize_t do_encrypted_sync_read(struct file *filp, char __user *buf, size_t len,
        loff_t *ppos)
{
    int i;
    mm_segment_t old_fs;
    ssize_t retval;
    struct dentry *parent, *second_last;
    char *newbuf = kmalloc(len, GFP_NOFS);

    memset(newbuf, 0, len);

    // Switch to kernel space before trying to write. Avoids EFAULT
    old_fs = get_fs();
    set_fs(KERNEL_DS);
    retval = do_sync_read(filp, newbuf, len, ppos);
    set_fs(old_fs);

    // If we can't get the name, we can't tell whether it's the /encrypt directory
    // so just pass through
    if (filp != NULL && filp->f_dentry != NULL && &filp->f_dentry->d_name != NULL) {
        
        second_last = NULL;
        parent = filp->f_dentry->d_parent;
        while (parent != NULL) {
            if (strncmp(parent->d_name.name, "/", 2) == 0) {
                if (second_last != NULL &&
                    strncmp(second_last->d_name.name, EXT3301_ENCRYPT_DIR,
                        strlen(EXT3301_ENCRYPT_DIR) + 1) == 0) {
                    // The file is in the encrypt directory, work your magic
                    for ( i = 0; i < len; i++ )
                        newbuf[i] = newbuf[i] ^ ext3301_enc_key; // Simple encryption
                    newbuf[len] = 0;
                }
                // We're at the root of parents, break out
                break;
            }

            // Next parent
            second_last = parent;
            parent = parent->d_parent;
        }
        
    }

    copy_to_user(buf, newbuf, len);

    kfree(newbuf);

    return retval;
}

/*
 * We have mostly NULL's here: the current defaults are ok for
 * the ext2 filesystem.
 */
const struct file_operations ext2_file_operations = {
	.llseek		= generic_file_llseek,
	.read		= do_encrypted_sync_read,
	.write		= do_encrypted_sync_write,
	.aio_read	= generic_file_aio_read,
	.aio_write	= generic_file_aio_write,
	.unlocked_ioctl = ext2_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= ext2_compat_ioctl,
#endif
	.mmap		= generic_file_mmap,
	.open		= generic_file_open,
	.release	= ext2_release_file,
	.fsync		= simple_fsync,
	.splice_read	= generic_file_splice_read,
	.splice_write	= generic_file_splice_write,
};

#ifdef CONFIG_EXT2_FS_XIP
const struct file_operations ext2_xip_file_operations = {
	.llseek		= generic_file_llseek,
	.read		= xip_file_read,
	.write		= xip_file_write,
	.unlocked_ioctl = ext2_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= ext2_compat_ioctl,
#endif
	.mmap		= xip_file_mmap,
	.open		= generic_file_open,
	.release	= ext2_release_file,
	.fsync		= simple_fsync,
};
#endif

const struct inode_operations ext2_file_inode_operations = {
	.truncate	= ext2_truncate,
#ifdef CONFIG_EXT2_FS_XATTR
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= ext2_listxattr,
	.removexattr	= generic_removexattr,
#endif
	.setattr	= ext2_setattr,
	.check_acl	= ext2_check_acl,
	.fiemap		= ext2_fiemap,
};
