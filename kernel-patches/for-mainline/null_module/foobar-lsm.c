#include <linux/security.h>
#include <linux/module.h>
#include <linux/namei.h>

static void log_path(char *op, struct dentry *dentry, struct vfsmount *mnt)
{
	char *page, *name;

        page = (char *)__get_free_page(GFP_KERNEL);
        if (!page) {
		printk(KERN_ERR "foobar(%s): Unable to get page for path %p/%p\n",
			op, mnt, dentry);
		goto out;
	}

	name=d_path(dentry, mnt, page, PAGE_SIZE);
	if (IS_ERR(name)){
		printk(KERN_ERR "foobar(%s): Error path %p/%p overflowed buffer\n",
			op, mnt, dentry);
		goto out;
	}

	printk(KERN_INFO "foobar(%s): %p/%p->'%s'\n",
		op, mnt, dentry, name);

out:
	if (page)
		free_page((unsigned long)page);
}

static int foobar_inode_mkdir(struct inode *inode, struct dentry *dentry,
                                 struct vfsmount *mnt, int mask)
{
	log_path("inode_mkdir", dentry, mnt);

	return 0;
}

static int foobar_inode_rmdir(struct inode *inode, struct dentry *dentry,
			      struct vfsmount *mnt)
{
	log_path("inode_rmdir", dentry, mnt);

	return 0;
}

static int foobar_inode_create(struct inode *inode, struct dentry *dentry,
                               struct vfsmount *mnt, int mask)
{
	log_path("inode_create", dentry, mnt);

	return 0;
}

static int foobar_inode_link(struct dentry *old_dentry, 
			     struct vfsmount *old_mnt,
			     struct inode *inode,
			     struct dentry *new_dentry,
			     struct vfsmount *new_mnt)
{
	log_path("inode_link (old)", old_dentry, old_mnt);
	log_path("inode_link (new)", new_dentry, new_mnt);

	return 0;
}

static int foobar_inode_unlink(struct inode *dir, struct dentry *dentry,
                             struct vfsmount *mnt)
{
	log_path("inode_unlink", dentry, mnt);

	return 0;
}

static int foobar_inode_mknod(struct inode *inode, struct dentry *dentry,
			      struct vfsmount *mnt, int mode, dev_t dev)
{
	log_path("inode_mknod", dentry, mnt);

	return 0;
}

static int foobar_inode_rename(struct inode *old_inode,
			       struct dentry *old_dentry, 
			       struct vfsmount *old_mnt,
			       struct inode *new_inode,
			       struct dentry *new_dentry,
			       struct vfsmount *new_mnt)
{
	log_path("inode_rename (old)", old_dentry, old_mnt);
	log_path("inode_rename (new)", new_dentry, new_mnt);

	return 0;
}

static int foobar_inode_setattr(struct dentry *dentry, struct vfsmount *mnt, 
				struct iattr *iattr)
{
	log_path("inode_setattr", dentry, mnt);

	return 0;
}

static int foobar_inode_setxattr(struct dentry *dentry, struct vfsmount *mnt, 
			         char *name, void *value, size_t size, 
				 int flags)
{
	log_path("inode_setxattr", dentry, mnt);

	return 0;
}

static int foobar_inode_getxattr(struct dentry *dentry, 
				 struct vfsmount *mnt, char *name)
{
	log_path("inode_getxattr", dentry, mnt);

	return 0;
}

static int foobar_inode_listxattr(struct dentry *dentry,
				  struct vfsmount *mnt)
{
	log_path("inode_listxattr", dentry, mnt);

	return 0;
}

static int foobar_inode_removexattr(struct dentry *dentry, 
				    struct vfsmount *mnt, char *name)
{
	log_path("inode_removexattr", dentry, mnt);

	return 0;
}

static int foobar_inode_symlink(struct inode *dir,
			        struct dentry *dentry, struct vfsmount *mnt, 
				const char *old_name)
{
	log_path("inode_symlink", dentry, mnt);

	return 0;
}

static int foobar_inode_permission(struct inode *inode, int mask,
                                      struct nameidata *nd)
{
	log_path("inode_permission", nd->dentry, nd->mnt);

	return 0;
}

struct security_operations foobar_ops = {
	.inode_create =		foobar_inode_create,
	.inode_link =		foobar_inode_link,
	.inode_unlink =		foobar_inode_unlink,
	.inode_mkdir =		foobar_inode_mkdir,
	.inode_rmdir =		foobar_inode_rmdir,
	.inode_mknod =		foobar_inode_mknod,
	.inode_rename =		foobar_inode_rename,
	.inode_setattr =	foobar_inode_setattr,
	.inode_setxattr =	foobar_inode_setxattr,
	.inode_getxattr =	foobar_inode_getxattr,
        .inode_listxattr =      foobar_inode_listxattr,
        .inode_removexattr =    foobar_inode_removexattr,
        .inode_symlink =        foobar_inode_symlink,
//	.inode_permission =	foobar_inode_permission,
};

static int __init foobar_init(void)
{
int error;

	if ((error = register_security(&foobar_ops))) {
		printk(KERN_ERR "Unable to load dummy module\n");
	}

	return error;
}

static void __exit foobar_exit(void)
{
	if (unregister_security(&foobar_ops))
		printk(KERN_ERR "Unable to properly unregister module\n");
}

module_init(foobar_init);
module_exit(foobar_exit);

MODULE_DESCRIPTION("Test module");
MODULE_LICENSE("GPL");
