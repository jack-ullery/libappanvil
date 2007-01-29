#include <linux/security.h>
#include <linux/module.h>

static void log_path(char *op, struct path *path)
{
	char *page, *name;

        page = (char *)__get_free_page(GFP_KERNEL);
        if (!page) {
		printk(KERN_ERR "foobar(%s): Unable to get page for path %p/%p\n",
			op, path->mnt, path->dentry);
		goto out;
	}

	name=d_path(path->dentry, path->mnt, page, PAGE_SIZE);
	if (IS_ERR(name)){
		printk(KERN_ERR "foobar(%s): Error path %p/%p overflowed buffer\n",
			op, path->mnt, path->dentry);
		goto out;
	}

	printk(KERN_INFO "foobar(%s): %p/%p->'%s'\n",
		op, path->mnt, path->dentry, name);

out:
	if (page)
		free_page((unsigned long)page);
}

static int foobar_inode_getattr(struct path *path)
{
	log_path("inode_getattr", path);

	return 0;
}

struct security_operations foobar_ops = {
	.inode_getattr =		foobar_inode_getattr,
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
