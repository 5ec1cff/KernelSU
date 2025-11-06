#include <linux/file.h>
#include <linux/fs.h>

struct ksu_file_proxy_data {
	struct file* orig;
	struct file_operations ops;
};

struct ksu_file_proxy_data* ksu_make_proxy(struct file* fp);
void ksu_delete_proxy(struct ksu_file_proxy_data* data);
