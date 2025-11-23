#ifndef __KSU_H_KSU_MANAGER
#define __KSU_H_KSU_MANAGER

#include <linux/cred.h>
#include <linux/types.h>

#define KSU_INVALID_UID -1

extern uid_t ksu_manager_uid; // DO NOT DIRECT USE

static inline bool ksu_is_manager_uid_valid()
{
    return ksu_manager_uid != KSU_INVALID_UID;
}

#ifndef CONFIG_KSU_SUSFS
static inline bool is_manager()
{
    return unlikely(ksu_manager_uid == current_uid().val);
}
#else
static inline bool is_manager()
{
    return unlikely(ksu_manager_uid == current_uid().val % 100000);
}
#endif // #ifndef CONFIG_KSU_SUSFS

static inline uid_t ksu_get_manager_uid()
{
    return ksu_manager_uid;
}

#ifndef CONFIG_KSU_SUSFS
static inline void ksu_set_manager_uid(uid_t uid)
{
    ksu_manager_uid = uid;
}
#else
static inline void ksu_set_manager_uid(uid_t uid)
{
    ksu_manager_uid = uid % 100000;
}
#endif // #ifndef CONFIG_KSU_SUSFS

static inline void ksu_invalidate_manager_uid()
{
    ksu_manager_uid = KSU_INVALID_UID;
}

int ksu_observer_init(void);
#endif
