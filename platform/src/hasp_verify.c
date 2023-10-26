#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/prctl.h>

#include "hasp_api.h"
#include "hasp_vcode.h"
#include "hasp_log.h"

#define DEFAULT_INTERVAL_S (15 * 60)
#define MAX_INTERVAL_S (24 * 60 * 60)

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#define ATOMIC_READ(x) __atomic_fetch_add(x, 0, __ATOMIC_RELAXED)
#define ATOMIC_SET(x, y) __atomic_store_n(x, y, __ATOMIC_RELAXED)

struct shm_data
{
    uint64_t feature_id;
    uint64_t status;
    uint64_t timestamp;
    uint64_t interval;
};

static char *shm_key = "hasp_verify";

static unsigned char data[] =
    {
        0x74, 0x65, 0x73, 0x74, 0x20, 0x73, 0x74, 0x72,
        0x69, 0x6E, 0x67, 0x20, 0x31, 0x32, 0x33, 0x34};

static unsigned int datalen = sizeof(data);
static unsigned int need_stop = 0;

/******************************************************************************
 * Utils
 ******************************************************************************/

static void signal_handler(int signo)
{
    if (signo == SIGUSR1)
    {
        LOG_LEVEL_SET_DEBUG();
        LOG_INFO("hasp_monitor: recv SIGUSR1");
    }

    if (signo == SIGUSR2)
    {
        LOG_LEVEL_SET_INFO();
        LOG_INFO("hasp_monitor: recv SIGUSR2");
    }

    if (signo == SIGINT)
    {
        LOG_INFO("hasp_monitor: recv SIGINT, stop");
        need_stop = 1;
    }

    if (signo == SIGTERM)
    {
        LOG_INFO("hasp_monitor: recv SIGTERM, stop");
        need_stop = 1;
    }

    if (signo == SIGABRT)
    {
        LOG_INFO("hasp_monitor: recv SIGABRT, stop");
        need_stop = 1;
    }

    if (signo == SIGSEGV)
    {
        LOG_INFO("hasp_monitor: recv SIGSEGV, stop");
        need_stop = 1;
    }
}

static uint64_t current_timestamp()
{
    struct timespec temp;
    clock_gettime(CLOCK_MONOTONIC, &temp);
    return temp.tv_sec;
}

static void log_hex_string(const char *tag, unsigned char *data, unsigned int datalen)
{
    int wlen = 0;
    char buffer[4096] = {0};

    wlen = snprintf(buffer, sizeof(buffer), "%s", tag);
    for (unsigned int i = 0; i < datalen; i++)
    {
        wlen += snprintf(buffer + wlen, sizeof(buffer) - wlen, "%02X ", data[i]);
    }

    LOG_DEBUG("%s", buffer);
}

static void log_hasp_status(hasp_status_t status)
{
    switch (status)
    {
    case HASP_STATUS_OK:
        LOG_INFO("hasp_monitor: Operation completed successfully");
        break;
    case HASP_MEM_RANGE:
        LOG_INFO("hasp_monitor: Invalid memory address");
        break;
    case HASP_INV_PROGNUM_OPT:
        LOG_INFO("hasp_monitor: Unknown/invalid Feature ID option");
        break;
    case HASP_INSUF_MEM:
        LOG_INFO("hasp_monitor: Memory allocation failed");
        break;
    case HASP_TMOF:
        LOG_INFO("hasp_monitor: Too many open Features");
        break;
    case HASP_ACCESS_DENIED:
        LOG_INFO("hasp_monitor: Feature access denied");
        break;
    case HASP_INCOMPAT_FEATURE:
        LOG_INFO("hasp_monitor: Incompatible Feature");
        break;
    case HASP_HASP_NOT_FOUND:
        LOG_INFO("hasp_monitor: HASP Key not found");
        break;
    case HASP_TOO_SHORT:
        LOG_INFO("hasp_monitor: Encryption/decryption length too short");
        break;
    case HASP_INV_HND:
        LOG_INFO("hasp_monitor: Invalid handle");
        break;
    case HASP_INV_FILEID:
        LOG_INFO("hasp_monitor: Invalid file ID / memory descriptor");
        break;
    case HASP_OLD_DRIVER:
        LOG_INFO("hasp_monitor: Driver or support daemon version too old");
        break;
    case HASP_NO_TIME:
        LOG_INFO("hasp_monitor: Real time support not available");
        break;
    case HASP_SYS_ERR:
        LOG_INFO("hasp_monitor: Generic error from host system call");
        break;
    case HASP_NO_DRIVER:
        LOG_INFO("hasp_monitor: HASP driver not found");
        break;
    case HASP_INV_FORMAT:
        LOG_INFO("hasp_monitor: Unrecognized info format");
        break;
    case HASP_REQ_NOT_SUPP:
        LOG_INFO("hasp_monitor: Request not supported");
        break;
    case HASP_INV_UPDATE_OBJ:
        LOG_INFO("hasp_monitor: Invalid update object");
        break;
    case HASP_KEYID_NOT_FOUND:
        LOG_INFO("hasp_monitor: Key with specified ID was not found");
        break;
    case HASP_INV_UPDATE_DATA:
        LOG_INFO("hasp_monitor: Update data consistency check failed");
        break;
    case HASP_INV_UPDATE_NOTSUPP:
        LOG_INFO("hasp_monitor: Update not supported by this key");
        break;
    case HASP_INV_UPDATE_CNTR:
        LOG_INFO("hasp_monitor: Update counter mismatch");
        break;
    case HASP_INV_VCODE:
        LOG_INFO("hasp_monitor: Invalid Vendor Code");
        break;
    case HASP_ENC_NOT_SUPP:
        LOG_INFO("hasp_monitor: Requested encryption algorithm not supported");
        break;
    case HASP_INV_TIME:
        LOG_INFO("hasp_monitor: Invalid date/time");
        break;
    case HASP_NO_BATTERY_POWER:
        LOG_INFO("hasp_monitor: Clock has no power");
        break;
    case HASP_NO_ACK_SPACE:
        LOG_INFO("hasp_monitor: Update requested ack., but no area to return it");
        break;
    case HASP_TS_DETECTED:
        LOG_INFO("hasp_monitor: Terminal services (remote terminal) detected");
        break;
    case HASP_FEATURE_TYPE_NOT_IMPL:
        LOG_INFO("hasp_monitor: Feature type not implemented");
        break;
    case HASP_UNKNOWN_ALG:
        LOG_INFO("hasp_monitor: Unknown algorithm");
        break;
    case HASP_INV_SIG:
        LOG_INFO("hasp_monitor: Signature check failed");
        break;
    case HASP_FEATURE_NOT_FOUND:
        LOG_INFO("hasp_monitor: Feature not found");
        break;
    case HASP_NO_LOG:
        LOG_INFO("hasp_monitor: Trace log is not enabled");
        break;
    case HASP_LOCAL_COMM_ERR:
        LOG_INFO("hasp_monitor: Communication error between application and local LM");
        break;
    case HASP_UNKNOWN_VCODE:
        LOG_INFO("hasp_monitor: Vendor Code not recognized by API)");
        break;
    case HASP_INV_SPEC:
        LOG_INFO("hasp_monitor: Invalid XML spec");
        break;
    case HASP_INV_SCOPE:
        LOG_INFO("hasp_monitor: Invalid XML scope");
        break;
    case HASP_TOO_MANY_KEYS:
        LOG_INFO("hasp_monitor: Too many keys connected");
        break;
    case HASP_TOO_MANY_USERS:
        LOG_INFO("hasp_monitor: Too many users");
        break;
    case HASP_BROKEN_SESSION:
        LOG_INFO("hasp_monitor: Broken session");
        break;
    case HASP_REMOTE_COMM_ERR:
        LOG_INFO("hasp_monitor: Communication error between local and remote License Manager");
        break;
    case HASP_FEATURE_EXPIRED:
        LOG_INFO("hasp_monitor: The feature is expired");
        break;
    case HASP_OLD_LM:
        LOG_INFO("hasp_monitor: HASP LM version is too old");
        break;
    case HASP_DEVICE_ERR:
        LOG_INFO("hasp_monitor: HASP SL secure storage I/O error or USB request error");
        break;
    case HASP_UPDATE_BLOCKED:
        LOG_INFO("hasp_monitor: Update installation not allowed");
        break;
    case HASP_TIME_ERR:
        LOG_INFO("hasp_monitor: System time has been tampered");
        break;
    case HASP_SCHAN_ERR:
        LOG_INFO("hasp_monitor: Secure channel communication error");
        break;
    case HASP_STORAGE_CORRUPT:
        LOG_INFO("hasp_monitor: Secure storage contains garbage");
        break;
    case HASP_NO_VLIB:
        LOG_INFO("hasp_monitor: Vendor lib cannot be found");
        break;
    case HASP_INV_VLIB:
        LOG_INFO("hasp_monitor: Vendor lib cannot be loaded");
        break;
    case HASP_SCOPE_RESULTS_EMPTY:
        LOG_INFO("hasp_monitor: No feature matching scope found");
        break;
    case HASP_VM_DETECTED:
        LOG_INFO("hasp_monitor: Virtual machine detected");
        break;
    case HASP_HARDWARE_MODIFIED:
        LOG_INFO("hasp_monitor: HASP update incompatible with this hardware: HASP key is locked to other hardware");
        break;
    case HASP_USER_DENIED:
        LOG_INFO("hasp_monitor: Login denied because of user restrictions");
        break;
    case HASP_UPDATE_TOO_OLD:
        LOG_INFO("hasp_monitor: Update was already installed");
        break;
    case HASP_UPDATE_TOO_NEW:
        LOG_INFO("hasp_monitor: Another update must be installed first");
        break;
    case HASP_OLD_VLIB:
        LOG_INFO("hasp_monitor: Vendor lib is too old");
        break;
    case HASP_UPLOAD_ERROR:
        LOG_INFO("hasp_monitor: Upload via ACC failed, e.g. because of illegal format");
        break;
    case HASP_INV_RECIPIENT:
        LOG_INFO("hasp_monitor: Invalid XML \"recipient\" parameter");
        break;
    case HASP_INV_DETACH_ACTION:
        LOG_INFO("hasp_monitor: Invalid XML \"action\" parameter");
        break;
    case HASP_TOO_MANY_PRODUCTS:
        LOG_INFO("hasp_monitor: Scope does not specify a unique Product");
        break;
    case HASP_INV_PRODUCT:
        LOG_INFO("hasp_monitor: Invalid Product information");
        break;
    case HASP_UNKNOWN_RECIPIENT:
        LOG_INFO("hasp_monitor: Unknown Recipient: update can only be applied to the Recipient specified in hasp_detach(), and not to this computer");
        break;
    case HASP_INV_DURATION:
        LOG_INFO("hasp_monitor: Invalid duration specified");
        break;
    case HASP_CLONE_DETECTED:
        LOG_INFO("hasp_monitor: Cloned HASP SL secure storage detected");
        break;
    case HASP_UPDATE_ALREADY_ADDED:
        LOG_INFO("hasp_monitor: Specified V2C update already installed in the LLM");
        break;
    case HASP_HASP_INACTIVE:
        LOG_INFO("hasp_monitor: Specified Hasp Id is in Inactive state");
        break;
    case HASP_NO_DETACHABLE_FEATURE:
        LOG_INFO("hasp_monitor: No detachable feature exists");
        break;
    case HASP_TOO_MANY_HOSTS:
        LOG_INFO("hasp_monitor: Scope does not specify a unique host");
        break;
    case HASP_REHOST_NOT_ALLOWED:
        LOG_INFO("hasp_monitor: Rehost is not allowed for any license");
        break;
    case HASP_LICENSE_REHOSTED:
        LOG_INFO("hasp_monitor: License is rehosted to other machine");
        break;
    case HASP_REHOST_ALREADY_APPLIED:
        LOG_INFO("hasp_monitor: Old rehost license try to apply");
        break;
    case HASP_CANNOT_READ_FILE:
        LOG_INFO("hasp_monitor: File not found or access denied");
        break;
    case HASP_EXTENSION_NOT_ALLOWED:
        LOG_INFO("hasp_monitor: Extension of license not allowed as number of detached licenses is greater than current concurrency count");
        break;
    case HASP_DETACH_DISABLED:
        LOG_INFO("hasp_monitor: Detach of license not allowed as product contains VM disabled feature and host machine is a virtual machine");
        break;
    case HASP_REHOST_DISABLED:
        LOG_INFO("hasp_monitor: Rehost of license not allowed as container contains VM disabled feature and host machine is a virtual machine");
        break;
    case HASP_DETACHED_LICENSE_FOUND:
        LOG_INFO("hasp_monitor: Format SL-AdminMode or migrate SL-Legacy to SL-AdminMode not allowed as container has detached license");
        break;
    case HASP_RECIPIENT_OLD_LM:
        LOG_INFO("hasp_monitor: Recipient of the requested operation is older than expected");
        break;
    case HASP_SECURE_STORE_ID_MISMATCH:
        LOG_INFO("hasp_monitor: Secure storage ID mismatch");
        break;
    case HASP_DUPLICATE_HOSTNAME:
        LOG_INFO("hasp_monitor: Duplicate Hostname found while key contains Hostname Fingerprinting");
        break;
    case HASP_MISSING_LM:
        LOG_INFO("hasp_monitor: The Sentinel License Manager is required for this operation");
        break;
    case HASP_FEATURE_INSUFFICIENT_EXECUTION_COUNT:
        LOG_INFO("hasp_monitor: You are attempting to consume multiple executions during log in to a Feature");
        break;
    case HASP_INCOMPATIBLE_PLATFORM:
        LOG_INFO("hasp_monitor: You are attempting to perform an operation not compatible with target platform");
        break;
    case HASP_HASP_DISABLED:
        LOG_INFO("hasp_monitor: The key is disabled due to suspected tampering");
        break;
    case HASP_SHARING_VIOLATION:
        LOG_INFO("hasp_monitor: The key is inaccessible due to sharing");
        break;
    case HASP_KILLED_SESSION:
        LOG_INFO("hasp_monitor: The session was killed due a network malfunction or manually from ACC");
        break;
    case HASP_VS_DETECTED:
        LOG_INFO("hasp_monitor: Program running on a virtual storage");
        break;
    case HASP_IDENTITY_REQUIRED:
        LOG_INFO("hasp_monitor: An identity is required");
        break;
    case HASP_IDENTITY_UNAUTHENTICATED:
        LOG_INFO("hasp_monitor: The identity is not authenticated");
        break;
    case HASP_IDENTITY_DISABLED:
        LOG_INFO("hasp_monitor: The identity is disabled");
        break;
    case HASP_IDENTITY_DENIED:
        LOG_INFO("hasp_monitor: The identity doesn't have enough permission for the operation");
        break;
    case HASP_IDENTITY_SHARING_VIOLATION:
        LOG_INFO("hasp_monitor: A session for this identity from a different machine already exists");
        break;
    case HASP_IDENTITY_TOO_MANY_MACHINES:
        LOG_INFO("hasp_monitor: The maximum number of machines usable by the identity was reached");
        break;
    case HASP_IDENTITY_SERVER_NOT_READY:
        LOG_INFO("hasp_monitor: The server is not ready to authenticate");
        break;
    case HASP_NO_API_DYLIB:
        LOG_INFO("hasp_monitor: A required API dynamic library was not found");
        break;
    case HASP_INV_API_DYLIB:
        LOG_INFO("hasp_monitor: The found and assigned API dynamic library could not verified");
        break;
    case HASP_INVALID_OBJECT:
        LOG_INFO("hasp_monitor: Object incorrectly initialized");
        break;
    case HASP_INVALID_PARAMETER:
        LOG_INFO("hasp_monitor: Invalid function parameter");
        break;
    case HASP_ALREADY_LOGGED_IN:
        LOG_INFO("hasp_monitor: Logging in twice to the same object");
        break;
    case HASP_ALREADY_LOGGED_OUT:
        LOG_INFO("hasp_monitor: Logging out twice from the same object");
        break;
    case HASP_OPERATION_FAILED:
        LOG_INFO("hasp_monitor: Incorrect use of system or platform");
        break;
    case HASP_NO_EXTBLOCK:
        LOG_INFO("hasp_monitor: No classic memory extension block available");
        break;
    case HASP_INV_PORT_TYPE:
        LOG_INFO("hasp_monitor: Invalid port type");
        break;
    case HASP_INV_PORT:
        LOG_INFO("hasp_monitor: Invalid port value");
        break;
    case HASP_NET_DLL_BROKEN:
        LOG_INFO("hasp_monitor: Dot-Net DLL found broken");
        break;
    case HASP_NOT_IMPL:
        LOG_INFO("hasp_monitor: Capability isn't available");
        break;
    case HASP_INT_ERR:
        LOG_INFO("hasp_monitor: Internal API error");
        break;
    case HASP_FIRST_HELPER:
        LOG_INFO("hasp_monitor: Reserved for Sentinel helper libraries");
        break;
    case HASP_FIRST_HASP_ACT:
        LOG_INFO("hasp_monitor: Reserved for Sentinel Activation API");
        break;
    default:
        LOG_INFO("hasp_monitor: failed with status %u", status);
        break;
    }
}

static hasp_status_t encrypt_decrypt(hasp_handle_t handle)
{
    hasp_status_t status;
    unsigned char buffer[32] = {0};
    memcpy(buffer, data, datalen);

    log_hex_string("hasp_monitor: Raw data: ", buffer, datalen);

    status = hasp_encrypt(handle, buffer, datalen);
    if (status != HASP_STATUS_OK)
    {
        LOG_INFO("hasp_monitor: Encrypting failed");
        return status;
    }
    else
    {
        log_hex_string("hasp_monitor: Encrypted data: ", buffer, datalen);
    }

    status = hasp_decrypt(handle, buffer, datalen);
    if (status != HASP_STATUS_OK)
    {
        LOG_INFO("hasp_monitor: Decrypting failed");
        return status;
    }
    else
    {
        log_hex_string("hasp_monitor: Decrypted data: ", buffer, datalen);
    }

    return status;
}

/******************************************************************************
 * For Hasp Verify Master Process
 ******************************************************************************/

void hasp_monitor(uint64_t feature_id, uint64_t interval)
{
    uint64_t hasp_monitor_feature_id = feature_id;
    uint64_t hasp_monitor_interval = interval;

    if (hasp_monitor_interval >= MAX_INTERVAL_S)
    {
        hasp_monitor_interval = MAX_INTERVAL_S;
    }

    if (hasp_monitor_interval == 0)
    {
        hasp_monitor_interval = DEFAULT_INTERVAL_S;
    }

    LOG_INFO("hasp_monitor: Feature ID: %ld, Interval: %ld s", hasp_monitor_feature_id, hasp_monitor_interval);

    signal(SIGUSR1, signal_handler);
    signal(SIGUSR2, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGABRT, signal_handler);
    signal(SIGSEGV, signal_handler);

    char path[256];
    char path_old[512];
    char path_new[512];

    int size = sizeof(struct shm_data);
    int fd = shm_open(shm_key, O_RDWR, 0777);
    if (fd < 0)
    {
        LOG_DEBUG("hasp_monitor: Could not find shared file '%s', try create it", shm_key);

        sprintf(path, "%s.%d", shm_key, getpid());
        fd = shm_open(path, O_CREAT | O_RDWR, 0777);
        if (fd < 0)
        {
            LOG_ERROR("hasp_monitor: Could not create shared file '%s', error %d: %s", shm_key, errno, strerror(errno));
            return;
        }

        if (ftruncate(fd, size) < 0)
        {
            LOG_ERROR("hasp_monitor: Could not truncate shared file '%s', error %d: %s", path, errno, strerror(errno));
            shm_unlink(path);
            return;
        }

        void *addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, SEEK_SET);
        if (addr == NULL)
        {
            LOG_ERROR("hasp_monitor: Could not mmap shared file '%s', error %d: %s", path, errno, strerror(errno));
            shm_unlink(path);
            return;
        }

        memset(addr, 0, size);
        munmap(addr, size);

        sprintf(path_old, "/dev/shm/%s", path);
        sprintf(path_new, "/dev/shm/%s", shm_key);

        int r = link(path_old, path_new);
        if (r == -1)
        {
            LOG_DEBUG("hasp_monitor: Create link('%s', '%s'), error %d: %s", path_old, path_new, errno, strerror(errno));
        }
        else
        {
            LOG_DEBUG("hasp_monitor: Create link('%s', '%s') success", path_old, path_new);
        }
        unlink(path_old);

        fd = shm_open(shm_key, O_RDWR, 0777);
        if (fd < 0)
        {
            LOG_ERROR("hasp_monitor: Could not open shared file '%s', error %d: %s", shm_key, errno, strerror(errno));
            return;
        }
    }
    else
    {
        LOG_DEBUG("hasp_monitor: Open shared file '%s' success", shm_key);
    }

    struct shm_data *shm = (struct shm_data *)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, SEEK_SET);
    if (shm == NULL)
    {
        LOG_ERROR("hasp_monitor: Could not mmap shared file '%s', error %d: %s", shm_key, errno, strerror(errno));
        shm_unlink(shm_key);
        return;
    }

    /*
     * <feature> <die_at_expiration>
     * Whether the current session should be terminated if the expiration date of the current Feature has passed. Possible values are:
     *  0 - Allow the session to continue (default).
     *  1 - Terminate the session.
     */
    const char *scope = "<haspscope>\n"
                        " <feature die_at_expiration=\"1\" />\n"
                        "</haspscope>\n";
    while (!need_stop)
    {
        hasp_handle_t handle;
        hasp_status_t status = hasp_login_scope(hasp_monitor_feature_id, scope, (hasp_vendor_code_t)vendor_code, &handle);
        if (status != HASP_STATUS_OK)
        {
            log_hasp_status(status);
            sleep(1);
            continue;
        }
        else
        {
            LOG_INFO("hasp_monitor: Login success");
        }

        while (!need_stop)
        {
            status = encrypt_decrypt(handle);
            if (status == HASP_STATUS_OK)
            {
                uint64_t timestamp = current_timestamp();
                ATOMIC_SET(&shm->feature_id, hasp_monitor_feature_id);
                ATOMIC_SET(&shm->status, 1);
                ATOMIC_SET(&shm->timestamp, timestamp);
                ATOMIC_SET(&shm->interval, hasp_monitor_interval);

                LOG_DEBUG("hasp_monitor: Set feature_id: %ld, timestamp: %ld, interval: %ld, status: %ld", hasp_monitor_feature_id, timestamp, hasp_monitor_interval, 1LU);
            }
            else
            {
                goto error_logout;
            }

            for (int i = 0; !need_stop && i < hasp_monitor_interval; i++)
            {
                sleep(1);
            }
        }

    error_logout:
        log_hasp_status(status);
        hasp_logout(handle);
        sleep(1);
    }

    /*
     * MAP_SHARED
     *
     * Share this mapping.
     * Updates to the mapping are visible to other processes that map this file, and are carried through to the underlying file.
     * The file may not actually be updated until msync(2) or munmap() is called.
     */
    munmap(shm, sizeof(struct shm_data));

    /*
     * hasp_monitor 退出时如果执行了 shm_unlink(), shm_key 文件会被释放
     * hasp_monitor 重启后会创建新的 shm_key 文件，而运行中的 firewall 则使用的是与旧的 shm_key 文件相关的共享内存
     * 所以此处不执行 shm_unlink()
     */
    // shm_unlink(shm_key);

    return;
}

/******************************************************************************
 * For Hasp Verify Slave Process
 ******************************************************************************/

static void *hasp_verify_cycle(void *arg)
{
    uint64_t expect_feature_id = *(uint64_t *)arg;
    struct shm_data *addr = NULL;
    struct shm_data temp;
    int size = sizeof(struct shm_data);

    LOG_INFO("hasp_verify: Expect Feature ID: %ld", expect_feature_id);

    char thread_name[16];
    snprintf(thread_name, sizeof(thread_name), "hasp");
    prctl(PR_SET_NAME, (unsigned long long)thread_name, NULL, NULL, NULL);

    signal(SIGUSR1, signal_handler);
    signal(SIGUSR2, signal_handler);

    int fd = shm_open(shm_key, O_RDONLY, 0644);
    if (fd < 0)
    {
        LOG_INFO("hasp_verify: Could not get authorization information, open shared file '%s' error %d: %s", shm_key, errno, strerror(errno));
        goto error_out;
    }

    addr = (struct shm_data *)mmap(NULL, size, PROT_READ, MAP_SHARED, fd, SEEK_SET);
    if (addr == NULL)
    {
        LOG_INFO("hasp_verify: Could not get authorization information, mmap shared file '%s' error %d: %s", shm_key, errno, strerror(errno));
        goto error_out;
    }

    while (1)
    {
        memset(&temp, 0, sizeof(temp));
        temp.feature_id = addr->feature_id;
        temp.timestamp = addr->timestamp;
        temp.interval = addr->interval;
        temp.status = addr->status;
        LOG_DEBUG("hasp_verify: Get feature_id: %ld, timestamp: %ld, interval: %ld, status: %ld", temp.feature_id, temp.timestamp, temp.interval, temp.status);

        if (expect_feature_id != temp.feature_id)
        {
            LOG_INFO("hasp_verify: Unexpected feature id");
            goto error_out;
        }

        if (current_timestamp() - temp.timestamp > temp.interval * 2)
        {
            LOG_INFO("hasp_verify: Timestamp not updated for a long time");
            goto error_out;
        }

        if (temp.status == 0)
        {
            LOG_INFO("hasp_verify: Invalid authorization information");
            goto error_out;
        }

        sleep(1);
    }

error_out:
    /*
     * MAP_SHARED
     *
     * Share this mapping.
     * Updates to the mapping are visible to other processes that map this file, and are carried through to the underlying file.
     * The file may not actually be updated until msync(2) or munmap() is called.
     */
    if (addr)
    {
        munmap(addr, size);
        addr = NULL;
    }

    // 此处不执行 shm_unlink(shm_key); 避免 firewall 退出时删除 shm_key 文件

    free(arg);
    arg = NULL;

    exit(0);

    return NULL;
}

void hasp_verify(uint64_t feature_id)
{
    pthread_t tid;
    uint64_t *hasp_verify_feature_id = (uint64_t *)calloc(1, sizeof(uint64_t));
    *hasp_verify_feature_id = feature_id;
    if (pthread_create(&tid, NULL, hasp_verify_cycle, hasp_verify_feature_id) < 0)
    {
        LOG_INFO("hasp_verify: Could not create hasp verify thread, error %d: %s", errno, strerror(errno));
        exit(0);
    }
}