/* mountall
 *
 * Copyright © 2009 Canonical Ltd.
 * Author: Scott James Remnant <scott@netsplit.com>.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif /* HAVE_CONFIG_H */


#include <libudev.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/utsname.h>
#include <sys/sendfile.h>

#include <ftw.h>
#include <grp.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <paths.h>
#include <stdio.h>
#include <limits.h>
#include <mntent.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <fnmatch.h>
#include <dirent.h>

#include <nih/macros.h>
#include <nih/alloc.h>
#include <nih/string.h>
#include <nih/list.h>
#include <nih/signal.h>
#include <nih/child.h>
#include <nih/io.h>
#include <nih/main.h>
#include <nih/option.h>
#include <nih/logging.h>
#include <nih/error.h>
#include <nih/hash.h>

#include <nih-dbus/dbus_connection.h>
#include <nih-dbus/dbus_proxy.h>

#include "dbus/upstart.h"
#include "com.ubuntu.Upstart.h"


typedef struct mount Mount;

typedef int (*MountHook) (Mount *mnt);

struct mount {
	NihList             entry;

	char *              mountpoint;
	int                 mountpoint_ready;
	pid_t               mount_pid;
	int                 mounted;

	char *              device;
	struct udev_device *udev_device;
	NihHash *           physical_dev_ids;
	int                 physical_dev_ids_needed;
	int                 check;
	pid_t               fsck_pid;
	int                 device_ready;

	char *              type;
	int                 nodev;
	char *              opts;
	char *              mount_opts;

	MountHook           hook;
};

typedef struct path {
	const char *path;
	Mount *     mnt;
	int         device;
} Path;

typedef struct filesystem {
	char *name;
	int   nodev;
} Filesystem;

typedef struct process {
	NihList       entry;
	Mount *       mnt;
	char * const *args;
	pid_t         pid;
	void (*handler) (Mount *mnt, pid_t pid, int status);
} Process;


enum exit {
	EXIT_OK,	/* Ok */
	EXIT_ERROR,	/* General/OS error */
	EXIT_FSCK,	/* Filesystem check failed */
	EXIT_MOUNT,	/* Failed to mount a filesystem */
	EXIT_REBOOT,	/* Require a reboot */
};


Mount *new_mount            (const char *mountpoint, const char *device,
			     int check, const char *type, const char *opts,
			     MountHook hook);
Mount *find_mount           (const char *mountpoint);
void   update_mount         (Mount *mnt, const char *device, int check,
			     const char *type, const char *opts,
			     MountHook hook);
void   update_mount_dev_ids (Mount *mnt);

int    has_option           (Mount *mnt, const char *option, int current);
char * get_option           (const void *parent, Mount *mnt, const char *option,
			     int current);
char * cut_options          (const void *parent, Mount *mnt, ...);

int    is_swap              (Mount *mnt);
int    is_virtual           (Mount *mnt);
int    is_remote            (Mount *mnt);
int    is_fhs               (Mount *mnt);
int    needs_remount        (Mount *mnt);

void   build_paths          (void);
int    path_compar          (const void *a, const void *b);

void   parse_fstab          (void);
void   parse_mountinfo      (void);
void   parse_filesystems    (void);
void   cleanup              (void);

void   device_ready         (Mount *mnt);
void   mountpoint_ready     (Mount *mnt);
void   mounted              (Mount *mnt);
void   trigger_events       (void);
void   children_ready       (Mount *mnt, int pass);

pid_t  spawn                (Mount *mnt, char * const *args, int wait,
			     void (*handler) (Mount *mnt, pid_t pid, int status));
void   spawn_child_handler  (Process *proc, pid_t pid,
			     NihChildEvents event, int status);

void   run_mount            (Mount *mnt, int fake);
void   run_mount_finished   (Mount *mnt, pid_t pid, int status);

void   run_swapon           (Mount *mnt);
void   run_swapon_finished  (Mount *mnt, pid_t pid, int status);

int    fsck_lock            (Mount *mnt);
void   fsck_unlock          (Mount *mnt);
void   queue_fsck           (Mount *mnt);
void   run_fsck_queue       (void);
int    run_fsck             (Mount *mnt);
void   run_fsck_finished    (Mount *mnt, pid_t pid, int status);

void   write_mtab           (void);

int    has_showthrough      (Mount *root);
void   mount_showthrough    (Mount *root);

void   upstart_disconnected (DBusConnection *connection);
void   emit_event           (const char *name);
void   emit_event_error     (void *data, NihDBusMessage *message);

void   udev_monitor_watcher (struct udev_monitor *udev_monitor,
			     NihIoWatch *watch, NihIoEvents events);
void   usr1_handler         (void *data, NihSignal *signal);

int    dev_hook             (Mount *mnt);
int    tmp_hook             (Mount *mnt);
int    var_run_hook         (Mount *mnt);

void   delayed_exit         (int code);

struct {
	/* com mon */
	Mount *mnt;
	/* tmp_hook */
	int    purge;
	time_t barrier;
} nftw_hook_args;

static const struct {
	const char *mountpoint;
	const char *device;
	int         check;
	const char *type;
	const char *opts;
	MountHook   hook;
} builtins[] = {
	{ "/",                        "/dev/root", TRUE,  "rootfs",      "defaults",                        NULL         },
	{ "/proc",                    NULL,        FALSE, "proc",        "nodev,noexec,nosuid",             NULL         },
	{ "/proc/sys/fs/binfmt_misc", NULL,        FALSE, "binfmt_misc", NULL,                              NULL         },
	{ "/sys",                     NULL,        FALSE, "sysfs",       "nodev,noexec,nosuid",             NULL         },
	{ "/sys/fs/fuse/connections", NULL,        FALSE, "fusectl",     NULL,                              NULL         },
	{ "/sys/kernel/debug",        NULL,        FALSE, "debugfs",     NULL,                              NULL         },
	{ "/sys/kernel/security",     NULL,        FALSE, "securityfs",  NULL,                              NULL         },
	{ "/spu",                     NULL,        FALSE, "spufs",       "gid=spu",                         NULL         },
	{ "/dev",                     NULL,        FALSE, "tmpfs",       "mode=0755",                       dev_hook     },
	{ "/dev/pts",                 NULL,        FALSE, "devpts",      "noexec,nosuid,gid=tty,mode=0620", NULL         },
	{ "/dev/shm",                 NULL,        FALSE, "tmpfs",       "nosuid,nodev",                    NULL         },
	{ "/tmp",                     NULL,        FALSE, NULL,          NULL,                              tmp_hook     },
	{ "/var/run",                 NULL,        FALSE, "tmpfs",       "mode=0755,nosuid,showthrough",    var_run_hook },
	{ "/var/lock",                NULL,        FALSE, "tmpfs",       "nodev,noexec,nosuid,showthrough", NULL         },
	{ "/lib/init/rw",             NULL,        FALSE, "tmpfs",       "mode=0755,nosuid",                NULL         },
	{ NULL }
}, *builtin;

static const char *fhs[] = {
	"/",
	"/boot",			/* Often separate */
	"/dev",				/* udev */
	"/dev/pts",			/* Built-in */
	"/dev/shm",			/* Built-in */
	"/home",
	"/lib/init/rw",			/* Built-in */
	"/opt",
	"/proc",			/* Linux appendix */
	"/proc/sys/fs/binfmt_misc",	/* Built-in */
	"/spu",				/* Built-in */
	"/srv"
	"/sys",				/* Not in FHS yet */
	"/sys/fs/fuse/connections",	/* Built-in */
	"/sys/kernel/debug",		/* Built-in */
	"/sys/kernel/security",		/* Built-in */
	"/tmp",
	"/usr",
	"/usr/local",
	"/usr/var",			/* Recommendation for /var symlink */
	"/var",
	"/var/cache/man",
	"/var/cache/fonts",
	"/var/lib",
	"/var/lock",
	"/var/log",
	"/var/mail",
	"/var/opt",
	"/var/run",
	"/var/spool",
	"/var/tmp",
	"/var/yp",
	NULL
};


NihList *mounts = NULL;

Path *paths = NULL;
size_t num_paths = 0;

Filesystem *filesystems = NULL;
size_t num_filesystems = 0;

NihList *procs = NULL;

int written_mtab = FALSE;

int exit_code = EXIT_OK;


static NihList *fsck_queue = NULL;
static NihHash *fsck_locks = NULL;


/**
 * upstart:
 *
 * Proxy to Upstart daemon.
 **/
static NihDBusProxy *upstart = NULL;


/**
 * daemonise:
 *
 * Set to TRUE if we should become a daemon, rather than just running
 * in the foreground.
 **/
static int daemonise = FALSE;

/**
 * force_fsck:
 *
 * Set to TRUE if we should pass -f to fsck invocations.
 **/
static int force_fsck = FALSE;

/**
 * fsck_fix:
 *
 * Set to TRUE if we should pass -y to fsck invocations.
 **/
static int fsck_fix = FALSE;

/**
 * no_remote:
 *
 * Set to TRUE if we should ignore remote filesystems.
 **/
static int no_remote = FALSE;

/**
 * tmptime:
 *
 * Set to the number of hours grace files and directories in /tmp
 * are given before being removed.
 **/
static int tmptime = 0;


static void
dequote (char *str)
{
	size_t len;

	nih_assert (str != NULL);

	if ((str[0] != '"') && (str[0] != '\''))
		return;

	len = strlen (str);
	len -= 2;

	memmove (str, str + 1, len);
	str[len] = '\0';
}

Mount *
new_mount (const char *mountpoint,
	   const char *device,
	   int         check,
	   const char *type,
	   const char *opts,
	   MountHook   hook)
{
	Mount *mnt;

	nih_assert (mountpoint != NULL);

	mnt = NIH_MUST (nih_new (NULL, Mount));
	nih_list_init (&mnt->entry);

	mnt->mountpoint = NIH_MUST (nih_strdup (mounts, mountpoint));
	mnt->mountpoint_ready = FALSE;
	mnt->mount_pid = -1;
	mnt->mounted = FALSE;

	mnt->device = device ? NIH_MUST (nih_strdup (mounts, device)) : NULL;
	mnt->udev_device = NULL;
	mnt->physical_dev_ids = NULL;
	mnt->physical_dev_ids_needed = FALSE;
	mnt->check = check;
	mnt->fsck_pid = -1;
	mnt->device_ready = FALSE;

	if (mnt->device) {
		if (! strncmp (mnt->device, "UUID=", 5)) {
			dequote (mnt->device + 5);
		} else if (! strncmp (mnt->device, "LABEL=", 6)) {
			dequote (mnt->device + 6);
		} else {
			dequote (mnt->device);
		}
	}

	mnt->type = type ? NIH_MUST (nih_strdup (mounts, type)) : NULL;
	mnt->nodev = FALSE;
	mnt->opts = opts ? NIH_MUST (nih_strdup (mounts, opts)) : NULL;
	mnt->mount_opts = NULL;

	mnt->hook = hook;

	nih_alloc_set_destructor (mnt, nih_list_destroy);
	nih_list_add (mounts, &mnt->entry);

	nih_debug ("%s: %s %s %s%s%s",
		   mnt->mountpoint,
		   mnt->device ?: "-",
		   mnt->type ?: "-",
		   mnt->opts ?: "-",
		   mnt->check ? " check" : "",
		   mnt->hook ? " hook" : "");

	return mnt;
}

Mount *
find_mount (const char *mountpoint)
{
	nih_assert (mountpoint != NULL);

	NIH_LIST_FOREACH (mounts, iter) {
		Mount *mnt = (Mount *)iter;

		if (! strcmp (mnt->mountpoint, mountpoint))
			return mnt;
	}

	return NULL;
}

void
update_mount (Mount *     mnt,
	      const char *device,
	      int         check,
	      const char *type,
	      const char *opts,
	      MountHook   hook)
{
	nih_assert (mnt != NULL);

	if (device) {
		if (mnt->device)
			nih_unref (mnt->device, mounts);
		mnt->device = NIH_MUST (nih_strdup (mounts, device));

		if (! strncmp (mnt->device, "UUID=", 5)) {
			dequote (mnt->device + 5);
		} else if (! strncmp (mnt->device, "LABEL=", 6)) {
			dequote (mnt->device + 6);
		} else {
			dequote (mnt->device);
		}
	}

	if (check >= 0)
		mnt->check = check;

	if (type) {
		/* Remove the current hook if we change the type */
		if ((! mnt->type)
		    || strcmp (type, mnt->type))
			mnt->hook = NULL;

		if (mnt->type)
			nih_unref (mnt->type, mounts);
		mnt->type = NIH_MUST (nih_strdup (mounts, type));
	}

	if (opts) {
		if (mnt->opts)
			nih_unref (mnt->opts, mounts);
		mnt->opts = NIH_MUST (nih_strdup (mounts, opts));
	}

	if (hook)
		mnt->hook = hook;

	nih_debug ("%s: %s %s %s%s%s",
		   mnt->mountpoint,
		   mnt->device ?: "-",
		   mnt->type ?: "-",
		   mnt->opts ?: "-",
		   mnt->check ? " check" : "",
		   mnt->hook ? " hook" : "");
}

static void
destroy_device (NihListEntry *entry)
{
	struct udev_device *dev;

	nih_assert (entry != NULL);

	dev = (struct udev_device *)entry->data;
	nih_assert (dev != NULL);

	udev_device_unref (dev);
	nih_list_destroy (&entry->entry);
}

static void
add_device (NihList *           devices,
	    struct udev_device *srcdev,
	    struct udev_device *newdev,
	    size_t *            nadded)
{
	NihListEntry *new_entry;

	nih_assert (devices != NULL);
	nih_assert (newdev != NULL);

	udev_device_ref (newdev);

	new_entry = NIH_MUST (nih_list_entry_new (devices));
	new_entry->data = newdev;
	nih_alloc_set_destructor (new_entry, destroy_device);
	nih_list_add (devices, &new_entry->entry);

	if (nadded)
		(*nadded)++;

	if (srcdev)
		nih_debug ("traverse: %s -> %s",
			   udev_device_get_sysname (srcdev),
			   udev_device_get_sysname (newdev));
}

void
update_mount_dev_ids (Mount *mnt)
{
	nih_local NihList *devices = NULL;
	NihHash *          results;
	struct udev *      udev;

	nih_assert (mnt != NULL);
	nih_assert (mnt->udev_device != NULL);

	if (! mnt->physical_dev_ids_needed)
		return;

	mnt->physical_dev_ids_needed = FALSE;

	if (mnt->physical_dev_ids) {
		nih_free (mnt->physical_dev_ids);
		nih_debug ("recomputing physical_dev_ids for %s",
			   mnt->mountpoint);
	}

	results = NIH_MUST (nih_hash_string_new (mnt, 10));
	mnt->physical_dev_ids = results;

	nih_assert (udev = udev_device_get_udev (mnt->udev_device));

	devices = NIH_MUST (nih_list_new (NULL));
	add_device (devices, NULL, mnt->udev_device, NULL);

	while (! NIH_LIST_EMPTY (devices)) {
		NihListEntry *      entry;

		struct udev_device *dev;
		struct udev_device *newdev;

		size_t              nadded;

		const char *        syspath;
		nih_local char *    slavespath = NULL;

		const char *        dev_id;

		DIR *               dir;
		struct dirent *     ent;

		entry = (NihListEntry *)devices->next;
		dev = (struct udev_device *)entry->data;

		/* Does this device have a parent? */

		newdev = udev_device_get_parent_with_subsystem_devtype (
			dev, "block", "disk");
		if (newdev) {
			add_device (devices, dev, newdev, NULL);
			goto finish;
		}

		/* Does this device have slaves? */

		nadded = 0;

		nih_assert (syspath = udev_device_get_syspath (dev));
		slavespath = NIH_MUST (nih_sprintf (NULL, "%s/slaves",
						    syspath));

		if ((dir = opendir (slavespath))) {
			while ((ent = readdir (dir))) {
				nih_local char *slavepath = NULL;

				if ((! strcmp (ent->d_name, "."))
				    || (! strcmp (ent->d_name, "..")))
					continue;

				slavepath = NIH_MUST (nih_sprintf (NULL,
					"%s/%s", slavespath, ent->d_name));

				newdev = udev_device_new_from_syspath (
					udev, slavepath);
				if (! newdev) {
					nih_warn ("%s: %s", slavepath,
						  "udev_device_new_from_syspath"
						  " failed");
					continue;
				}

				add_device (devices, dev, newdev, &nadded);
				udev_device_unref (newdev);
			}

			closedir (dir);
		} else if (errno != ENOENT) {
			nih_warn ("%s: opendir: %s", slavespath,
				  strerror (errno));
		}

		if (nadded > 0)
			goto finish;

		/* This device has no parents or slaves; we’ve reached the
		 * physical device.
		 */

		dev_id = udev_device_get_sysattr_value (dev, "dev");
		if (dev_id) {
			nih_local NihListEntry *entry = NULL;

			entry = NIH_MUST (nih_list_entry_new (results));
			entry->str = NIH_MUST (nih_strdup (entry, dev_id));

			if (nih_hash_add_unique (results, &entry->entry)) {
				nih_debug ("results: %s -> %s",
					   mnt->mountpoint, dev_id);
			}
		} else {
			nih_warn ("%s: failed to get sysattr 'dev'", syspath);
		}

finish:
		nih_free (entry);
	}
}


int
has_option (Mount *     mnt,
	    const char *option,
	    int         current)
{
	const char *opts;
	size_t      i;

	nih_assert (mnt != NULL);
	nih_assert (option != NULL);

	opts = current ? mnt->mount_opts : mnt->opts;
	if (! opts)
		return FALSE;

	i = 0;
	while (i < strlen (opts)) {
		size_t j;
		size_t k;

		j = strcspn (opts + i, ",=");
		k = strcspn (opts + i + j, ",");

		if (! strncmp (opts + i, option, j))
			return TRUE;

		i += j + k + 1;
	}

	return FALSE;
}

char *
get_option (const void *parent,
	    Mount *     mnt,
	    const char *option,
	    int         current)
{
	const char *opts;
	size_t      i;

	nih_assert (mnt != NULL);
	nih_assert (option != NULL);

	opts = current ? mnt->mount_opts : mnt->opts;
	if (! opts)
		return NULL;

	i = 0;
	while (i < strlen (opts)) {
		size_t j;
		size_t k;

		j = strcspn (opts + i, ",=");
		k = strcspn (opts + i + j, ",");

		if (! strncmp (opts + i, option, j))
			return nih_strndup (parent, opts + i + j + 1,
					    k ? k - 1 : 0);

		i += j + k + 1;
	}

	return NULL;
}

char *
cut_options (const void *parent,
	     Mount *     mnt,
	     ...)
{
	va_list args;
	char *  opts;
	size_t  i;

	nih_assert (mnt != NULL);

	va_start (args, mnt);

	opts = NIH_MUST (nih_strdup (parent, mnt->opts));

	i = 0;
	while (i < strlen (opts)) {
		size_t      j;
		size_t      k;
		va_list     options;
		const char *option;

		j = strcspn (opts + i, ",=");
		k = strcspn (opts + i + j, ",");

		va_copy (options, args);
		while ((option = va_arg (options, const char *)) != NULL) {
			if (! strncmp (opts + i, option, j))
				break;
		}
		va_end (options);

		if (option) {
			memmove (opts + (i ? i - 1 : 0), opts + i + j + k,
				 strlen (opts) - i - j - k + 1);
			if (i)
				i--;
		} else {
			i += j + k + 1;
		}
	}

	va_end (args);

	return opts;
}


int
is_swap (Mount *mnt)
{
	nih_assert (mnt != NULL);

	if (! mnt->type) {
		return FALSE;
	} else if (strcmp (mnt->type, "swap")) {
		return FALSE;
	} else if (! mnt->device) {
		return FALSE;
	} else {
		return TRUE;
	}
}

int
is_virtual (Mount *mnt)
{
	nih_assert (mnt != NULL);

	return mnt->nodev;
}

int
is_remote (Mount *mnt)
{
	nih_assert (mnt != NULL);

	if (has_option (mnt, "_netdev", FALSE)) {
		return TRUE;
	} else if (! mnt->type) {
		return FALSE;
	} else if (strcmp (mnt->type, "nfs")
		   && strcmp (mnt->type, "nfs4")
		   && strcmp (mnt->type, "smbfs")
		   && strcmp (mnt->type, "cifs")
		   && strcmp (mnt->type, "coda")
		   && strcmp (mnt->type, "ncp")
		   && strcmp (mnt->type, "ncpfs")
		   && strcmp (mnt->type, "ocfs2")
		   && strcmp (mnt->type, "gfs")) {
		return FALSE;
	} else {
		return TRUE;
	}
}

int
is_fhs (Mount *mnt)
{
	nih_assert (mnt != NULL);

	for (const char * const *path = fhs; path && *path; path++)
		if (! strcmp (*path, mnt->mountpoint))
			return TRUE;

	return FALSE;
}

int
needs_remount (Mount *mnt)
{
	nih_assert (mnt != NULL);

	if (mnt->mounted && has_option (mnt, "ro", TRUE)
	    && mnt->opts && (! has_option (mnt, "ro", FALSE))) {
		return TRUE;
	} else {
		return FALSE;
	}
}


void
build_paths (void)
{
	NIH_LIST_FOREACH (mounts, iter) {
		Mount *mnt = (Mount *)iter;
		Path * path;

		if (mnt->mountpoint[0] == '/') {
			paths = NIH_MUST (nih_realloc (paths, NULL,
						       sizeof (Path) * (num_paths + 1)));
			path = &paths[num_paths++];

			path->path = mnt->mountpoint;
			path->mnt = mnt;
			path->device = FALSE;
		}

		if (mnt->device
		    && strncmp (mnt->device, "/dev/", 5)
		    && (! mnt->nodev)) {
			paths = NIH_MUST (nih_realloc (paths, NULL,
						       sizeof (Path) * (num_paths + 1)));
			path = &paths[num_paths++];

			path->path = mnt->device;
			path->mnt = mnt;
			path->device = TRUE;
		}
	}

	qsort (paths, num_paths, sizeof (Path),
	       path_compar);
}

int
path_compar (const void *a,
	     const void *b)
{
	const Path *path_a;
	const Path *path_b;
	int         ret;

	path_a = a;
	path_b = b;

	ret = strcmp (path_a->path, path_b->path);
	if (ret) {
		return ret;
	} else if (path_a->device && (! path_b->device)) {
		return 1;
	} else if (path_b->device && (! path_a->device)) {
		return -1;
	} else {
		return 0;
	}
}


void
parse_fstab (void)
{
	FILE *         fstab;
	struct mntent *mntent;

	nih_debug ("updating mounts");

	fstab = setmntent (_PATH_MNTTAB, "r");
	if (! fstab) {
		nih_fatal ("%s: %s", _PATH_MNTTAB, strerror (errno));
		delayed_exit (EXIT_ERROR);
		return;
	}

	while ((mntent = getmntent (fstab)) != NULL) {
		Mount *         mnt;
		nih_local char *fsname = NULL;

		mnt = find_mount (mntent->mnt_dir);
		if (mnt) {
			update_mount (mnt,
				      mntent->mnt_fsname,
				      mntent->mnt_passno != 0,
				      mntent->mnt_type,
				      mntent->mnt_opts,
				      NULL);
		} else {
			mnt = new_mount (mntent->mnt_dir,
					 mntent->mnt_fsname,
					 mntent->mnt_passno != 0,
					 mntent->mnt_type,
					 mntent->mnt_opts,
					 NULL);
		}
	}

	endmntent (fstab);
}

void
parse_mountinfo (void)
{
	FILE *          mountinfo;
	nih_local char *buf = NULL;
	size_t          bufsz;

	nih_debug ("updating mounts");

	mountinfo = fopen ("/proc/self/mountinfo", "r");
	if ((! mountinfo) && (errno == ENOENT)) {
		Mount *mnt;

		nih_debug ("mounting /proc");
		if (mount ("none", "/proc", "proc",
			   MS_NODEV | MS_NOEXEC | MS_NOSUID, NULL) < 0) {
			nih_fatal ("%s: %s: %s", "/proc",
				   _("unable to mount"),
				   strerror (errno));
			delayed_exit (EXIT_MOUNT);
			return;
		}

		mnt = find_mount ("/proc");
		if (mnt)
			mnt->mounted = 1;

		mountinfo = fopen ("/proc/self/mountinfo", "r");
	}
	if (! mountinfo) {
		nih_fatal ("%s: %s", "/proc/self/mountinfo",
			   strerror (errno));
		delayed_exit (EXIT_MOUNT);
		return;
	}

	bufsz = 4096;
	buf = NIH_MUST (nih_alloc (NULL, bufsz));

	while (fgets (buf, bufsz, mountinfo) != NULL) {
		char * saveptr;
		char * ptr;
		char * mountpoint;
		char * type;
		char * device;
		char * mount_opts;
		char * super_opts;
		Mount *mnt;

		while ((! strchr (buf, '\n')) && (! feof (mountinfo))) {
			buf = NIH_MUST (nih_realloc (buf, NULL, bufsz + 4096));
			fgets (buf + bufsz - 1, 4097, mountinfo);
			bufsz += 4096;
		}

		/* mount ID */
		ptr = strtok_r (buf, " \t\n", &saveptr);
		if (! ptr)
			continue;

		/* parent ID */
		ptr = strtok_r (NULL, " \t\n", &saveptr);
		if (! ptr)
			continue;

		/* major:minor */
		ptr = strtok_r (NULL, " \t\n", &saveptr);
		if (! ptr)
			continue;

		/* root */
		ptr = strtok_r (NULL, " \t\n", &saveptr);
		if (! ptr)
			continue;

		/* mountpoint */
		mountpoint = strtok_r (NULL, " \t\n", &saveptr);
		if (! mountpoint)
			continue;

		/* mount opts */
		mount_opts = strtok_r (NULL, " \t\n", &saveptr);
		if (! mount_opts)
			continue;

		/* optional fields */
		while (((ptr = strtok_r (NULL, " \t\n", &saveptr)) != NULL)
		       && strcmp (ptr, "-"))
			;
		if (! ptr)
			continue;

		/* type */
		type = strtok_r (NULL, " \t\n", &saveptr);
		if (! type)
			continue;
		if (! strcmp (type, "rootfs"))
			type = NULL;

		/* device */
		device = strtok_r (NULL, " \t\n", &saveptr);
		if (! device)
			continue;
		if (! strcmp (device, "/dev/root"))
			device = NULL;

		/* superblock opts */
		super_opts = strtok_r (NULL, " \t\n", &saveptr);
		if (! super_opts)
			continue;


		mnt = find_mount (mountpoint);
		if (mnt) {
			update_mount (mnt, device, -1, type, NULL, NULL);

			if (mnt->mount_opts)
				nih_unref (mnt->mount_opts, mounts);
		} else {
			mnt = new_mount (mountpoint, device, FALSE, type, NULL, NULL);
		}

		mnt->mounted = 1;
		mnt->mount_opts = NIH_MUST (nih_sprintf (mounts, "%s,%s",
							 mount_opts, super_opts));
	}

	if (fclose (mountinfo) < 0) {
		nih_fatal ("%s: %s", "/proc/self/mountinfo",
			   strerror (errno));
		delayed_exit (EXIT_ERROR);
		return;
	}
}

void
parse_filesystems (void)
{
	FILE *          fs;
	nih_local char *buf = NULL;
	size_t          bufsz;

	nih_debug ("reading filesystems");

	fs = fopen ("/proc/filesystems", "r");
	if (! fs) {
		nih_fatal ("%s: %s", "/proc/filesystems",
			   strerror (errno));
		delayed_exit (EXIT_ERROR);
		return;
	}

	bufsz = 4096;
	buf = NIH_MUST (nih_alloc (NULL, bufsz));

	while (fgets (buf, bufsz, fs) != NULL) {
		char *      ptr;
		int         nodev;
		Filesystem *filesystem;

		while (((ptr = strchr (buf, '\n')) == NULL) && (! feof (fs))) {
			buf = NIH_MUST (nih_realloc (buf, NULL, bufsz + 4096));
			fgets (buf + bufsz - 1, 4097, fs);
			bufsz += 4096;
		}

		*ptr = '\0';
		if (! strncmp (buf, "nodev\t", 6)) {
			nodev = TRUE;
			ptr = buf + 6;
			nih_debug ("%s (nodev)", ptr);
		} else if (buf[0] == '\t') {
			nodev = FALSE;
			ptr = buf + 1;
			nih_debug ("%s", ptr);
		} else
			continue;

		filesystems = NIH_MUST (nih_realloc (filesystems, NULL,
						     sizeof (Filesystem) * (num_filesystems + 1)));
		filesystem = &filesystems[num_filesystems++];

		filesystem->name = NIH_MUST (nih_strdup (filesystems, ptr));
		filesystem->nodev = nodev;
	}

	if (fclose (fs) < 0) {
		nih_fatal ("%s: %s", "/proc/filesystems",
			  strerror (errno));
		delayed_exit (EXIT_ERROR);
		return;
	}
}

void
cleanup (void)
{
	NIH_LIST_FOREACH_SAFE (mounts, iter) {
		Mount *mnt = (Mount *)iter;
		int    drop = FALSE;
		size_t j;

		/* Check through the known filesystems, if this is a nodev
		 * filesystem then mark it as such so we don't wait for any
		 * device to be ready.  Otherwise if we didn't find the
		 * filesystem type, and no device is specified, drop as this
		 * is platform-dependent (e.g. spufs).
		 */
		if (mnt->type) {
			for (j = 0; j < num_filesystems; j++)
				if (! strcmp (mnt->type, filesystems[j].name))
					break;

			if (j < num_filesystems) {
				if (filesystems[j].nodev && (! is_remote (mnt))
				    && strcmp (filesystems[j].name, "fuse"))
					mnt->nodev = TRUE;
			} else if ((! mnt->device) && (! mnt->mounted)) {
				nih_debug ("%s: dropping unknown filesystem",
					   mnt->mountpoint);
				drop = TRUE;
			} else if (! strcmp (mnt->type, "ignore")) {
				nih_debug ("%s: dropping ignored filesystem",
					   mnt->mountpoint);
				drop = TRUE;
			}
		}

		/* Drop anything that's not auto-mounted which isn't already
		 * mounted.
		 */
		if (has_option (mnt, "noauto", FALSE) && (! mnt->mounted)) {
			nih_debug ("%s: dropping noauto filesystem",
				   mnt->mountpoint);
			drop = TRUE;
		}

		if (no_remote && is_remote (mnt)) {
			nih_debug ("%s: dropping remote filesystem (--no-remote)",
				   mnt->mountpoint);
			drop = TRUE;
		}

		if (drop) {
			nih_free (mnt);
		} else if (! strcmp (mnt->mountpoint, "/")) {
			nih_debug ("local   %s", mnt->mountpoint);
		} else if (is_fhs (mnt)) {
			if (is_virtual (mnt)) {
				nih_debug ("virtual %s", mnt->mountpoint);
			} else if (is_remote (mnt)) {
				nih_debug ("remote  %s", mnt->mountpoint);
			} else {
				nih_debug ("local   %s", mnt->mountpoint);
			}
		} else if (is_swap (mnt)) {
			nih_debug ("swap    %s", mnt->device);
		}
	}
}


void
device_ready (Mount *mnt)
{
	nih_assert (mnt != NULL);
	nih_assert (mnt->device != NULL);
	nih_assert (mnt->type != NULL);

	nih_debug ("%s", mnt->mountpoint);

	/* Activate swap devices as soon as the device is ready;
	 * don't mount filesystems until the mountpoint is ready
	 * as well.
	 */
	mnt->device_ready = TRUE;
	if (is_swap (mnt)) {
		run_swapon (mnt);
	} else if (mnt->mountpoint_ready)
		run_mount (mnt, FALSE);
}

void
mountpoint_ready (Mount *mnt)
{
	nih_assert (mnt != NULL);

	nih_debug ("%s", mnt->mountpoint);

	/* Activate nodev filesystems as soon as the mountpoint
	 * is ready, otherwise don't mount filesystems until the
	 * device is ready.  Be sure to ignore swap partitions
	 * since they're mounted in device_ready() itself.
	 */
	mnt->mountpoint_ready = TRUE;
	if (mnt->nodev
	    || (is_remote (mnt) && mnt->mounted && (! needs_remount (mnt)))
	    || (! mnt->type)
	    || (mnt->device_ready && (! is_swap (mnt))))
		run_mount (mnt, FALSE);
}

void
mounted (Mount *mnt)
{
	nih_assert (mnt != NULL);

	nih_debug ("%s", mnt->mountpoint);

	if (mnt->hook) {
		if (mnt->hook (mnt) < 0) {
			delayed_exit (EXIT_ERROR);
			return;
		}
	}

	mnt->mounted = 1;

	/* Any previous mount options no longer apply
	 * (ie. we're not read-only anymore)
	 */
	if (mnt->mount_opts)
		nih_unref (mnt->mount_opts, mounts);
	mnt->mount_opts = NULL;

	if (! written_mtab)
		write_mtab ();

	trigger_events ();

	/* Mount points underneath this are now ready for mounting,
	 * unless this was the root filesystem in which case they
	 * were already ready anyway so don't mark them again.
	 */
	if (! is_swap (mnt)) {
		if (strcmp (mnt->mountpoint, "/")) {
			children_ready (mnt, 0);
		} else {
			children_ready (mnt, 2);
		}
	}
}

void
trigger_events (void)
{
	size_t     num_virtual = 0;
	size_t     num_virtual_mounted = 0;
	static int virtual_triggered = FALSE;
	size_t     num_swap = 0;
	size_t     num_swap_mounted = 0;
	static int swap_triggered = FALSE;
	size_t     num_remote = 0;
	size_t     num_remote_mounted = 0;
	static int remote_triggered = FALSE;
	size_t     num_local = 0;
	size_t     num_local_mounted = 0;
	static int local_triggered = FALSE;
	size_t     num_fhs = 0;
	size_t     num_fhs_mounted = 0;
	static int fhs_triggered = FALSE;
	size_t     num_mounts = 0;
	size_t     num_mounted = 0;

	NIH_LIST_FOREACH (mounts, iter) {
		Mount *mnt = (Mount *)iter;

		if (! strcmp (mnt->mountpoint, "/")) {
			num_fhs++;
			num_local++;
			if (mnt->mounted && (! needs_remount (mnt))) {
				num_fhs_mounted++;
				num_local_mounted++;
			}

		} else if (is_fhs (mnt)) {
			int mounted = FALSE;

			if (is_virtual (mnt)) {
				num_virtual++;
				if (mnt->mounted) {
					num_virtual_mounted++;
					mounted = TRUE;
				}
			} else if (is_remote (mnt)) {
				num_remote++;
				if (mnt->mounted) {
					num_remote_mounted++;
					mounted = TRUE;
				}
			} else {
				num_local++;
				if (mnt->mounted && (! needs_remount (mnt))) {
					num_local_mounted++;
					mounted = TRUE;
				}
			}

			num_fhs++;
			if (mounted) {
				num_fhs_mounted++;
				num_mounted++;
			}

		} else if (is_swap (mnt)) {
			num_swap++;
			if (mnt->mounted) {
				num_swap_mounted++;
				num_mounted++;
			}

		} else if (mnt->mounted) {
			num_mounted++;
		}

		num_mounts++;
	}

	nih_debug ("virtual %zi/%zi remote %zi/%zi local %zi/%zi (%zi/%zi) swap %zi/%zi [%zi/%zi]",
		   num_virtual_mounted, num_virtual,
		   num_remote_mounted, num_remote,
		   num_local_mounted, num_local,
		   num_fhs_mounted, num_fhs,
		   num_swap_mounted, num_swap,
		   num_mounted, num_mounts);

	if ((! virtual_triggered) && (num_virtual_mounted == num_virtual)) {
		nih_info ("virtual filesystems finished");
		emit_event ("virtual-filesystems");
		virtual_triggered = TRUE;
	}
	if ((! remote_triggered) && (num_remote_mounted == num_remote)) {
		nih_info ("remote finished");
		emit_event ("remote-filesystems");
		remote_triggered = TRUE;
	}
	if ((! local_triggered) && (num_local_mounted == num_local)) {
		nih_info ("local finished");
		emit_event ("local-filesystems");
		local_triggered = TRUE;
	}
	if ((! fhs_triggered) && (num_fhs_mounted == num_fhs)) {
		nih_info ("fhs mounted");
		emit_event ("filesystem");
		fhs_triggered = TRUE;
	}

	if ((! swap_triggered) && (num_swap_mounted == num_swap)) {
		nih_info ("swap finished");
		emit_event ("all-swaps");
		swap_triggered = TRUE;
	}

	if (num_mounted == num_mounts) {
		nih_info ("finished");
		emit_event ("all-filesystems");
		nih_main_loop_exit (EXIT_OK);
	}
}

void
children_ready (Mount *root,
		int    pass)
{
	size_t i = 0;

	nih_assert (root != NULL);

	while ((i < num_paths)
	       && ((paths[i].mnt != root) || paths[i].device))
		i++;
	nih_assert (i++ < num_paths);

	while ((i < num_paths)
	       && (! strncmp (paths[i].path, root->mountpoint,
			      strlen (root->mountpoint)))
	       && ((! strcmp (root->mountpoint, "/"))
		   || (paths[i].path[strlen (root->mountpoint)] == '/')
		   || (paths[i].path[strlen (root->mountpoint)] == '\0'))) {
		Path *      path;
		struct stat statbuf;

		path = &paths[i++];
		if (lstat (path->path, &statbuf) < 0) {
			nih_debug ("ignored %s: %s", path->path,
				   strerror (errno));
			continue;
		}

		if (path->device) {
			/* Do not consider devices ready in the "mounted ro"
			 * pass, only when writable.
			 */
			if (pass != 1) {
				if ((S_ISREG (statbuf.st_mode)
				     || S_ISDIR (statbuf.st_mode))) {
					device_ready (path->mnt);
				} else {
					nih_debug ("ignored %s: not regular",
						   path->path);
				}
			}
		} else {
			/* We can, and indeed want to, mount nodev
			 * filesystems while the root filesystem is still
			 * read-only - but don't want to remount them once
			 * it's remounted r/w.
			 */
			if (path->mnt->nodev) {
				if (pass != 2)
					mountpoint_ready (path->mnt);
			} else {
				if (pass != 1)
					mountpoint_ready (path->mnt);
			}

			/* Children of this mount point aren't ready until
			 * this mountpoint is mounted, unless they're always
			 * expected to show through.
			 */
			while ((i < num_paths)
			       && (! strncmp (paths[i].path, path->path,
					      strlen (path->path)))
			       && ((paths[i].path[strlen (path->path)] == '/')
				   || (paths[i].path[strlen (path->path)] == '\0')))
			{
				if ((! paths[i].device)
				    && paths[i].mnt->type
				    && has_option (paths[i].mnt, "showthrough", FALSE)
				    && (lstat (paths[i].path, &statbuf) == 0)
				    && S_ISDIR (statbuf.st_mode)) {
					mountpoint_ready (paths[i].mnt);
				} else {
					nih_debug ("skipped %s", paths[i].path);
				}

				i++;
			}
		}
	}
}


pid_t
spawn (Mount *         mnt,
       char * const *  args,
       int             wait,
       void (*handler) (Mount *mnt, pid_t pid, int status))
{
	pid_t    pid;
	int      fds[2];
	char     flag = '!';
	Process *proc;

	nih_assert (mnt != NULL);
	nih_assert (args != NULL);
	nih_assert (args[0] != NULL);

	NIH_ZERO (pipe2 (fds, O_CLOEXEC));

	fflush (stdout);
	fflush (stderr);

	pid = fork ();
	if (pid < 0) {
		close (fds[0]);
		close (fds[1]);

		nih_fatal ("%s %s: %s", args[0],
			   is_swap (mnt) ? mnt->device : mnt->mountpoint,
			   strerror (errno));
		delayed_exit (EXIT_ERROR);
		return -1;
	} else if (! pid) {
		nih_local char *msg = NULL;

		for (char * const *arg = args; arg && *arg; arg++)
			NIH_MUST (nih_strcat_sprintf (&msg, NULL, msg ? " %s" : "%s", *arg));

		nih_debug ("%s", msg);

		execvp (args[0], args);
		nih_fatal ("%s %s [%d]: %s", args[0],
			   is_swap (mnt) ? mnt->device : mnt->mountpoint,
			   getpid (), strerror (errno));
		write (fds[1], &flag, 1);
		exit (0);
	} else {
		int ret;

		close (fds[1]);
		ret = read (fds[0], &flag, 1);
		close (fds[0]);

		if (ret > 0) {
			delayed_exit (EXIT_ERROR);
			return -1;
		}
	}

	nih_debug ("%s %s [%d]", args[0],
		   is_swap (mnt) ? mnt->device : mnt->mountpoint,
		   pid);

	proc = NIH_MUST (nih_new (NULL, Process));
	nih_list_init (&proc->entry);

	proc->mnt = mnt;

	proc->args = args;
	if (! wait)
		nih_ref (proc->args, proc);

	proc->pid = pid;

	proc->handler = handler;

	nih_list_add (procs, &proc->entry);

	if (wait) {
		siginfo_t info;

		NIH_ZERO (waitid (P_PID, pid, &info, WEXITED));
		spawn_child_handler (proc, pid, info.si_code == CLD_EXITED ? NIH_CHILD_EXITED : NIH_CHILD_KILLED,
				     info.si_status);
		return 0;
	} else {
		NIH_MUST (nih_child_add_watch (NULL, pid, NIH_CHILD_EXITED|NIH_CHILD_KILLED|NIH_CHILD_DUMPED,
					       (NihChildHandler)spawn_child_handler, proc));
		return pid;
	}
}

void
spawn_child_handler (Process *      proc,
		     pid_t          pid,
		     NihChildEvents event,
		     int            status)
{
	nih_assert (proc != NULL);
	nih_assert (pid == proc->pid);

	nih_list_remove (&proc->entry);

	if (event != NIH_CHILD_EXITED) {
		const char *sig;

		sig = nih_signal_to_name (status);
		if (sig) {
			nih_fatal ("%s %s [%d] killed by %s signal", proc->args[0],
				   is_swap (proc->mnt) ? proc->mnt->device : proc->mnt->mountpoint,
				   pid, sig);
		} else {
			nih_fatal ("%s %s [%d] killed by signal %d", proc->args[0],
				   is_swap (proc->mnt) ? proc->mnt->device : proc->mnt->mountpoint,
				   pid, status);
		}

		delayed_exit (EXIT_ERROR);

		nih_free (proc);
		return;
	} else if (status) {
		nih_warn ("%s %s [%d] terminated with status %d", proc->args[0],
			  is_swap (proc->mnt) ? proc->mnt->device : proc->mnt->mountpoint,
			  pid, status);
	} else {
		nih_info ("%s %s [%d] exited normally", proc->args[0],
			  is_swap (proc->mnt) ? proc->mnt->device : proc->mnt->mountpoint,
			  pid);
	}

	if (proc->handler)
		proc->handler (proc->mnt, pid, status);

	nih_free (proc);

	/* Exit now if there's a delayed exit */
	delayed_exit (EXIT_OK);
}


void
run_mount (Mount *mnt,
	   int    fake)
{
	nih_local char **args = NULL;
	size_t           args_len = 0;

	nih_assert (mnt != NULL);

	if (fake) {
		nih_debug ("mtab %s", mnt->mountpoint);
	} else if (mnt->mount_pid > 0) {
		nih_debug ("%s: already mounting", mnt->mountpoint);
		return;
	} else if (mnt->mounted) {
		if (needs_remount (mnt)) {
			nih_info ("remounting %s", mnt->mountpoint);
		} else {
			nih_debug ("%s: already mounted", mnt->mountpoint);
			mounted (mnt);
			return;
		}
	} else if (! mnt->type) {
		nih_debug ("%s: hook", mnt->mountpoint);
		mounted (mnt);
		return;
	} else {
		nih_info ("mounting %s", mnt->mountpoint);
	}

	args = NIH_MUST (nih_str_array_new (NULL));
	NIH_MUST (nih_str_array_add (&args, NULL, &args_len, "mount"));
	if (fake) {
		NIH_MUST (nih_str_array_add (&args, NULL, &args_len, "-f"));
	} else if ((! written_mtab)
		   && strcmp (mnt->type, "ntfs")
		   && strcmp (mnt->type, "ntfs-3g")) {
		NIH_MUST (nih_str_array_add (&args, NULL, &args_len, "-n"));
	} else if (has_showthrough (mnt)) {
		NIH_MUST (nih_str_array_add (&args, NULL, &args_len, "-n"));
	}
	NIH_MUST (nih_str_array_add (&args, NULL, &args_len, "-a"));
	NIH_MUST (nih_str_array_add (&args, NULL, &args_len, "-t"));
	NIH_MUST (nih_str_array_add (&args, NULL, &args_len, mnt->type));
	if (mnt->opts) {
		nih_local char *opts = NULL;

		opts = cut_options (NULL, mnt, "showthrough", NULL);
		if (mnt->mounted && (! fake)) {
			char *tmp;

			tmp = NIH_MUST (nih_strdup (NULL, "remount,"));
			NIH_MUST (nih_strcat (&tmp, NULL, opts));

			nih_discard (opts);
			opts = tmp;
		}

		NIH_MUST (nih_str_array_add (&args, NULL, &args_len, "-o"));
		NIH_MUST (nih_str_array_addp (&args, NULL, &args_len, opts));
	} else if (mnt->mounted && (! fake)) {
		NIH_MUST (nih_str_array_add (&args, NULL, &args_len, "-o"));
		NIH_MUST (nih_str_array_add (&args, NULL, &args_len, "remount"));
	}
	NIH_MUST (nih_str_array_add (&args, NULL, &args_len, mnt->device ?: "none"));
	if (has_showthrough (mnt) && (! fake)) {
		nih_local char *mountpoint = NULL;

		mountpoint = NIH_MUST (nih_sprintf (NULL, "/dev/%s",
						    mnt->mountpoint));

		for (size_t i = 5; i < strlen (mountpoint); i++)
			if (mountpoint[i] == '/')
				mountpoint[i] = '.';

		nih_debug ("diverting mount to %s", mountpoint);
		if ((mkdir (mountpoint, 0755) < 0)
		    && (errno != EEXIST)) {
			nih_fatal ("mkdir %s: %s", mountpoint, strerror (errno));

			delayed_exit (EXIT_ERROR);
			return;
		} else
			NIH_MUST (nih_str_array_add (&args, NULL, &args_len, mountpoint));
	} else {
		NIH_MUST (nih_str_array_add (&args, NULL, &args_len, mnt->mountpoint));
	}

	if (fake) {
 		spawn (mnt, args, TRUE, NULL);
	} else if (has_option (mnt, "showthrough", FALSE)) {
 		spawn (mnt, args, TRUE, run_mount_finished);
	} else {
		mnt->mount_pid = spawn (mnt, args, FALSE, run_mount_finished);
	}
}

void
run_mount_finished (Mount *mnt,
		    pid_t  pid,
		    int    status)
{
	nih_assert (mnt != NULL);
	nih_assert ((mnt->mount_pid == pid)
		    || (mnt->mount_pid == -1));

	mnt->mount_pid = -1;

	if (status & ~(16 | 64)) {
		nih_error ("Filesystem could not be mounted: %s",
			   mnt->mountpoint);

		if (is_fhs (mnt) && (! is_remote (mnt)))
			delayed_exit (EXIT_MOUNT);
		return;
	}

	mount_showthrough (mnt);
	mounted (mnt);
}


void
run_swapon (Mount *mnt)
{
	nih_local char **args = NULL;
	size_t           args_len = 0;
	nih_local char * pri = NULL;

	nih_assert (mnt != NULL);
	nih_assert (mnt->device != NULL);

	if (mnt->mounted) {
		nih_debug ("%s: already activated", mnt->device);
		mounted (mnt);
		return;
	} else if (mnt->mount_pid > 0) {
		nih_debug ("%s: already activating", mnt->device);
		return;
	}

	nih_info ("activating %s", mnt->device);

	args = NIH_MUST (nih_str_array_new (NULL));
	NIH_MUST (nih_str_array_add (&args, NULL, &args_len, "swapon"));

	if (((pri = get_option (NULL, mnt, "pri", FALSE)) != NULL)
	    && *pri) {
		NIH_MUST (nih_str_array_add (&args, NULL, &args_len, "-p"));
		NIH_MUST (nih_str_array_add (&args, NULL, &args_len, pri));
	}
	NIH_MUST (nih_str_array_add (&args, NULL, &args_len, mnt->device));

	mnt->mount_pid = spawn (mnt, args, FALSE, run_swapon_finished);
}

void
run_swapon_finished (Mount *mnt,
		     pid_t  pid,
		     int    status)
{
	nih_assert (mnt != NULL);
	nih_assert (mnt->mount_pid == pid);

	mnt->mount_pid = -1;

	/* Swapon doesn't return any useful status codes, so we just
	 * carry on regardless if it failed.
	 */
	if (status)
		nih_warn ("Problem activating swap: %s", mnt->device);

	mounted (mnt);
}


/* Returns: TRUE if the devices were successfully locked; FALSE if something
 * else had already locked one or more of them.
 */
int
fsck_lock (Mount *mnt)
{
	nih_assert (mnt != NULL);
	nih_assert (mnt->physical_dev_ids != NULL);

	NIH_HASH_FOREACH (mnt->physical_dev_ids, iter) {
		char *dev_id = ((NihListEntry *)iter)->str;

		if (nih_hash_lookup (fsck_locks, dev_id))
			return FALSE;
	}

	NIH_HASH_FOREACH (mnt->physical_dev_ids, iter) {
		char *        dev_id = ((NihListEntry *)iter)->str;
		NihListEntry *entry;

		entry = NIH_MUST (nih_list_entry_new (fsck_locks));
		entry->str = NIH_MUST (nih_strdup (entry, dev_id));

		nih_hash_add (fsck_locks, &entry->entry);

		nih_debug ("%s: lock dev_id %s", mnt->mountpoint, dev_id);
	}

	return TRUE;
}

void
fsck_unlock (Mount *mnt)
{
	nih_assert (mnt != NULL);
	nih_assert (mnt->physical_dev_ids != NULL);

	NIH_HASH_FOREACH (mnt->physical_dev_ids, iter) {
		char *        dev_id = ((NihListEntry *)iter)->str;
		NihListEntry *entry;

		entry = (NihListEntry *)nih_hash_lookup (fsck_locks, dev_id);
		nih_assert (entry != NULL);

		nih_free (entry);

		nih_debug ("%s: unlock dev_id %s", mnt->mountpoint, dev_id);
	}
}

void
queue_fsck (Mount *mnt)
{
	NihListEntry *entry;

	nih_assert (mnt != NULL);

	entry = NIH_MUST (nih_list_entry_new (fsck_queue));
	entry->data = mnt;
	nih_list_add (fsck_queue, &entry->entry);

	nih_debug ("%s: queuing check", mnt->mountpoint);

	run_fsck_queue ();
}

void
run_fsck_queue (void)
{
	NIH_LIST_FOREACH_SAFE (fsck_queue, iter) {
		NihListEntry *entry = (NihListEntry *)iter;
		Mount *mnt = (Mount *)entry->data;

		if (run_fsck (mnt)) {
			nih_free (entry);
			nih_debug ("%s: dequeuing check", mnt->mountpoint);
		}
	}
}

/* Returns: TRUE if the check can be dequeued, FALSE if it should be retried
 * later.
 */
int
run_fsck (Mount *mnt)
{
	nih_local char **args = NULL;
	size_t           args_len = 0;

	nih_assert (mnt != NULL);
	nih_assert (mnt->device != NULL);
	nih_assert (mnt->type != NULL);

	if (mnt->device_ready) {
		nih_debug ("%s: already ready", mnt->mountpoint);
		device_ready (mnt);
		return TRUE;
	} else if (! mnt->check
		   && (! force_fsck || strcmp (mnt->mountpoint, "/"))) {
		nih_debug ("%s: no check required", mnt->mountpoint);
		device_ready (mnt);
		return TRUE;
	} else if (mnt->mounted && (! has_option (mnt, "ro", TRUE))) {
		nih_debug ("%s: mounted filesystem", mnt->mountpoint);
		device_ready (mnt);
		return TRUE;
	} else if (mnt->fsck_pid > 0) {
		nih_debug ("%s: already checking", mnt->mountpoint);
		return TRUE;
	}

	update_mount_dev_ids (mnt);

	if (! fsck_lock (mnt))
		/* Another instance has already locked one or more of the
		 * physical devices.
		 */
		return FALSE;

	nih_info ("checking %s", mnt->mountpoint);

	args = NIH_MUST (nih_str_array_new (NULL));
	NIH_MUST (nih_str_array_add (&args, NULL, &args_len, "fsck"));
	if (fsck_fix) {
		NIH_MUST (nih_str_array_add (&args, NULL, &args_len, "-y"));
	} else {
		NIH_MUST (nih_str_array_add (&args, NULL, &args_len, "-a"));
	}
	if (force_fsck)
		NIH_MUST (nih_str_array_add (&args, NULL, &args_len, "-f"));
	NIH_MUST (nih_str_array_add (&args, NULL, &args_len, "-t"));
	NIH_MUST (nih_str_array_add (&args, NULL, &args_len, mnt->type));
	NIH_MUST (nih_str_array_add (&args, NULL, &args_len, mnt->device));

	mnt->fsck_pid = spawn (mnt, args, FALSE, run_fsck_finished);

	return TRUE;
}

void
run_fsck_finished (Mount *mnt,
		   pid_t  pid,
		   int    status)
{
	nih_assert (mnt != NULL);
	nih_assert (mnt->fsck_pid == pid);

	mnt->fsck_pid = -1;

	if (status & 2) {
		nih_error ("System must be rebooted: %s",
			   mnt->mountpoint);
		delayed_exit (EXIT_REBOOT);
		return;
	} else if (status & 4) {
		nih_error ("Filesystem has errors: %s",
			   mnt->mountpoint);
		if (is_fhs (mnt))
			delayed_exit (EXIT_FSCK);
		return;
	} else if (status & (8 | 16 | 128)) {
		nih_fatal ("General fsck error");
		delayed_exit (EXIT_ERROR);
		return;
	} else if (status & 1) {
		nih_info ("Filesystem errors corrected: %s",
			  mnt->mountpoint);
	} else if (status & 32) {
		nih_info ("Filesytem check cancelled: %s",
			  mnt->mountpoint);
	}

	fsck_unlock (mnt);
	run_fsck_queue ();

	device_ready (mnt);
}


void
write_mtab (void)
{
	int mtab;

	if (((mtab = open (_PATH_MOUNTED, O_CREAT | O_TRUNC | O_WRONLY, 0644)) < 0)
	    || (close (mtab) < 0))
		return;

	NIH_LIST_FOREACH (mounts, iter) {
		Mount *mnt = (Mount *)iter;

		if (! mnt->mounted)
			continue;
		if (! mnt->type)
			continue;
		if (is_swap (mnt))
			continue;

		run_mount (mnt, TRUE);
	}

	written_mtab = TRUE;
}


int
has_showthrough (Mount *root)
{
	size_t i = 0;

	nih_assert (root != NULL);

	/* Root cannot have showthroughs */
	if (! strcmp (root->mountpoint, "/"))
		return FALSE;

	while ((i < num_paths)
	       && ((paths[i].mnt != root) || paths[i].device))
		i++;
	nih_assert (i++ < num_paths);

	while ((i < num_paths)
	       && (! strncmp (paths[i].path, root->mountpoint,
			      strlen (root->mountpoint)))
	       && ((paths[i].path[strlen (root->mountpoint)] == '/')
		   || (paths[i].path[strlen (root->mountpoint)] == '\0'))) {
		Path *path;

		path = &paths[i++];
		if (path->device)
			continue;
		if (! has_option (path->mnt, "showthrough", FALSE))
			continue;
		if (! path->mnt->mounted)
			continue;

		/* Mount option that should show though */
		return TRUE;
	}

	return FALSE;
}

void
mount_showthrough (Mount *root)
{
	nih_local char * mountpoint = NULL;
	size_t           i = 0;
	nih_local char **args = NULL;
	size_t           args_len = 0;
	int              move = FALSE;

	nih_assert (root != NULL);

	/* Root cannot have showthroughs */
	if (! strcmp (root->mountpoint, "/"))
		return;

	while ((i < num_paths)
	       && ((paths[i].mnt != root) || paths[i].device))
		i++;
	nih_assert (i++ < num_paths);

	/* This is the mountpoint we actually used */
	mountpoint = NIH_MUST (nih_sprintf (NULL, "/dev/%s", root->mountpoint));
	for (size_t i = 5; i < strlen (mountpoint); i++)
		if (mountpoint[i] == '/')
			mountpoint[i] = '.';

	while ((i < num_paths)
	       && (! strncmp (paths[i].path, root->mountpoint,
			      strlen (root->mountpoint)))
	       && ((paths[i].path[strlen (root->mountpoint)] == '/')
		   || (paths[i].path[strlen (root->mountpoint)] == '/'))) {
		Path *           path;
		nih_local char * submount = NULL;
		nih_local char **args = NULL;
		size_t           args_len = 0;

		path = &paths[i++];
		if (path->device)
			continue;
		if (! has_option (path->mnt, "showthrough", FALSE))
			continue;
		if (! path->mnt->mounted)
			continue;

		submount = NIH_MUST (nih_sprintf (NULL, "%s%s", mountpoint,
						  path->mnt->mountpoint + strlen (root->mountpoint)));

		args = NIH_MUST (nih_str_array_new (NULL));
		NIH_MUST (nih_str_array_add (&args, NULL, &args_len, "mount"));
		NIH_MUST (nih_str_array_add (&args, NULL, &args_len, "-n"));
		NIH_MUST (nih_str_array_add (&args, NULL, &args_len, "--bind"));
		NIH_MUST (nih_str_array_add (&args, NULL, &args_len, path->mnt->mountpoint));
		NIH_MUST (nih_str_array_add (&args, NULL, &args_len, submount));

		nih_debug ("binding %s to %s", path->mnt->mountpoint, submount);


		if (spawn (path->mnt, args, TRUE, NULL) < 0)
			return;

		move = TRUE;
	}

	if (move) {
		args = NIH_MUST (nih_str_array_new (NULL));
		NIH_MUST (nih_str_array_add (&args, NULL, &args_len, "mount"));
		NIH_MUST (nih_str_array_add (&args, NULL, &args_len, "-n"));
		NIH_MUST (nih_str_array_add (&args, NULL, &args_len, "--move"));
		NIH_MUST (nih_str_array_add (&args, NULL, &args_len, mountpoint));
		NIH_MUST (nih_str_array_add (&args, NULL, &args_len, root->mountpoint));

		nih_debug ("moving %s", root->mountpoint);

		if (spawn (root, args, TRUE, NULL) < 0)
			return;

		if ((rmdir (mountpoint) < 0)
		    && (errno != EEXIST))
			nih_warn ("rmdir %s: %s", mountpoint, strerror (errno));

		if (written_mtab)
			run_mount (root, TRUE);
	}
}


void
upstart_disconnected (DBusConnection *connection)
{
	nih_fatal (_("Disconnected from Upstart"));
	delayed_exit (EXIT_ERROR);
}

void
emit_event (const char *name)
{
	DBusPendingCall *pending_call;
	nih_local char **env = NULL;

	nih_assert (name != NULL);

	env = NIH_MUST (nih_str_array_new (NULL));

	pending_call = NIH_SHOULD (upstart_emit_event (upstart,
						       name, env, FALSE,
						       NULL, emit_event_error, NULL,
						       NIH_DBUS_TIMEOUT_NEVER));
	if (! pending_call) {
		NihError *err;

		err = nih_error_get ();
		nih_warn ("%s", err->message);
		nih_free (err);

		return;
	}

	dbus_pending_call_unref (pending_call);
}

void
emit_event_error (void *          data,
		  NihDBusMessage *message)
{
	NihError *err;

	err = nih_error_get ();
	nih_warn ("%s", err->message);
	nih_free (err);
}


void
udev_monitor_watcher (struct udev_monitor *udev_monitor,
		      NihIoWatch *         watch,
		      NihIoEvents          events)
{
	struct udev_device *    udev_device;
	const char *            action;
	const char *            subsystem;
	const char *            kernel;
	const char *            devname;
	const char *            uuid;
	const char *            label;
	struct udev_list_entry *devlinks;

	udev_device = udev_monitor_receive_device (udev_monitor);
	if (! udev_device)
		return;

	action    = udev_device_get_action (udev_device);
	subsystem = udev_device_get_subsystem (udev_device);
	kernel    = udev_device_get_sysname (udev_device);
	devname   = udev_device_get_devnode (udev_device);
	devlinks  = udev_device_get_devlinks_list_entry (udev_device);
	uuid      = udev_device_get_property_value (udev_device, "ID_FS_UUID");
	label     = udev_device_get_property_value (udev_device, "ID_FS_LABEL");

	if ((! subsystem)
	    || strcmp (subsystem, "block")) {
		udev_device_unref (udev_device);
		return;
	}

	if ((! action)
	    || (strcmp (action, "add")
	        && strcmp (action, "change"))) {
		udev_device_unref (udev_device);
		return;
	}

	/* devmapper and md devices must be "ready" before we'll try them */
	if ((! strncmp (kernel, "dm-", 3))
	    || (! strncmp (kernel, "md", 2))) {
		const char *usage;
		const char *type;

		usage = udev_device_get_property_value (udev_device, "ID_FS_USAGE");
		type = udev_device_get_property_value (udev_device, "ID_FS_TYPE");

		if ((! usage) && (! type)) {
			nih_debug ("ignored %s (not yet ready?)", devname);
			udev_device_unref (udev_device);
			return;
		}
	}

	nih_debug ("%s %s %s %s", subsystem, devname, uuid, label);

	NIH_LIST_FOREACH (mounts, iter) {
		Mount *mnt = (Mount *)iter;

		if (! mnt->device)
			continue;

		if ((! strncmp (mnt->device, "UUID=", 5))
		    && uuid
		    && (! strcmp (mnt->device + 5, uuid))) {
			struct udev_list_entry *devlink;

			nih_debug ("%s by uuid", mnt->mountpoint);

			for (devlink = devlinks; devlink;
			     devlink = udev_list_entry_get_next (devlink)) {
				const char *name = udev_list_entry_get_name (devlink);

				if (! strncmp (name, "/dev/disk/by-uuid/", 18)) {
					update_mount (mnt, name, -1, NULL, NULL, NULL);
					break;
				}
			}

			if (! devlink)
				update_mount (mnt, devname, -1, NULL, NULL, NULL);
		} else if ((! strncmp (mnt->device, "LABEL=", 6))
			   && label
			   && (! strcmp (mnt->device + 6, label))) {
			struct udev_list_entry *devlink;

			nih_debug ("%s by label", mnt->mountpoint);

			for (devlink = devlinks; devlink;
			     devlink = udev_list_entry_get_next (devlink)) {
				const char *name = udev_list_entry_get_name (devlink);

				if (! strncmp (name, "/dev/disk/by-label/", 18)) {
					update_mount (mnt, name, -1, NULL, NULL, NULL);
					break;
				}
			}

			if (! devlink)
				update_mount (mnt, devname, -1, NULL, NULL, NULL);
		} else if (! strcmp (mnt->device, devname)) {
			nih_debug ("%s by name", mnt->mountpoint);
		} else {
			struct udev_list_entry *devlink;

			for (devlink = devlinks; devlink;
			     devlink = udev_list_entry_get_next (devlink)) {
				const char *name = udev_list_entry_get_name (devlink);

				if (! strcmp (mnt->device, name)) {
					nih_debug ("%s by link %s", mnt->mountpoint,
						   name);
					break;
				}
			}

			if (! devlink)
				continue;
		}

		if (mnt->udev_device)
			udev_device_unref (mnt->udev_device);

		mnt->udev_device = udev_device;
		udev_device_ref (mnt->udev_device);

		mnt->physical_dev_ids_needed = TRUE;

		queue_fsck (mnt);
	}

	udev_device_unref (udev_device);
}

void
usr1_handler (void *     data,
	      NihSignal *signal)
{
	if (no_remote)
		return;

	nih_debug ("Received SIGUSR1 (network device up)");

	NIH_LIST_FOREACH (mounts, iter) {
		Mount *mnt = (Mount *)iter;

		if (is_remote (mnt)
		    && (! mnt->mounted))
			device_ready (mnt);
	}
}


int dev_hook_walk (const char *       fpath,
		   const struct stat *sb,
		   int                typeflag,
		   struct FTW *       ftwbuf)
{
	Mount * mnt = nftw_hook_args.mnt;
	char dest[PATH_MAX];

	strcpy (dest, mnt->mountpoint);
	strcat (dest, fpath + 17);

	if (S_ISDIR (sb->st_mode)) {
		if ((mkdir (dest, sb->st_mode & ~S_IFMT) < 0)
		    && (errno != EEXIST))
			nih_warn ("%s: %s", dest, strerror (errno));
	} else if (S_ISLNK (sb->st_mode)) {
		char target[PATH_MAX];
		ssize_t len;

		len = readlink (fpath, target, sizeof target);
		target[len] = '\0';

		if ((symlink (target, dest) < 0)
		    && (errno != EEXIST))
			nih_warn ("%s: %s", dest, strerror (errno));
	} else {
		if ((mknod (dest, sb->st_mode, sb->st_rdev) < 0)
		    && (errno != EEXIST))
			nih_warn ("%s: %s", dest, strerror (errno));
	}

	return FTW_CONTINUE;
}


int
dev_hook (Mount *mnt)
{
	nih_assert (mnt != NULL);

	nih_debug ("populating %s", mnt->mountpoint);

	nftw_hook_args.mnt = mnt;
	nftw ("/lib/udev/devices", dev_hook_walk, 1024,
	      FTW_ACTIONRETVAL | FTW_PHYS | FTW_MOUNT);
	nftw_hook_args.mnt = NULL;

	return 0;
}

int tmp_hook_walk (const char *       fpath,
		   const struct stat *sb,
		   int                typeflag,
		   struct FTW *       ftwbuf)
{
	Mount * mnt = nftw_hook_args.mnt;
	const char *name = fpath + ftwbuf->base;

	if (! ftwbuf->level)
		return FTW_CONTINUE;

	if (S_ISDIR (sb->st_mode)) {
		if (strcmp (name, "lost+found")
		    && (nftw_hook_args.purge
			|| ((sb->st_mtime < nftw_hook_args.barrier
			     && (sb->st_ctime < nftw_hook_args.barrier)))))
		{
			if (rmdir (fpath) < 0)
				nih_warn ("%s: %s", fpath, strerror (errno));
		}

	} else {
		if (strcmp (name, "quota.user")
		    && strcmp (name, "aquota.user")
		    && strcmp (name, "quote.group")
		    && strcmp (name, "aquota.group")
		    && strcmp (name, ".journal")
		    && fnmatch ("...security*", name, FNM_PATHNAME)
		    && (nftw_hook_args.purge
			|| ((sb->st_mtime < nftw_hook_args.barrier)
			    && (sb->st_ctime < nftw_hook_args.barrier)
			    && (sb->st_atime < nftw_hook_args.barrier))
			|| ((ftwbuf->level == 1)
			    && (! fnmatch (".X*-lock", fpath + ftwbuf->base, FNM_PATHNAME)))))
		{
			if (unlink (fpath) < 0)
				nih_warn ("%s: %s", fpath, strerror (errno));
		}

	}

	return FTW_CONTINUE;
}

int
tmp_hook (Mount *mnt)
{
	struct stat statbuf;

	nih_assert (mnt != NULL);

	if ((lstat (mnt->mountpoint, &statbuf) < 0)
	    || (! (statbuf.st_mode & S_IWOTH))) {
		nih_debug ("cowardly not cleaning up %s", mnt->mountpoint);
		return 0;
	} else if (tmptime < 0) {
		nih_debug ("not cleaning up %s", mnt->mountpoint);
		return 0;
	}

	nih_debug ("cleaning up %s", mnt->mountpoint);

	if (tmptime > 0) {
		nftw_hook_args.purge = FALSE;
		nftw_hook_args.barrier = time (NULL) - (tmptime * 3600);
	} else {
		nftw_hook_args.purge = TRUE;
		nftw_hook_args.barrier = 0;
	}

	nftw_hook_args.mnt = mnt;
	nftw (mnt->mountpoint, tmp_hook_walk, 1024,
	      FTW_ACTIONRETVAL | FTW_DEPTH | FTW_PHYS | FTW_MOUNT);
	nftw_hook_args.mnt = NULL;

	return 0;
}

	int var_run_hook_walk (const char *       fpath,
			       const struct stat *sb,
			       int                typeflag,
			       struct FTW *       ftwbuf)
	{
		Mount * mnt = nftw_hook_args.mnt;
		char dest[PATH_MAX];

		strcpy (dest, mnt->mountpoint);
		strcat (dest, fpath + 22);

		if (S_ISDIR (sb->st_mode)) {
			if ((mkdir (dest, sb->st_mode & ~S_IFMT) < 0)
			    && (errno != EEXIST))
				nih_warn ("%s: %s", dest, strerror (errno));
		} else if (S_ISLNK (sb->st_mode)) {
			char target[PATH_MAX];
			ssize_t len;

			len = readlink (fpath, target, sizeof target);
			target[len] = '\0';

			if ((symlink (target, dest) < 0)
			    && (errno != EEXIST))
				nih_warn ("%s: %s", dest, strerror (errno));
		} else {
			int     in_fd;
			int     out_fd;
			char    buf[4096];
			ssize_t len;

			in_fd = open (fpath, O_RDONLY);
			if (in_fd < 0) {
				nih_warn ("%s: %s", fpath, strerror (errno));
				return FTW_CONTINUE;
			}

			out_fd = open (dest, O_WRONLY | O_CREAT | O_TRUNC,
				       0644);
			if (out_fd < 0) {
				nih_warn ("%s: %s", dest, strerror (errno));
				close (in_fd);
				return FTW_CONTINUE;
			}

			while ((len = read (in_fd, buf, sizeof buf)) > 0)
				write (out_fd, buf, len);

			close (in_fd);
			if (close (out_fd) < 0)
				nih_warn ("%s: %s", dest, strerror (errno));
		}

		return FTW_CONTINUE;
	}


int
var_run_hook (Mount *mnt)
{
	char  path[PATH_MAX];
	int   fd;
	FILE *fp;

	nih_assert (mnt != NULL);

	if (nih_main_write_pidfile (getpid ()) < 0) {
		NihError *err;

		err = nih_error_get ();
		nih_warn ("%s: %s", nih_main_get_pidfile (), err->message);
		nih_free (err);
	}

	nih_debug ("creating %s/utmp", mnt->mountpoint);

	strcpy (path, mnt->mountpoint);
	strcat (path, "/utmp");

	if (((fd = open (path, O_WRONLY | O_CREAT | O_TRUNC, 0664)) < 0)
	    || (close (fd) < 0)) {
		nih_warn ("%s: %s", path, strerror (errno));
	} else {
		struct group *grp;

		grp = getgrnam ("utmp");
		if (grp)
			chown (path, 0, grp->gr_gid);
	}


	nih_debug ("creating %s/motd", mnt->mountpoint);

	strcpy (path, mnt->mountpoint);
	strcat (path, "/motd");

	fp = fopen (path, "w");
	if (! fp) {
		nih_warn ("%s: %s", path, strerror (errno));
	} else {
		struct utsname uts;

		uname (&uts);
		fprintf (fp, "%s %s %s %s %s\n",
			 uts.sysname, uts.nodename, uts.release, uts.version,
			 uts.machine);
		fflush (fp);

		if ((fd = open ("/etc/motd.tail", O_RDONLY)) >= 0) {
			char    buf[4096];
			ssize_t len;

			while ((len = read (fd, buf, sizeof buf)) > 0)
				write (fileno (fp), buf, len);

			close (fd);
		}

		if (fclose (fp))
			nih_warn ("%s: %s", path, strerror (errno));
	}


	nih_debug ("populating %s from initramfs", mnt->mountpoint);

	nftw_hook_args.mnt = mnt;
	nftw ("/dev/.initramfs/varrun", var_run_hook_walk, 1024,
	      FTW_ACTIONRETVAL | FTW_PHYS | FTW_MOUNT);
	nftw_hook_args.mnt = NULL;

	return 0;
}


int
tmptime_option (NihOption * option,
		const char *arg)
{
        int *value;

        nih_assert (option != NULL);
        nih_assert (option->value != NULL);
        nih_assert (arg != NULL);

        value = (int *)option->value;

	if (strcmp (arg, "infinite")
	    && strcmp (arg, "infinity")) {
		*value = atoi (arg);
	} else {
		*value = -1;
	}

        return 0;
}

/**
 * options:
 *
 * Command-line options accepted by this program.
 **/
static NihOption options[] = {
	{ 0, "daemon", N_("Detach and run in the background"),
	  NULL, NULL, &daemonise, NULL },
	{ 0, "force-fsck", N_("Force check of all filesystems"),
	  NULL, NULL, &force_fsck, NULL },
	{ 0, "fsck-fix", N_("Attempt to fix all fsck errors"),
	  NULL, NULL, &fsck_fix, NULL },
	{ 0, "no-remote", N_("Ignore remote filesystems"),
	  NULL, NULL, &no_remote, NULL },
	{ 0, "tmptime", N_("Grace to give files in /tmp"),
	  NULL, "HOURS", &tmptime, tmptime_option },

	NIH_OPTION_LAST
};


int
main (int   argc,
      char *argv[])
{
	char **              args;
	DBusConnection *     connection;
	struct udev *        udev;
	struct udev_monitor *udev_monitor;
	Mount *              root;
	int                  ret;

	nih_main_init (argv[0]);

	nih_option_set_synopsis (_("Mount filesystems on boot"));
	nih_option_set_help (
		_("By default, mountall does not detach from the "
		  "console and remains in the foreground.  Use the --daemon "
		  "option to have it detach."));

	args = nih_option_parser (NULL, argc, argv, options, FALSE);
	if (! args)
		exit (EXIT_ERROR);

	nih_signal_reset ();

	/* Initialise the connection to Upstart */
	connection = NIH_SHOULD (nih_dbus_connect (DBUS_ADDRESS_UPSTART, upstart_disconnected));
	if (! connection) {
		NihError *err;

		err = nih_error_get ();
		nih_fatal ("%s: %s", _("Could not connect to Upstart"),
			   err->message);
		nih_free (err);

		exit (EXIT_ERROR);
	}

	upstart = NIH_SHOULD (nih_dbus_proxy_new (NULL, connection,
						  NULL, DBUS_PATH_UPSTART,
						  NULL, NULL));
	if (! upstart) {
		NihError *err;

		err = nih_error_get ();
		nih_fatal ("%s: %s", _("Could not create Upstart proxy"),
			   err->message);
		nih_free (err);

		exit (EXIT_ERROR);
	}

	/* Initialise the connection to udev */
	nih_assert (udev = udev_new ());
	nih_assert (udev_monitor = udev_monitor_new_from_netlink (udev, "udev"));
	nih_assert (udev_monitor_filter_add_match_subsystem_devtype (udev_monitor, "block", NULL) == 0);
	nih_assert (udev_monitor_enable_receiving (udev_monitor) == 0);

	NIH_MUST (nih_io_add_watch (NULL, udev_monitor_get_fd (udev_monitor),
				    NIH_IO_READ,
				    (NihIoWatcher)udev_monitor_watcher,
				    udev_monitor));

	/* Initialse mount table with built-in filesystems, then parse
	 * from /etc/fstab and /proc/self/mountinfo to find out what else
	 * we need to do.
	 */
	mounts = NIH_MUST (nih_list_new (NULL));
	for (builtin = builtins; builtin->mountpoint; builtin++)
		new_mount (builtin->mountpoint, builtin->device, builtin->check,
			   builtin->type, builtin->opts, builtin->hook);

	parse_fstab ();
	parse_mountinfo ();

	/* Parse /proc/filesystems and eliminate anything we don't know
	 * about, or anything that's got "noauto" in its options, etc.
	 */
	parse_filesystems ();
	cleanup ();

	/* Build a path table so we can lookup both children mountpoints
	 * and devices.  Initialise a process list.
	 */
	build_paths ();
	procs = NIH_MUST (nih_list_new (NULL));

	/* Initialise the fsck queue. */
	fsck_queue = NIH_MUST (nih_list_new (NULL));
	fsck_locks = NIH_MUST (nih_hash_string_new (NULL, 10));

	/* Sanity check, the root filesystem should be already mounted */
	root = find_mount ("/");
	if (! root->mounted) {
		nih_fatal ("%s", _("root filesystem isn't mounted"));
		exit (EXIT_ERROR);
	}

	/* Become daemon */
	if (daemonise) {
		pid_t pid;

		/* Fork once because Upstart makes us a session leader,
		 * or we may be a session leader of an existing process
		 * group.
		 */
		pid = fork ();
		if (pid < 0) {
			nih_fatal ("%s: %s", _("Unable to become daemon"),
				   strerror (errno));

			exit (EXIT_ERROR);
		} else if (pid > 0) {
			exit (0);
		}

		/* Create a new session */
		setsid ();

		/* Fork again so that we're not the leader of that session */
		pid = fork ();
		if (pid < 0) {
			nih_fatal ("%s: %s", _("Unable to become daemon"),
				   strerror (errno));

			exit (EXIT_ERROR);
		} else if (pid > 0) {
			exit (0);
		}

		/* Usual daemon cleanups */
		if (chdir ("/"))
			;
		umask (0);

		/* Send all logging output to syslog */
		//openlog (program_name, LOG_PID, LOG_DAEMON);
		//nih_log_set_logger (nih_logger_syslog);

		nih_signal_set_ignore (SIGHUP);

		nih_signal_set_handler (SIGINT, nih_signal_handler);
		NIH_MUST (nih_signal_add_handler (NULL, SIGINT, nih_main_term_signal, NULL));
	}

	nih_signal_set_handler (SIGCHLD, nih_signal_handler);

	/* Handle TERM and INT signals gracefully */
	nih_signal_set_handler (SIGTERM, nih_signal_handler);
	NIH_MUST (nih_signal_add_handler (NULL, SIGTERM, nih_main_term_signal, NULL));

	/* SIGUSR1 tells us that a network device came up */
	nih_signal_set_handler (SIGUSR1, nih_signal_handler);
	NIH_MUST (nih_signal_add_handler (NULL, SIGUSR1, usr1_handler, NULL));


	/* All of the mountpoints under the root filesystem are now ready
	 * for mounting, even though it's still read-only.  All of the
	 * devices will be ready when it's mounted for writing.  This means
	 * we'll mount all of the nodev filesystems.
	 *
	 * Once that's done, mark the root mountpoint itself ready so we
	 * can remount the root filesystem when the device itself is ready.
	 */
	children_ready (root, 1);
	mountpoint_ready (root);

	ret = nih_main_loop ();

	nih_discard (fsck_queue);
	nih_discard (fsck_locks);

	nih_main_unlink_pidfile ();

	return ret;
}

void
delayed_exit (int code)
{
	exit_code = nih_max (exit_code, code);

	if (exit_code && NIH_LIST_EMPTY (procs)) {
		nih_main_unlink_pidfile ();
		exit (exit_code);
	}
}
