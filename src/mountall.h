/* mountall 
 *
 * Copyright © 2010 Canonical Ltd.
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

int stop_dev_timer (const char * mountpoint)
	__attribute__ ((warn_unused_result));
int restart_dev_timer (const char * mountpoint)
	__attribute__ ((warn_unused_result));
int change_mount_device (const char * devname, const char * path)
	__attribute__ ((warn_unused_result));
