/**
 * This file is part of Hercules.
 * http://herc.ws - http://github.com/HerculesWS/Hercules
 *
 * Copyright (C) 2012-2015  Hercules Dev Team
 * Copyright (C)  Athena Dev Teams
 *
 * Hercules is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef CHAR_INTER_H
#define CHAR_INTER_H

#include "common/hercules.h"
#include "common/db.h"
#include "common/sql.h"

#include <stdarg.h>

/**
 * inter interface
 **/
struct inter_interface {
	Sql* sql_handle;
	const char* (*msg_txt) (int msg_number);
	bool (*msg_config_read) (const char *cfg_name, bool allow_override);
	void (*do_final_msg) (void);
	const char* (*job_name) (int class_);
	void (*vmsg_to_fd) (int fd, int u_fd, int aid, char* msg, va_list ap);
	void (*msg_to_fd) (int fd, int u_fd, int aid, char *msg, ...) __attribute__((format(printf, 4, 5)));
	void (*savereg) (int account_id, int char_id, const char *key, unsigned int index, intptr_t val, bool is_string);
	int (*accreg_fromsql) (int account_id,int char_id, int fd, int type);
	int (*config_read) (const char* cfgName);
	int (*vlog) (char* fmt, va_list ap);
	int (*log) (char* fmt, ...);
	int (*init_sql) (const char *file);
	int (*mapif_init) (int fd);
	int (*check_ttl_wisdata_sub) (DBKey key, DBData *data, va_list ap);
	int (*check_ttl_wisdata) (void);
	int (*check_length) (int fd, int length);
	int (*parse_frommap) (int fd);
	void (*final) (void);
};

#ifdef HERCULES_CORE
extern unsigned int party_share_level;

void inter_defaults(void);
#endif // HERCULES_CORE

HPShared struct inter_interface *inter;

#endif /* CHAR_INTER_H */
