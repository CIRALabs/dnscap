/*
 * Copyright (c) 2018 Cisco Systems and/or its Affiliates
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _ACLM_H_
#define _ACLM_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <sqlite3.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <resolv.h>
#include <signal.h>

#define TRUE 1
#define FALSE 0
static sqlite3 *dbh,*dbh2;
static char *dbname;
static char *db2name;
static char *chname=NULL;

static int havedb = FALSE;
static int tnodes= 0;
static time_t thetime;

#define GRACEPERIOD 3600	/* one hour */

#include "dnscap_common.h"

static logerr_t *logerr;

output_t aclm_output;

int aclm_checkname(const char *rrname);
int aclm_addrule(char *rrname, u_int type, const char *ipaddr,u_long ttl);
void aclm_do_dns_sect(ns_msg *msg, ns_sect sect);
void aclm_do_dns_rr(ns_msg *msg, ns_rr *rr, u_int id, ns_sect sect);
void aclm_cleanup();
int aclm_add_cname(const char *orig,const char *cname);
struct d_ent *aclm_deptfind(struct d_ent *dt,  int hilo);


struct d_ent 
{
  time_t d_t;			/* time */
  u_int d_id;
  char *d_name;
  struct d_ent *d_low;
  struct d_ent *d_hi;
};

struct d_ent *dtree;
struct d_ent *aclm_dtinsert(struct d_ent *dt,const char *rrname, u_int id) ;
int aclm_dtsearch(struct d_ent *dt, struct d_ent *parent,
	     const char *rrname, u_int id);

#ifdef DEBUG
void debugtree(struct d_ent *dt, struct d_ent *parent);
#endif

char *intsqinit="create table rules (name text collate nocase,"
  "rule text PRIMARY KEY,"
  "insert_time integer, ttl integer);"
  "create table cnames (name text collate nocase,"
  "realname text);";

#endif /* _ACLM_H */
