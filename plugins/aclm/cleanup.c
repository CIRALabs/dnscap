/* Copyright (c) 2018 Cisco Systems and/or its Affiliates                      
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
/*
 * Purpose of these functions is to remove old entries.  The logic is
 * simple, perhaps too simple in this case.  Remove any entry that is
 * older than the maximum of the TTL in the response or N minutes.
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/time.h>
#include <errno.h>
#define TRUE 1
#define FALSE 0
#define GRACEPERIOD 3600	/* one hour */
static sqlite3 *dbh;


int main(int argc, char *argv[]) 
{
  int ch;
  char *dbname=NULL;
  char *p;
  u_long exptime;
  int sqerr;
  
  while ((ch=getopt(argc,argv,"D:e:")) != EOF )
    {
      switch (ch) {
      case 'D':
	dbname=strdup(optarg);
	break;
      case 'e':
	exptime=strtoul(optarg,&p,0);

	if ( *p != '\0' )
	  goto error;
	break;
	  
      default:
      error:
	fprintf(stderr,"usage: %s -D (database name) [ -e expire time ]\n",
		argv[0]);
	exit(-1);
      }
    }
  
  if ( dbname == NULL ) {
    fprintf(stderr,"usage: %s -D (database name) [ -e expire time ]\n",
	    argv[0]);
    exit(-1);
  }
  
  if ((sqerr=sqlite3_open_v2(dbname,&dbh,SQLITE_OPEN_READWRITE,NULL))
      != SQLITE_OK ) {
    fprintf(stderr, "sqlite3_open_v2: %s\n",sqlite3_errstr(sqerr));
  }

  /* we'll do a 10 second loop, looking for old entries. */

  while ( TRUE ) {
    char sel[2000];
    sqlite3_stmt *stmt,*s2;
    const char *tail;
    
    char *errstr;
    int err;
    time_t t;

    t=time(&t);
    /* we add a grace period by SUBTRACTING it from t */
    t -= GRACEPERIOD;

    sprintf(sel,"select rule from rules where insert_time + ttl < %lu",(u_long) t);
    
    if ((err=sqlite3_prepare_v2(dbh,sel,1500,&stmt,&tail))!=SQLITE_OK) {
      fprintf(stderr,"select1: %s\n",sqlite3_errstr(err));
      exit(-1);
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) { /* get the rule and whack it */
      char *loc;
      char *newrule=strdup(sqlite3_column_text(stmt,0));

      /* change -I to -D */
      loc=strstr(newrule,"-I");
      *(++loc)='D';
      /* for now just print the rule */
      printf("%s\n",newrule);
      free(newrule);
    }

    sqlite3_finalize(stmt);
    /* remove old rows */
    sprintf(sel,"delete from rules where insert_time + ttl < %lu",(u_long) t);
    err=sqlite3_exec(dbh,sel,0,0,&errstr);
    if ( errstr != NULL ){
      fprintf(stderr,"delete:  %s",errstr);
      sqlite3_free(errstr);
      exit(-1);
    }

    sleep(10);
  }
  
}

