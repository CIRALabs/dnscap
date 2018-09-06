/* Copyright (c) 2018 Cisco Systems and/or its Affiliates                      
 * All rights reserved.  
 *
 * Original Template
 *
 * Copyright (c) 2016, OARC, Inc.                                              
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

#include "aclm.h"

/* simple routine just checks to see if a rrname is in the db, and returns
 * a boolean.
 */

int aclm_checkname(const char *rrname) {
  static char sel[2000];	/* well beyond largest domain name */
  sqlite3_stmt *stmt;
  const char *tail;
  int ct;
  int err=0;
  
  sprintf(sel,"select name from hosts where name = \'%s\';",rrname);
  
  if ((err=sqlite3_prepare_v2(dbh,sel,1500,&stmt,&tail))!=SQLITE_OK) {
    fprintf(stderr,"checkname: %s\n",sqlite3_errstr(err));
    return 0;
  }
  err= sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  return (err == SQLITE_ROW)?1:0;
}
 

/* we could in thoery generalize these two routines... */

char aclm_is_cname(const char *rrname) {
  static char sel[2000];	/* well beyond largest domain name */
  sqlite3_stmt *stmt;
  const char *tail;
  int ct;
  int err=0;
  
  sprintf(sel,"select name from cnames where realname = \'%s\';",rrname);
  
  if ((err=sqlite3_prepare_v2(dbh2,sel,1500,&stmt,&tail))!=SQLITE_OK) {
    fprintf(stderr,"is_cname: %s\n",sqlite3_errstr(err));
    return 0;
  }
  err= sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  return (err == SQLITE_ROW)?1:0;
}
 
/* this routine adds a cname into our interest database, with an annotation
 * as to why.  We will NOT copy the whole rule in this case, but simply mark
 * it as a CNAME and to what.  That way if the original rule changes we don't
 * need to keep track.
 *
 * PROGRAM SIDE EFFECT: when cleaning of rules occurs, cname rules for hosts
 *                      MUST ALSO be cleaned.
 */

int aclm_add_cname(const char *orig,const char *cname) {
  static char sel[2000];	/* well beyond largest domain name */
  sqlite3_stmt *stmt;
  const char *tail;
  char *errstr;
  int err=0;

  /* first determine if there is already a row for orig */
  sprintf(sel,"select name from cnames where realname = \'%s\';", cname);
  
  if ((err=sqlite3_prepare_v2(dbh2,sel,1000,&stmt,&tail))!=SQLITE_OK) {
    fprintf(stderr,"add_cname: select: %s",sqlite3_errstr(err));
    return -1;
  }
  if (sqlite3_step(stmt) != SQLITE_ROW) { /* name doesn't exist, do an insert */
    sqlite3_finalize(stmt);
    sprintf(sel,"insert into cnames (name,realname) values (\'%s\', \'%s\' );",
	    orig, cname);
    err=sqlite3_exec(dbh2,sel,0,0,&errstr);
    if ( errstr != NULL ) {
      fprintf(stderr,"add_cname: insert: %s\n",errstr);
      sqlite3_free(errstr);
      return -1;
    }
  } else { 			/* record *does* exist.  update it */
    sqlite3_finalize(stmt);
    sprintf(sel,"update cnames set realname = \'%s\' where name = \'%s\';",
	    cname,orig);
    err=sqlite3_exec(dbh2,sel,0,0,&errstr);
    if ( errstr != NULL ) {
      fprintf(stderr,"add_cname: update: %s\n",errstr);
      sqlite3_free(errstr);
      return -1;
    }
  }
  return 0;
  
}
  


/* add a firewall rule */
int aclm_addrule(char *rrname, u_int type, const char *ipaddr,u_long ttl) {
  static char sel[2000];	/* well beyond largest domain name */
  sqlite3_stmt *stmt;
  const char *tail;
  char *thename;
  int ct;
  int err=0;

  /* only keep the rules database open for a brief period. */

  /* we need retrieve any CNAME information for rrname */
  sprintf(sel,"select name from cnames where realname = \'%s\';",rrname);
  if ((err=sqlite3_prepare_v2(dbh2,sel,1000,&stmt,&tail))!=SQLITE_OK) {
    fprintf(stderr,"addrule: cnamecheck: %s",sqlite3_errstr(err));
    return 0;
  }
  
  /* a CNAME should only ever have one entry */

  if ( sqlite3_step(stmt) == SQLITE_ROW ) {
    thename=strdup(sqlite3_column_text(stmt,0));
  } else {
    thename=rrname;
  }
  sqlite3_finalize(stmt);
  
  
  sprintf(sel,"select dowhat,name,direction,tproto,srcprt,dstprt,direction_initiated from hosts where name = \'%s\';",thename);
  
  if ((err=sqlite3_prepare_v2(dbh,sel,1000,&stmt,&tail))!=SQLITE_OK) {
    fprintf(stderr,"addrule: prepare1: %s",sqlite3_errstr(err));
    return 0;
  }
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    char rulename[500];
    sqlite3_stmt *s2;
    const char *t2;
    int ct;
    int err2=0;
    int dowhat = sqlite3_column_int(stmt,0);
    int direction = sqlite3_column_int(stmt,2);
    int srcprt;
    int dstprt;
    
    /* we need to put together the rulename */
    sprintf(rulename,"%s -I %s %s %s",
	    type==ns_t_aaaa? "ip6tables" : "iptables",
	    chname,
	    direction==0? "-s": "-d",
	    ipaddr);
    
    if (strcmp(sqlite3_column_text(stmt,3),"all")) {
      strcat(rulename," -p ");
      strcat(rulename,sqlite3_column_text(stmt,3));
      srcprt=sqlite3_column_int(stmt,4);
      dstprt=sqlite3_column_int(stmt,5);
      if (srcprt > 0) {
	char port[6];

	strcat(rulename," --sport ");
	sprintf(port,"%d",srcprt);
	strcat(rulename,port);
      }
      if (dstprt > 0) {
	char port[6];

	strcat(rulename," --dport ");
	sprintf(port,"%d",dstprt);
	strcat(rulename,port);
      }
    }
    
    if ( dowhat == 0 )
      strcat(rulename," -j ACCEPT");
    else
      strcat(rulename," -j REJECT");
    
    
    /* rulename put together. check for dups */
    sprintf(sel,"select rule from rules where rule= \'%s\';",rulename);
    if ((err=sqlite3_prepare_v2(dbh2,sel,1000,&s2,&t2)) != SQLITE_OK ) {
      fprintf(stderr,"addrule: prepare2: %s\n",sqlite3_errstr(err));
      sqlite3_finalize(s2);
      sqlite3_finalize(stmt);
      return(0);
    }
    
    if (sqlite3_step(s2) != SQLITE_ROW ) /* not a duplicate */    {
      time_t t;
      char *errstr;
      
      sqlite3_finalize(s2);
      t=time(&t);
      
      fprintf(stderr,"%s\n",rulename);
      sprintf(sel,"insert into rules (name, rule,insert_time, ttl) values ( \'%s\', \'%s\', %d, %lu );", thename, rulename, (int) t, ttl );
      
      err=sqlite3_exec(dbh2,sel,0,0,&errstr);
      if ( errstr != NULL ){
	fprintf(stderr,"addrule: insert: %s",errstr);
	sqlite3_finalize(stmt);
	sqlite3_free(errstr);
	return(0);
      }
    }
    
    else { /* row exists, just update the time */
	time_t t;
	char *errstr;

	t=time(&t);
	
	sprintf(sel,"update rules set insert_time = %d , ttl = %lu where name=\'%s\';",
		(int) t,ttl, thename);
	err=sqlite3_exec(dbh2,sel,0,0,&errstr); 
	if ( errstr != NULL ){
	  fprintf(stderr,"addrule: update2: %s",errstr);
	  sqlite3_finalize(stmt);
	  sqlite3_free(errstr);
	  return(0);
	}
    }
  }
}
 


void
aclm_usage()
{
	fprintf(stderr,
		"\naclm.so options:\n"
		"\t-d         Configuration Database name\n"
		"\t-r         Output rules database name\n"
		);
}
 

void
aclm_getopt(int *argc, char **argv[])
{
	/*
	 * The "getopt" function will be called from the parent to
	 * process plugin options.
	 */
	int c;
	while ((c = getopt(*argc, *argv, "c:d:")) != EOF) {
		switch(c) {
		case 'c':
		        chname=strdup(optarg);
			break;
		case 'd':
  		        havedb= TRUE;
		        dbname=strdup(optarg);
			if ((db2name=(char *) malloc((strlen(dbname)+5)*sizeof(char))) == NULL) {
			  perror("db2name: %s");
			  exit(-1);
			}
			sprintf(db2name,"%s.int",dbname);
			break;

		default:
			aclm_usage();
			exit(1);
		}
	}
	if ( chname == NULL ) {
	  chname=strdup("INPUT");
	}
	
}
 

int
aclm_start(logerr_t *a_logerr)
{
	/*
	 * The "start" function is called once, when the program
	 * starts.  It is used to initialize the plugin.  If the
	 * plugin wants to write debugging and or error messages,
	 * it should save the a_logerr pointer passed from the
	 * parent code.
	 */
  int sqerr;
  struct stat sbuf;
  char *errstr;
  
  
  if ( havedb == FALSE )
    return 0;
  
  thetime = (time_t) 0;
  
  if ((sqerr=sqlite3_open_v2(dbname,&dbh,SQLITE_OPEN_READONLY,NULL))
      != SQLITE_OK ) {
    havedb=FALSE;
    fprintf(stderr, "sqlite3_open_v2: %s\n",sqlite3_errstr(sqerr));
    return 0;
  }


  /* stat here */
  if ( stat(db2name,&sbuf) == EOF ) { /* initialize database if it doesn't exist */
    if ((sqerr=sqlite3_open_v2(db2name,&dbh2,SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE, NULL))
	!= SQLITE_OK) {
      havedb=FALSE;
      fprintf(stderr, "sqlite3_open_v2: %s\n",sqlite3_errstr(sqerr));
    }
    /* create tables */
    sqerr=sqlite3_exec(dbh2,intsqinit,0,0,&errstr);
    if ( errstr != NULL ){
      fprintf(stderr,"delete:  %s",errstr);
      sqlite3_free(errstr);
      havedb=FALSE;
    }
  } else { 			/* database already exists */
    if ((sqerr=sqlite3_open_v2(db2name,&dbh2,SQLITE_OPEN_READWRITE,NULL))
      != SQLITE_OK ) {
      havedb=FALSE;
      fprintf(stderr, "sqlite3_open_v2: %s\n",sqlite3_errstr(sqerr));
      return 0;
    }
    aclm_cleanup(); 			/* clean up old entries on startup */
  }
  return 0;
}
 

void
aclm_stop()
{
	/*
	 * The "start" function is called once, when the program
	 * is exiting normally.  It might be used to clean up state,
	 * free memory, etc.
	 */
  sqlite3_close(dbh);
  sqlite3_close(dbh2);
}

int
aclm_open(my_bpftimeval ts)
{
	/*
	 * The "open" function is called at the start of each
	 * collection interval, which might be based on a period
	 * of time or a number of packets.  In the original code,
	 * this is where we opened an output pcap file.
	 */
	return 0;
}

int
aclm_close(my_bpftimeval ts)
{
	/*
	 * The "close" function is called at the end of each
	 * collection interval, which might be based on a period
	 * of time or on a number of packets.  In the original code
	 * this is where we closed an output pcap file.
	 */
	return 0;
}

void
aclm_output(const char *descr, iaddr from, iaddr to, uint8_t proto, unsigned flags,
    unsigned sport, unsigned dport, my_bpftimeval ts,
    const u_char *pkt_copy, const unsigned olen,
    const u_char *payload, const unsigned payloadlen) {
	/*
	 * Here you can "process" a packet.  The function is named
	 * "output" because in the original code this is where
	 * packets were outputted.
	 *
	 * if flags & PCAP_OUTPUT_ISDNS != 0 then payload is the start of a DNS message.
	 */
	ns_msg msg;
	time_t now;

	if ( ! (flags & DNSCAP_OUTPUT_ISDNS) )
	  return;
	
	descr="ACLM firewall rule builder";
	
	if (ns_initparse(payload, payloadlen, &msg) < 0) {
		fputs(strerror(errno), stderr);
		return;
	}

	now=time(&now);

	if (now - thetime > 60) {
	  aclm_cleanup();
	  thetime=now;
	}
	
	aclm_do_dns_sect(&msg, ns_s_qd);
	aclm_do_dns_sect(&msg, ns_s_an);
	aclm_do_dns_sect(&msg,ns_s_ar);
	// the additional record is only safe if we've already seen the name.
	// see below
}
 
 

void
aclm_do_dns_sect(ns_msg *msg, ns_sect sect) {
	int rrnum, rrmax;
	ns_rr rr;
	u_int id;
	
	id = ns_msg_id(*msg);
	rrmax = ns_msg_count(*msg, sect);
	if (rrmax == 0) {
		return;
	}
	for (rrnum = 0; rrnum < rrmax; rrnum++) {
		if (ns_parserr(msg, sect, rrnum, &rr)) {
			fputs(strerror(errno), stderr);
			return;
		}
		if (!ns_msg_getflag(*msg,ns_f_qr)) {
		  u_int type = ns_rr_type(rr);
		  if (( type == ns_t_aaaa || type == ns_t_a ) &&
		      (sect != ns_s_ar)) {
		    if (aclm_checkname(ns_rr_name(rr)))
			dtree=aclm_dtinsert(dtree,ns_rr_name(rr),id);
		    return;
		  }
		}
		aclm_do_dns_rr(msg, &rr, id, sect);
	}
}

void
aclm_do_dns_rr(ns_msg *msg, ns_rr *rr, u_int id, ns_sect sect) {
	char buf[NS_MAXDNAME];
	u_int type, isquery;
	const u_char *rd;
	char *rrname;
	static char lastname[NS_MAXDNAME];
	int n;
	
	rrname=ns_rr_name(*rr);
	
	/* if we don't know the name we don't care. */
	if ( (! aclm_checkname(rrname)) && (! aclm_is_cname(rrname) ))
	  return;
	
	/* could still be a cname here */
	memset(buf, 0, sizeof(buf));
	if ( (rd = ns_rr_rdata(*rr)) == NULL )
	  return;
	type = ns_rr_type(*rr);
	
	switch (type) {
	case ns_t_a:
		if (ns_msg_end(*msg) - rd < 4)
			goto error;
		inet_ntop(AF_INET, rd, buf, sizeof buf);
		break;
	case ns_t_aaaa:
		if (ns_msg_end(*msg) - rd < 16)
			goto error;
		inet_ntop(AF_INET6, rd, buf, sizeof buf);
		break;
        case ns_t_cname:
	        n = ns_name_uncompress(ns_msg_base(*msg), ns_msg_end(*msg),
				 rd, buf, sizeof buf);
		if (n < 0)
		  goto error;
		aclm_add_cname(rrname,buf); /* add no rules, just return */
		return;

	default:
	error:
	  break;
	}
	if (buf[0] != '\0') {
#ifdef DEBUG	  
	  debugtree(dtree,NULL);
#endif
	  if ( ! strcasecmp(lastname,ns_rr_name(*rr)))
	    aclm_addrule(rrname,type,buf,ns_rr_ttl(*rr));
	  else if (sect != ns_s_ar ) /* not ok if we haven't already seen the name */
	    if (aclm_dtsearch(dtree,NULL,ns_rr_name(*rr),id) || aclm_is_cname(rrname) ) {
	      aclm_addrule(rrname,type,buf,ns_rr_ttl(*rr));
	      strcpy(lastname,ns_rr_name(*rr));
	    }
	  if ( tnodes > 100 )
	    fprintf(stderr,"aclm: warning: # nodes: %d\n",tnodes);
	}
	
}

#ifdef DEBUG
void debugtree(struct d_ent *dt, struct d_ent *parent) {

  if ( dt == NULL || dt->d_t == 1 )
    return;

  fprintf(stderr,"%s <- dt=%s -> %s\n",
	  dt->d_low == NULL? "none" : dt->d_low->d_name, dt->d_name,
	  dt->d_hi== NULL? "none" : dt->d_hi->d_name);
  debugtree(dt->d_low,dt);
  debugtree(dt->d_hi,dt);
  return;
}

#endif

/* insert an entry into the tree.  we only want to report on queries
 * we have received.
 */


struct d_ent *aclm_dtinsert(struct d_ent *dt,const char *rrname, u_int id) 
{
  int sc;

  /* base case: dt = NULL */

  if ( dt == NULL || dt->d_t == 1) { // create a new element at this point
    if ( dt == NULL ) {	     /* special root kludge */
      if ((dt=malloc(sizeof(struct d_ent))) == NULL)
	  perror("malloc");
      memset(dt,0,sizeof(struct d_ent));
    }
    if (( dt->d_name = (char *) malloc(strlen(rrname)*sizeof(u_char)+1)) == NULL )
      perror("malloc");
    
    strcpy(dt->d_name,rrname);
    dt->d_id=id;
    dt->d_t=time(&(dt->d_t));
    tnodes++;
    return dt;

  }

  /* entry exists.  may or may not have children on either side.
   */
  
  sc=strcasecmp(rrname,dt->d_name);

  if ( sc < 0 ) { // less than current value, go low
    dt->d_low=aclm_dtinsert(dt->d_low,rrname,id);
    return dt;
  }

  if (sc > 0 ) { // greater than current value, go high
    dt->d_hi=aclm_dtinsert(dt->d_hi,rrname,id);
    return dt;
  }

  /* if here then, then a dup.  update id and time, and return */

  dt->d_id=id;
  dt->d_t=time(&(dt->d_t));
  return dt;
}

/* for deletions, may need to rebalance the tree.  find appropriate
 * element and return, or NULL if there is none. hi = 1.
 */

struct d_ent *aclm_deptfind(struct d_ent *dt,  int hilo) 
{

  if (dt == NULL ) 		/* no point in searching */
    return NULL;

  if (hilo) {
    if ( dt->d_hi != NULL )
      return aclm_deptfind(dt->d_hi,hilo);
  }
  else if ( dt->d_low != NULL )
    return aclm_deptfind(dt->d_low,hilo);
  
  return(dt); 			/* we've gone as far as we can go */
}


/*
 * Walk tree, return NULL for nothing found, return valid subtree or
 * node otherwise.
 *
 * Side effects:
 *    print rrname, expecting that dump will print the address.
 *    Remove entry and reconnect tree as required.  Will require
 *    parent node.  If parent is NULL we are at the root.
 */
    
int aclm_dtsearch(struct d_ent *dt, struct d_ent *parent,
	     const char *rrname, u_int id)
{
  int sc,ret;
  struct d_ent *dn;
  time_t now;
  int cleanup=0;
  
  now=time(&now);
  /* base case: empty tree, and hack for if we're at a preallocated root.
   */

  if ( dt == NULL )
    return 0;

  if ( dt->d_t == 1 )
    return 0;
  
  /* we have an entry.  That doesn't mean we have children, but the base
     case handles that.
  */


  if (  dt->d_t < (now - 60)) {	/* clean up entry later */
    cleanup=1;
  }
  
  /* now check and see if we have a match. */
     
  sc=strcasecmp(rrname,dt->d_name);

  if ( sc < 0 ) // rrname < current node.  search low.
    ret= aclm_dtsearch(dt->d_low,dt,rrname,id);
  else if ( sc > 0 ) // rrname > current node, go high.
    ret= aclm_dtsearch(dt->d_hi,dt,rrname,id);
  else {
    /* here we have a match on the name. we need to check the id.
     * if the id doesn't match, then ignore.
     */

    if ( dt->d_id == id ) { // we have a match.  print and clean up.
      cleanup=1;
      ret=1;
    } else
      ret=0;
  }
  
    
  if ( cleanup == 1 ) {
    struct d_ent *dp,*dp2;		/* used for promotion at the bottom */
    

    /* three cases: leaf, internal, root
     * leaf: children are nulls.  just deallocate and return.
     * internal: find replacement and reattach.
     * root: find replacement, copy values and 
     */
    
    free(dt->d_name);		/* always free the name */

    /* first, check and see if we're at the root.  if we are, then there
     * are three possibilities:
     *    1.  there is a single entry in the tree.  Just signal with
     *        d_t = 1;
     *    2.  there is more than one entry, but one child, in which case
     *        promote the child by copy to preseve root memory.
     *    3.  There is more than one entry and multiple children, in which
     *        case preserve one child, promote the other, and then reattach.
     */
    if ( parent == NULL ) {
	struct d_ent *dnew,*newdhi;
      if ( dt->d_hi == NULL && dt->d_low == NULL ) {
	dt->d_t=1;		/* 1. single entry */
	tnodes--;
	return ret;
      }
      
      if ( ! ( dt->d_hi != NULL && dt->d_low != NULL )) {
	/* 2. one child is not null.  figure out which one */

	if ( dt->d_low != NULL ) { 
	                                 /* this means that dt->d_hi *is* NULL */
	  dnew=dt->d_low;	/* preserve memory of dt_low to free */
	  bcopy(dt->d_low,dt,sizeof(struct d_ent)); /* copy d_low to dt */
	} else {				    /* d_hi is NOT NULL
						     * and d_lo is */
	  dnew=dt->d_hi;	/* preserve d_hi */
	  bcopy(dt->d_hi,dt,sizeof(struct d_ent)); /* as above */
	}
	free(dnew);
	tnodes--;
	return ret;
      }

      /* 3. Now both lo AND hi are occupied. preserve dhi and promote d_lo */
      newdhi=dt->d_hi;
      dnew=dt->d_low;
      bcopy(dt->d_low,dt,sizeof(struct d_ent));
      free(dnew);
      
      /* reattach dhi */
      if ( dt->d_hi == NULL ) /* simple reaattach if new d_hi is NULL */
	dt->d_hi=newdhi;
      else {		/* otherwise find a good spot */
	dnew=aclm_deptfind(dt->d_hi,1); /* old d_low->d_hi < old d_hi */
	dnew->d_hi=newdhi;		/* attach old dt->hi to new spot */
      }
      tnodes--;
      return ret;
    }

    /* Now we are not in the root.  We are either a leaf or internal node
     * try leaf first.
     */

    if ( dt->d_hi == NULL && dt->d_low == NULL ) { /* we are a leaf. */
      if ( parent->d_hi == dt )			   /* see where we attach */
	parent->d_hi = NULL;			   /* we were high */
      else
	parent->d_low = NULL;	/* we were low */
      free(dt);
      tnodes--;
      return ret;
    }
    
    /* non-leaf internal node. see if we can just promote first.
     * That means that either d_hi or d_low MUST be NULL
     */
    
    if (!(dt->d_hi != NULL && dt->d_low != NULL)) { /* one IS NULL */
      if ( dt->d_hi != NULL ) {	/* promote d_hi */
	if ( parent->d_hi == dt )
	  parent->d_hi = dt->d_hi;
	else
	  parent->d_low = dt->d_hi;
      } else 			/* promote d_low */
	if ( parent->d_hi == dt )
	  parent->d_hi = dt->d_low;
	else
	  parent->d_low= dt->d_low;
      tnodes--;
      free(dt);
      return ret;
    }
    
  /* finally, last case.  internal node where both d_hi and d_low are
   * occupied.  Promote d_low and reattach d_hi.*/

    dp=dt->d_hi;		/* preserve d_hi */
    if ( parent->d_low== dt )	/* attach to parent */
      parent->d_low=dt->d_low;
    else
      parent->d_hi=dt->d_low;

    dp2=aclm_deptfind(dt->d_low,1);	/* find a spot for dt->d_hi */
    dp2->d_hi=dp;		/* reattach d_hi */
    free(dt);			/* free dt */
    tnodes--;
  }
    
  return ret;
}

void aclm_cleanup() 
{
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
    
    if ((err=sqlite3_prepare_v2(dbh2,sel,1500,&stmt,&tail))!=SQLITE_OK) {
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
    err=sqlite3_exec(dbh2,sel,0,0,&errstr);
    if ( errstr != NULL ){
      fprintf(stderr,"delete:  %s",errstr);
      sqlite3_free(errstr);
      exit(-1);
    }
}

  
