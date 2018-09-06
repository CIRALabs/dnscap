# ACLM component for DNSCAP

This plugin is an early capability that reviews queries on the wire,
and outputs iptables access control list entries based on their
resolution for selected domains.

## Usage

    dnscap -1 -P ../plugins/aclm/.libs/aclm.so -d {hostsdb}

The database has the following schema:

    create table hosts ( dowhat integer, name text collate nocase,
       	          direction integer, tproto char(5), srcprt integer,
                  dstprt integer, direction_initiated integer );
	
    /* dowhat: 0 = permit, 1 = reject/deny
     * name is the hostname
     * direction: 0 = outbound, 1 = inbound
     * tproto = tcp, udp, or all
     * srcprt = source port (unused for tproto = all)
     * dstprt = destination port (unused for tproto = all)
     * direction_initiated = 1 inbound, 2 outbound
     */

For example:

insert into hosts values (0, "cnn.com", 0, "all", 0, 0, 1);

This would cause dnscap to look for cnn.com and add output ACL entries
for any transport protocol.  Direction initiated is outbound.  Source
and destination port are not meaningful in this example.



    Copyright (c) 2018 Cisco Systems and/or its Affiliates
    All rights reserved.  

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions
    are met:

    1. Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in
       the documentation and/or other materials provided with the
       distribution.

    3. Neither the name of the copyright holder nor the names of its
       contributors may be used to endorse or promote products derived
       from this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
    FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
    COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
    INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
    BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
    LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
    CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
    LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
    ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.

