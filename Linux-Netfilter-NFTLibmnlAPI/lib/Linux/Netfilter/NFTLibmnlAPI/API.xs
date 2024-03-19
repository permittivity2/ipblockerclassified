#define PERL_NO_GET_CONTEXT // we'll define thread context if necessary (faster)
#include "EXTERN.h"         // globals/constant import locations
#include "perl.h"           // Perl symbols, structures and constants definition
#include "XSUB.h"           // xsubpp functions and macros
#include <stdlib.h>         // rand()
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/select.h>
#include <string.h>

#include <libmnl/libmnl.h>	    // Netfilter NFT minimal api user space interface
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/netfilter/nf_conntrack_tcp.h>

// additional c code goes here

MODULE = Linux::Netfilter::NFTLibmnlAPI::API PACKAGE = Linux::Netfilter::NFTLibmnlAPI::API
PROTOTYPES: ENABLE

 # XS code goes here

 # XS comments begin with " #" to avoid them being interpreted as pre-processor
 # directives

unsigned int
rand()

void
srand(seed)
  unsigned int seed

void
put_msg(buf, i, seq)
  char *buf
  uint16_t i
  int seq
