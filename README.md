# ipblockerclassified
A classed and threaded version of ipBlocker


I started ipBlocker over ten years ago.  It works.  It works very well.

However, another fella made Fail2Ban (https://www.keycdn.com/support/fail2ban).

I like the idea of Fail2Ban except it doesn't work.  I have tried a few times.  After a while the various scripts stop reading files.  It just locks up or something.  I have tried to debug it.  I have changed lots of parameters.  Etc etc.  No bueno.

So, here is my code to try to take what I did over ten years ago and make it something better based on the Fail2Ban idea.

Minimum debian (Ubuntu packages) to install:

  sudo apt install libdatetime-perl libconfig-file-perl liblog-any-adapter-callback-perl libregexp-ipv6-perl liblockfile-simple-perl liblog-log4perl-perl libgetopt-argparse-perl liblog-any-adapter-log4perl-perl liblog-dispatch-filerotate-perl
