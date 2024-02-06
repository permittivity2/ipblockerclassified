{"version":5,"vars":[{"kind":2,"definition":1,"name":"Net::IPBlocker::GrepRegexpsSSHD","line":2},{"kind":2,"containerName":"","name":"strict","line":4},{"containerName":"","line":5,"name":"warnings","kind":2},{"containerName":"","name":"Exporter","line":6,"kind":2},{"kind":2,"containerName":"Regexp","name":"IPv6","line":7},{"kind":2,"containerName":"Log","name":"Any","line":8},{"containerName":"","name":"threads","line":9,"kind":2},{"kind":2,"containerName":"Data","line":10,"name":"Dumper"},{"kind":13,"containerName":null,"line":12,"name":"$Data"},{"line":12,"name":"Dumper","containerName":"Sortkeys","kind":12},{"name":"$Data","line":13,"containerName":null,"kind":13},{"line":13,"name":"Dumper","containerName":"Indent","kind":12},{"definition":"our","containerName":"Net::IPBlocker::GrepRegexpsSSHD","name":"@EXPORT_OK","line":15,"kind":13},{"definition":"my","line":17,"name":"$logger","containerName":null,"localvar":"my","kind":13},{"kind":13,"line":17,"name":"$log","containerName":null},{"kind":13,"localvar":"my","containerName":null,"name":"$REGEX_IPV4","line":18,"definition":"my"},{"definition":"my","name":"$REGEX_IPV6","line":19,"containerName":null,"kind":13,"localvar":"my"},{"signature":{"documentation":"# FILEPATH: Untitled-1\n\npackage Net::IPBlocker::GrepRegexpsSSHD;\n\nuse strict;\nuse warnings;\nuse Exporter;\nuse Regexp::IPv6     qw($IPv6_re);\nuse Log::Any qw($log);  # Allegedly handles lots of different logging modules\nuse threads;\nuse Data::Dumper;\n\nlocal $Data::Dumper::Sortkeys = 1;\nlocal $Data::Dumper::Indent   = 1;\n\nour @EXPORT_OK = qw(grep_regexps);\n\nmy $logger = $log;\nmy $REGEX_IPV4 = q/\\b((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\\b/;\nmy $REGEX_IPV6      = q/\\b($IPv6_re)\\b/;\n\n=head1 NAME\n\nNet::IPBlocker::GrepRegexpsDefault - Default regular expressions for IP blocking for sshd logs (auth.log)\n\n=head1 SYNOPSIS\n\nThis works with the Net::IPBlocker module to provide a framework for getting bad IPs from a ssh log file.\n\nThe calling code will always pass in the log object and the log contents.\n\nThe sshd log has two special items.  We don't want to add IPs to be blocked with special user names.  \nAlso, the sshd log is usually an auth log so we filter out lines that don't have sshd in them.\nBoth of these may be set in the configs file like this (as an example):\n\n logs_to_review[authlog][filterin][01] = \"sshd\"\n logs_to_review[authlog][filterin][02] = \"openssh\"\n logs_to_review[authlog][filterout][01] = \"sshd.*for johnboy\"\n logs_to_review[authlog][filterout][02] = \"sshd.*Accepted.*for trinity\"\n logs_to_review[authlog][filterout][03] = \"sshd.*Accepted.*for neo\"\n\n\n=head1 DESCRIPTION\n\nThis module provides a default regular expression sub for IP blocking. \nThese regular expressions can be used with the L<Net::IPBlocker> module to match and block IP addresses.\n\n=head1 METHODS\n\n=head2 get_regexps\n\nReturns an array of default regular expressions for IP blocking.\n\n    my @regexps = Net::IPBlocker::GrepRegexpsDefault->get_regexps();\n\n Description:  Using the logobj, this greps against the log contents for matching lines and then gets the\n               IP address on each line.\n Requires:     $self, $log\n Returns:      Hash reference of IP addresses with count of how many times the IP address was found","parameters":[{"label":"$self"},{"label":"$logobj"}],"label":"grep_regexps($self,$logobj)"},"kind":12,"detail":"($self,$logobj)","line":61,"name":"grep_regexps","containerName":"Net::IPBlocker::GrepRegexpsSSHD","children":[{"localvar":"my","kind":13,"definition":"my","name":"$self","line":62,"containerName":"grep_regexps"},{"kind":13,"line":62,"name":"$logobj","containerName":"grep_regexps"},{"definition":"my","name":"$TID","line":63,"containerName":"grep_regexps","localvar":"my","kind":13},{"name":"tid","line":63,"containerName":"grep_regexps","kind":12},{"line":64,"name":"$logger","containerName":"grep_regexps","kind":13},{"kind":12,"line":64,"name":"debug","containerName":"grep_regexps"},{"kind":13,"containerName":"grep_regexps","line":66,"name":"$logger"},{"kind":12,"name":"debug","line":66,"containerName":"grep_regexps"},{"name":"$logobj","line":66,"containerName":"grep_regexps","kind":13},{"name":"$logger","line":66,"containerName":"grep_regexps","kind":13},{"line":66,"name":"is_debug","containerName":"grep_regexps","kind":12},{"kind":13,"localvar":"my","line":67,"name":"$matches","containerName":"grep_regexps","definition":"my"},{"name":"@log_contents","line":68,"containerName":"grep_regexps","definition":"my","kind":13,"localvar":"my"},{"containerName":"grep_regexps","line":68,"name":"$logobj","kind":13}],"definition":"sub","range":{"start":{"line":61,"character":0},"end":{"character":9999,"line":68}}},{"name":"threads","line":63,"kind":12},{"kind":12,"line":66,"name":"Dumper"},{"kind":12,"line":68,"name":"logcontents"},{"line":70,"name":"$logger","containerName":null,"kind":13},{"kind":12,"line":70,"name":"debug","containerName":"Net::IPBlocker::GrepRegexpsSSHD"},{"line":70,"name":"Dumper","kind":12},{"kind":13,"line":70,"name":"@log_contents","containerName":null},{"containerName":null,"line":70,"name":"$logger","kind":13},{"containerName":"Net::IPBlocker::GrepRegexpsSSHD","line":70,"name":"is_debug","kind":12},{"kind":13,"containerName":null,"name":"@log_contents","line":72},{"line":74,"name":"$logger","containerName":null,"kind":13},{"line":74,"name":"info","containerName":"Net::IPBlocker::GrepRegexpsSSHD","kind":12},{"kind":13,"line":74,"name":"@log_contents","containerName":null},{"localvar":"my","kind":13,"containerName":null,"name":"$filterin","line":75,"definition":"my"},{"kind":13,"name":"%logobj","line":75,"containerName":null},{"name":"filterin","line":75,"kind":12},{"kind":13,"localvar":"my","definition":"my","containerName":null,"line":76,"name":"$pattern"},{"containerName":null,"line":76,"name":"%logobj","kind":13},{"line":76,"name":"filterin","kind":12},{"kind":13,"containerName":null,"line":76,"name":"$filterin"},{"containerName":null,"name":"$logger","line":77,"kind":13},{"name":"debug","line":77,"containerName":"Net::IPBlocker::GrepRegexpsSSHD","kind":12},{"kind":13,"containerName":null,"line":77,"name":"@log_contents"},{"kind":13,"containerName":null,"line":79,"name":"@log_contents"},{"kind":13,"containerName":null,"name":"@log_contents","line":79},{"kind":13,"containerName":null,"line":81,"name":"$logger"},{"kind":12,"containerName":"Net::IPBlocker::GrepRegexpsSSHD","line":81,"name":"info"},{"kind":13,"line":81,"name":"@log_contents","containerName":null},{"kind":13,"localvar":"my","containerName":null,"name":"$filterout","line":83,"definition":"my"},{"kind":13,"line":83,"name":"%logobj","containerName":null},{"kind":12,"name":"filterout","line":83},{"localvar":"my","kind":13,"definition":"my","containerName":null,"name":"$pattern","line":84},{"line":84,"name":"%logobj","containerName":null,"kind":13},{"kind":12,"line":84,"name":"filterout"},{"kind":13,"containerName":null,"line":84,"name":"$filterout"},{"kind":13,"containerName":null,"name":"$logger","line":85},{"kind":12,"containerName":"Net::IPBlocker::GrepRegexpsSSHD","line":85,"name":"debug"},{"kind":13,"containerName":null,"line":87,"name":"@log_contents"},{"name":"@log_contents","line":87,"containerName":null,"kind":13},{"kind":13,"containerName":null,"name":"$logger","line":89},{"containerName":"Net::IPBlocker::GrepRegexpsSSHD","line":89,"name":"info","kind":12},{"line":89,"name":"@log_contents","containerName":null,"kind":13},{"kind":13,"localvar":"my","containerName":null,"line":92,"name":"$regex","definition":"my"},{"containerName":null,"name":"%logobj","line":92,"kind":13},{"kind":12,"name":"regexpdeny","line":92},{"containerName":null,"name":"$pattern","line":93,"definition":"my","localvar":"my","kind":13},{"kind":13,"line":93,"name":"%logobj","containerName":null},{"line":93,"name":"regexpdeny","kind":12},{"containerName":null,"name":"$regex","line":93,"kind":13},{"containerName":null,"line":94,"name":"$logger","kind":13},{"containerName":"Net::IPBlocker::GrepRegexpsSSHD","line":94,"name":"debug","kind":12},{"localvar":"my","kind":13,"definition":"my","containerName":null,"line":96,"name":"@current_matches"},{"containerName":null,"line":96,"name":"@log_contents","kind":13},{"kind":13,"name":"$logger","line":97,"containerName":null},{"name":"debug","line":97,"containerName":"Net::IPBlocker::GrepRegexpsSSHD","kind":12},{"name":"Dumper","line":97,"kind":12},{"kind":13,"name":"@current_matches","line":97,"containerName":null},{"kind":13,"name":"$logger","line":97,"containerName":null},{"kind":12,"containerName":"Net::IPBlocker::GrepRegexpsSSHD","name":"is_debug","line":97},{"localvar":"my","kind":13,"definition":"my","containerName":null,"line":99,"name":"$line"},{"kind":13,"containerName":null,"name":"@current_matches","line":99},{"kind":13,"containerName":null,"name":"$line","line":100},{"containerName":null,"line":101,"name":"$logger","kind":13},{"name":"debug","line":101,"containerName":"Net::IPBlocker::GrepRegexpsSSHD","kind":12},{"containerName":null,"line":103,"name":"$ip_address","definition":"my","kind":13,"localvar":"my"},{"containerName":null,"name":"$line","line":103,"kind":13},{"name":"%line","line":103,"containerName":null,"kind":13},{"containerName":null,"name":"%matches","line":104,"kind":13},{"line":104,"name":"$ip_address","containerName":null,"kind":13},{"kind":13,"containerName":null,"name":"$logger","line":105},{"containerName":"Net::IPBlocker::GrepRegexpsSSHD","name":"debug","line":105,"kind":12},{"kind":13,"name":"$logger","line":110,"containerName":null},{"containerName":"Net::IPBlocker::GrepRegexpsSSHD","name":"debug","line":110,"kind":12},{"kind":12,"line":110,"name":"Dumper"},{"kind":13,"containerName":null,"line":110,"name":"$matches"},{"name":"$logger","line":110,"containerName":null,"kind":13},{"containerName":"Net::IPBlocker::GrepRegexpsSSHD","line":110,"name":"is_debug","kind":12},{"kind":13,"localvar":"my","definition":"my","line":112,"name":"$log_msg","containerName":null},{"kind":13,"line":113,"name":"$log_msg","containerName":null},{"kind":13,"containerName":null,"name":"$matches","line":113},{"kind":13,"name":"$logger","line":114,"containerName":null},{"containerName":"Net::IPBlocker::GrepRegexpsSSHD","line":114,"name":"debug","kind":12},{"kind":13,"containerName":null,"name":"$log_msg","line":114},{"containerName":null,"line":116,"name":"$matches","kind":13},{"range":{"start":{"character":0,"line":121},"end":{"character":9999,"line":122}},"children":[],"definition":"sub","name":"gdr","line":121,"containerName":"Net::IPBlocker::GrepRegexpsSSHD","detail":"()","signature":{"label":"gdr()","parameters":[],"documentation":" Description: This is the gosh darn retaliatory strike and attack method.  It will strike the malicious IP addresses\n              with a malformed tcp packet to the port that the malicious IP address was attacking."},"kind":12}]}