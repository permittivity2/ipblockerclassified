{"vars":[{"kind":2,"line":3,"name":"strict","containerName":""},{"name":"warnings","line":4,"containerName":"","kind":2},{"kind":2,"name":"lib","line":5,"containerName":""},{"containerName":"Net","line":6,"name":"IPBlocker","kind":2},{"containerName":"Log::Any","line":7,"name":"Adapter","kind":2},{"name":"Log4perl","line":8,"containerName":"Log","kind":2},{"name":"Dumper","line":9,"containerName":"Data","kind":2},{"containerName":"Getopt","line":10,"name":"ArgParse","kind":2},{"name":"Carp","line":11,"containerName":"","kind":2},{"kind":2,"containerName":"List","line":12,"name":"Util"},{"line":14,"name":"$Data","containerName":null,"kind":13},{"kind":12,"line":14,"name":"Dumper","containerName":"Sortkeys"},{"name":"$Data","line":15,"containerName":null,"kind":13},{"kind":12,"line":15,"containerName":"Indent","name":"Dumper"},{"line":17,"name":"Log","containerName":"Any::Adapter","kind":12},{"containerName":"main::","line":17,"name":"set","kind":12},{"containerName":null,"name":"$logger","localvar":"my","line":19,"definition":"my","kind":13},{"kind":12,"line":19,"name":"get_logger"},{"line":21,"name":"main","kind":12},{"kind":12,"definition":"sub","range":{"start":{"line":25,"character":0},"end":{"character":9999,"line":60}},"line":25,"children":[{"localvar":"my","containerName":"main","name":"$clargs","kind":13,"definition":"my","line":28},{"containerName":"main","line":30,"name":"$clargs","kind":13},{"kind":12,"containerName":"main","line":30,"name":"loglevel"},{"kind":13,"line":30,"containerName":"main","name":"$clargs"},{"line":30,"name":"log4perlconf","containerName":"main","kind":12},{"name":"$msg","containerName":"main","localvar":"my","line":31,"definition":"my","kind":13},{"line":32,"name":"$msg","containerName":"main","kind":13},{"line":33,"name":"$msg","containerName":"main","kind":13},{"kind":13,"name":"$msg","line":34,"containerName":"main"},{"containerName":"main","name":"$logger","localvar":"my","line":37,"definition":"my","kind":13},{"name":"$clargs","line":37,"containerName":"main","kind":13},{"localvar":"my","name":"$ipbArgs","containerName":"main","definition":"my","kind":13,"line":40},{"line":41,"name":"$clargs","containerName":"main","kind":13},{"name":"configsfile","line":41,"containerName":"main","kind":12},{"kind":13,"name":"$clargs","line":42,"containerName":"main"},{"containerName":"main","line":42,"name":"dumpconfigsandexit","kind":12},{"containerName":"main","line":43,"name":"$clargs","kind":13},{"kind":12,"containerName":"main","line":43,"name":"forceremovelockfile"},{"name":"$clargs","line":45,"containerName":"main","kind":13},{"name":"iptables","line":45,"containerName":"main","kind":12},{"name":"$clargs","line":46,"containerName":"main","kind":13},{"containerName":"main","line":46,"name":"lockfile","kind":12},{"kind":13,"line":47,"name":"$clargs","containerName":"main"},{"line":47,"name":"prodmode","containerName":"main","kind":12},{"line":48,"containerName":"main","name":"$clargs","kind":13},{"line":48,"containerName":"main","name":"queuechecktime","kind":12},{"line":49,"containerName":"main","name":"$clargs","kind":13},{"kind":12,"line":49,"containerName":"main","name":"queuecycles"},{"kind":13,"line":50,"containerName":"main","name":"$clargs"},{"line":50,"name":"readentirefile","containerName":"main","kind":12},{"kind":13,"line":51,"name":"$clargs","containerName":"main"},{"kind":12,"containerName":"main","line":51,"name":"totalruntime"},{"kind":13,"definition":"my","line":54,"localvar":"my","containerName":"main","name":"$ipb"},{"kind":12,"line":54,"containerName":"main","name":"new"},{"kind":13,"line":54,"name":"$ipbArgs","containerName":"main"},{"kind":13,"containerName":"main","line":56,"name":"$logger"},{"line":56,"name":"info","containerName":"main","kind":12},{"kind":13,"name":"$ipb","line":59,"containerName":"main"},{"containerName":"main","line":59,"name":"go","kind":12}],"containerName":"main::","name":"main"},{"kind":12,"line":28,"name":"setupArgParse"},{"kind":12,"name":"croak","line":34},{"kind":12,"line":37,"name":"setup_logger"},{"kind":12,"name":"configsfile","line":41},{"kind":12,"line":42,"name":"dumpconfigsandexit"},{"line":43,"name":"forceremovelockfile","kind":12},{"kind":12,"name":"iptables","line":45},{"kind":12,"name":"lockfile","line":46},{"line":47,"name":"prodmode","kind":12},{"kind":12,"line":48,"name":"queuechecktime"},{"kind":12,"line":49,"name":"queuecycles"},{"kind":12,"name":"readentirefile","line":50},{"kind":12,"name":"totalruntime","line":51},{"name":"Net","line":54,"containerName":"IPBlocker","kind":12},{"kind":12,"definition":"sub","range":{"end":{"character":9999,"line":93},"start":{"line":62,"character":0}},"detail":"($clargs)","children":[{"definition":"my","kind":13,"line":63,"localvar":"my","name":"$clargs","containerName":"setup_logger"},{"line":66,"containerName":"setup_logger","name":"$clargs","kind":13},{"line":66,"containerName":"setup_logger","name":"log4perlconf","kind":12},{"kind":13,"line":68,"containerName":"setup_logger","name":"$clargs"},{"containerName":"setup_logger","line":68,"name":"log4perlconf","kind":12},{"line":71,"containerName":"setup_logger","name":"$clargs","kind":13},{"containerName":"setup_logger","line":71,"name":"logwatch_interval","kind":12},{"containerName":"setup_logger","line":72,"name":"init_and_watch","kind":12},{"containerName":"setup_logger","line":72,"name":"$clargs","kind":13},{"kind":12,"line":72,"containerName":"setup_logger","name":"log4perlconf"},{"line":72,"containerName":"setup_logger","name":"$clargs","kind":13},{"kind":12,"line":72,"name":"logwatch_interval","containerName":"setup_logger"},{"kind":12,"line":74,"name":"init","containerName":"setup_logger"},{"kind":13,"name":"$clargs","line":74,"containerName":"setup_logger"},{"line":74,"containerName":"setup_logger","name":"log4perlconf","kind":12},{"name":"$loglevel","containerName":"setup_logger","localvar":"my","line":78,"definition":"my","kind":13},{"kind":13,"containerName":"setup_logger","line":78,"name":"$clargs"},{"name":"loglevel","line":78,"containerName":"setup_logger","kind":12},{"containerName":"setup_logger","name":"$conf","localvar":"my","line":79,"kind":13,"definition":"my"},{"kind":12,"line":87,"containerName":"setup_logger","name":"init"},{"name":"$conf","line":87,"containerName":"setup_logger","kind":13},{"localvar":"my","containerName":"setup_logger","name":"$logger","kind":13,"definition":"my","line":91},{"line":92,"containerName":"setup_logger","name":"$logger","kind":13}],"line":62,"signature":{"documentation":"","label":"setup_logger($clargs)","parameters":[{"label":"$clargs"}]},"containerName":"main::","name":"setup_logger"},{"line":68,"name":"croak","kind":12},{"kind":12,"line":72,"containerName":"Log4perl","name":"Log"},{"containerName":"Log4perl","line":74,"name":"Log","kind":12},{"line":87,"containerName":"Log4perl","name":"Log","kind":12},{"name":"get_logger","line":91,"kind":12},{"kind":12,"name":"croak","line":91},{"name":"setupArgParse","containerName":"main::","children":[{"definition":"my","kind":13,"line":132,"localvar":"my","name":"$args","containerName":"setupArgParse"},{"kind":13,"definition":"my","line":134,"localvar":"my","containerName":"setupArgParse","name":"$description"},{"kind":13,"line":135,"name":"$description","containerName":"setupArgParse"},{"containerName":"setupArgParse","line":136,"name":"$description","kind":13},{"definition":"my","kind":13,"line":137,"localvar":"my","name":"$ap","containerName":"setupArgParse"},{"kind":12,"name":"new_parser","line":137,"containerName":"setupArgParse"},{"kind":13,"line":139,"containerName":"setupArgParse","name":"$description"},{"line":143,"name":"$ap","containerName":"setupArgParse","kind":13},{"containerName":"setupArgParse","line":143,"name":"add_arg","kind":12},{"name":"$helpreadentirefile","containerName":"setupArgParse","localvar":"my","line":150,"definition":"my","kind":13},{"kind":13,"containerName":"setupArgParse","line":151,"name":"$helpreadentirefile"},{"containerName":"setupArgParse","line":152,"name":"$helpreadentirefile","kind":13},{"name":"$ap","line":153,"containerName":"setupArgParse","kind":13},{"containerName":"setupArgParse","line":153,"name":"add_arg","kind":12},{"line":159,"name":"$helpreadentirefile","containerName":"setupArgParse","kind":13},{"kind":13,"containerName":"setupArgParse","line":162,"name":"$ap"},{"name":"add_arg","line":162,"containerName":"setupArgParse","kind":12},{"localvar":"my","name":"$helpqueuechecktime","containerName":"setupArgParse","kind":13,"definition":"my","line":169},{"kind":13,"containerName":"setupArgParse","line":170,"name":"$helpqueuechecktime"},{"line":171,"name":"$helpqueuechecktime","containerName":"setupArgParse","kind":13},{"kind":13,"line":172,"name":"$helpqueuechecktime","containerName":"setupArgParse"},{"containerName":"setupArgParse","line":173,"name":"$helpqueuechecktime","kind":13},{"name":"$ap","line":174,"containerName":"setupArgParse","kind":13},{"kind":12,"name":"add_arg","line":174,"containerName":"setupArgParse"},{"name":"$helpqueuechecktime","line":179,"containerName":"setupArgParse","kind":13},{"line":182,"containerName":"setupArgParse","name":"$ap","kind":13},{"line":182,"containerName":"setupArgParse","name":"add_arg","kind":12},{"containerName":"setupArgParse","line":190,"name":"$ap","kind":13},{"kind":12,"containerName":"setupArgParse","line":190,"name":"add_arg"},{"line":198,"name":"$ap","containerName":"setupArgParse","kind":13},{"line":198,"name":"add_arg","containerName":"setupArgParse","kind":12},{"name":"$ap","line":206,"containerName":"setupArgParse","kind":13},{"name":"add_arg","line":206,"containerName":"setupArgParse","kind":12},{"containerName":"setupArgParse","line":213,"name":"$ap","kind":13},{"kind":12,"name":"add_arg","line":213,"containerName":"setupArgParse"},{"kind":13,"line":223,"name":"$ap","containerName":"setupArgParse"},{"line":223,"containerName":"setupArgParse","name":"add_arg","kind":12},{"name":"$help","containerName":"setupArgParse","localvar":"my","line":238,"definition":"my","kind":13},{"kind":13,"line":239,"name":"$help","containerName":"setupArgParse"},{"kind":13,"line":240,"name":"$help","containerName":"setupArgParse"},{"containerName":"setupArgParse","line":241,"name":"$help","kind":13},{"kind":13,"name":"$help","line":242,"containerName":"setupArgParse"},{"name":"$help","line":243,"containerName":"setupArgParse","kind":13},{"kind":13,"line":244,"containerName":"setupArgParse","name":"$ap"},{"kind":12,"name":"add_arg","line":244,"containerName":"setupArgParse"},{"kind":13,"line":249,"containerName":"setupArgParse","name":"$help"},{"kind":13,"containerName":"setupArgParse","line":252,"name":"$ap"},{"line":252,"containerName":"setupArgParse","name":"add_arg","kind":12},{"name":"$ap","line":260,"containerName":"setupArgParse","kind":13},{"kind":12,"name":"add_arg","line":260,"containerName":"setupArgParse"},{"kind":13,"line":267,"containerName":"setupArgParse","name":"$ap"},{"line":267,"name":"add_arg","containerName":"setupArgParse","kind":12},{"kind":13,"line":276,"name":"$ap","containerName":"setupArgParse"},{"line":276,"containerName":"setupArgParse","name":"parse_args","kind":12}],"line":131,"definition":"sub","range":{"start":{"character":0,"line":131},"end":{"character":9999,"line":277}},"kind":12},{"kind":12,"containerName":"ArgParse","line":137,"name":"Getopt"},{"kind":12,"name":"prog","line":138},{"kind":12,"line":139,"name":"description"},{"line":140,"name":"epilog","kind":12},{"kind":12,"line":145,"name":"type"},{"kind":12,"line":146,"name":"dest"},{"kind":12,"line":147,"name":"help"},{"kind":12,"line":155,"name":"type"},{"line":156,"name":"dest","kind":12},{"line":159,"name":"help","kind":12},{"name":"type","line":164,"kind":12},{"name":"dest","line":165,"kind":12},{"kind":12,"name":"help","line":166},{"line":176,"name":"type","kind":12},{"kind":12,"line":177,"name":"dest"},{"name":"help","line":179,"kind":12},{"kind":12,"line":184,"name":"type"},{"line":185,"name":"dest","kind":12},{"name":"default","line":186,"kind":12},{"line":187,"name":"help","kind":12},{"name":"type","line":192,"kind":12},{"kind":12,"name":"dest","line":193},{"kind":12,"name":"default","line":194},{"kind":12,"line":195,"name":"help"},{"line":200,"name":"choices","kind":12},{"kind":12,"name":"dest","line":201},{"name":"default","line":202,"kind":12},{"name":"help","line":203,"kind":12},{"kind":12,"name":"type","line":208},{"kind":12,"name":"dest","line":209},{"line":210,"name":"help","kind":12},{"line":215,"name":"type","kind":12},{"name":"dest","line":216,"kind":12},{"line":220,"name":"help","kind":12},{"name":"type","line":225,"kind":12},{"kind":12,"line":226,"name":"dest"},{"kind":12,"name":"help","line":229},{"kind":12,"name":"type","line":246},{"kind":12,"line":247,"name":"dest"},{"line":248,"name":"default","kind":12},{"kind":12,"line":249,"name":"help"},{"name":"type","line":254,"kind":12},{"kind":12,"line":255,"name":"dest"},{"kind":12,"name":"default","line":256},{"name":"help","line":257,"kind":12},{"kind":12,"line":262,"name":"type"},{"name":"dest","line":263,"kind":12},{"kind":12,"line":264,"name":"help"},{"kind":12,"line":269,"name":"type"},{"name":"default","line":272,"kind":12},{"kind":12,"name":"help","line":273}],"version":5}