use 5.034000;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME              => 'Linux::Netfilter::NFTLibmnlAPI',
    VERSION_FROM      => 'lib/Linux/Netfilter/NFTLibmnlAPI.pm', 
    PREREQ_PM         => { 'Test::More' => 0, 'ExtUtils::MakeMaker' => '7.12' }, 
    ABSTRACT_FROM     => 'lib/Linux/Netfilter/NFTLibmnlAPI.pm', 
    AUTHOR            => 'Jeff G <someemail@forge.name>',
    CCFLAGS           => '-Wall -std=c99',
    OPTIMIZE          => '-O3',
    LICENSE           => 'gpl',
    XSMULTI           => 1,
);
