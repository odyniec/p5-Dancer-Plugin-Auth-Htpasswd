use strict;
use warnings;
use Module::Build;

my $class = Module::Build->subclass(
    class => 'My::Builder',
    code => q{
        sub ACTION_docs {
            use Pod::Readme;
            use Pod::Select;
            
            my $self = shift;
            
            podselect({ -output => 'README.pod' },
                'lib/Dancer/Plugin/Auth/Htpasswd.pm');

            chmod 0644, 'README';
            my $parser = Pod::Readme->new();
            $parser->parse_from_file('README.pod', 'README');
            
            return $self->SUPER::ACTION_docs;
        }
    }
);

my $builder = $class->new(
    module_name         => 'Dancer::Plugin::Auth::Htpasswd',
    license             => 'perl',
    dist_author         => q{Michal Wojciechowski <odyniec@cpan.org>},
    dist_version_from   => 'lib/Dancer/Plugin/Auth/Htpasswd.pm',
    requires => {
        'Authen::Htpasswd' => 0,
        'Dancer' => 1.3070,
    },
    configure_requires => {
        'Pod::Readme' => 0,
        'Pod::Select' => 0,
    },
    build_requires => {
        'Pod::Readme' => 0,
        'Pod::Select' => 0,
        'Test::More' => 0,
    },
    add_to_cleanup      => [ 'Dancer-Plugin-Auth-Htpasswd-*' ],
    create_makefile_pl => 'traditional',
    meta_merge => {
        resources => {
            repository => 'https://github.com/odyniec/Dancer-Plugin-Auth-Htpasswd'
        }
    }
);

$builder->create_build_script();
