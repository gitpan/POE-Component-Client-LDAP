use Module::Build;
# See perldoc Module::Build for details of how this works

Module::Build->new
    ( module_name     => 'POE::Component::Client::LDAP',
      license         => 'perl',
      requires	=> {
		'perl'			=> '5.6',
		'Net::LDAP'		=> '0.31',
		'Net::LDAP::ASN'	=> 0,
		'Convert::ASN1'		=> 0,
		'POE'			=> 0,
		'POE::Filter::Stream'	=> 0,
		'POE::Session'		=> 0,
		'POE::Kernel'		=> 0,
		'POE::Wheel::ReadWrite'	=> 0,
		'POE::Wheel::SocketFactory'	=> 0,
		'POE::Driver::SysRW'	=> 0,
      },
      build_requires => {
		'Module::Build'		=> 0,
      },
      create_readme => 1,
    )->create_build_script;
