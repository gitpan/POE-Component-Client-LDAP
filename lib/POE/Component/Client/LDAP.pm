package POE::Component::Client::LDAP;

=head1 NAME

POE::Component::Client::LDAP - subclass of Net::LDAP which uses POE to speak via sockets in async mode.

=head1 SYNOPSIS

 use POE;
 use POE::Component::Client::LDAP;
 
 POE::Session->create(
 	inline_states => {
 		_start => sub {
 			my ($heap, $session) = @_[HEAP, SESSION];
 			$heap->{ldap} = POE::Component::Client::LDAP->new(
 				'localhost',
 				callback => $session->postback( 'connect' ),
 			);
 		},
 		connect => sub {
 			my ($heap, $session, $callback_args) = @_[HEAP, SESSION, ARG1];
			if ( $callback_args->[0] ) {
 				$heap->{ldap}->bind(
 					callback => $session->postback( 'bind' ),
 				);
			}
			else {
 				delete $heap->{ldap};
				print "Connection Failed\n";
			}
 		},
 		bind => sub {
 			my ($heap, $session) = @_[HEAP, SESSION];
 			$heap->{ldap}->search(
 				base => "ou=People,dc=domain,dc=net",
 				filter => "(objectClass=person)",
 				callback => $session->postback( 'search' ),
 			);
 		},
 		search => sub {
 			my ($heap, $ldap_return) = @_[HEAP, ARG1];
 			my $ldap_search = shift @$ldap_return;
 
 			foreach (@$ldap_return) {
 				print $_->dump;
 			}
 
 			delete $heap->{ldap} if $ldap_search->done;
 		},
 	},
 );
 
 POE::Kernel->run();

=head1 DESCRIPTION

POE::Component::Client::LDAP->new() starts up a new POE::Session and POE::Wheel to manage socket communications for an underlying Net::LDAP object, allowing it to be used in async mode properly within a POE program.

=cut

use base 'Net::LDAP';

use 5.006;
use Net::LDAP::ASN qw(LDAPResponse);
use POE qw(Filter::Stream Filter::ASN1 Wheel::SocketFactory Wheel::ReadWrite Driver::SysRW);
use Carp;

sub DEBUGGING () { 0 }

use strict;
use warnings;

our $VERSION = '0.03';

my $poe_states = {
	_start => sub {
		my ($kernel, $session, $heap, $host, $ldap_object, $arg) = @_[KERNEL, SESSION, HEAP, ARG0..ARG2];
		$heap->{oldhosts} = $heap->{hosts} = ref( $host ) eq 'ARRAY' ? $host : [$host];
		
		$heap->{connect_callback} = $arg->{callback};
		$heap->{port} = $arg->{port} || '389';

		$heap->{ldap_object} = $ldap_object; 
		
		$ldap_object->{_send_postback} = sub {
			confess( "LDAP send attempted before connection started" );
		};
		
		$ldap_object->{_shutdown_postback} = $session->postback( 'remove_ldap' );
		
		$kernel->yield( 'attempt_connection' );
	},
	attempt_connection => sub {
		my $heap = $_[HEAP];
		my $hosts = $heap->{hosts};
		
		if (@$hosts) {
			warn "Attempting conenction to host: $hosts->[0]\n" if DEBUGGING;
			$heap->{ldap_object}->{_send_postback} = sub {
				confess( "LDAP send attempted before connection set up" );
			};
			$heap->{wheel} = POE::Wheel::SocketFactory->new(
				RemoteAddress	=> $hosts->[0],
				RemotePort	=> $heap->{port},
				# No way to do LocalAddr, Proto, MultiHomed, or Timeout yet
				SuccessEvent	=> 'sf_success',
				FailureEvent	=> 'sf_failure',
			);
		}
		else {
			$heap->{connect_callback}->();
			delete $heap->{connect_callback};
		}
	},
	_stop => sub {
		warn "_stop\n" if DEBUGGING;
	},
	sf_success => sub {
		my ($heap, $session, $sock, $addr, $port) = @_[HEAP, SESSION, ARG0..ARG2];
		$heap->{wheel} = POE::Wheel::ReadWrite->new(
			Handle => $sock,
			Driver => POE::Driver::SysRW->new(),
			InputFilter => POE::Filter::ASN1->new(),
			OutputFilter => POE::Filter::Stream->new(),
			InputEvent => 'got_input',
			FlushedEvent => 'flushed_output', # TODO: handle this
			ErrorEvent => 'wheel_error', # TODO: handle this
		);
		$heap->{ldap_object}->{_send_postback} = $session->postback( 'send_message' );
		$heap->{connect_callback}->( 1, $heap->{hosts}->[0], $addr, $port);
	},
	sf_failure => sub {
		my ($kernel, $heap, $operation, $errnum, $errstr) = @_[KERNEL, HEAP, ARG0..ARG2];
		$heap->{connect_callback}->( 0, $heap->{hosts}->[0], $operation, $errnum, $errstr );
		
		shift @{$heap->{hosts}}; # Top one failed, remove it and try again
		$kernel->yield( 'attempt_connection' );
		
		warn("sf_failure: @_\n") if DEBUGGING;
	},
	remove_ldap => sub {
		my $heap = $_[HEAP];

		my $ldap_object =  $heap->{ldap_object};
		delete $ldap_object->{_shutdown_postback};
		delete $ldap_object->{_send_postback};

		delete $heap->{ldap_object};
		delete $heap->{connect_callback};
		delete $heap->{wheel};
	},
	got_input => sub {
		my ($heap, $input) = @_[HEAP, ARG0];
		my $result = $LDAPResponse->decode($input);

		my $mid = $result->{messageID};
		my $mesg = $heap->{ldap_object}->inner->{net_ldap_mesg}->{$mid};

		unless ($mesg) {
			if (my $ext = $result->{protocolOp}{extendedResp}) {
				if (($ext->{responseName} || '') eq '1.3.6.1.4.1.1466.20036') {
					# TODO: handle this
					die("Notice of Disconnection");
				}
			}

			# TODO: handle this
			# print "Unexpected PDU, ignored\n";
			return;
		}
    
		$mesg->decode($result);
	},
	send_message => sub {
		my ($heap, $response_args) = @_[HEAP, ARG1];
		$heap->{wheel}->put( $response_args->[0] );
	},
};

=head1 INTERFACE DIFFERENCES

With regards to Net::LDAP, all interfaces are to be used as documented, with the following exceptions.

=over 2

=item POE::Component::Client::LDAP->new( hostname, callback => $coderef, OPTIONS )

A call to new() is non-blocking, always returning an object.

The 'callback' argument has been added and should always be supplied to notify your code when a connection is established.

Only LDAP connections are supported at this time, LDAPS and LDAPI will be in a future release.

Connection errors are not handled at this time, again in a future release.

The 'async' option is always turned on, and whatever value you pass in will be ignored.

=cut

sub new {
  my $class = shift;
  my $self = bless {}, (ref $class || $class);

  my $host = shift if @_ % 2;
  my $arg = &Net::LDAP::_options;

  POE::Session->create(
    inline_states => $poe_states,
    args => [ $host, $self, $arg ],
  );

  $self->{net_ldap_resp} = {};
  $self->{net_ldap_version} = $arg->{version} || $Net::LDAP::LDAP_VERSION;
  $self->{net_ldap_async} = 1;

  $self->debug( $arg->{debug} || 0 );
  
  return $self->outer();
}

=item $object->async()

Async mode is always turned on and so this call will always return true, if you pass it a value to set it a fatal exception will be raised, even if value is true.

=cut

sub async {
	my $self = shift;
	if (@_) {
		die();
	}
	else {
		return $self->inner->{net_ldap_async}; 
	}
}

=item $object->sync()

Async mode is required, this call will cause a fatal exception.

=cut

sub sync {
	die();
}

=item $object->sock()

This call will throw a fatal exception.

Because POE is being used to handle socket communications I have chosen to not expose the raw socket at this time.

=back

=cut

sub socket {
	die();
}

sub disconnect {
	my $self = shift;
	$self->inner->_drop_conn()
}

sub _drop_conn {
  # Called as inner
  my $self = shift;
  warn( "_drop_conn\n" ) if DEBUGGING;  
  $self->{_shutdown_postback}->();
}

sub _sendmesg {
  my $self = shift;
  my $mesg = shift;

  $self->{_send_postback}->( $mesg->pdu );

  my $mid = $mesg->mesg_id;

  $self->inner->{net_ldap_mesg}->{$mid} = $mesg;
}

sub _recvresp {
	die();
}

sub DESTROY {
	my $self = shift;
	$self->inner->_drop_conn()
		unless --$self->inner->{net_ldap_refcnt};
		
	warn( "Nddet::LDAP Refcount: " . $self->inner->{net_ldap_refcnt} . "\n" ) if DEBUGGING;
}

=head1 CALLBACK SEMANTICS

The callback semantics documented here are for reference, the callbacks are handled by Net::LDAP and I've only documented them for reference here. The exception to this is the callback for new() which does not exist in Net::LDAP, and thus I have defined myself.

=over 2

=item new

No arguments are passed to indicate that the connection list has been exhausted and no further attempts will be made.

The first argument is a boolean indicator of whether a connection has succeeded or failed. The second argument contains the host spec used to attempt the connection.

In the case of a success the third and fourth arguments contain the address and port connected to respectively.

In the case of a failure the third argument contains the name of the operation that failed, and the fourth and fifth arguments hold numeric and string values of $! respectively.

=item search

The first argument is always the Net::LDAP::Search object presiding over this search run. The 'done' method on this object may be consulted to know when all the possible replies have been received.

The second and following arguments are Net::LDAP::Entry objects returned from the search.

=item others

Forthcoming

=back

=head1 BUGS

Failures of many kinds are not very well handled at this time, also canceling running connection requests is not implemented.

=head1 AUTHOR

Jonathan Steinert
hachi@cpan.org

=head1 LICENSE

Copyright 2004 Jonathan Steinert (hachi@cpan.org)

This program is free software; you can redistribute it
and/or modify it under the same terms as Perl itself.

=cut

