# Net::SMTP_auth.pm
#
# alex pleiner 2001, 2003, zeitform Internet Dienste
# thanks to Graham Barr <gbarr@pobox.com> for Net::SMTP
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

# Net::SMTP_auth is a small extension to G. Barr's Net::SMTP
# to authenticate to an SMTP server using one of the AUTH
# methods PLAIN, LOGIN or CRAM-MD5 (see RFC2554 for details).
# This module can be expanded and is a very first implementation.

package Net::SMTP_auth;

require 5.001;

use strict;
use vars qw($VERSION @ISA);
use Socket 1.3;
use Carp;
use IO::Socket;
use Net::Cmd;
use Net::Config;
use Net::SMTP;
use MIME::Base64;
use Digest::HMAC_MD5 qw(hmac_md5_hex);

$VERSION = "0.05";

@ISA = qw(Net::SMTP);

# all other method taken from Net::SMTP

sub auth_types {
  my $me = shift;

  if (exists ${*$me}{'net_smtp_esmtp'}) {

    my $esmtp = ${*$me}{'net_smtp_esmtp'};

    if(exists $esmtp->{AUTH}) {
      return wantarray ? split(/\s+/, $esmtp->{AUTH}) : $esmtp->{AUTH};
    }
  }

  return;
}


sub auth {
  my $me = shift;
  my $auth_type = shift ||
       carp 'Net::SMTP_auth: missing argument "auth_type" to method "auth"';
  my $user = shift;
  my $pass = shift;

  ## go for auth login
  if (uc($auth_type) eq "LOGIN") {
    $me->_AUTH("LOGIN");
    if ( $me->code() == 334 ) {
      my $encoded_user = encode_base64($user); chomp $encoded_user;
      $me->command($encoded_user)->response();
      if ( $me->code() == 334 ) {
        my $encoded_pass = encode_base64($pass); chomp $encoded_pass;
	$me->command($encoded_pass)->response(); 
        if ( $me->code() == 235 ) {
	  return 1;
	}
      }
    }

    return;

  ## go for auth cram-md5
  } elsif (uc($auth_type) eq "CRAM-MD5") { 
    $me->_AUTH("CRAM-MD5");
    if ( $me->code() == 334 ) {
      my $stamp = $me->message;
      my $hmac = hmac_md5_hex(decode_base64($stamp), $pass);
      my $answer = encode_base64($user . " " . $hmac); $answer =~ s/\n//g;
      $me->command($answer)->response();
      if ( $me->code() == 235 ) {
	return 1;
      }
    }

    return;

  ## go for auth plain
  } elsif (uc($auth_type) eq "PLAIN") {
    $me->_AUTH("PLAIN");
    if ( $me->code() == 334 ) {
      my $string = encode_base64("\000$user\000$pass"); $string =~ s/\n//g;
      $me->command($string)->response();
      if ( $me->code() == 235 ) {
	return 1;
      }
    }

    return;

  ## other auth methods not supported
  } else {
    carp "Net::SMTP_auth: authentication type \"$auth_type\" not supported";
    return;
  }

}


sub _AUTH { shift->command("AUTH", @_)->response()  == CMD_OK } 

1;


__END__

=head1 NAME

Net::SMTP_auth - Simple Mail Transfer Protocol Client with AUTHentication

=head1 SYNOPSIS

    use Net::SMTP_auth;

    # Constructors
    $smtp = Net::SMTP_auth->new('mailhost');
    $smtp = Net::SMTP_auth->new('mailhost', Timeout => 60);

=head1 DESCRIPTION

This module implements a client interface to the SMTP and ESMTP
protocol AUTH service extension, enabling a perl5 application to talk 
to and authenticate against SMTP servers. This documentation assumes 
that you are familiar with the concepts of the SMTP protocol described 
in RFC821 and with the AUTH service extension described in RFC2554.

A new Net::SMTP_auth object must be created with the I<new> method. Once
this has been done, all SMTP commands are accessed through this object.

The Net::SMTP_auth class is a subclass of Net::SMTP, which itself is
a subclass of Net::Cmd and IO::Socket::INET.

=head1 EXAMPLES

This example authenticates via CRAM-MD5 and sends a small message to 
the postmaster at the SMTP server known as mailhost:

    #!/usr/bin/perl -w

    use Net::SMTP_auth;

    $smtp = Net::SMTP_auth->new('mailhost');
    $smtp->auth('CRAM-MD5', 'user', 'password');

    $smtp->mail($ENV{USER});
    $smtp->to('postmaster');

    $smtp->data();
    $smtp->datasend("To: postmaster\n");
    $smtp->datasend("\n");
    $smtp->datasend("A simple test message\n");
    $smtp->dataend();

    $smtp->quit;

=head1 CONSTRUCTOR

=over 4

=item new Net::SMTP_auth [ HOST, ] [ OPTIONS ]

This is the constructor for a new Net::SMTP_auth object. It is
taken from Net::SMTP as all other methods (except I<auth> and 
I<auth_types>) are, too.

=head1 METHODS

Unless otherwise stated all methods return either a I<true> or I<false>
value, with I<true> meaning that the operation was a success. When a method
states that it returns a value, failure will be returned as I<undef> or an
empty list.

=over 4

=item auth_types ()

Returns the AUTH methods supported by the server as an array or in a 
space separated string. This string is exacly the line given by the SMTP 
server after the C<EHLO> command containing the keyword C<AUTH>.

=item auth ( AUTH, USER, PASSWORD )

Authenticates the user C<USER> via the authentication method C<AUTH>
and the password C<PASSWORD>. Returns I<true> if successful and I<false>
if the authentication failed. Remember that the connection is not closed
if the authentication fails. You may issue a different authentication 
attempt. If you once are successfully authenticated, you cannot send
the C<AUTH> command again.

=back

=head1 SEE ALSO

L<Net::SMTP> and L<Net::Cmd>

=head1 AUTHOR

Alex Pleiner <alex@zeitform.de>, zeitform Internet Dienste.
Thanks to Graham Barr <gbarr@pobox.com> for Net::SMTP.

=head1 COPYRIGHT

Copyright (c) 2001, 2003 zeitform Internet Dienste. All rights reserved.
This program is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut



