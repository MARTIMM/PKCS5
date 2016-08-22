#!/usr/bin/env perl6

use v6.c;
use Test;

use PKCS5::PBKDF2;
use OpenSSL::Digest;

#-------------------------------------------------------------------------------
subtest {
  my PKCS5::PBKDF2 $p .= new(:CGH(&md5));
  isa-ok $p, PKCS5::PBKDF2;

  my Str $spw = $p.derive-hex(
    Buf.new('pencil'.encode),
    Buf.new( 65, 37, 194, 71, 228, 58, 177, 233, 60, 109, 255, 118),
    1,
  );

  is $spw, '12edf6c31d1b70cf001b8007de508ba4', '1 iteration hex md5';

  $spw = $p.derive-hex(
    Buf.new('pencil'.encode),
    Buf.new( 65, 37, 194, 71, 228, 58, 177, 233, 60, 109, 255, 118),
    4096,
  );

  is $spw, '58c208a6087ea3f1671bb86da22045b8', '4096 iteration hex md5';

}, 'md5 prf';

#-------------------------------------------------------------------------------
subtest {
  my PKCS5::PBKDF2 $p .= new(:CGH(&sha256));

  my Str $spw = $p.derive-hex(
    Buf.new('pencil'.encode),
    Buf.new( 65, 37, 194, 71, 228, 58, 177, 233, 60, 109, 255, 118),
    4096,
  );

  is $spw,
     'a97517ae572f9dac71586d340dd460562a11da09d4a6e5f9afedc4675add8556',
     '4096 iteration hex sha256';

}, 'sha256 prf';

#-------------------------------------------------------------------------------
subtest {
  my PKCS5::PBKDF2 $p .= new;

  my Buf $spw1 = $p.derive(
    Buf.new('pencil'.encode),
    Buf.new( 65, 37, 194, 71, 228, 58, 177, 233, 60, 109, 255, 118),
    1,
  );

  is $spw1.>>.fmt('%02x').join,
     'f305212412b600a373561fc27b941c350ba9d399',
     '1 iteration buf';

  my Str $spw2 = $p.derive-hex(
    Buf.new('pencil'.encode),
    Buf.new( 65, 37, 194, 71, 228, 58, 177, 233, 60, 109, 255, 118),
    1,
  );

  is $spw2, 'f305212412b600a373561fc27b941c350ba9d399', '1 iteration hex';

  $spw2 = $p.derive-hex(
    Buf.new('pencil'.encode),
    Buf.new( 65, 37, 194, 71, 228, 58, 177, 233, 60, 109, 255, 118),
    4096,
  );

  is $spw2, '1d96ee3a529b5a5f9e47c01f229a2cb8a6e15f7d', '4096 iteration hex';

}, 'sha1 prf';

#-------------------------------------------------------------------------------
subtest {
  my PKCS5::PBKDF2 $p .= new(:dklen(30));

  my Str $spw2 = $p.derive-hex(
    Buf.new('pencil'.encode),
    Buf.new( 65, 37, 194, 71, 228, 58, 177, 233, 60, 109, 255, 118),
    4096,
  );

  is $spw2,
     '1d96ee3a529b5a5f9e47c01f229a2cb8a6e15f7dd4329078905280f7e1a3',
     '4096 iteration hex with dklen=30';

}, 'sha1 prf with different dklen';

#-------------------------------------------------------------------------------
done-testing;
