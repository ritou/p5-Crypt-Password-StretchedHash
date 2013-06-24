# NAME

Crypt::Password::StretchedHash - simple library for password hashing and stretching

# SYNOPSIS

This module provides Generation / Verification method for hashed password string.
There are two methods to handle parameters simply.

    use Test::More;
    use Crypt::Password::StretchedHash;
    use Digest::SHA;

    # crypt
    my $pwhash = Crypt::Password::StretchedHash->crypt(
        password        => q{password},
        hash            => Digest::SHA->new("sha256"),
        salt            => q{salt},
        stretch_count   => 5000,
        format          => q{base64},
    );
    is($pwhash, q{4hvvzqZio+l9vGifQ7xF2+FKiyWRcb4lV3OSo9PsfUw=});

    # verify
    my $result = Crypt::Password::StretchedHash->verify(
        password        => q{password},
        password_hash   => q{4hvvzqZio+l9vGifQ7xF2+FKiyWRcb4lV3OSo9PsfUw=},
        hash            => Digest::SHA->new("sha256"),
        salt            => q{salt},
        stretch_count   => 5000,
        format          => q{base64},
    );

    unless ( $result ) {
        # password error
    }

if you use class of the hash information(Crypt::Passwoed::SaltedHash::HashInfo),
there are two methods to generate/verify string for DB Store. 

    use Your::Password::HashInfo;
    use Crypt::Password::StretchedHash;
    

    my $hash_info = Your::Password::HashInfo->new;
    # crypt
    my $password = ...;
    my $pwhash_with_hashinfo = crypt_with_hashinfo(
        password    => $password,
        hash_info   => $hash_info,
    );
    

    # verify
    my $password = ...;
    my $pwhash_with_hashinfo = ...;
    my $result = verify_with_hashinfo(
        password        => $password,
        password_hash   => $pwhash_with_hashinfo,
        hash_info   => $hash_info,
    );
    

    unless ( $result ) {
        # password error
    }

# DESCRIPTION

Crypt::Password::StretchedHash is simple library for password hashing and stretching.
This module is available in generation and validation of the stretched password hash.

# METHODS

## crypt( %params ) : String

Generates stretched password hash.
This uses the following hash algorithm.

    for (1..$params{stretch_count}) {
        $hash->add( $pwhash, $params{password}, $salt );
        $pwhash = $hash->digest;
    }

- $params{password}

    This is password string.

- $params{hash}
 

    This is a hash function.
    This value must be the object of Digest::SHA or Digest::SHA3.

- $params{salt}
 

    This is salt string.

- $params{stretch\_count}

    This is stretching count.
    The value will depend on a kind of hash function and the server load.

- $params{format}

    This value is optional.
    If it has none, the password hash is returned with a binary string.
    If it has "hex", the password hash is returned with hexadecimal representation.
    If it has "base64", the password hash is returned with base64 representation.

## verify( %params ) : Int

Verifies stretched password hash.
This compares the value of $params{password\_hash} with the generated using crypt method.

## crypt\_with\_hashinfo( %params ) : String

Generates stretched password hash with hash information.

## verify\_with\_hashinfo( %params ) : Int

Verifies stretched password hash with hash information.
This compares the value of $params{password\_hash} with the generated using crypt method.

# LICENSE

Copyright (C) Ryo Ito.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

# AUTHOR

Ryo Ito <ritou.06@gmail.com>
