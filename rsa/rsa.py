# RSA Encryption

## Import(s) ##
import sys, random, pickle

## Util(s) ##
def print_usage( command='' ):
    if command == 'init':
        print 'init <keys_filename> <prime_length>'
    elif command == 'encrypt':
        print 'encrypt <keys_filename> <plaintext_filename> <ciphertext_filename>'
    elif command == 'decrypt':
        print 'decrypt <keys_filename> <ciphertext_filename> <decrypted_filename>'
    else:
        print 'Usage:'
        print '\tinit - rsa setup -> takes keys_filename and prime_length as inputs'
        print '\tencrypt -> takes keys_filename, plaintext_filename, and ciphertext_filename as inputs'
        print '\tdecrypt -> takes keys_filename, ciphertext_filename, and decrypted_filename as inputs '

def miller_rabin_test( a, s, d, n ):
    atop = pow( a, d, n )
    if atop == 1:
        return True
    for i in xrange( s - 1 ):
        if atop == n - 1:
            return True
        atop = ( atop * atop ) % n
    return atop == n - 1

def miller_rabin( n, confidence ):
    d = n - 1
    s = 0
    while d % 2 == 0:
        d >>= 1
        s += 1

    for i in range( confidence ):
        a = 0
        while a == 0:
            a = random.randrange( n )
        if not miller_rabin_test( a, s, d, n ):
            return False
    return True

def euclid_gcd( a, b ):
    if a < b:
        a, b = b, a
    while b != 0:
        a, b = b, a % b
    return a

def ext_euclid( a, b ):
    if b == 0:
        return 1, 0, a
    else:
        x, y, gcd = ext_euclid( b, a % b )
        return y, x - y * ( a // b ), gcd

def inverse_mod( a, m ):
    x, y, gcd = ext_euclid( a, m )
    if gcd == 1:
        return x % m
    else:
        return None

## Class(es) ##
class RSAKey( object ):
    meta = dict( )
    primality_confidence = 20

    def gen_keys( self, nbits ):
        # generate p ( nbits-bit prime )
        while 1:
            p = random.getrandbits( nbits )
            if miller_rabin( p, self.primality_confidence ):
                self.meta.update( { 'p' : p } )
                break
        # generate q ( nbits-bit prime )
        while 1:
            q = random.getrandbits( nbits )
            if miller_rabin( q, self.primality_confidence ):
                self.meta.update( { 'q' : q } )
                break

        # compute modulus: ( p * q )
        modulus = long( self.meta[ 'p' ] * self.meta[ 'q' ] )
        self.meta.update( { 'modulus' : modulus } )

        # compute phi: ( ( p - 1 )( q - 1 ) )
        phi = long( ( self.meta[ 'p' ] - 1 ) * ( self.meta[ 'q' ] - 1 ) )
        self.meta.update( { 'phi' : phi } )

        # choose e s.t 1 < e < phi and euclid_gcd( e, phi ) = 1
        while 1:
            while 1:
                e = random.randrange( phi )
                if e == 0: continue
                if euclid_gcd( e, phi ) == 1:
                    self.meta.update( { 'e' : e } )
                    self.meta.update( { 'pub_key' : ( modulus, e ) } )
                    break

            # compute d:
            d = long( inverse_mod( long( self.meta[ 'e' ] ), phi ) )
            if d is None: continue
            else:
                self.meta.update( { 'd' : d } )
                self.meta.update( { 'priv_key' : ( modulus, d ) } )
                break
        public_key = (modulus, e)
        private_key = (modulus, d)
        return public_key, private_key

    def encrypt( self, pub_key, plain_text):
        ciphertext = ''
        for char in plain_text:
            ciphertext += str( pow( ord( char ), pub_key[ 1 ], pub_key[ 0 ] ) ) + '\n'
        return ciphertext

    def decrypt( self, priv_key, cipher_text):
        decrypted = ''
        for chunk in cipher_text:
            decrypted += chr( pow( long( chunk ), priv_key[ 1 ], priv_key[ 0 ] ) )
        return decrypted

    def dump( self, filename ):
        try:
            handle = open( filename, 'w' )
            pickle.dump( self.meta, handle )
            handle.close( )
            print 'Wrote generated keys to: ' + str( filename )
        except BaseException as e:
            print e

    def load( self, filename ):
        try:
            handle = open( filename, 'r' )
            self.meta = dict( pickle.load( handle ) )
            handle.close( )
        except BaseException as e:
            print e

    def show_keys( self, keys_fn ):
        try:
            self.load( keys_fn )
            print self.meta
        except BaseException as e:
            print e

## Main ##
if __name__ == "__main__":
    if len( sys.argv ) > 1:
        if str( sys.argv[ 1 ] ) == 'init':
            if len( sys.argv ) != 4:
                print 'Invalid number of inputs to init, expects 2, given ' + str( len( sys.argv ) - 2 )
                print_usage( 'init' )
            else:
                keys = RSAKey( )
                keys.gen_keys( str( sys.argv[ 2 ] ), int( sys.argv[ 3 ] ) )
        elif str( sys.argv[ 1 ] ) == 'encrypt':
            if len( sys.argv ) != 5:
                print 'Invalid number of inputs to encrypt, expects 3, given ' + str( len( sys.argv ) - 2 )
                print_usage( 'encrypt' )
            else:
                keys = RSAKey( )
                keys.encrypt( str( sys.argv[ 2 ] ), str( sys.argv[ 3 ] ), str( sys.argv[ 4 ] ) )
        elif str( sys.argv[ 1 ] ) == 'decrypt':
            if len( sys.argv ) != 5:
                print 'Invalid number of inputs to decrypt, expects 3, given ' + str( len( sys.argv ) - 2 )
                print_usage( 'decrypt' )
            else:
                keys = RSAKey( )
                keys.decrypt( str( sys.argv[ 2 ] ), str( sys.argv[ 3 ] ), str( sys.argv[ 4 ] ) )
        elif str( sys.argv[ 1 ] ) == 'showkeys':
            if len( sys.argv ) != 3:
                print 'Invalid number of inputs to showkeys, expects 1, given ' + str( len( sys.argv ) - 2 )
            else:
                keys = RSAKey( )
                keys.show_keys( str( sys.argv[ 2 ] ) )
        else:
            print 'Unrecognized input: ' + str( sys.argv[ 1 ] )
            print_usage( )

    else:
        print 'Invalid number of inputs'
        print_usage( )
