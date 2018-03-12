#!/usr/bin/python3

import lmots
import lms
import hss

import sys
import binascii

def print_usage():
    print( "Usage:" )
    print( "" )
    print( "   ./command_line_interface.py sign pubfile file1 file2 ... " )
    print( "Generate public/private key pair, write public key to pubfile, \n"
           "sign messages in file1, file2, ... "
           "and store signatures as file1.sig, file2.sig, ..." )
    print( "" )
    print( "   ./command_line_interface.py verify pubfile file1 file2 ... " )
    print("Verify signatures file1.sig, file2.sig, ... for \n"
          "messages file1, file2, ... using public key pubfile" )
    print("")
           

def main():
    if len( sys.argv ) < 4:
        print_usage()
        print( "error: too few arguments; aborting" )
        sys.exit()        
    if sys.argv[1] not in ["sign", "verify"]:
        print_usage()
        print( "error: action is not sign/verify" )
        sys.exit()        
    if sys.argv[1] == "sign":
        pub_key_file = sys.argv[ 2 ]
        msg_files = sys.argv[ 3: ]
        L = 2        
        hss_prv, hss_pub = hss.hss_gen_keypair( L )
        with open( pub_key_file, 'wb' ) as f:
            f.write( hss_pub["serialized"] )
        for mf in msg_files:
            with open( mf, 'r' ) as f:
                msg = f.read()
            msg_bytearray = bytearray( msg.encode() )
            hss_sign = hss.hss_sign( msg_bytearray, hss_prv )
            with open( mf + ".sig", 'wb' ) as sigfile:
                sigfile.write( hss_sign["serialized"] )
    if sys.argv[1] == "verify":
        pub_key_file = sys.argv[ 2 ]
        msg_files = sys.argv[ 3: ]
        hss_pub = hss.hss_read_public_key_from_file( pub_key_file )
        for mf in msg_files:
            with open( mf, 'r' ) as f:
                msg = f.read()
            msg_bytearray = bytearray( msg.encode() )
            sig_file = mf + ".sig"
            hss_sign = hss.hss_read_signature_from_file( sig_file )
            valid = hss.hss_verify( msg_bytearray, hss_sign, hss_pub )
            print( "Verifying {} with signature {} using key {}: {}".format(
                mf, sig_file, pub_key_file, valid ) )

            

if __name__ == "__main__":
    main()

