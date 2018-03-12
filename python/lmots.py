import os
import sys
import math
import copy
import hashlib as H

from utils import *

import binascii

lmots_typestring_to_typecode = {
    "lmots_reserved": 0,
    "lmots_sha256_n32_w1": 1,
    "lmots_sha256_n32_w2": 2,
    "lmots_sha256_n32_w4": 3,
    "lmots_sha256_n32_w8": 4
}

lmots_typecode_to_typestring = [
    "lmots_reserved",
    "lmots_sha256_n32_w1",
    "lmots_sha256_n32_w2",
    "lmots_sha256_n32_w4",
    "lmots_sha256_n32_w8"
]

lmots_typecode_to_params = [
    # n   w   p   ls 
    ( None, None, None, None ),
    ( 32, 1, 265, 7 ),
    ( 32, 2, 133, 6 ),
    ( 32, 4, 67, 4 ),
    ( 32, 8, 34, 0 )
]

LMOTS_I_LEN = 16

LMOTS_D_MESG = int( "0x8181", 0 )  # u16str( int( "0x8181", 0 ) ) = b'\x81\x81'
LMOTS_D_PBLC = int( "0x8080", 0 )  # u16str( int( "0x8080", 0 ) ) = b'\x80\x80'


def lmots_gen_keypair( typestring, I = None, q = None,
                       use_pseudorandom_with_SEED = None ):
    prv = lmots_gen_private_key( typestring, I, q, use_pseudorandom_with_SEED )
    pub = lmots_gen_public_key( typestring, prv )
    return (prv, pub)


def lmots_sign( message, private_key ):
    if lmots_is_private_key_exhausted( private_key ):
        print( "Warning: lmots key is exhausted. Signature set to None" )
        return None
    signature = lmots_compute_message_signature( message, private_key )
    return signature


def lmots_verify( message, signature, public_key ):
    if not signature:
        return False
    correct = lmots_is_correct_signature( message, signature, public_key )
    return correct



### Private key

def lmots_gen_private_key( typestring, I = None, q = None,
                           use_pseudorandom_with_SEED = None ):    
    typecode = lmots_typestring_to_typecode[ typestring ]
    n, w, p, ls = lmots_typecode_to_params[ typecode ]
    I = I or lmots_gen_I()
    q = q or lmots_q()
    x = []
    for i in range( p ):
        if use_pseudorandom_with_SEED:
            x_i = H.sha256( I + u32str( q ) + u16str( i ) + u8str( int( "0xff", 0 ) ) +
                            use_pseudorandom_with_SEED ).digest()
        else:
            x_i = os.urandom( n )
        x.append( x_i )
    serialized = lmots_priv_key_serialize( typecode, I, q, x )
    times_used = 0
    prv = {
        "typecode": typecode,
        "I": I,
        "q": q,
        "x": x,
        "serialized": serialized,
        "times_used": times_used,
        "use_pseudorandom_with_SEED": use_pseudorandom_with_SEED
    }
    return prv


def lmots_gen_I():
    return os.urandom( LMOTS_I_LEN )
        

def lmots_q():
    return 0


def lmots_priv_key_serialize( typecode, I, q, x ):
    serialized = u32str( typecode ) + I + u32str( q )
    for x_i in x:
        serialized = serialized + x_i
    return serialized


def lmots_is_private_key_exhausted( private_key ):
    return private_key["times_used"] > 0

def lmots_update_usage_counter( private_key ):
    private_key["times_used"] += 1


def lmots_print_private_key( private_key ):
    print( "LMOTS private key:" )
    print( "typecode:", private_key["typecode"] )
    print( "I:", binascii.hexlify( private_key["I"] ) )
    print( "q:", private_key["q"] )
    print( "SEED:", binascii.hexlify( private_key["use_pseudorandom_with_SEED"] ) )
    for i, x in enumerate( private_key["x"] ):
        print( "x[{}]: {}".format( i, binascii.hexlify( x ) ) )
    print( "===" )


    
### Public key
        
def lmots_gen_public_key( typestring, prv ):
    typecode = lmots_typestring_to_typecode[ typestring ]
    I = copy.deepcopy( prv["I"] )
    q = copy.deepcopy( prv["q"] )
    x = copy.deepcopy( prv["x"] )
    K = lmots_compute_K( typecode, I, q, x )
    serialized = lmots_serialize_pub_key( typecode, I, q, K )
    pub = {
        "typecode" : typecode,
        "I" : I,
        "q" : q,
        "K" : K,
        "serialized": serialized
    }
    return pub


def lmots_compute_K( typecode, I, q, x ):
    n, w, p, ls = lmots_typecode_to_params[ typecode ]
    y = []
    for i in range( p ):
        tmp = x[i]
        for j in range( 2 ** w - 1 ):
            tmp = H.sha256( I + u32str(q) + u16str(i) + u8str(j) + tmp ).digest()
        y.append( tmp )
    h = H.sha256()
    h.update( I + u32str(q) + u16str( LMOTS_D_PBLC ) )
    for y_i in y:
        h.update( y_i )
    K = h.digest()
    return K


def lmots_serialize_pub_key( typecode, I, q, K ):
    return( u32str( typecode ) + I + u32str( q ) + K )


def lmots_deserialize_pub_key( serialized ):
    typecode = to_int( serialized[ 0 : u32str_bytelen ] )  # u32str( typecode )
    I = serialized[ u32str_bytelen : u32str_bytelen + LMOTS_I_LEN ]  # I (16 bytes)
    q = to_int( serialized[ u32str_bytelen + LMOTS_I_LEN :
                            u32str_bytelen + LMOTS_I_LEN + u32str_bytelen ]) # u32str(q)
    n, w, p, ls = lmots_typecode_to_params[ typecode ]
    K = serialized[ u32str_bytelen + LMOTS_I_LEN + u32str_bytelen :
                    u32str_bytelen + LMOTS_I_LEN + u32str_bytelen + n ]
    pub = {
        "typecode" : typecode,
        "I" : I,
        "q" : q,
        "K" : K,
        "serialized": serialized
    }
    return pub
    


### Sign

def lmots_compute_message_signature( message, private_key ):
    typecode = private_key["typecode"]
    n, w, p, ls = lmots_typecode_to_params[ typecode ]
    I = copy.deepcopy( private_key["I"] )
    q = copy.deepcopy( private_key["q"] )
    x = copy.deepcopy( private_key["x"] )
    C = lmots_gen_C_for_signature( n )
    y = lmots_compute_y( message, typecode, I, q, C, x )
    lmots_update_usage_counter( private_key )
    serialized = lmots_serialize_signature( typecode, C, y )    
    signature = {
        "typecode": typecode,
        "C": C,
        "y": y,
        "serialized": serialized
    }
    return signature

    
def lmots_gen_C_for_signature( n ):
    return os.urandom( n )


def lmots_compute_y( message, typecode, I, q, C, x ):    
    n, w, p, ls = lmots_typecode_to_params[ typecode ]
    y = []
    Q = H.sha256( I + u32str(q) + u16str(LMOTS_D_MESG) + C + message ).digest()
    for i in range( p ):
        a = lmots_coef( Q + lmots_chksum(Q, w, ls), i, w )
        tmp = x[i]
        for j in range( a ):            
            tmp = H.sha256( I + u32str(q) + u16str(i) + u8str(j) + tmp ).digest()
        y.append( tmp )
    return y


def lmots_serialize_signature( typecode, C, y ):
    serialized = u32str( typecode ) + C
    for y_i in y:
        serialized = serialized + y_i
    return serialized


def lmots_deserialize_signature( serialized ):
    typecode = to_int( serialized[ 0 : u32str_bytelen ] ) # u32str( typecode )
    n, w, p, ls = lmots_typecode_to_params[ typecode ]
    C = serialized[ u32str_bytelen: u32str_bytelen + n ]    # n-byte C 
    y = []
    for i in range( p ):
        y.append( serialized[ u32str_bytelen + n + i * n :
                              u32str_bytelen + n + (i+1) * n ] )
    signature = {
        "typecode": typecode,
        "C": C,
        "y": y,
        "serialized": serialized
    }
    return signature


def lmots_deserialize_signature_from_lms( part_of_ser_lms_signature ):
    signature = lmots_deserialize_signature( part_of_ser_lms_signature )
    signature["serialized"] = lmots_serialize_signature(
        signature["typecode"], signature["C"], signature["y"] )
    sig_len = len( signature["serialized"] )
    return( signature, part_of_ser_lms_signature[ sig_len : ] )


def lmots_chksum( S, w, ls ):
    tmp = 0
    for i in range( len(S) * 8 // w ):
        tmp = tmp + ( 2 ** w - 1 ) - lmots_coef( S, i, w )
    return u16str( tmp << ls )


def lmots_coef( S, i, w ):
    # test:
    # from bitstring import *
    # a = BitArray( '0b 0001 0010 0011 0100' )
    # s = a.bytes
    # b = [ lmots_coef( s, i, 2 ) for i in range( len(a) // 2 ) ]
    tmp1 = ( 2**w - 1 )
    shift = 8 - ( w * ( i % ( 8 // w )) + w )    
    tmp2 = lmots_byte( S, math.floor( i * w // 8 ) ) >> shift    
    return tmp1 & tmp2


def lmots_byte( S, i ):
    return S[i]


### Verify

def lmots_is_correct_signature( message, signature, public_key ):
    if lmots_is_pub_key_too_short( public_key ):
        return False
    pubtype = public_key["typecode"]
    if lmots_is_wrong_keylength( pubtype, public_key ):
        return False
    I = copy.deepcopy( public_key["I"] )
    q = copy.deepcopy( public_key["q"] )
    K = copy.deepcopy( public_key["K"] )
    kc = lmots_compute_key_candidate( message, signature, pubtype, I, q )
    if not kc:
        return False
    print()
    print( "Key       (K) :", K )
    print( "Candidate (Kc):", kc )
    return kc == K


def lmots_is_pub_key_too_short( public_key ):
    return len( public_key["serialized"] ) < 4


def lmots_is_wrong_keylength( pubtype, public_key ):
    n, w, p, ls = lmots_typecode_to_params[ pubtype ]
    return len( public_key["serialized"] ) != 24 + n


def lmots_compute_key_candidate( message, signature, pubtype, I, q ):
    if lmots_is_signature_too_short( signature ):
        return None
    sigtype = signature["typecode"]
    if sigtype != pubtype:
        return None
    n, w, p, ls = lmots_typecode_to_params[ sigtype ]
    if lmots_is_wrong_signature_length( sigtype, signature ):
        return None
    C = copy.deepcopy( signature["C"] )
    y = copy.deepcopy( signature["y"] )
    Q = H.sha256( I + u32str(q) + u16str( LMOTS_D_MESG ) + C + message ).digest()
    z = []
    for i in range( p ):
        a = lmots_coef( Q + lmots_chksum( Q, w, ls ), i, w )
        tmp = y[i]
        for j in range( a, 2 ** w - 1 ):            
            tmp = H.sha256( I + u32str(q) + u16str(i) + u8str(j) + tmp ).digest()
        z.append( tmp )
    h = H.sha256()
    h.update( I + u32str(q) + u16str( LMOTS_D_PBLC ) )
    for z_i in z:
         h.update( z_i )
    kc = h.digest()
    return kc


def lmots_is_signature_too_short( signature ):
    return len( signature["serialized"] ) < 4


def lmots_is_wrong_signature_length( sigtype, signature ):
    n, w, p, ls = lmots_typecode_to_params[ sigtype ]
    return len( signature["serialized"] ) != 4 + n * (p+1)


# def lmots_is_wrong_ots_signature_length_in_lms( ots_sigtype, ots_signature ):
#     n, w, p, ls = lmots_typecode_to_params[ ots_sigtype ]
#     return len( signature["serialized"] ) != 12 + n * (p+1)
