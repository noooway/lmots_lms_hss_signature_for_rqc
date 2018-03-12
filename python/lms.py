import sys
import copy
import hashlib as H

import lmots
from utils import *

import binascii

lms_typestring_to_typecode = {
    "lms_reserved": 0,
    "lms_sha256_m32_h5": 5,
    "lms_sha256_m32_h10": 6,
    "lms_sha256_m32_h15": 7,
    "lms_sha256_m32_h20": 8,
    "lms_sha256_m32_h25": 9
}

lms_typecode_to_typestring = [    
    "lms_reserved",
    None,
    None,
    None,
    None,
    "lms_sha256_m32_h5",
    "lms_sha256_m32_h10",
    "lms_sha256_m32_h15",
    "lms_sha256_m32_h20",
    "lms_sha256_m32_h25"
]

lms_typecode_to_params = [
    # m   h
    ( None, None ),
    ( None, None ),
    ( None, None ),
    ( None, None ),
    ( None, None ),
    ( 32, 5 ),
    ( 32, 10 ),
    ( 32, 15 ),
    ( 32, 20 ),
    ( 32, 25 )
]

LMS_D_LEAF = int( "0x8282", 0 )
LMS_D_INTR = int( "0x8383", 0 )

def lms_gen_keypair( typestring, ots_typestring = "lmots_sha256_n32_w1",
                     I = None, use_pseudorandom_with_SEED = None ):
    prv = lms_gen_private_key( typestring, ots_typestring, I, use_pseudorandom_with_SEED )
    pub = lms_gen_public_key( typestring, prv )
    return (prv, pub)


def lms_sign( message, private_key ):
    if lms_is_private_key_exhausted( private_key ):
        print( "Warning: lms key is exhausted. Signature set to None" )
        return None
    signature = lms_compute_message_signature( message, private_key )
    return signature


def lms_verify( message, signature, public_key ):
    if not signature:
        return False
    correct = lms_is_correct_signature( message, signature, public_key )
    return correct


def lms_is_private_key_exhausted( private_key ):
    typecode = private_key[ "typecode" ]
    m, h = lms_typecode_to_params[ typecode ]
    q = private_key[ "q" ]
    return q > 2**h - 1


### Private key

def lms_gen_private_key( typestring, ots_typestring = "lmots_sha256_n32_w1",
                         I = None, use_pseudorandom_with_SEED = None ):
    typecode = lms_typestring_to_typecode[ typestring ]
    m, h = lms_typecode_to_params[ typecode ]
    I = I or lms_gen_I()
    ots_priv = []
    ots_pub = []
    for q in range( 2 ** h ):
        priv, pub = lmots.lmots_gen_keypair( ots_typestring, I, q,
                                             use_pseudorandom_with_SEED )
        ots_priv.append( priv )
        ots_pub.append( pub )
    q = 0
    prv = {
        "typecode": typecode, 
        "I": I,
        "q": q,
        "ots_typecode": lmots.lmots_typestring_to_typecode[ ots_typestring ],
        "ots_priv": ots_priv,
        "ots_pub": ots_pub,
        "use_pseudorandom_with_SEED": use_pseudorandom_with_SEED
    }
    return prv


def lms_gen_I():
    return lmots.lmots_gen_I()
        

def lms_update_q( private_key ):
    private_key["q"] += 1


def lms_short_print_private_key_for_hss( private_key, hss_idx ):
    print( "LMS private key:", hss_idx )
    print( "lms_typecode:", private_key["typecode"] )
    print( "ots_typecode:", private_key["ots_typecode"] )
    print( "I:", binascii.hexlify( private_key["I"] ) )
    print( "q:", private_key["q"] )
    print( "SEED:", binascii.hexlify( private_key["use_pseudorandom_with_SEED"] ) )
    
    
### Public key

def lms_gen_public_key( typestring, prv ):
    typecode = lms_typestring_to_typecode[ typestring ]
    ots_typecode = prv["ots_typecode"]
    I = copy.deepcopy( prv["I"] )
    q = copy.deepcopy( prv["q"] )
    ots_pub = copy.deepcopy( prv["ots_pub"] )
    T1 = lms_compute_T1( typecode, I, ots_pub )
    serialized = lms_serialize_pub_key( typecode, ots_typecode, I, T1 )
    pub = {
        "typecode" : typecode,
        "ots_typecode" : ots_typecode,
        "I" : I,
        "T1" : T1,        
        "serialized": serialized
    }
    return pub


def lms_compute_T1( typecode, I, ots_pub ):
    stack = []
    m, h = lms_typecode_to_params[ typecode ]
    num_lmots_keys = len( ots_pub )
    for i in range( 2 ** h ):
        r = i + num_lmots_keys
        # In alg 6b:
        # tmp = H.sha256( I + u32str( node_num ) + u16str( LMS_D_LEAF ) + Kc ).digest()
        # use ots_pub[i]["K"]
        tmp = H.sha256( I + u32str(r) + u16str( LMS_D_LEAF ) +
                        ots_pub[i]["K"] ).digest()
        j = i
        while ( j % 2 == 1 ):
            r = ( r - 1 ) // 2
            j = ( j - 1 ) // 2
            left_side = stack.pop()
            tmp = H.sha256( I + u32str(r) + u16str( LMS_D_INTR ) +
                            left_side + tmp ).digest()
        stack.append( tmp )
    T1 = stack.pop()
    return T1


def lms_serialize_pub_key( typecode, ots_typecode, I, T1 ):
    return ( u32str( typecode ) + u32str( ots_typecode ) + I + T1 )


def lms_deserialize_pub_key( serialized ):
    lms_typecode = to_int( serialized[ 0 : u32str_bytelen ] )
    ots_typecode = to_int( serialized[ u32str_bytelen :
                                       u32str_bytelen + u32str_bytelen ] )
    I = serialized[ u32str_bytelen + u32str_bytelen :
                    u32str_bytelen + u32str_bytelen + lmots.LMOTS_I_LEN ]
    m, h = lms_typecode_to_params[ lms_typecode ]
    T1 = serialized[ u32str_bytelen + u32str_bytelen + lmots.LMOTS_I_LEN :
                     u32str_bytelen + u32str_bytelen + lmots.LMOTS_I_LEN + m ]
    pub = {
        "typecode" : lms_typecode,
        "ots_typecode" : ots_typecode,
        "I" : I,
        "T1" : T1,        
        "serialized": serialized,
    }
    return pub
    

def lms_deserialize_public_key_from_hss( part_of_ser_hss_pubkey ):
    pub = lms_deserialize_pub_key( part_of_ser_hss_pubkey )
    pub["serialized"] = lms_serialize_pub_key(
        pub["typecode"], pub["ots_typecode"], pub["I"], pub["T1"] )
    pub_len = len( pub["serialized"] )
    return( pub, part_of_ser_hss_pubkey[ pub_len : ] )


### Sign

def lms_compute_message_signature( message, private_key ):
    typecode = private_key["typecode"]
    ots_typecode = private_key["ots_typecode"]
    I = copy.deepcopy( private_key["I"] )
    q = copy.deepcopy( private_key["q"] )
    ots_priv = copy.deepcopy( private_key["ots_priv"] )
    ots_pub = copy.deepcopy( private_key["ots_pub"] )
    ots_signature = lmots.lmots_sign( message, ots_priv[q] )
    lms_update_q( private_key )
    leaf_to_root_path = lms_compute_leaf_to_root_path( typecode, I, q, ots_pub )
    serialized = lms_serialize_signature( q, typecode, ots_signature, leaf_to_root_path )
    signature = {
        "q": q,
        "typecode": typecode,
        "ots_signature": ots_signature,
        "leaf_to_root_path": leaf_to_root_path,
        "serialized": serialized,
    }
    return signature


def lms_compute_leaf_to_root_path( typecode, I, q, ots_pub ):
    m, h = lms_typecode_to_params[ typecode ]
    node_num = 2 ** h + q
    path_node_numbers = []
    while( node_num > 1 ):
        if is_odd( node_num ):
            sibling = node_num - 1
        else:
            sibling = node_num + 1
        path_node_numbers.append( sibling )
        node_num = node_num // 2
    # warning: highly non-optimal recursive calculation
    path = [ lms_tree_node_hash( typecode, I, x, ots_pub ) for x in path_node_numbers ]
    return path


def lms_tree_node_hash( typecode, I, r, ots_pub ):
    m, h = lms_typecode_to_params[ typecode ]
    if r >= 2 ** h :
        out = H.sha256( I + u32str(r) + u16str( LMS_D_LEAF ) +
                        ots_pub[ r - 2**h ]["K"] ).digest()
    else:
        T2r = lms_tree_node_hash( typecode, I, 2 * r, ots_pub )
        T2r1 = lms_tree_node_hash( typecode, I, 2 * r + 1, ots_pub )
        out = H.sha256( I + u32str(r) + u16str( LMS_D_INTR ) + T2r + T2r1 ).digest()
    return out


def lms_serialize_signature( q, typecode, ots_signature, leaf_to_root_path ):
    serialized = u32str( q ) + ots_signature["serialized"] + u32str( typecode )
    for p in leaf_to_root_path:
        serialized = serialized + p
    return serialized


def lms_deserialize_signature( serialized ):
    q = to_int( serialized[ 0 : u32str_bytelen ] )
    ots_signature, remaining_serialized = lmots.lmots_deserialize_signature_from_lms(
        serialized[ u32str_bytelen : ] )
    typecode = to_int( remaining_serialized[ 0 : u32str_bytelen ] )
    m, h = lms_typecode_to_params[ typecode ]
    leaf_to_root_path = []
    for i in range( h ): # todo: unnecessary node (top) incuded in leaf-to-root path?
        leaf_to_root_path.append(
            remaining_serialized[ u32str_bytelen + i * m :
                                  u32str_bytelen + (i+1) * m ] )
    signature = {
        "q": q,
        "typecode": typecode,
        "ots_signature": ots_signature,
        "leaf_to_root_path": leaf_to_root_path,
        "serialized": serialized
    }
    return signature


def lms_deserialize_signature_from_hss( part_of_ser_hss_signature ):
    signature = lms_deserialize_signature( part_of_ser_hss_signature )
    signature["serialized"] = lms_serialize_signature(
        signature["q"], signature["typecode"],
        signature["ots_signature"], signature["leaf_to_root_path"] )
    sig_len = len( signature["serialized"] )
    return( signature, part_of_ser_hss_signature[ sig_len : ] )


### Verify

def lms_is_correct_signature( message, signature, public_key ):
    if lms_is_pub_too_short( public_key ):
        return False
    pubtype = public_key['typecode']
    m, h = lms_typecode_to_params[ pubtype ]
    if lms_is_pub_wrong_len( public_key ):
        return False
    I = public_key['I']
    T1 = public_key['T1']
    ots_pubtype = public_key['ots_typecode']
    # debug
    # print( "check lmots key:", lmots.lmots_verify( message,
    #                                                signature['ots_signature'],
    #                                                public_key["used_ots_pub_debug"] ) )
    # debug
    Tc = lms_compute_root_candidate( message, signature, I, pubtype, ots_pubtype )
    print()
    print( "Key       (T1):", T1 )
    print( "Candidate (Tc):", Tc )
    if not Tc:
        return False
    return Tc == T1


def lms_is_pub_too_short( public_key ):    
    return len( public_key["serialized"] ) < 4

def lms_is_pub_wrong_len( public_key ):
    m, h = lms_typecode_to_params[ public_key["typecode"] ]
    return len( public_key["serialized"] ) != 24 + m


def lms_compute_root_candidate( message, signature, I, pubtype, ots_pubtype ):
    if lms_is_signature_too_short( signature ):
        return None
    q = signature['q']
    ots_sigtype = signature['ots_signature']['typecode']
    if ots_sigtype != ots_pubtype:
        return None
    if lms_is_signature_too_short_wrt_ots_parameters( ots_sigtype, signature ):
        return None
    ots_signature = signature['ots_signature']
    sigtype = signature['typecode']
    if sigtype != pubtype:
        return None
    m, h = lms_typecode_to_params[ pubtype ]
    if q >= 2 ** h or lms_is_signature_length_not_exact( sigtype, ots_sigtype, signature ):
        return None
    path = copy.deepcopy( signature['leaf_to_root_path'] )
    Kc = lmots.lmots_compute_key_candidate( message, ots_signature, ots_pubtype, I, q )
    #
    node_num = 2 ** h + q
    tmp = H.sha256( I + u32str( node_num ) + u16str( LMS_D_LEAF ) + Kc ).digest()
    i = 0
    while( node_num > 1 ):
        if is_odd( node_num ):
            tmp = H.sha256( I + u32str( node_num // 2 ) + u16str( LMS_D_INTR ) +
                            path[i] + tmp ).digest()
        else:
            tmp = H.sha256( I + u32str( node_num // 2 ) + u16str( LMS_D_INTR ) +
                            tmp + path[i] ).digest()
        node_num = node_num // 2
        i = i + 1
    Tc = tmp
    return Tc

def lms_is_signature_too_short( signature ):
    return len( signature["serialized"] ) < 8 

def lms_is_signature_too_short_wrt_ots_parameters( ots_sigtype, signature ):
    n, w, p, ls = lmots.lmots_typecode_to_params[ ots_sigtype ]
    return len( signature["serialized"] ) < 12 + n * (p + 1 )

def lms_is_signature_length_not_exact( sigtype, ots_sigtype, signature ):
    n, w, p, ls = lmots.lmots_typecode_to_params[ ots_sigtype ]
    m, h = lms_typecode_to_params[ sigtype ]
    return len( signature["serialized"] ) != 12 + n * (p+1) + m * h

