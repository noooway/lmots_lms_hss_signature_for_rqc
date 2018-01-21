import sys
import hashlib

import lmots


lms_typestring_to_typecode = {
    "lms_reserved": 0,
    "lms_sha256_m32_h5": 1,
    "lms_sha256_m32_h10": 2,
    "lms_sha256_m32_h15": 3,
    "lms_sha256_m32_h20": 4,
    "lms_sha256_m32_h25": 5
}

lms_typecode_to_typestring = [    
    "lms_reserved",
    "lms_sha256_m32_h5",
    "lms_sha256_m32_h10",
    "lms_sha256_m32_h15",
    "lms_sha256_m32_h20",
    "lms_sha256_m32_h25"
]

lms_typecode_to_params = [
    # m   h
    ( None, None ),
    ( 32, 5 ),
    ( 32, 10 ),
    ( 32, 15 ),
    ( 32, 20 ),
    ( 32, 25 )
]

LMS_D_LEAF = "0x8282"
LMS_D_INTR = "0x8383"


def lms_gen_keypair( typestring ):
    prv = lms_gen_private_key( typestring )
    pub = lms_gen_public_key( typestring, prv )
    return (prv, pub)


def lms_sign( message, private_key ):
    signature = lms_compute_message_signature( message, private_key )
    return signature


def lms_verify( message, signature, public_key ):
    correct = lms_is_correct_signature( message, signature, public_key )
    return correct


def lms_is_exhausted( private_key ):
    # typecode = private_key[ "typecode" ]
    # h, m = lms_typecode_to_params[ typecode ]
    # q = private_key[ "q" ]
    # return q >= 2**h - 1 # todo: recheck
    pass


### Private key

def lms_gen_private_key( typestring, ots_typestring = "lmots_sha256_n32_w1" ):
    typecode = lms_typestring_to_typecode[ typestring ]
    h, m = lms_typecode_to_params[ typecode ]
    I = lms_gen_I()
    ots_priv = []
    ots_pub = []
    for q in range( 2 ** h ):
        priv, pub = lmots_gen_keypair( ots_typestring, I, q )
        ots_priv.append( priv )
        ots_pub.append( pub )
    q = 0
    prv = {
        "typecode": typecode, 
        "I": I,
        "q": q,
        "ots_typecode": lmots.lmots_typestring_to_typecode[ ots_typestring ],
        "ots_priv": ots_priv,
        "ots_pub": ots_pub
    }
    return prv


def lms_gen_I():
    return lmots.lmots_gen_I()
        

def lms_update_q( private_key ):
    private_key["q"] += 1


### Public key

def lms_gen_public_key( typestring, prv ):
    typecode = lms_typestring_to_typecode[ typestring ]
    ots_typecode = prv["ots_typecode"]
    I = prv["I"]
    q = prv["q"]
    ots_pub = prv["ots_pub"]
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
    h, m = lms_typecode_to_params[ typecode ]
    num_lmots_keys = len( ots_pub ) # todo: 2 ** h ?
    H = hashlib.sha256()
    for i in range( 2 ** h ):
        r = i + num_lmots_keys
        tmp = H.digest( I + u32str(r) + u16str( LMS_D_LEAF ) + ots_pub[i] )
        j = i
        while ( j % 2 == 1 ):
            r = ( r - 1 ) // 2 # todo: recheck // or /
            j = ( j - 1 ) // 2
            left_side = stack.pop()
            tmp = H.digest( I + u32str(r) + u16str( LMS_D_INTR ) + left_side + tmp )
        stack.append( tmp )
    T1 = stack.pop()
    return T1


def lms_serialize_pub_key( typecode, ots_typecode, I, T1 ):
    return ( u32str( typecode ) + u32str( ots_typecode ) + I + T1 )





### Sign

def lms_compute_message_signature( message, private_key ):
    typecode = private_key["typecode"]
    ots_typecode = private_key["ots_typecode"]
    I = private_key["I"]
    q = private_key["q"]
    ots_priv = private_key["ots_priv"]
    ots_pub = private_key["ots_pub"]
    ots_signature = lmots.lmots_sign( message, ots_priv[q] )
    lms_update_q( private_key )
    leaf_to_root_path = lms_compute_leaf_to_root_path( typecode, I, q, ots_pub )
    serialized = lms_serialize_signature( q, typecode, ots_signature, leaf_to_root_path )
    signature = {
        "q": q,
        "typecode": typecode,
        "ots_signature": ots_signature,
        "leaf_to_root_path": leaf_to_root_path,
        "serialized": serialized
    }
    return signature


def lms_compute_leaf_to_root_path( typecode, I, q, ots_pub ):
    # use lms_tree_node_string
    pass


def lms_tree_node_string( typecode, I, r, ots_pub ):
    H = hashlib.sha256()
    h, m = lms_typecode_to_params[ typecode ]
    if r >= 2 ** h :
        out = H.digest( I + u32str(r) + u16str( LMS_D_LEAF ) + ots_pub[ r - 2**h ] )
    else:
        T2r = lms_tree_node_string( I, 2 * r, ots_pub )
        T2r1 = lms_tree_node_string( I, 2 * r + 1, ots_pub )
        out = H.digest( I + u32str(r) + u16str( LMS_D_INTR ) + T2r + T2r1 )
    return out


def lms_serialize_signature( q, typecode, ots_signature, leaf_to_root_path ):
    pass






### Verify


def lms_is_correct_signature( message, signature, public_key ):
    if lms_pub_too_short( public_key ):
        return False
    pubtype = public_key['typecode']
    h, m = lms_typecode_to_params[ pubtype ]
    if lms_pub_wrong_len( public_key ):
        return False
    I = public_key['I']
    T1 = public_key['T1']
    ots_pubtype = public_key['ots_typecode']
    Tc = lms_compute_root_candidate( message, signature, I, pubtype, ots_pubtype )
    if not Tc:
        return False
    return Tc == T1


def lms_pub_too_short( public_key ):
    # return len( public_key["serialized"] ) < 4 
    pass

def lms_pub_wrong_len( public_key ):
    h, m = lms_typecode_to_params[ public_key["typecode"] ]    
    # return len( public_key["serialized"] ) != 20 + m
    pass


def lms_compute_root_candidate( message, signature, I, pubtype, ots_pubtype ):
    if lms_signature_too_short( signature ):
        return None
    q = signature['q']
    ots_sigtype = signature['ots_signature']['typecode']
    if ots_sigtype != ots_pubtype:
        return None
    if lms_is_wrong_signature_length_wrt_ots_parameters( ots_sigtype, signature ):
        return None
    ots_signature = signature['ots_signature']
    sigtype = signature['typecode']
    if sigtype != pubtype:
        return None
    h, m = lms_typecode_to_params[ pubtype ]
    if q >= 2 ** h or lms_if_signature_length_not_exact( sigtype, ots_sigtype, signature ):
        return None
    path = signature['leaf_to_root_path']
    Kc = lmots.lmots_compute_key_candidate( message, ots_signature, ots_pubtype, I, q )
    #
    node_num = 2 ** h + q
    H = hashlib.sha256()
    tmp = H.digest( I + u32str( node_num ) + u16str( LMS_D_LEAF ) + Kc )
    i = 0
    while( node_num > 1 ):
        if is_odd( node_num ):
            tmp = H.digest( I + u32str( node_num // 2 ) + u16str( LMS_D_INTR ) +
                            path[i] + tmp )
        else:
            tmp = H.digest( I + u32str( node_num // 2 ) + u16str( LMS_D_INTR ) +
                            tmp + path[i] )
        node_num = node_num // 2
        i = i + 1
    Tc = tmp
    return Tc

def lms_signature_too_short( signature ):
    # return len( signature["serialized"] ) < 8 
    pass

def lms_is_wrong_signature_length_wrt_ots_parameters( ots_sigtype, signature ):
    n, w, p = lmots.lmots_typecode_to_params[ ots_sigtype ]
    # return len( signature["serialized"] ) < 12 + n * (p + 1 )
    pass

def lms_if_signature_length_not_exact( sigtype, ots_sigtype, signature ):
    n, w, p = lmots.lmots_typecode_to_params[ ots_sigtype ]
    h, m = lms_typecode_to_params[ sigtype ]
    # return len( signature["serialized"] ) != 12 + n * (p+1) + m * h
    pass

def is_odd( x ):
    if isinstance( x, int ):
        return ( x % 2 == 1 )
    else:
        raise ValueError( "not int in is_odd" )
