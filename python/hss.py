import sys
import hashlib

import lms

def hss_gen_keypair( L ):
    prv = hss_gen_private_key( L )
    pub = hss_gen_public_key( L, prv )
    return (prv, pub)


def hss_sign( message, private_key ):
    signature = hss_compute_message_signature( message, private_key )
    return signature


def hss_verify( message, signature, public_key ):
    correct = hss_is_correct_signature( message, signature, public_key )
    return correct



### Private key

def hss_gen_private_key( L ):
    lms_typestring = "lms_sha256_m32_h5"
    lms_typecode = lms.lms_typestring_to_typecode[ lms_typestring ]
    lms_prv = []
    lms_pub = []
    for i in range( L ):
        prv_i, pub_i = lms_gen_keypair( lms_typestring )
        lms_prv.append( prv_i )
        lms_pub.append( pub_i )    
    prv = {
        "lms_typecode": lms_typecode, 
        "L": L,        
        "lms_prv": lms_prv,
        "lms_pub": lms_pub
    }
    return prv


def hss_serialize_private_key( private_key ):
    pass


### Public key

def hss_gen_public_key( L, private_key ):
    pub0 = private_key["lms_pub"][0]
    serialized = hss_serialize_public_key( L, pub0 )
    pub = {
        "L": L,
        "pub0": pub0,
        "serialized": serialized
    }
    return pub


def hss_serialize_public_key( L, pub0 ):
    return( u32str(L) + pub0 )


### Sign

def hss_compute_message_signature( message, private_key ):
    # todo: recheck sig
    sig = [ None ] * L
    lms_typecode = private_key["lms_typecode"]
    L = private_key["L"]
    lms_prv = private_key["lms_prv"]
    lms_pub = private_key["lms_pub"]
    d = L - 1
    while lms.lms_is_exhausted( lms_prv[d] ):
        d = d - 1
        if d < 0:
            sys.exit( "hss exhausted" )
    # todo: def hss_regenerate_keys
    for i in range( d, L ):
        prv_i, pub_i = lms_gen_keypair( lms_typecode_to_typestring[ lms_typecode ] )
        lms_prv[i] = prv_i
        lms_pub[i] = pub_i
    for i in range( d, L ):
        sig[i-1] = lms_sign( lms_pub[i], lms_prv[i-1] )
    sig[L-1] = lms_sign( message, lms_prv[L-1] )
    # todo: recheck; L is different from Npsk
    signed_pub_keys = []
    for i in range( L ):
        signed_pub_keys.append( sig[i] + pub[i+1] ) # todo: possible i+1 > L ?
    signature = {
        "L": L,
        "signed_pub_keys": signed_pub_keys,
        "serialized": None
    }
    return signature


def hss_serialize_signature():
    pass



### Verify

def hss_is_correct_signature( message, signature, public_key ):
    sig_Npsk = signature["Npsk"]
    pub_L = public_key["L"]
    if sig_Npks + 1 != pub_L:
        return False
    #
    siglist = [ extract_lms_sig(x) for x in signature["signed_pub_keys"] ]
    publist = [ extract_lms_pub(x) for x in signature["signed_pub_keys"] ]
    siglist.append( extract_lms_sig( signature["signed_pub_keys"][-1] ) ) # todo: ?
    #
    key = public_key
    for i in range( sig_Npsk ):
        sig = siglist[i]
        msg = publist[i]
        if not lms_verify( msg, sig, key ):
            return False
        key = msg
    return lms_verify( message, siglist[Npsk], key )


def extract_lms_sig( signed_pub_key_element ):
    pass

def extract_lms_pub( signed_pub_key_element ):
    pass
