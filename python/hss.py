import os
import sys
import copy

import lms
from utils import *

def hss_gen_keypair( L, lms_typestring = "lms_sha256_m32_h5",
                     ots_typestring = "lmots_sha256_n32_w1",
                     pseudorandom_lms = False ):
    prv = hss_gen_private_key( L, lms_typestring, ots_typestring,
                               pseudorandom_lms )
    pub = hss_gen_public_key( L, prv )
    return (prv, pub)


def hss_sign( message, private_key ):
    signature = hss_compute_message_signature( message, private_key )
    return signature


def hss_verify( message, signature, public_key ):
    if not signature:
        return False
    correct = hss_is_correct_signature( message, signature, public_key )
    return correct



### Private key

def hss_gen_private_key( L, lms_typestring, ots_typestring, pseudorandom_lms ):
    lms_typecode = lms.lms_typestring_to_typecode[ lms_typestring ]
    lms_prv = []
    lms_pub = []
    for i in range( L ):
        if pseudorandom_lms:
            m, h = lms.lms_typecode_to_params[ lms_typecode ]
            SEED = os.urandom( m )
        else:
            SEED = None
        prv_i, pub_i = lms.lms_gen_keypair( lms_typestring, ots_typestring,
                                            use_pseudorandom_with_SEED = SEED )
        lms_prv.append( prv_i )
        lms_pub.append( pub_i )
    sig = [ None ] * L
    for i in range( L-1 ):
        sig[i] = lms.lms_sign( lms_pub[i+1]["serialized"], lms_prv[i] )
    prv = {
        "L": L,
        "lms_typestring": lms_typestring,
        "ots_typestring": ots_typestring, 
        "lms_prv": lms_prv,
        "lms_pub": lms_pub,
        "sig": sig
    }
    return prv


def hss_serialize_private_key( private_key ):
    pass


def hss_short_print_private_key( private_key ):
    print( "HSS private key:" )
    print( "L:", private_key["L"] )
    print( "lms_typestring:", private_key["lms_typestring"] )
    print( "ots_typestring:", private_key["ots_typestring"] )
    for idx, lms_prv in enumerate( private_key["lms_prv"] ):
        lms.lms_short_print_private_key_for_hss( lms_prv, idx )

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
    return( u32str(L) + pub0["serialized"] )


def hss_deserialize_public_key( serialized ):    
    L = to_int( serialized[ 0 : u32str_bytelen ] )  # u32str(L)
    pub0 = lms.lms_deserialize_pub_key( serialized[ u32str_bytelen : ] )
    pub = {
        "L": L,
        "pub0": pub0,
        "serialized": serialized
    }
    return pub


def hss_read_public_key_from_file( filename ):
    with open( filename, 'rb' ) as f:
        pub_serialized = f.read()
        pub = hss_deserialize_public_key( pub_serialized )
    return pub


### Sign

def hss_compute_message_signature( message, private_key ):
    lms_typecode = lms.lms_typestring_to_typecode[ private_key["lms_typestring"] ]
    L = private_key["L"]
    lms_prv = private_key["lms_prv"] # no deepcopy; should change dynamically
    lms_pub = private_key["lms_pub"] # no deepcopy; should change dynamically
    sig = private_key["sig"] # no deepcopy; should change dynamically
    i = L - 1
    last_exhausted = None
    while lms.lms_is_private_key_exhausted( lms_prv[i] ):
        last_exhausted = i
        i = i - 1
        if i < 0:
            print( "HSS is exhausted. Signature set to None" )
            return None
    if last_exhausted:
        hss_regenerate_keys( L, last_exhausted, lms_prv, lms_pub, sig, lms_typecode )
    sig[L-1] = lms.lms_sign( message, lms_prv[L-1] )
    signed_pub_keys = []
    Npsk = L - 1
    for i in range( Npsk ):
        signed_pub_keys.append(
            { "sig" : sig[i],
              "pub" : lms_pub[i+1],
              "serialized" : sig[i]["serialized"] + lms_pub[i+1]["serialized"] } )
    serialized = hss_serialize_signature( Npsk, signed_pub_keys, sig[Npsk] )
    # todo: is L=1 special case? are "signed_pub_keys" should be excluded from signature?
    signature = {
        "Npsk": Npsk,
        "signed_pub_keys": signed_pub_keys,
        "msg_sig": sig[Npsk], 
        "serialized": serialized
    }
    return signature


def hss_regenerate_keys( L, last_exhausted, lms_prv, lms_pub, sig, lms_typecode ):
    for i in range( last_exhausted, L ):
        prv_i, pub_i = lms.lms_gen_keypair(
            lms.lms_typecode_to_typestring[ lms_typecode ] )
        lms_prv[i] = prv_i
        lms_pub[i] = pub_i
    for i in range( last_exhausted, L ):
        sig[i-1] = lms.lms_sign( lms_pub[i]["serialized"], lms_prv[i-1] )
    

def hss_serialize_signature( Npsk, signed_pub_keys, msg_sig ):
    serialized = u32str( Npsk )
    for pub_key_sig in signed_pub_keys:
        serialized = serialized + pub_key_sig["serialized"]
    serialized = serialized + msg_sig["serialized"]
    return serialized


def hss_deserialize_signature( serialized ):
    Npsk = to_int( serialized[ 0 : u32str_bytelen ] )
    signed_pub_keys = []
    remaining_ser = serialized[ u32str_bytelen : ]
    for i in range( Npsk ):
        lms_sig, remaining_ser = lms.lms_deserialize_signature_from_hss( remaining_ser )
        lms_pub, remaining_ser = lms.lms_deserialize_public_key_from_hss( remaining_ser )
        signed_pub_keys.append(
            { "sig" : lms_sig,
              "pub" : lms_pub,
              "serialized" : lms_sig["serialized"] + lms_pub["serialized"] } )
    msg_sig, remaining_ser = lms.lms_deserialize_signature_from_hss( remaining_ser )
    signature = {
        "Npsk": Npsk,
        "signed_pub_keys": signed_pub_keys,
        "msg_sig": msg_sig, 
        "serialized": serialized
    }
    return signature


def hss_read_signature_from_file( filename ):
    with open( filename, 'rb' ) as f:
        sig_serialized = f.read()
        sig = hss_deserialize_signature( sig_serialized )
    return sig


### Verify

def hss_is_correct_signature( message, signature, public_key ):    
    sig_Npsk = signature["Npsk"]    
    pub_L = public_key["L"]
    if sig_Npsk + 1 != pub_L:
        return False
    #
    siglist = [ extract_lms_sig(x) for x in signature["signed_pub_keys"] ]
    publist = [ extract_lms_pub(x) for x in signature["signed_pub_keys"] ]
    siglist.append( signature["msg_sig"] )
    #
    # todo: is L=1 case special?
    key = public_key["pub0"]
    for i in range( sig_Npsk ):
        sig = siglist[i]
        msg = publist[i]["serialized"]
        if not lms.lms_verify( msg, sig, key ):
            return False
        #key = msg
        key = publist[i]
    return lms.lms_verify( message, siglist[sig_Npsk], key )


def extract_lms_sig( signed_pub_key_element ):
    return signed_pub_key_element["sig"]

def extract_lms_pub( signed_pub_key_element ):
    return signed_pub_key_element["pub"]
