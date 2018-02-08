import sys
import copy

import lms
from utils import *

def hss_gen_keypair( L ):
    prv = hss_gen_private_key( L )
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

def hss_gen_private_key( L ):
    lms_typestring = "lms_sha256_m32_h5"
    lms_typecode = lms.lms_typestring_to_typecode[ lms_typestring ]
    lms_prv = []
    lms_pub = []
    for i in range( L ):
        prv_i, pub_i = lms.lms_gen_keypair( lms_typestring )
        lms_prv.append( prv_i )
        lms_pub.append( pub_i )
    sig = [ None ] * L
    for i in range( L-1 ):
        sig[i] = lms.lms_sign( lms_pub[i+1]["serialized"], lms_prv[i] )
    prv = {
        "lms_typecode": lms_typecode, 
        "L": L,        
        "lms_prv": lms_prv,
        "lms_pub": lms_pub,
        "sig": sig
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
    return( u32str(L) + pub0["serialized"] )


### Sign

def hss_compute_message_signature( message, private_key ):
    lms_typecode = private_key["lms_typecode"]
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
