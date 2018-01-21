import sys
import hashlib

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

LMOTS_D_MESG = "0x8181"
LMOTS_D_PBLC = "0x8080"


def lmots_gen_keypair( typestring, I = None, q = None ):
    prv = lmots_gen_private_key( typestring, I, q )
    pub = lmots_gen_public_key( typestring, prv )
    return (prv, pub)


def lmots_sign( message, private_key ):
    signature = lmots_compute_message_signature( message, private_key )
    return signature


def lmots_verify( message, signature, public_key ):
    correct = lmots_is_correct_signature( message, signature, public_key )
    return correct



### Private key

def lmots_gen_private_key( typestring, I = None, q = None ):    
    typecode = lmots_typestring_to_typecode[ typestring ]
    n, w, p = lmots_typecode_to_params[ typecode ]
    I = I or lmots_gen_I()
    q = q or lmots_gen_q()
    x = []
    for i in range( p ):
        uniform_nbyte = None # todo
        x.append( uniform_nbyte )
    serialized = lmots_priv_key_serialize( typecode, I, q, x )
    prv = {
        "typecode": typecode, 
        "I": I,
        "q": q,
        "x": x,
        "serialized": serialized
    }
    return prv


def lmots_gen_I():
    pass
        

def lmots_gen_q():    
    #return 0x00000000
    pass


def lmots_priv_key_serialize( typecode, I, q, x ):
    serialized = u32str( typecode ) + I + u32str( q )
    for x_i in x:
        serialized = serialized + x_i
    return serialized



### Public key
        
def lmots_gen_public_key( typestring, prv ):
    typecode = lmots_typestring_to_typecode[ typestring ]
    I = prv["I"]
    q = prv["q"]
    x = prv["x"]
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
    H = hashlib.sha256()
    n, w, p = lmots_typecode_to_params( typecode )    
    y = []
    for i in range( p ):
        tmp = x[i]
        for j in range( 2 ** w - 1 ):
            tmp = H.digest( I + u32str(q) + u16str(i) + u8str(j) + tmp )
        y.append( tmp )
    H = hashlib.sha256()
    H.update( I + u32str(q) + u16str( LMOTS_D_PBLC ) )
    for y_i in y:
        H.update( y_i )
    K = H.digest()
    return K


def lmots_serialize_pub_key( typecode, I, q, K ):
    return( u32str( typecode ) + I + u32str( q ) + K )

        

### Sign

def lmots_compute_message_signature( message, private_key ):
    typecode = private_key["typecode"]
    I = private_key["I"]
    q = private_key["q"]
    x = private_key["x"]
    C = lmots_gen_C_for_signature()
    y = lmots_compute_y( message, typecode, I, q, C, x )
    serialized = lmots_serialize_signature( typecode, C, y )
    signature = {
        "typecode": typecode,
        "C": C,
        "y": y,
        "serialized": serialized
    }
    return signature

    
def lmots_gen_C_for_signature():
    pass


def lmots_compute_y( message, typecode, I, q, C, x ):    
    n, w, p = lmots_typecode_to_params[ typecode ]
    H = hashlib.sha256()
    y = []
    Q = H.digest( I + u32str(q) + u16str(LMOTS_D_MESG) + C + message )
    for i in range( p ):
        a = lmots_coef( Q + lmots_chksum(Q), i, w )
        tmp = x[i]
        for j in range( a ):            
            tmp = H.digest( I + u32str(q) + u16str(i) + u8str(j) + tmp )
        y.append( tmp )
    return y


def lmots_serialize_signature( typecode, C, y ):
    serialized = u32str( typecode ) + C
    for y_i in y:
        serialized = serialized + y_i
    return serialized


def lmots_coef( S, i, w ):
    out = ( 2**w - 1 ) & lmots_byte( S, floor( i * w // 8 ) )
    shift = 8 - ( w * ( i % ( 8 // w )) + w )    
    return out >> shift

def lmots_byte( S, i ):
    #return S[i]
    pass

def lmots_chksum( input_string, str_len_in_bytes ):
    pass
    # tmp = 0
    # for i in range( str_len_in_bytes * 8 / w ):
    #     tmp = tmp + ( 2 ** w - 1 ) - lmots_coef( input_string, i, w )
    # return ( tmp << ls )



### Verify

def lmots_is_correct_signature( message, signature, public_key ):
    if lmots_pub_key_too_short( public_key ):
        return False
    pubtype = public_key["typecode"]
    if lmots_is_wrong_keylength( pubtype, public_key ):
        return False
    I = public_key["I"]
    q = public_key["q"]
    K = public_key["K"]
    kc = lmots_compute_key_candidate( message, signature, pubtype, I, q )
    if not kc:
        return False
    #
    return kc == K

def lmots_pub_key_too_short( public_key ):
    #return len( public_key["serialized"] ) < 4
    pass


def lmots_is_wrong_keylength( pubtype, public_key ):
    n, w, p = lmots_typecode_to_params[ pubtype ]
    #return len( public_key["serialized"] ) != 24 + n
    pass


def lmots_compute_key_candidate( message, signature, pubtype, I, q ):
    if lmots_is_signature_too_short( signature ):
        return None
    sigtype = signature["typecode"]
    if sigtype != pubtype:
        return None
    n, w, p = lmots_typecode_to_params[ sigtype ]
    if lmots_is_wrong_signature_length( sigtype, signature ):
        return None
    C = signature["C"]
    y = signature["y"]
    H = hashlib.sha256()
    Q = H.digest( I + u32str(q) + u16str( LMOTS_D_MESG ) + C + message )
    z = []
    for i in range( p ):
        a = lmots_coef( Q + lmots_chksum( Q ), i, w )
        tmp = y[i]
        H = hashlib.sha256()
        for j in range( 2 ** w - 1 ):            
            tmp = H.digest( I + u32str(q) + u16str(i) + u8str(j) + tmp )
        z.append( tmp )
    H = hashlib.sha256()
    H.update( I + u32str(q) + u16str( LMOTS_D_PBLC ) )
    for z_i in z:
         H.update( z_i )
    kc = H.digest()
    return kc


def lmots_is_signature_too_short( signature ):
    #return len( signature["serialized"] ) < 4
    pass


def lmots_is_wrong_signature_length( sigtype, signature ):
    n, w, p = lmots_typecode_to_params[ sigtype ]
    #return len( signature["serialized"] ) != 4 + n * (p+1)
    pass


def lmots_is_wrong_ots_signature_length_in_lms( ots_sigtype, ots_signature ):
    n, w, p = lmots_typecode_to_params[ sigtype ]
    #return len( signature["serialized"] ) != 12 + n * (p+1)
    pass
