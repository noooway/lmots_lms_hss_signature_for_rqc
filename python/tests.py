import lmots
import lms
import hss

### LMOTS

message = "go to hell"
msg_bytearray = bytearray()
msg_bytearray.extend( message.encode() )

lmots_typestring = "lmots_sha256_n32_w2"
lmots_prv, lmots_pub = lmots.lmots_gen_keypair( lmots_typestring )
lmots_sign = lmots.lmots_sign( msg_bytearray, lmots_prv )

# serialize/deserialize
lmots_deser_pub = lmots.lmots_deserialize_pub_key( lmots_pub["serialized"] )
lmots_deser_sign = lmots.lmots_deserialize_signature( lmots_sign["serialized"] )
print( "LMOTS compare serialized/deserialized pub key:",
       lmots_deser_pub == lmots_pub )
print( "LMOTS compare serialized/deserialized signature:",
       lmots_deser_sign == lmots_sign )

# test single signature
lmots_correct = lmots.lmots_verify( msg_bytearray, lmots_sign, lmots_pub )
print( "LMOTS signature verification:", lmots_correct )

# test exhaustion
lmots_sign = lmots.lmots_sign( msg_bytearray, lmots_prv )
lmots_correct = lmots.lmots_verify( msg_bytearray, lmots_sign, lmots_pub )
print( "LMOTS signing 2'nd time (key exhaustion):", lmots_correct )




### LMS 

message = "go to hell"
msg_bytearray = bytearray()
msg_bytearray.extend( message.encode() )

lms_typestring = "lms_sha256_m32_h5"
lms_prv, lms_pub = lms.lms_gen_keypair( lms_typestring )
lms_sign = lms.lms_sign( msg_bytearray, lms_prv )

# serialize/deserialize
lms_deser_pub = lms.lms_deserialize_pub_key( lms_pub["serialized"] )
lms_deser_sign = lms.lms_deserialize_signature( lms_sign["serialized"] )
print( "LMS compare serialized/deserialized pub key:",
       lms_deser_pub == lms_pub )
print( "LMS compare serialized/deserialized signature:",
       lms_deser_sign == lms_sign )

# test single signature
lms_correct = lms.lms_verify( msg_bytearray, lms_sign, lms_pub )
print( "LMS signature verification:", lms_correct )

# test exhaustion
lms_h = 5
for i in range( 2**lms_h + 3 ):
    print( "LMS signing {}'th time".format( i + 1 ) ) 
    msg_bytearray = bytearray()
    msg_bytearray.extend( str(i).encode() )
    lms_sign = lms.lms_sign( msg_bytearray, lms_prv )
    lms_correct = lms.lms_verify( msg_bytearray, lms_sign, lms_pub )
    print( lms_correct )



### HSS

message = "go to hell"
msg_bytearray = bytearray()
msg_bytearray.extend( message.encode() )

L = 2
hss_prv, hss_pub = hss.hss_gen_keypair( L )
hss_sign = hss.hss_sign( msg_bytearray, hss_prv )

# serialize/deserialize
hss_deser_pub = hss.hss_deserialize_public_key( hss_pub["serialized"] )
hss_deser_sign = hss.hss_deserialize_signature( hss_sign["serialized"] )
print( "HSS compare serialized/deserialized pub key:",
       hss_deser_pub == hss_pub )
print( "HSS compare serialized/deserialized signature:",
       hss_deser_sign == hss_sign )

# test single signature
hss_correct = hss.hss_verify( msg_bytearray, hss_sign, hss_pub )
print( "HSS signature verification:", hss_correct )

# test exhaustion
default_lms_h = 5
n_of_keys = ( 2 ** default_lms_h ) ** L
for i in range( 1, n_of_keys + 3 ):
    print( "HSS signing {}'th time".format( i + 1 ) ) 
    msg_bytearray = bytearray()
    msg_bytearray.extend( str(i).encode() )
    hss_sign = hss.hss_sign( msg_bytearray, hss_prv )
    hss_correct = hss.hss_verify( msg_bytearray, hss_sign, hss_pub )
    print( hss_correct )




