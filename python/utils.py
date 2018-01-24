def u32str( x ):
    return x.to_bytes( 4, 'big' )

def u16str( x ):
    return x.to_bytes( 2, 'big' )

def u8str( x ):
    return x.to_bytes( 1, 'big' )

