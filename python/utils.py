def u32str( x ):
    return x.to_bytes( 4, 'big' )

def u16str( x ):
    return x.to_bytes( 2, 'big' )

def u8str( x ):
    return x.to_bytes( 1, 'big' )

u32str_bytelen = 4
u16str_bytelen = 2
u8str_bytelen  = 1

def is_odd( x ):
    if isinstance( x, int ):
        return ( x % 2 == 1 )
    else:
        raise ValueError( "not int in is_odd" )

def to_int( bytestr ):
    return int.from_bytes( bytestr, byteorder='big' )


