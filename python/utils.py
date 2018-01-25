def u32str( x ):
    return x.to_bytes( 4, 'big' )

def u16str( x ):
    return x.to_bytes( 2, 'big' )

def u8str( x ):
    return x.to_bytes( 1, 'big' )

def is_odd( x ):
    if isinstance( x, int ):
        return ( x % 2 == 1 )
    else:
        raise ValueError( "not int in is_odd" )
