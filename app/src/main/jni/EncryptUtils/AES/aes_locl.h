#ifndef HEADER_AES_LOCL_H
# define HEADER_AES_LOCL_H

# if defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_AMD64) || defined(_M_X64))
#  define SWAP(x) (_lrotl(x, 8) & 0x00ff00ff | _lrotr(x, 8) & 0xff00ff00)
#  define GETU32(p) SWAP(*((u32 *)(p)))
#  define PUTU32(ct, st) { *((u32 *)(ct)) = SWAP((st)); }
# else
#  define GETU32(pt) (((AES_u32)(pt)[0] << 24) ^ ((AES_u32)(pt)[1] << 16) ^ ((AES_u32)(pt)[2] <<  8) ^ ((AES_u32)(pt)[3]))
#  define PUTU32(ct, st) { (ct)[0] = (AES_u8)((st) >> 24); (ct)[1] = (AES_u8)((st) >> 16); (ct)[2] = (AES_u8)((st) >>  8); (ct)[3] = (AES_u8)(st); }
# endif

# ifdef AES_LONG
typedef unsigned long u32;
# else
typedef unsigned int AES_u32;
# endif
typedef unsigned char AES_u8;

# undef FULL_UNROLL

#endif                          /* !HEADER_AES_LOCL_H */
