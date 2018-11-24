import struct, sys
def pkcs7(src, blocksize=16):
    pad = blocksize - (len(src) % blocksize)
    dst = list(src)
    if pad != blocksize:
        for i in range(0, pad):
            dst.append(chr(pad))
    
    return ''.join(dst)


def pkcs7_validate(src, blocksize=16):
    if ord(src[-1]) > 0:
        padding = ord(src[-1])
        tmp_src = src
        
        if len(src) == 16:
            src_len = 1
        else:
            src_len = len(src) - 16
       
               
        unpadded = src[:(len(src)%16)*blocksize-padding]
        # Not padded. Which raises an error
        if padding < 1 or padding > 15:
            raise ValueError('String is not padded or the string is corrupt')
        # Str of pad bytes
        pad_str = tmp_src[len(unpadded):]

        # Validate that each pad byte is the same
        for byte in pad_str:
            if ord(byte) != padding:
                raise ValueError('Padding bytes must be consistent')

        # Padding is validated, return the unpadded string
        return unpadded
    else:
        raise ValueError('Padding is not integer')

