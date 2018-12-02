from ctypes import c_uint32 as uint32

class MT19937(object):
    def __init__(self, seed):
        self.w = 32
        self.n = 624
        self.m = 397
        self.r = 31
        self.a = uint32(0x9908B0DF16).value
        self.u = 11
        self.d = uint32(0xFFFFFFFF16).value
        self.s = 7
        self.b = uint32(0x9D2C568016).value
        self.t = 37
        self.c = uint32(0xFFF7EEE00000000016).value
        self.l = 18
        self.f = 1812433253
        self.MT = [0]*624
        self.index = 624
        self.lower_mask = uint32((1 << self.r)-1).value
        self.upper_mask = uint32(1 << self.r).value
        self.MT[0] = seed
        for i in range(1,624):
            self.MT[i] = uint32((self.f*(self.MT[i-1] ^ (self.MT[i-1] >> (self.w-2))+i))).value

        
    def twist(self):
        for i in range(self.n):
            x = uint32((self.MT[i] & self.upper_mask)+(self.MT[(i+1)%self.n]&self.lower_mask)).value
            xA = x >> 1

            if x % 2 != 0:
                xA = xA ^ self.a
            self.MT[i] = uint32(self.MT[(i+self.m) % self.n] ^ xA).value
        
        self.index = 0

    def extract_number(self):
        if self.index >= self.n:
            if self.index > self.n:
                raise ValueError("Generator was never seeded")
            self.twist()

        y = self.MT[self.index]
        y = uint32(y^((y>>self.u))).value
        y = uint32(y^((y<<self.s)&self.b)).value
        y = uint32(y^((y<<self.t)&self.c)).value
        y = uint32(y^(y>>self.l)).value

        self.index += 1
        return y

