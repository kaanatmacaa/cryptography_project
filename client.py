import random 
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256
from Crypto import Random   # a bit better secure random number generation 
import math
import client_basics as cb

def is_valid(self, p):
    if p == self.zero: return True
    l = (p.y ** 2) % self.q
    r = ((p.x ** 3) + self.a * p.x + self.b) % self.q
    return l == r

def order(self, g):
        """order of point g
        >>> o = ec.order(g)
        >>> assert ec.is_valid(a) and ec.mul(a, o) == ec.zero
        >>> assert o <= ec.q
        """
        assert self.is_valid(g) and g != self.zero
        for i in range(1, self.q + 1):
            if self.mul(g, i) == self.zero:
                return i
            pass
        raise Exception("Invalid order") 
        pass

x = 93223115898197558905062012489877327981787036929201444813217704012422483432813
y = 8985629203225767185464920094198364255740987346743912071843303975587695337619

E = Curve.get_curve('secp256k1')

point = Point(x,y,E)

P = E.generator
n = E.order

sa = random.randint(0, n-1) #sa is private key

qa = sa * point  #qa is public key

#signature generation
k = random.randint(1, n-2)

R = k * point
r = R*x

