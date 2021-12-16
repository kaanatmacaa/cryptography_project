from random import randint, seed
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256
from Crypto import Random   # a bit better secure random number generation 
import math
import client_basics as cb

x = 93223115898197558905062012489877327981787036929201444813217704012422483432813
y = 8985629203225767185464920094198364255740987346743912071843303975587695337619

E = Curve.get_curve('secp256k1')

P = Point(x,y,E)

n = P.order #finds order of point P

sa = Random.randint(0, n-1) #sa is private key

qa = sa * P  #qa is public key