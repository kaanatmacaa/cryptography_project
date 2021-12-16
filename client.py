import random 
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256
from Crypto import Random   # a bit better secure random number generation 
import math
import client_basics as cb
import hashlib

x = 93223115898197558905062012489877327981787036929201444813217704012422483432813
y = 8985629203225767185464920094198364255740987346743912071843303975587695337619

E = Curve.get_curve('secp256k1')

p = E.generator
n = E.order

point = Point(x,y,E)

sa = random.randint(0, n-1) #sa is private key

qa = sa * point  #qa is public key

#signature generation
k = random.randint(1, n-2)

R = k * point
r = R*x

stuID = 28239
msg = {'ID': stuID, 'H': h, 'S': s, 'IKPUB.X': ikpub.x, 'IKPUB.Y': ikpub.y}

m = msg.len()

h = hashlib.sha3_256(r//m)