import random 
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256
from Crypto import Random   # a bit better secure random number generation 
import math
import client_basics as cb
import hashlib

stuID = 28239

x = 93223115898197558905062012489877327981787036929201444813217704012422483432813
y = 8985629203225767185464920094198364255740987346743912071843303975587695337619

E = Curve.get_curve('secp256k1')

p = E.generator
n = E.order
print("p: ", p)
print("n: ", n)

point = Point(x,y,E)
print("point: ", point)

sa = random.randint(0, n-1) #sa is private key
print("sa: ", sa)

qa = sa * point #qa is public key
print("qa: ",qa)

#signature generation
stuID = stuID.to_bytes(2,byteorder="big")
print("stuId: ", stuID)

m = 28239
k = random.randint(1, n-2)

R = k * point
#r = R.x
r = (R.x) % n

print("r:", r)

rb = r.to_bytes(32,byteorder="big")
mb = m.to_bytes(32,byteorder="big")

h = SHA3_256.SHA3_256_Hash(rb+mb, True)
h = SHA3_256.SHA3_256_Hash.digest(h)
h = int.from_bytes(h,"big")
h = h % n

s = (k- (sa*h)) 
s = s % n

msg = {'ID': stuID, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}

print("h: ", h)
print("s: ", s)

cb.IKRegReq(h,s,x,y)