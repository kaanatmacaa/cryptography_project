import random 
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256
from Crypto import Random   # a bit better secure random number generation 
import math
import client_basics as cb
import hashlib
import hw01_helper as helper

stuID = 28239

x = 93223115898197558905062012489877327981787036929201444813217704012422483432813
y = 8985629203225767185464920094198364255740987346743912071843303975587695337619

E = Curve.get_curve('secp256k1')

P = Point(x,y,E)

n = E.order #finds order of point P

print("n: ", n, "\n")

sa = random.randint(0, n-1) #sa is private key

qa = sa * P  #qa is public key

stuID = stuID.to_bytes(2,byteorder="big")
print(stuID)

m = 5
m_byte = m.to_bytes(32, 'big')
print("m : ", m , "\n", "m_byte", m_byte, "\n")

k = random.randint(1, n-2)

R = k * P

print("\nR:\n", R)
print("R on curve?", E.is_on_curve(R))
print("R.x : ", R.x , "\n")

r = (R.x) % n
r_byte = r.to_bytes(32, 'big')
print("r : ", r , "\n", "r_byte", r_byte, "\n")

print("R.x : ", R.x , "\n")

h_obj = SHA3_256.new()
h_obj.update(r_byte + m_byte)
print("r_byte + m_byte : ", (r_byte + m_byte), "\n")
h = h_obj.digest()

print ("h_obj: ", h_obj.hexdigest(), "\n")

h = h % n
s = (k  - (sa*h)) % n

m = (h,s)

print("m: ", m, "\n")



#signature generation
#msg = {'ID': stuID, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}