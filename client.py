import random 
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256
from Crypto import Random   # a bit better secure random number generation 
import math
import client_basics as cb
import hashlib
import hw01_helper as helper
import sys
#sys.getsizeof(m)

stuID = 28239

x = 93223115898197558905062012489877327981787036929201444813217704012422483432813
y = 8985629203225767185464920094198364255740987346743912071843303975587695337619

E = Curve.get_curve('secp256k1')

P = Point(x,y,E)

n = E.order #finds order of point P

print("n: ", n, "\n")

sa = random.randint(0, n-1) #sa is private key

qa = sa * P  #qa is public key

m = 5
m_byte = m.to_bytes(1, 'big')
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
print ("h_obj: ", h_obj.hexdigest(), "\n")
h = h_obj.digest()
h = int.from_bytes(h,"big")

print ("h: ", h, "\n")

h = h % n
s = (k  - (sa*h)) % n

m = (h,s)

print("m: ", m, "\n")

print("s: ", s)

V = (s * P) + (h * qa)

v = (V.x) % n

print("v: ", v, "\n")

v_byte = v.to_bytes(32, 'big')

print("v_byte: ", v_byte, "\n")

m = 5
m_byte = m.to_bytes(1,'big')
print("m : ", m , "\n", "m_byte", m_byte, "\n")

v_obj = SHA3_256.new()
v_obj.update(r_byte + m_byte)
print("v_byte + m_byte : ", (v_byte + m_byte), "\n")
print ("v_obj: ", v_obj.hexdigest(), "\n")

h_prime = v_obj.digest()
h_prime = int.from_bytes(h_prime,"big")


h_prime = h_prime % n

if h_prime == h :
    print("Succes!")

else :
    print("Fail!")


print("h_prime: ", h_prime, "\n")


cb.IKRegReq(h,s,x,y)



#signature generation
#msg = {'ID': stuID, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}