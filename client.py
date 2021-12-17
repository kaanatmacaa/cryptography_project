from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256
import Crypto.Random.random # a bit better secure random number generation 
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

sa = Crypto.Random.random.randint(0, n-1) #sa is private key
print("sa: ", sa)

qa = sa * p #qa is public key
print("qa: ",qa)

#signature generation
stuID = stuID.to_bytes(2,byteorder="big")
print("stuId: ", stuID)

m = 28239
k = Crypto.Random.random.randint(1, n-2)

R = k * p
r = (R.x) % n
print("r:", r)


r_byte = r.to_bytes(32, 'big')
m_byte = m.to_bytes(2, 'big')

h = SHA3_256.SHA3_256_Hash(r_byte+ m_byte, True)
h = SHA3_256.SHA3_256_Hash.digest(h)
h = int.from_bytes(h,"big")
h = h % n

s = (k- (sa*h)) 
s = s % n

print("h: ", h)
print("s: ", s)
print(E.is_on_curve(qa))
#cb.IKRegReq(h,s,qa.x,qa.y) ---------> ID: 28239 CODE: 106590
"""
ID: 28239 CODE: 106590
Sending message is:  {'ID': 28239, 
'H': 7483239667947657079221120183470408812468827778297638119224547277257303037189, 
'S': 37072444792267534329042480053454078134844330208514188234371033536238826941057, 
'IKPUB.X': 39976054850521507574967626301504309882077713530204759279452697237879489454571, 
'IKPUB.Y': 42826606605638080211453913302126934486778992853270815969562555968218429004241}
ID: 28239 CODE: 106590

"""

#signature verification
"""
h = 7483239667947657079221120183470408812468827778297638119224547277257303037189
s = 37072444792267534329042480053454078134844330208514188234371033536238826941057
p=(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 , 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
sa = 17353634583535269100214152160979107048399289142843300833199020552285271875066
"""

qa = sa * p #qa is public key
code = 106590

V = s*p + h*qa
v = V.x % n

v_byte = v.to_bytes(32, 'big')
m_byte = m.to_bytes(2, 'big')

h2 = SHA3_256.SHA3_256_Hash(v_byte+ m_byte, True)
h2 = SHA3_256.SHA3_256_Hash.digest(h2)
h2 = int.from_bytes(h2,"big")
h2 = h2 % n

if (h == h2):
    print("Accept!") #verified
else:
    print("Not verified!")
