from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256
import Crypto.Random.random # a bit better secure random number generation 
import math
import client_basics as cb
import hashlib
from Crypto.Hash import  HMAC

print("Cryptography Project - Kaan Atmaca & Eren Elcin")
print("2.1 - Key Generation:")
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

#sa = Crypto.Random.random.randint(0, n-1) #sa is private - identity key
sa = 17353634583535269100214152160979107048399289142843300833199020552285271875066
print("Identitiy Key is created")
print("Private IKey (sa): ", sa)

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
print("2.1 - Signature verification:")
qa = sa * p #qa is public key
#code = 106590

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
    print("Not verified!") #not verified

#cb.IKRegVerify(code) Registered successfully reset code: 706974
print("---------------------------------------------------------------------------------------")
print("")

#2.2 signed pre key

print("2.2 - Key Generation:")
#spk_priv = Crypto.Random.random.randint(0, n-1) #identity - private key
spk_priv = 108269724083693542106585217755545450673191652283464158754765257541145593369395
print("skp_priv: ", spk_priv)

spk_pub = spk_priv * p #qa is public key
print("skp_pub: ",spk_pub)

spk_x_bytes = spk_pub.x.to_bytes(32, 'big')
spk_y_bytes = spk_pub.y.to_bytes(32, 'big')

spk_m = spk_x_bytes + spk_y_bytes 

k3 = Crypto.Random.random.randint(1,n-2)
r3 = k3*p
r3x = r3.x % n

r3x_bytes = r3.x.to_bytes(32, 'big') 

h3 = SHA3_256.SHA3_256_Hash(r3x_bytes+ spk_m, True)
h3 = SHA3_256.SHA3_256_Hash.digest(h3)
h3 = int.from_bytes(h3,"big")
h3 = h3 % n

s3 = (k3 - (sa*h3)) 
s3 = s3 % n

print("h3: ", h3)
print("s3: ", s3)
print(E.is_on_curve(spk_pub))

#cb.ResetSPK(h, s) reseted spk do not comment out
#x5, y5, h4, s4  = cb.SPKReg(h3,s3,spk_pub.x,spk_pub.y)

print("2.2 - Key Verification")

x5 = 85040781858568445399879179922879835942032506645887434621361669108644661638219
y5 = 46354559534391251764410704735456214670494836161052287022185178295305851364841
h4 = 5803701983061410379326636803521956018914824623195521764663852100446683299651
s4 = 21565391023087327748986150625099922187627070532899292127264053909399474152791
print("x5: ", x5)
print("y5: ", y5)
print("h4: ", h4)
print("s4: ", s4)
sw_pub_ik = Point(x, y, E)

V2 = s4*p + h4*sw_pub_ik
v2 = V2.x % n

v2_byte = v2.to_bytes(32, 'big')
x5_byte = x5.to_bytes(32, 'big')
y5_byte = y5.to_bytes(32, 'big')
h5 = SHA3_256.SHA3_256_Hash(v2_byte + x5_byte + y5_byte, True)
h5 = SHA3_256.SHA3_256_Hash.digest(h5)
h5 = int.from_bytes(h5,"big")
h5 = h5 % n
if (h4 == h5):
    print("Accept!") #verified
else:
    print("Not verified!") #not verified

print("---------------------------------------------------------------------------------------")
print("")

#2.3 otk
print("2.3 - OTKS:")
sw_pub_spk = Point(x5, y5, E)
T = spk_priv * sw_pub_spk
t_byte_x = T.x.to_bytes(32, 'big')
t_byte_y = T.y.to_bytes(32, 'big')
m1_byte = b'NoNeedToRideAndHide'
U =  t_byte_x + t_byte_y  + m1_byte
k_hmac = SHA3_256.new(U).digest() 

for i in range(0,10):
    print("i: ", i)
    otk_priv = Crypto.Random.random.randint(0, n-1) #otk_priv is private key
    print("otk_priv_ ", i ,":", otk_priv)
    otk_pub = otk_priv * p #otk_pub is public key
    print("otk_pub_ ", i ,":",otk_pub)

    okt_x_y = otk_pub.x.to_bytes(32, 'big') + otk_pub.y.to_bytes(32, 'big') 
    hmac_object = HMAC.new(k_hmac, okt_x_y, digestmod=SHA3_256)
    hmac_object = hmac_object.hexdigest()
    
    a = cb.OTKReg(i, otk_pub.x, otk_pub.y, hmac_object)

    print("Result :", a)
    print("---------------------------------------------------------------------------------------")
    print("")