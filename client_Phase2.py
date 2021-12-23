from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256, SHA256
import Crypto.Random.random # a bit better secure random number generation 
import client_basics as cb
import client_basics_Phase2 as cb2
from Crypto.Hash import  HMAC
from Crypto.Cipher import AES

#3.1 Downloading Messages from the server

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
    print("Not verified!") #not verified

#cb.IKRegVerify(code) Registered successfully reset code: 706974

#2.2 signed pre key
spk_priv = 97386945159447522628161478992249335496917184340606559844874149341380030966312
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

x5, y5, h4, s4  = cb.SPKReg(h3,s3,spk_pub.x,spk_pub.y)

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

#2.3 otk

sw_pub_spk = Point(x5, y5, E)

T = spk_priv * sw_pub_spk

t_byte_x = T.x.to_bytes(32, 'big')
t_byte_y = T.y.to_bytes(32, 'big')
m1_byte = b"NoNeedToRideAndHide"

k_hmac = SHA3_256.SHA3_256_Hash(t_byte_x+ t_byte_y + m1_byte, True)
k_hmac = SHA3_256.SHA3_256_Hash.digest(k_hmac)

def otk_cal (k_hmac, okt):
    h_temp = HMAC.new(k_hmac, digestmod=SHA256)
    okt_x_y = okt.x.to_bytes(32, 'big') + okt.y.to_bytes(32, 'big')
    h_temp.update(okt_x_y)
    return h_temp.hexdigest()

#(okt.x.bit_length()+7)//8

otk_priv_arr = []

for i in range(0,10):

    otk_priv = Crypto.Random.random.randint(0, n-1) #otk_priv is private key
    print("otk_priv_ ", i ,":", otk_priv)

    otk_pub = otk_priv * p #otk_pub is public key
    print("otk_pub_ ", i ,":",otk_pub)

    #a = cb.OTKReg(i,otk_pub.x,otk_pub.y,otk_cal(k_hmac, otk_pub))
    a = "True"
    print("Result :", a)
    print("")
    otk_priv_arr.append(otk_priv)

print(otk_priv_arr)



#PHASE 2 
otk_priv_arr = [58812550160581575630508725941736887561194979997043183966966185494849940249251, 113134768184265094285950611350831621014151997963594796624397301921177885399934,
                20267076738575867168349684504005399720465890257461154860365299450991689807875, 78437127372312140030973816279715228984360670118096910250844032095937373991384,
                88238604028222129991341306324137765037896705104940596475795590577249277344506, 114029923154266917463210894558908505676709706603670706106915845597898785505321, 
                90731849819740707596931152818883722845170974802295882459622297656179653042346, 114616496261347604295832409209194250071998773458541013733988138469452990133859, 
                71060922069370357355738292982925762459434523425813481073577732910597829357146, 103462645275059932554340636620533275739926310988787191875565565529839223108967]

cb2.PseudoSendMsg(h, s) #Your favourite pseudo-client sent you 5 messages. You can get them from the server

print("1:")
idb1, otkid1, msgid1, msg1, ekx1, eky1 = cb2.ReqMsg(h, s)
print("2:")
idb2, otkid2, msgid2, msg2, ekx2, eky2 = cb2.ReqMsg(h, s)
print("3:")
idb3, otkid3, msgid3, msg3, ekx3, eky3 = cb2.ReqMsg(h, s)
print("4:")
idb4, otkid4, msgid4, msg4, ekx4, eky4 = cb2.ReqMsg(h, s)
print("5:")
idb5, otkid5, msgid5, msg5, ekx5, eky5 = cb2.ReqMsg(h, s)

#3.2.1 Session Key (KS) 
def findKS(otkid, ekx, eky):
    ek = Point(ekx, eky, E)
    T = otk_priv_arr[otkid] * ek
    U = (T.x).to_bytes(((T.x).bit_length()+7)//8, "big") + (T.y).to_bytes(((T.y).bit_length()+7)//8, "big") + b'MadMadWorld'
    #KS = SHA3_256.SHA3_256_Hash(U, True)
    #KS = SHA3_256.SHA3_256_Hash.digest(KS)
    KS = SHA3_256.new(U).digest()
    return KS

ks1 = findKS(otkid1, ekx1, eky1)
#ks2 = findKS(otkid2, ekx2, eky2)
#ks3 = findKS(otkid3, ekx3, eky3)
#ks4 = findKS(otkid4, ekx4, eky4)
#ks5 = findKS(otkid5, ekx5, eky5)

def findKdf(ks):
    ''' 
    kenc = SHA3_256.SHA3_256_Hash(ks + b'LeaveMeAlone' , True)
    kenc = SHA3_256.SHA3_256_Hash.digest(kenc)
    
    khmac = SHA3_256.SHA3_256_Hash(kenc + b'GlovesAndSteeringWhell' , True)
    khmac = SHA3_256.SHA3_256_Hash.digest(khmac)
    kkdf = SHA3_256.SHA3_256_Hash(khmac + b'YouWillNotHaveTheDrink' , True)
    kkdf = SHA3_256.SHA3_256_Hash.digest(kkdf)
    '''
    kenc = SHA3_256.new(ks + b'LeaveMeAlone').digest()
    khmac = SHA3_256.new(kenc + b'GlovesAndSteeringWheel').digest()
    kkdf = SHA3_256.new(khmac + b'YouWillNotHaveTheDrink').digest()

    return kenc, khmac, kkdf


kenc1, khmac1, kkdf1 = findKdf(ks1)
kenc2, khmac2, kkdf2 = findKdf(kkdf1)
kenc3, khmac3, kkdf3 = findKdf(kkdf2)
kenc4, khmac4, kkdf4 = findKdf(kkdf3)
kenc5, khmac5, kkdf5 = findKdf(kkdf4)

kencs = [kenc1, kenc2, kenc3, kenc4, kenc5]
khmacs = [khmac1, khmac2, khmac3, khmac4, khmac5]
cmsgs = []
nonces = []
hmacs = []
encs = []

"""
c1 -> khmac -> if valid -> aes decr -> m1 
"""

def findHmac(msg, i):
    print("msg: ", i)
    msg = msg.to_bytes((msg.bit_length()+7)//8,"big")
    nonce = msg[:8]
    hmac = msg[-32:]
    theMsg = msg[8:-32]
    hmac_new = HMAC.new(khmacs[i-1], digestmod=SHA256)
    hmac_new.update(theMsg)
    hmac_final= hmac_new.digest()
    print("hmac: ", hmac)
    print("hmac_final: ", hmac_final)
    if(hmac == hmac_final):
        print("True, msg authenticated!")
        cmsgs.append(theMsg)
        nonces.append(nonce)
        hmacs.append(hmac)
        encs.append(kencs[i-1])
        
    else:
        print("False, not authenticated!")

findHmac(msg1, 1)
findHmac(msg2, 2)
findHmac(msg3, 3)
findHmac(msg4, 4)
findHmac(msg5, 5)

def AesDecrypt(ctext, key, nonce):
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce) #keyenc, AES.MODE_CTR, nonce=ctext[0:8]
    dtext = cipher.decrypt(ctext)
    dtext = dtext.decode('UTF-8')
    print("plaintext: ", dtext)

AesDecrypt(cmsgs[0], encs[0], nonces[0])
AesDecrypt(cmsgs[1], encs[1], nonces[1])
AesDecrypt(cmsgs[2], encs[2], nonces[2])
AesDecrypt(cmsgs[3], encs[3], nonces[3])