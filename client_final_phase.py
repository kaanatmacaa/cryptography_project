from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256, SHA256
import Crypto.Random.random # a bit better secure random number generation 
import client_basics as cb
import client_basics_Phase2 as cb2
import client_basics_Phase3 as cb3
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
cb3.ResetOTK(h,s) #TODO
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

    a = cb.OTKReg(i,otk_pub.x,otk_pub.y,otk_cal(k_hmac, otk_pub)) #TODO
    #a = "True"
    print("Result :", a)
    print("")
    otk_priv_arr.append(otk_priv)


print("OTK_PRIV_ARR: ", otk_priv_arr)



#PHASE 2 
print("------------------------------------------------------")
print("PHASE 2: ")
print()
cb3.PseudoSendMsgPH3(h, s) #Your favourite pseudo-client sent you 5 messages. You can get them from the server
#PseudoSendMsgPH3
print("1:")
idb1, otkid1, msgid1, msg1, ekx1, eky1 = cb3.ReqMsg(h, s)
print("2:")
idb2, otkid2, msgid2, msg2, ekx2, eky2 = cb3.ReqMsg(h, s)
print("3:")
idb3, otkid3, msgid3, msg3, ekx3, eky3 = cb3.ReqMsg(h, s)
print("4:")
idb4, otkid4, msgid4, msg4, ekx4, eky4 = cb3.ReqMsg(h, s)
print("5:")
idb5, otkid5, msgid5, msg5, ekx5, eky5 = cb3.ReqMsg(h, s)

#3.2.1 Session Key (KS) 
def findKS(otkid, ekx, eky):
    ek = Point(ekx, eky, E)
    T = otk_priv_arr[otkid] * ek
    U = (T.x).to_bytes(((T.x).bit_length()+7)//8, "big") + (T.y).to_bytes(((T.y).bit_length()+7)//8, "big") + b'MadMadWorld'
    KS = SHA3_256.new(U).digest()
    return KS

ks1 = findKS(otkid1, ekx1, eky1)

def findKdf(ks):
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
ids = []

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
        ids.append(i)
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
    return dtext

dtext1 = AesDecrypt(cmsgs[0], encs[0], nonces[0])
dtext1 = bytes(dtext1, 'utf-8')
dtext2 = AesDecrypt(cmsgs[1], encs[1], nonces[1])
dtext2 = bytes(dtext2, 'utf-8')
dtext3 = AesDecrypt(cmsgs[2], encs[2], nonces[2])
dtext3 = bytes(dtext3, 'utf-8')
dtext4 = AesDecrypt(cmsgs[3], encs[3], nonces[3])
dtext4 = bytes(dtext4, 'utf-8')
dtext5 = AesDecrypt(cmsgs[4], encs[4], nonces[4]) #because now all the msg are correct (phase3)
dtext5 = bytes(dtext5, 'utf-8')

dtext_list = [dtext1, dtext2, dtext3, dtext4, dtext5]       #needed at phase3 for grading part. These are the msg we will send to pseudo client



#phase 3
print("")
print("------------------------------------------------------")
print("PHASE 3:")
sa = 17353634583535269100214152160979107048399289142843300833199020552285271875066
print("sa: ", sa)

qa = sa * p #qa is public key
print("qa: ",qa)

#signature generation
print("stuId: ", stuID)

ServerID = 18007
k = 1748178

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

stuID = int.from_bytes(stuID,"big")
print("stuId: ", stuID)

print("reqOTKB: ")

#KEYID, OTK_X, OTK_Y = cb3.reqOTKB(stuID, m, h, s)

KEYID =  54
OTK_X =  49423115135639117780110598800067102951151492842969517804762168007684819320280
OTK_Y =  103838483670827101067809167427012791940728140473666527481560818625322840035032

print("KEYID: ", KEYID)
print("OTK_X: ", OTK_X)
print("OTK_Y: ", OTK_Y)

otk_b = Point(OTK_X,OTK_Y, E) #public client

ek_a_priv = Crypto.Random.random.randint(1, n-2)
print("ek_a_priv: ", ek_a_priv)
ek_a_pub = ek_a_priv * p #qa is public key
print("ek_a_pub: ",ek_a_pub)

T = ek_a_priv * otk_b 
print("T: ",T)
U = (T.x).to_bytes(((T.x).bit_length()+7)//8, "big") + (T.y).to_bytes(((T.y).bit_length()+7)//8, "big") + b'MadMadWorld'
print("U: ",U)
KS_P3 = SHA3_256.new(U).digest()
print("KS_P3: ",KS_P3)

#creating the chain
def findKdf(ks):
    kenc = SHA3_256.new(ks + b'LeaveMeAlone').digest()
    khmac = SHA3_256.new(kenc + b'GlovesAndSteeringWheel').digest()
    kkdf = SHA3_256.new(khmac + b'YouWillNotHaveTheDrink').digest()
    return kenc, khmac, kkdf

kenc1_p3, khmac1_p3, kkdf1_p3 = findKdf(KS_P3)
kenc2_p3, khmac2_p3, kkdf2_p3 = findKdf(kkdf1_p3)
kenc3_p3, khmac3_p3, kkdf3_p3 = findKdf(kkdf2_p3)
kenc4_p3, khmac4_p3, kkdf4_p3 = findKdf(kkdf3_p3)
kenc5_p3, khmac5_p3, kkdf5_p3 = findKdf(kkdf4_p3)

#encryption
def AesEncrypt(ptext, key):
    cipher = AES.new(key, AES.MODE_CTR)
    ctext = cipher.nonce + cipher.encrypt(ptext)
    return ctext

ctext1 = AesEncrypt(dtext_list[0], kenc1_p3)
ctext2 = AesEncrypt(dtext_list[1], kenc2_p3)
ctext3 = AesEncrypt(dtext_list[2], kenc3_p3)
ctext4 = AesEncrypt(dtext_list[3], kenc4_p3)
ctext5 = AesEncrypt(dtext_list[4], kenc5_p3)

print("cipher after decrpyt1: ", ctext1)
print("cipher after decrpyt2: ", ctext2)
print("cipher after decrpyt3: ", ctext3)
print("cipher after decrpyt4: ", ctext4)
print("cipher after decrpyt5: ", ctext5)

def addHmac(ctext, hmac):
    hmac_p3 = HMAC.new(hmac, digestmod=SHA256)
    print("hmac_p3: ",hmac_p3)
    hmac_p3.update(ctext)
    print("hmac_p3: ",hmac_p3)
    hmac_final_p3 = hmac_p3.digest()
    print("hmac_final_p3: ",hmac_final_p3)
    fin = ctext + hmac_final_p3
    print("final: ", fin)
    fin = str(fin)
    return fin

fin1 = addHmac(ctext1, khmac1_p3)
fin2 = addHmac(ctext2, khmac2_p3)
fin3 = addHmac(ctext3, khmac3_p3)
fin4 = addHmac(ctext4, khmac4_p3)
fin5 = addHmac(ctext5, khmac5_p3)

print("")
cb3.SendMsg(stuID, ServerID, 54, 1, fin1, ek_a_pub.x, ek_a_pub.y) 
print("")
cb3.SendMsg(stuID, ServerID, 54, 2, fin2, ek_a_pub.x, ek_a_pub.y)
print("")
cb3.SendMsg(stuID, ServerID, 54, 3, fin3, ek_a_pub.x, ek_a_pub.y)
print("")
cb3.SendMsg(stuID, ServerID, 54, 4, fin4, ek_a_pub.x, ek_a_pub.y)
print("")
cb3.SendMsg(stuID, ServerID, 54, 5, fin5, ek_a_pub.x, ek_a_pub.y)
print("")

#4.2
#checking the status
numMSG, numOTK, StatusMSG = cb3.Status(stuID, h, s)
print("Num msg: ", numMSG)
print("Num otk: ", numOTK)
print("Status msg: ", StatusMSG)
#You have only 1 OTK left. Please register new OTKs. The largest key id is 9
largest_key_id = 9
otk_priv_arr2 = []
for i in range(largest_key_id+1, largest_key_id + 11 - numOTK):
    otk_priv = Crypto.Random.random.randint(0, n-1) #otk_priv is private key
    print("otk_priv_ ", i ,":", otk_priv)
    otk_pub = otk_priv * p #otk_pub is public key
    print("otk_pub_ ", i ,":",otk_pub)
    a = cb.OTKReg(i,otk_pub.x,otk_pub.y,otk_cal(k_hmac, otk_pub)) 
    print("Result :", a)
    print("")
    otk_priv_arr2.append(otk_priv)

print("otk_priv_arr2: ", otk_priv_arr2)
otk_priv_arr.append(otk_priv_arr2)
numMSG, numOTK, StatusMSG = cb3.Status(stuID, h, s)

#4.3

KEYID =  54
OTK_X =  49423115135639117780110598800067102951151492842969517804762168007684819320280
OTK_Y =  103838483670827101067809167427012791940728140473666527481560818625322840035032

print("KEYID: ", KEYID)
print("OTK_X: ", OTK_X)
print("OTK_Y: ", OTK_Y)

otk_b = Point(OTK_X,OTK_Y, E) #public client

ek_a_priv = Crypto.Random.random.randint(1, n-2)
print("ek_a_priv: ", ek_a_priv)
ek_a_pub = ek_a_priv * p #qa is public key
print("ek_a_pub: ",ek_a_pub)

T = ek_a_priv * otk_b 
print("T: ",T)
U = (T.x).to_bytes(((T.x).bit_length()+7)//8, "big") + (T.y).to_bytes(((T.y).bit_length()+7)//8, "big") + b'MadMadWorld'
print("U: ",U)
KS_P3 = SHA3_256.new(U).digest()
print("KS_P3: ",KS_P3)

#creating the chain
def findKdf(ks):
    kenc = SHA3_256.new(ks + b'LeaveMeAlone').digest()
    khmac = SHA3_256.new(kenc + b'GlovesAndSteeringWheel').digest()
    kkdf = SHA3_256.new(khmac + b'YouWillNotHaveTheDrink').digest()
    return kenc, khmac, kkdf

kenc1_p3, khmac1_p3, kkdf1_p3 = findKdf(KS_P3)
kenc2_p3, khmac2_p3, kkdf2_p3 = findKdf(kkdf1_p3)
kenc3_p3, khmac3_p3, kkdf3_p3 = findKdf(kkdf2_p3)
kenc4_p3, khmac4_p3, kkdf4_p3 = findKdf(kkdf3_p3)
kenc5_p3, khmac5_p3, kkdf5_p3 = findKdf(kkdf4_p3)

khmacs_p3 = [khmac1_p3, khmac2_p3, khmac3_p3, khmac4_p3,khmac5_p3 ]
kencs_p3 = [kenc1_p3, kenc2_p3, kenc3_p3, kenc4_p3,kenc5_p3 ]

#encryption
def AesEncrypt(ptext, key):
    cipher = AES.new(key, AES.MODE_CTR)
    ctext = cipher.nonce + cipher.encrypt(ptext)
    return ctext

ctext1 = AesEncrypt(dtext_list[0], kenc1_p3)
ctext2 = AesEncrypt(dtext_list[1], kenc2_p3)
ctext3 = AesEncrypt(dtext_list[2], kenc3_p3)
ctext4 = AesEncrypt(dtext_list[3], kenc4_p3)
ctext5 = AesEncrypt(dtext_list[4], kenc5_p3)

print("cipher after decrpyt1: ", ctext1)
print("cipher after decrpyt2: ", ctext2)
print("cipher after decrpyt3: ", ctext3)
print("cipher after decrpyt4: ", ctext4)
print("cipher after decrpyt5: ", ctext5)

#returning final ciphertext as byte and string
def addHmac(ctext, hmac):
    hmac_p3 = HMAC.new(hmac, digestmod=SHA256)
    print("hmac_p3: ",hmac_p3)
    hmac_p3.update(ctext)
    print("hmac_p3: ",hmac_p3)
    hmac_final_p3 = hmac_p3.digest()
    print("hmac_final_p3: ",hmac_final_p3)
    fin = ctext + hmac_final_p3
    print("final: ", fin)
    fin_s = str(fin)
    return fin, fin_s

fin1, fin1_s = addHmac(ctext1, khmac1_p3)
fin2, fin2_s = addHmac(ctext2, khmac2_p3)
fin3, fin3_s = addHmac(ctext3, khmac3_p3)
fin4, fin4_s = addHmac(ctext4, khmac4_p3)
fin5, fin5_s = addHmac(ctext5, khmac5_p3)

print("")
cb3.SendMsg(stuID, ServerID, 54, 1, fin1_s, ek_a_pub.x, ek_a_pub.y) 
print("")
cb3.SendMsg(stuID, ServerID, 54, 2, fin2_s, ek_a_pub.x, ek_a_pub.y)
print("")
cb3.SendMsg(stuID, ServerID, 54, 3, fin3_s, ek_a_pub.x, ek_a_pub.y)
print("")
cb3.SendMsg(stuID, ServerID, 54, 4, fin4_s, ek_a_pub.x, ek_a_pub.y)
print("")
cb3.SendMsg(stuID, ServerID, 54, 5, fin5_s, ek_a_pub.x, ek_a_pub.y)
print("")

#4.3 to check this part we will know decrypt as we did in phase2

to_be_decrypted = [fin1, fin2, fin3, fin4, fin5]
cmsgs_3 = []
nonces_3 = []
hmacs_3 = []
encs_3 = []

#seperating the fins
def findHmac(msg, i):
    print("msg: ", i)
    nonce = msg[:8]
    hmac = msg[-32:]
    theMsg = msg[8:-32]
    hmac_new = HMAC.new(khmacs_p3[i-1], digestmod=SHA256)
    hmac_new.update(theMsg)
    hmac_final= hmac_new.digest()
    cmsgs_3.append(theMsg)
    nonces_3.append(nonce)
    hmacs_3.append(hmac)
    encs_3.append(kencs_p3[i-1])

findHmac(fin1, 1) 
findHmac(fin2, 2)
findHmac(fin3, 3)
findHmac(fin4, 4)
findHmac(fin5, 5)

def AesDecrypt(ctext, key, nonce):
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce) #keyenc, AES.MODE_CTR, nonce=ctext[0:8]
    dtext = cipher.decrypt(ctext)
    dtext = dtext.decode('UTF-8')
    print("plaintext: ", dtext)
    return dtext

dtext1_3 = AesDecrypt(cmsgs_3[0], encs_3[0], nonces_3[0])
dtext1_3 = bytes(dtext1_3, 'utf-8')
dtext2_3 = AesDecrypt(cmsgs_3[1], encs_3[1], nonces_3[1])
dtext2_3 = bytes(dtext2_3, 'utf-8')
dtext3_3 = AesDecrypt(cmsgs_3[2], encs_3[2], nonces_3[2])
dtext3_3 = bytes(dtext3_3, 'utf-8')
dtext4_3 = AesDecrypt(cmsgs_3[3], encs_3[3], nonces_3[3])
dtext4_3 = bytes(dtext4_3, 'utf-8')
dtext5_3 = AesDecrypt(cmsgs_3[4], encs_3[4], nonces_3[4]) #because now all the msg are correct (phase3)
dtext5_3 = bytes(dtext5_3, 'utf-8')

#to check if we sent the correct dtexts to the server
print("Check for dtext1: ", dtext1_3==dtext1) 
print("Check for dtext2: ", dtext2_3==dtext2)
print("Check for dtext3: ", dtext3_3==dtext3)
print("Check for dtext4: ", dtext4_3==dtext4)
print("Check for dtext5: ", dtext5_3==dtext5)