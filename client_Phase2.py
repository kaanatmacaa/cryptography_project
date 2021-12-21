from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256 
import Crypto.Random.random # a bit better secure random number generation 
import client_basics as cb
import client_basics_Phase2 as cb2
from Crypto.Hash import  HMAC
from Crypto.Cipher import AES

#3.1 Downloading Messages from the server

stuID = 28239

x = 93223115898197558905062012489877327981787036929201444813217704012422483432813
y = 8985629203225767185464920094198364255740987346743912071843303975587695337619

otk_priv_arr = [83298859977202201362433530055836210215313344042615971439947510539930030876612, 80945415910468963656028379507369284051398331890366455637211132375624882502648,
                7214091485102261185920748254194797363592172604660303457233174528351288607051, 70886281761299209392969200283432734233583256311456827711451782319132481906688,
                108248073280373904869439311525542273291926606389745818048496004143136788243256, 104044224450327805637437872873428502239240515265355492529556983502788476155365, 
                103203770983879144180731786826568453319103211309535365529557208007997947676943, 100559165165887943168055795372494494335653406621330867942899724151753006345975,
                49863498070383577932144337502242096036832689161207973578547287608488769921260, 82300136510427911821748918458945211621400681495334556494558977052164509126856]


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
    T = ek * otk_priv_arr[otkid]
    U = T.x.to_bytes(32, "big") + T.y.to_bytes(32, "big") + b'MadMadWorld'
    KS = SHA3_256.SHA3_256_Hash(U, True)
    KS = SHA3_256.SHA3_256_Hash.digest(KS)
    return KS

ks1 = findKS(otkid1, ekx1, eky1)
#ks2 = findKS(otkid2, ekx2, eky2)
#ks3 = findKS(otkid3, ekx3, eky3)
#ks4 = findKS(otkid4, ekx4, eky4)
#ks5 = findKS(otkid5, ekx5, eky5)

def findKdf(ks):
    kenc = SHA3_256.SHA3_256_Hash(ks + b'LeaveMeAlone' , True)
    kenc = SHA3_256.SHA3_256_Hash.digest(kenc)
    khmac = SHA3_256.SHA3_256_Hash(kenc + b'GlovesAndSteeringWhell' , True)
    khmac = SHA3_256.SHA3_256_Hash.digest(khmac)
    kkdf = SHA3_256.SHA3_256_Hash(khmac + b'YouWillNotHaveTheDrink' , True)
    kkdf = SHA3_256.SHA3_256_Hash.digest(kkdf)
    return kenc, khmac, kkdf

kenc1, khmac1, kkdf1 = findKdf(ks1)
kenc2, khmac2, kkdf2 = findKdf(kkdf1)
kenc3, khmac3, kkdf3 = findKdf(kkdf2)
kenc4, khmac4, kkdf4 = findKdf(kkdf3)
kenc5, khmac5, kkdf5 = findKdf(kkdf4)



"""
c1 -> khmac -> if valid -> aes decr -> m1 
"""
khmac1_int = int.from_bytes(khmac1, "big")
len1 = len(str(khmac1_int))
idx1 = -(len1-1) 
msg1 = str(msg1)
if (int(msg1[idx1:]) == khmac1_int):
    print("Authenticated")
else:
    print("Not allowded")
    
khmac2_int = int.from_bytes(khmac2, "big")
len2 = len(str(khmac2_int))
idx2 = -(len2-1) 
msg2 = str(msg2)
if (int(msg2[idx2:]) == khmac2_int):
    print("Authenticated")
else:
    print("Not allowded")
    
