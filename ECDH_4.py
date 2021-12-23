from ecpy.curves     import Curve,Point
from ecpy.keys       import ECPublicKey, ECPrivateKey
from ecpy.ecdsa      import ECDSA
from Crypto import Random
from Crypto.Hash import SHA3_256
import random

# the curve

E = Curve.get_curve('secp256k1')
n = E.order
P = E.generator

sA = 111304550820752806697213486832847711075468340563138108181594099762322408827888
sB = 16648239150401009833470733558279798177495732625568307415002288177182875736378

#Missing Line
QB = sB*P
KAB = sA * QB
#Missing Line

K = SHA3_256.new(KAB.x.to_bytes((KAB.x.bit_length() + 7) // 8, byteorder='big')+b'ECDH Key Exchange')

print("K: ", K.hexdigest())