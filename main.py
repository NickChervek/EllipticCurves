import secrets
from hashlib import sha256
Pcurve = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 # Number of points in the field
Acurve = 0
Bcurve = 7
INFINITY_POINT = -1
xPoint = 55066263022277343669578718895168534326250603453777594175500187360389116729240
yPoint = 32670510020758816978083085130507043184471273380659243275938904335757337482424
GPoint = (xPoint,yPoint)


privKey = secrets.randbits(256)
print("Private Key:" + hex(privKey))
def modInverse(a):
    return pow(a,-1,Pcurve)

def equalModP(x,y):
    return (x-y)%Pcurve == 0

def reduceModP(x):
    return x % Pcurve

def addition(p1,p2):

    if p1 == INFINITY_POINT:
        return p2
    if p2 == INFINITY_POINT:
        return p1

    x1 = p1[0]
    y1 = p1[1]

    x2 = p2[0]
    y2 = p2[1]

    if equalModP(x1,x2) and equalModP(y1,-y2):
        return INFINITY_POINT

    if equalModP(x1,x2) and equalModP(y1,y2):
        m = reduceModP((3*x1*x1+Acurve)*modInverse(2*y1))
    else:
        m = reduceModP((y1-y2)*modInverse(x1-x2))

    b = reduceModP(y1-m*x1)
    x3 = reduceModP(m*m-x1-x2)
    y3 = reduceModP(-m*x3-b)

    return(x3,y3)

def doublePoint(point):
    return addition(point,point)

def multiply_two(GenPoint,times):
    binary_form = str(bin(times)[2:])[::-1]
    result = INFINITY_POINT # The identity element
    addend = GenPoint

    for bit in binary_form:
        if bit == "1":
            result = addition(result,addend)
        addend = doublePoint(addend)
    return result

def sign_transaction(message):
    hash = int(sha256(message.encode()).hexdigest(),base=16)
   # print(hash)
    k = secrets.randbits(256)
    p = multiply_two(GPoint,k)
    r = p[0] % N
    s = ((hash+r*privKey)*pow(k,-1,N))%N
    return (r,s,hash)


def verify_transaction(messageHash,r,s,public_key):

    sI = pow(s,-1,N)

    p_1 = multiply_two(GPoint,(messageHash*sI)%N)
    p_2 = multiply_two(public_key,(r*sI)%N)

    sum = addition(p_1,p_2)

    return sum[0] == r












public_key = multiply_two(GPoint,privKey)
uncompressed_key = "04" + "%064x" % public_key[0] + "%064x" % public_key[1]
print("Uncompressed Public Key: " + uncompressed_key)


message = "Test Transaction"
stuff = sign_transaction(message)
verified = verify_transaction(stuff[2],stuff[0],stuff[1],public_key)
print(verified)
