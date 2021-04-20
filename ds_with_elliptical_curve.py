from Crypto.Util.number import inverse, GCD
from random import randint
from asn1 import Encoder, Decoder, Numbers
from pygost import gost34112012256
from sage.all import *


def write_to_file(E, P, q, r, s, Q, p, A, B):
    Qx, Qy = lift(Q[0]), lift(Q[1])
    file = Encoder()
    file.start()
    file.enter(Numbers.Sequence)
    file.enter(Numbers.Set)
    file.enter(Numbers.Sequence)
    file.write(b'\x80\x06\x07\x00', Numbers.OctetString)
    file.write(b'gostSignKey', Numbers.UTF8String)
    file.enter(Numbers.Sequence)
    file.write(Qx, Numbers.Integer)
    file.write(Qy, Numbers.Integer)
    file.leave()
    file.enter(Numbers.Sequence)
    file.enter(Numbers.Sequence)
    file.write(p, Numbers.Integer)
    file.leave()
    file.enter(Numbers.Sequence)
    file.write(A, Numbers.Integer)
    file.write(B, Numbers.Integer)
    file.leave()
    file.enter(Numbers.Sequence)
    file.write(x, Numbers.Integer)
    file.write(y, Numbers.Integer)
    file.leave()
    file.write(q, Numbers.Integer)
    file.leave()
    file.enter(Numbers.Sequence)
    file.write(r, Numbers.Integer)
    file.write(s, Numbers.Integer)
    file.leave()
    file.leave()
    file.enter(Numbers.Sequence)
    file.leave()
    file.leave()
    file.leave()
    with open(signfile, "wb") as sign_file:
        sign_file.write(file.output())


def read_from_file(filename):
    data = b''
    with open(filename, "rb") as file:
        for line in file:
            data += line
    file = Decoder()
    file.start(data)
    file.enter()
    file.enter()
    file.enter()
    file.read()
    file.read()
    file.enter()
    Qx = file.read()[1]
    Qy = file.read()[1]
    file.leave()
    file.enter()
    file.enter()
    p = file.read()[1]
    file.leave()
    file.enter()
    A = file.read()[1]
    B = file.read()[1]
    file.leave()
    file.enter()
    Px = file.read()[1]
    Py = file.read()[1]
    file.leave()
    q = file.read()[1]
    file.leave()
    file.enter()
    r = file.read()[1]
    s = file.read()[1]
    file.leave()
    file.leave()
    file.enter()
    file.leave()
    file.leave()
    file.leave()
    return p, A, B, Px, Py, Qx, Qy, q, r, s


def set_sign(filename, p, A, B, Px, Py, r, d):
    data = b''
    with open(filename, "rb") as file:
        for line in file:
            data += line
    E = EllipticCurve(GF(p), [A, B])
    P = E([Px, Py])
    Q = d * P
    h = int(gost34112012256.new(data).hexdigest(), base=16)
    e = h % r
    if e == 0:
        e = 1
    while 1:
        k = randint(1, r)
        C = k * P
        Cx = lift(C[0])
        q = Cx % r
        if q == 0:
            continue
        s = (q * d + k * e) % r
        if s == 0:
            continue
        write_to_file(E, P, r, q, s, Q, p, A, B)
        return


def check_sign(filename):
    p, A, B, Px, Py, Qx, Qy, r, q, s = read_from_file(filename)
    dataToCheck = b''
    with open(originalfile, "rb") as plainText:
        for line in plainText:
            dataToCheck += line
    h = int(gost34112012256.new(dataToCheck).hexdigest(), base=16)
    if q < 0 or q > r or s < 0 or s > r:
        print("Подпись неверна!")
        return
    e = h % r
    if e == 0:
        e = 1
    v = inverse(e, r)
    z1 = (s * v) % r
    z2 = ((-q) * v) % r
    E = EllipticCurve(GF(p), [A, B])
    P = E([Px, Py])
    Q = E([Qx, Qy])
    C = z1 * P + z2 * Q
    Cx = lift(C[0])
    R = Cx % r
    if q == R:
        print("OK")
    else:
        print("Подпись неверна!")


p = 57896044628890729911196718984933305846544100325488685311213142875135838763683
r = 28948022314445364955598359492466652923270809441897180344196391207096541510137
A = -1
B = 51597193811365919768190236681066502033803499635094541650610225403695076439048
x = 21371456824977467041033238171905463424508399897529674896678501178686263573482
y = 52962982709744467108853563358242537068648343861092009194618855518747612108192
d = 936156208282304485759452259311675827964271926257804010246306978426750464093

originalfile = "orig_file.txt"
signfile = "sign_file.bin"
while True:
    n = int(input('1. Подписать файл\n2. Проверить подпись файла\n3. Сгенерировать ключи\n0. Выход\n'))
    if n == 1:
        set_sign(originalfile, p, A, B, x, y, r, d)
    elif n == 2:
        check_sign(signfile)
    elif n == 3:
        while True:
            d = randint(1, r - 1)
            if GCD(d, r) == 1:
                print("Ключ сгенерирован: d = ", d)
            break
    elif n == 0:
        break
    else:
        print('неизвестная команда!')
