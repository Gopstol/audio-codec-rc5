class Encrypt:
    def __init__(self, w, R, key, strip_extra_nulls=False):
        self.w = w  # размер блока (16, 32, 64)
        self.R = R  # число этапов (0 - 255)
        self.key = key  # значение ключа
        self.strip_extra_nulls = strip_extra_nulls

        self.T = 2 * (R + 1)
        self.w4 = w // 4
        self.w8 = w // 8
        self.mod = 2 ** self.w
        self.mask = self.mod - 1
        self.b = len(key)  # длина ключа

        self.counter_int = 0
        self.counter = self.counter_int.to_bytes(w//2, byteorder="little")
        self.nonce = (5).to_bytes(w//2, byteorder="little")
        self.iv = self.counter + self.nonce

        self.gamma_block = b''

        self.__keyAlign()
        self.__keyExtend()
        self.shuffle()

    def lshift(self, val, n):
        n %= self.w
        return ((val << n) & self.mask) | ((val & self.mask) >> (self.w - n))

    def rshift(self, val, n):
        n %= self.w
        return ((val & self.mask) >> n) | (val << (self.w - n) & self.mask)

    def const(self):
        if self.w == 16:
            return 0xB7E1, 0x9E37  # return P (e), Q (pi)
        elif self.w == 32:
            return 0xB7E15163, 0x9E3779B9
        elif self.w == 64:
            return 0xB7E151628AED2A6B, 0x9E3779B97F4A7C15

    def __keyAlign(self):
        if self.b == 0:
            self.c = 1
        elif self.b % self.w8:
            self.key += b'\x00' * (self.w8 - self.b % self.w8)  # заполняет ключ \x00 битами если нужно
            self.b = len(self.key)
            self.c = self.b // self.w8
        else:
            self.c = self.b // self.w8
        L = [0] * self.c
        for i in range(self.b - 1, -1, -1):
            L[i // self.w8] = (L[i // self.w8] << 8) + self.key[i]
        self.L = L

    def __keyExtend(self):
        P, Q = self.const()
        self.S = [(P + i * Q) % self.mod for i in range(self.T)]

    def shuffle(self):
        i, j, A, B = 0, 0, 0, 0
        for k in range(3 * max(self.c, self.T)):
            A = self.S[i] = self.lshift((self.S[i] + A + B), 3)
            B = self.L[j] = self.lshift((self.L[j] + A + B), A + B)
            i = (i + 1) % self.T
            j = (j + 1) % self.c

    def encryptBlock(self, A, B):
        A = int.from_bytes(A, byteorder="little")
        B = int.from_bytes(B, byteorder="little")
        A = (A + self.S[0]) % self.mod
        B = (B + self.S[1]) % self.mod
        for i in range(1, self.R + 1):
            A = (self.lshift((A ^ B), B) + self.S[2 * i]) % self.mod
            B = (self.lshift((A ^ B), A) + self.S[2 * i + 1]) % self.mod
        return (A.to_bytes(self.w8, byteorder='little')
                + B.to_bytes(self.w8, byteorder='little'))

    def decryptBlock(self, A, B):
        A = int.from_bytes(A, byteorder='little')
        B = int.from_bytes(B, byteorder='little')
        for i in range(self.R, 0, -1):
            B = self.rshift(B - self.S[2 * i + 1], A) ^ A
            A = self.rshift(A - self.S[2 * i], B) ^ B
        B = (B - self.S[1]) % self.mod
        A = (A - self.S[0]) % self.mod
        return (A.to_bytes(self.w8, byteorder='little')
                + B.to_bytes(self.w8, byteorder='little'))

    def encryptFile(self, inpFileName, outFileName):
        with open(inpFileName, 'rb') as inp, open(outFileName, 'wb') as out:
            self.counter_int = 0
            self.counter = self.counter_int.to_bytes(self.w // 2, byteorder="little")
            self.nonce = (5).to_bytes(self.w // 2, byteorder="little")
            self.iv = self.counter + self.nonce
            run = True
            while run:
                text = inp.read(self.w4)
                if not text:
                    break
                if len(text) != self.w4:
                    run = False
                self.gamma_block = self.encryptBlock(self.key, self.iv)
                text = int.from_bytes(text, byteorder="little") ^ int.from_bytes(self.gamma_block, byteorder="little")
                self.counter_int += 1
                self.counter = self.counter_int.to_bytes(self.w // 2, byteorder="little")
                self.iv = self.counter + self.nonce
                # print(text, text.to_bytes(self.w4, byteorder="little"))
                out.write(text.to_bytes(self.w4, byteorder="little"))
