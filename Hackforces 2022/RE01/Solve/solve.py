from Cryptodome.Cipher import AES
import numpy as np

AESiv = np.array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], "<u1").tobytes()
AESkey = np.array([172, 195, 87, 162, 90, 34, 56, 190, 116, 30, 56, 39, 178, 152, 180, 162], "<u1").tobytes()
keyxor = np.array([55, 149, 172, 107, 34, 65, 179, 64, 172, 84, 90, 168, 155, 86, 44, 61, 116, 166, 109, 136, 90, 56, 86, 51, 106, 88, 95, 182, 9, 135, 99, 197, 48, 80, 3, 122, 186, 168, 176, 164, 20, 136, 197, 3, 103, 42, 154, 140, 100, 164, 163, 4, 78, 179, 45, 129, 136, 112, 112, 95, 197, 53, 144, 38], "<u1").tobytes()
cipher = np.array([20, 213, 68, 180, 24, 42, 157, 37, 64, 77, 7, 207, 54, 12, 45, 89, 15, 27, 150, 96, 45, 27, 175, 38, 188, 247, 66, 99, 123, 106, 66, 62, 60, 180, 96, 253, 2, 57, 92, 10, 132, 192, 165, 139, 20, 110, 191, 169, 158, 195, 222, 93, 90, 45, 52, 178, 49, 240, 221, 119, 42, 167, 89, 218], "<u1").tobytes()

c = []
for i in range(len(cipher)):
    c.append(cipher[i] ^ keyxor[i % len(keyxor)])
    
AESCipher = np.array(c, "<u1").tobytes()
aes = AES.new(AESkey, AES.MODE_CBC, AESiv)
out = aes.decrypt(AESCipher)
print(b"FPTUHacking{" + out + b"}")