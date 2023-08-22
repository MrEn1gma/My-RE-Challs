from z3 import *

s = Solver()

this = [BitVec("x%d"%i, 8) for i in range(49)]

cmp = [114, 135, 1381, 57, 238, 2263, 130, 165, 2111, 111, 
    191, 2398, 50, 184, 2736, 116, 125, 1291, 66, 249, 2973, 
    125, 229, 2924, 123, 182, 1487, 134, 194, 1423, 1467, 6350, 
    43390, 27392, 55831, 561844, 1241188, 149593, 150057, 999, 
    676039, 35823, 877, 307, 719, 417, 56, 51, 102, 53, 50, 49, 52, 52]

s.add(this[1] + this[0] % 19 == cmp[0])
s.add(this[2] + this[0] + 19 == cmp[1])
s.add( this[3] + 19 * this[0] == cmp[2] )
s.add( this[5] + this[4] % 20 == cmp[3] )
s.add( this[4] + this[6] + 20 == cmp[4] )
s.add( this[7] + 20 * this[4] == cmp[5] )
s.add( this[9] + this[8] % 21 == cmp[6] )
s.add( this[8] + this[10] + 21 == cmp[7] )
s.add( this[11] + 21 * this[8] == cmp[8] )
s.add( this[13] + this[12] % 22 == cmp[9] )
s.add( this[12] + this[14] + 22 == cmp[10] )
s.add( this[15] + 22 * this[12] == cmp[11] )
s.add( this[17] + this[16] % 23 == cmp[12] )
s.add( this[18] + this[16] + 23 == cmp[13] )
s.add( this[19] + 23 * this[16] == cmp[14] )
s.add( this[21] + this[20] % 24 == cmp[15] )
s.add( this[20] + this[22] + 24 == cmp[16] )
s.add( this[23] + 24 * this[20] == cmp[17] )
s.add( this[25] + this[24] % 25 == cmp[18] )
s.add( this[24] + this[26] + 25 == cmp[19] )
s.add( this[27] + 25 * this[24] == cmp[20] )
s.add( this[29] + this[28] % 26 == cmp[21] )
s.add( this[28] + this[30] + 26 == cmp[22] )
s.add( this[31] + 26 * this[28] == cmp[23] )
s.add( this[33] + this[32] % 27 == cmp[24] )
s.add( this[34] + this[32] + 27 == cmp[25] )
s.add( this[35] + 27 * this[32] == cmp[26] )
s.add( this[37] + this[36] % 28 == cmp[27] )
s.add( this[36] + this[38] + 28 == cmp[28] )
s.add( this[39] + 28 * this[36] == cmp[29] )
s.add( this[40] + 28 * this[36] == cmp[30] )
s.add( this[43]
 + this[47]
 + this[42]
 + this[46]
 + this[41]
 + this[45]
 + this[44]
 + this[48]
 + (this[33] ^ this[34]) * (this[38] + this[39] + this[36] + this[37] + this[40] + this[35]) == cmp[31] )
s.add( this[43]
 + this[47]
 + this[42]
 + this[46]
 + this[41]
 + this[45]
 + this[44]
 + this[48]
 + (this[33] ^ this[35] ^ this[34]) * (this[38] + this[39] + this[36] + this[37] + this[40]) == cmp[32] )
s.add( (this[33] + this[34] + this[35]) * (this[39] ^ this[38] ^ this[36] ^ this[40] ^ this[37])
 - this[48]
 - this[44]
 - this[45]
 - this[41]
 - this[46]
 - this[42]
 - this[47]
 - this[43] == cmp[33] )
s.add( this[43]
 + this[47]
 + this[42]
 + this[46]
 + this[41]
 + this[45]
 + this[44]
 + this[48]
 + (this[26] ^ this[25]) * (this[29] + this[32] + this[27] + this[30] + this[31] + this[28]) == cmp[34] )
s.add( this[29]
 + this[28]
 + (this[27] ^ this[26] ^ this[25])
 + this[32] * this[30] * this[31]
 - this[48]
 - this[44]
 - this[45]
 - this[41]
 - this[46]
 - this[42]
 - this[47]
 - this[43] == cmp[35] )
s.add( this[26]
 + this[27]
 + this[25]
 + (this[32] ^ this[31] ^ (this[29] * this[30] * this[28]))
 - this[48]
 - this[44]
 - this[45]
 - this[41]
 - this[46]
 - this[42]
 - this[47]
 - this[43] == cmp[36] )
s.add( this[17] * this[18] * this[19]
 + (this[23] ^ this[22] ^ this[20] ^ this[24] ^ this[21])
 - this[48]
 - this[44]
 - this[45]
 - this[41]
 - this[46]
 - this[42]
 - this[47]
 - this[43] == cmp[37] )
s.add( this[43]
 + this[47]
 + this[20]
 + this[42]
 + this[46]
 + this[41]
 + this[45]
 + this[44]
 + this[48]
 + this[17] * this[18] * this[19]
 - this[24]
 - this[21]
 - this[23]
 - this[22] == cmp[38] )
s.add( this[22]
 + this[23]
 + this[43]
 + this[47]
 + this[20]
 + this[42]
 + this[46]
 + this[21]
 + this[24]
 + this[41]
 + this[45]
 + this[44]
 + this[48]
 + (this[17] ^ this[19] ^ this[18]) == cmp[39] )
s.add( this[10] * this[11] * this[9]
 + (this[16] ^ this[13] ^ this[15] ^ this[14] ^ this[12])
 - this[48]
 - this[44]
 - this[45]
 - this[41]
 - this[46]
 - this[42]
 - this[47]
 - this[43] == cmp[40] )
s.add( (this[10] + this[9]) * (this[16] ^ this[13] ^ this[15] ^ this[14] ^ (this[11] + this[12]))
 - this[48]
 - this[44]
 - this[45]
 - this[41]
 - this[46]
 - this[42]
 - this[47]
 - this[43] == cmp[41] )
s.add( this[13]
 + this[16]
 + this[43]
 + this[47]
 + this[10]
 + this[42]
 + this[46]
 + this[15]
 + this[41]
 + this[45]
 + this[9]
 + this[12]
 + this[44]
 + this[48]
 - this[14]
 - this[11] == cmp[42] )
s.add( this[43]
 + this[47]
 + this[42]
 + this[46]
 + this[2]
 + this[41]
 + this[45]
 + this[44]
 + this[48]
 - (this[7] ^ this[6] ^ this[4] ^ this[8] ^ this[5] ^ this[3])
 - this[1] == cmp[43] )
s.add( this[1]
 + this[6]
 + this[7]
 + this[4]
 + this[5]
 + this[8]
 + this[3]
 + (this[47] ^ this[43] ^ this[46] ^ this[42] ^ this[45] ^ this[41] ^ this[48] ^ this[44])
 - this[2] == cmp[44] )
s.add( this[1]
 + this[43]
 + this[47]
 + this[42]
 + this[46]
 + this[41]
 + this[45]
 + this[44]
 + this[48]
 - (this[7] ^ this[6] ^ this[4] ^ this[8] ^ this[5] ^ this[3])
 - this[2] == cmp[45] )
s.add( this[41] == cmp[46] )
s.add( this[42] == cmp[47] )
s.add( this[43] == cmp[48] )
s.add( this[44] == cmp[49] )
s.add( this[45] == cmp[50] )
s.add( this[46] == cmp[51] )
s.add( this[47] == cmp[52] )
s.add( this[48] == cmp[53] )

if(s.check() == sat):
    m = s.model()
    flag = ""
    for i in this:
        flag += chr(m[i].as_long())
    print(flag)
else:
    print("No Solution.")