# Filename: differential_spn.py
# Author: MATH 4175 Group 7 (Andrew Tran, Anthony Tran, Jack Greer, Jason Pak, Michael Peters)
# Date: 3 Dec 2022 (Date Last Modified: 3 Dec 2022)
# Description: This file contains a Python algorithm that performs a differential attack
# on the Baby SPN.

from tabulate import tabulate

# There's gotta be a better way to do this data structure ngl
# Doing a dict for clarity, consider a regular list
pi_s = {0x0: 0xE, 0x1: 0x4, 0x2: 0xD, 0x3: 0x1,\
        0x4: 0x2, 0x5: 0xF, 0x6: 0xB, 0x7: 0x8,\
        0x8: 0x3, 0x9: 0xA, 0xA: 0x6, 0xB: 0xC,\
        0xC: 0x5, 0xD: 0x9, 0xE: 0x0, 0xF: 0x7}

pi_s_inv = {0x0: 0xE, 0x1: 0x3, 0x2: 0x4, 0x3: 0x8,\
            0x4: 0x1, 0x5: 0xC, 0x6: 0xA, 0x7: 0xF,\
            0x8: 0x7, 0x9: 0xD, 0xA: 0x9, 0xB: 0x6,\
            0xC: 0xB, 0xD: 0x2, 0xE: 0x0, 0xF: 0x5}

# 1. Make a difference distribution table, analogous to Difference Distribution Table given in
# the slide 7 of section 4.4 in class notes, for the given S-box.

# Define N_D(x', y') = set of (x, x*) in Del(x') such that y ^ y* = y'
# e.g., the number of pairs with input difference equal to x' and output difference equal to y'
# (for a given S-box)
difference_distribution_table = [[0 for row in range(16)] for col in range(16)]
# We'll consider each x'
for x_prime in range(16):
    for x in range(16):
        x_star = x ^ x_prime
        y = pi_s[x]
        y_star = pi_s[x_star]
        y_prime = y ^ y_star
        difference_distribution_table[x_prime][y_prime] += 1

print(tabulate(difference_distribution_table,\
                headers=[x for x in range(16)],\
                    tablefmt="fancy_grid", showindex="always"))

# 2. Consider plaintexts such that x ^ x* = x' = 000 001. Using your difference distribution table
# from the previous problem, find three distribution trails Tr1, Tr2, Tr3, all starting from P6,
# whereeas Tr1 ending at the last bit of S32, that is at H6, the second trail Tr2 ending at the
# last 2 bits of S32, that is at H5 and H6, and the third trail Tr3 ending at all three bits of S32,
# that is, at H4, H5 and H6.
# Sketch all these three trials clearly and upload them as pdf files.

# Given a fixed x' = 000 001

