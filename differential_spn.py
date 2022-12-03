# Filename: differential_spn.py
# Author: MATH 4175 Group 7 (Andrew Tran, Anthony Tran, Jack Greer, Jason Pak, Michael Peters)
# Date: 3 Dec 2022 (Date Last Modified: 3 Dec 2022)
# Description: This file contains a Python algorithm that performs a differential attack
# on the Baby SPN.

from tabulate import tabulate

# This dict represents the S-box
pi_s = {0b000: 0b110, 0b001: 0b101, 0b010: 0b001, 0b011: 0b000,\
        0b100: 0b011, 0b101: 0b010, 0b110: 0b111, 0b111: 0b100}
# This dict represents the inverse of the S-box
pi_s_inv = {0b000: 0b011, 0b001: 0b010, 0b010: 0b101, 0b011: 0b100,\
            0b100: 0b111, 0b101: 0b001, 0b110: 0b000, 0b111: 0b110}

# 1. Make a difference distribution table, analogous to Difference Distribution Table given in
# the slide 7 of section 4.4 in class notes, for the given S-box.

# Define N_D(x', y') = set of (x, x*) in Del(x') such that y ^ y* = y'
# e.g., the number of pairs with input difference equal to x' and output difference equal to y'
# (for a given S-box)

difference_distribution_table = [[0 for row in range(8)] for col in range(8)]
# We'll consider each x'
for x_prime in range(8):
    for x in range(8):
        x_star = x ^ x_prime

        y = pi_s[x]
        y_star = pi_s[x_star]
        y_prime = y ^ y_star
        
        difference_distribution_table[x_prime][y_prime] += 1

print(tabulate(difference_distribution_table,\
                headers=[x for x in range(8)],\
                    tablefmt="fancy_grid", showindex="always"))


# 2. Consider plaintexts such that x ^ x* = x' = 000 001. Using your difference distribution table
# from the previous problem, find three distribution trails Tr1, Tr2, Tr3, all starting from P6,
# whereas Tr1 ending at the last bit of S32, that is at H6, the second trail Tr2 ending at the
# last 2 bits of S32, that is at H5 and H6, and the third trail Tr3 ending at all three bits of S32,
# that is, at H4, H5 and H6.
# Sketch all these three trials clearly and upload them as pdf files.


# Given a fixed x' = 000 001

# We're considering the cases where
# H = 000001 with probability 1/4
# H = 000011 with probability 1/8
# H = 000111 with probability 1/8
# Out of our candidates, we have three eligible right 4 tuples:
# x        | 
# 