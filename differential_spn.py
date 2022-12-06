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

# List of plaintext and ciphertext pairs for problem 4
# Note: the only relevant right 4-tuples are derived from pairs 2, 4, and 6,
# (indices 1, 3, and 5) because those are the only pairs where the first three
# bits of y match with the first three bits of y* (in other words, the first
# three bits of y' = 0b000). We need these bits of y' to be 0 because we care
# about paths that end at H4, H5, and/or H6, but not H1, H2, and H3.
# x_list = ["100111", "000111", "001100", "011000", "001000", "011010"]
# x_star_list = ["100110", "000110", "001101", "011001", "001001", "011011"]
# y_list = ["100100", "110010", "111001", "011101", "001101", "101001"]
# y_star_list = ["1111110","110110","100000","011111","000011","101000"]

x_list =      [0b100111, 0b000111, 0b001100, 0b011000, 0b001000, 0b011010]
x_star_list = [0b100110, 0b000110, 0b001101, 0b011001, 0b001001, 0b011011]
y_list =      [0b100100, 0b110010, 0b111001, 0b011101, 0b001101, 0b101001]
y_star_list = [0b111110, 0b110110, 0b100000, 0b011111, 0b000011, 0b101000]

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

print("Difference Distribution Table:")
print(tabulate(difference_distribution_table,\
                headers=[x for x in range(8)],\
                    tablefmt="fancy_grid", showindex="always"))


# 2. Consider plaintexts such that x ^ x* = x' = 000 001. Using your difference distribution table
# from the previous problem, find three distribution trails Tr1, Tr2, Tr3, all starting from P6,
# whereas Tr1 ending at the last bit of S32, that is at H6, the second trail Tr2 ending at the
# last 2 bits of S32, that is at H5 and H6, and the third trail Tr3 ending at all three bits of S32,
# that is, at H4, H5 and H6.
# Sketch all these three trials clearly and upload them as pdf files.


u_prime = [0 for i in range(6)]
count1 = 0
count2 = 0
count3 = 0
weighted_average_count = [0 for i in range(8)]

# Prepare
diff_spn_q5_results = [[0 for col in range(9)] for row in range(5)]


for key_candidate in range(8):
    # For each of our four right tuples, take
    # for i in range
    for i in range(6):
        # Select three suitable right 4-tuples from our plaintext-ciphertext pairs
        # A right 4-tuple has:
        # x ^ x* = x' = 0b000001 (which is true for all of our given plaintext)
        # y ^ y* = y' = 0b000--- (in other words, the first three bits of y and y*
        # match each other)
        if((x_list[i] ^ x_star_list[i] == 0b000001) and \
            (y_list[i] & 0b111000) == (y_star_list[i] & 0b111000)):
            v = key_candidate ^ (y_list[i] & 0b111)
            u = pi_s_inv[v]
            v_star = key_candidate ^ (y_star_list[i] & 0b111)
            u_star = pi_s_inv[v_star]
            u_prime[i] = u ^ u_star
            if(u_prime[i] == 0b001):
                count1 += 1
                diff_spn_q5_results[1][key_candidate + 1] += 1
            elif(u_prime[i] == 0b011):
                count2 += 1
                diff_spn_q5_results[2][key_candidate + 1] += 1
            elif(u_prime[i] == 0b111):
                count3 += 1
                diff_spn_q5_results[3][key_candidate + 1] += 1
    weighted_average_count[key_candidate] = (0.25 * count1) + \
                                            (0.125 * count2) + \
                                            (0.125 * count3)
    diff_spn_q5_results[4][key_candidate + 1] = (0.25 * count1) + \
                                            (0.125 * count2) + \
                                            (0.125 * count3)
                                            
    # Reset the counts for the next key guess
    count1 = 0
    count2 = 0
    count3 = 0

# Print out the results for Question 5 in a final tabular format
print("Question 5 Results:")
diff_spn_q5_results[0] = ["Key Guess", 0, 1, 2, 3, 4, 5, 6, 7]
diff_spn_q5_results[1][0] = "Trail 1 Count"
diff_spn_q5_results[2][0] = "Trail 2 Count"
diff_spn_q5_results[3][0] = "Trail 3 Count"
diff_spn_q5_results[4][0] = "Weighted Avg (C)"

# From this, we can tell that the last three bits of the key are 0b011
# Beautiful mang
print(tabulate(diff_spn_q5_results, tablefmt = "rounded_grid"))
print("The last three bits of the key must be 0b011!")