import math

# sizes of consts where set_size=2^12, 2^16, 2^20, resp.
consts = {'N_BF': [851_085, 12_660_342, 197_052_485],
          'N_OT': [901_106, 12_948_963, 198_793_103],
          'N_CC': [42_882, 262_924, 1_644_397]}

sigma = 128
lam = 40
sizes = ['2^12', '2^16', '2^20']

# P_i
results_pi = []
for i in range(len(sizes)):
    Not, Ncc, Nbf = consts['N_OT'][i], consts['N_CC'][i], consts['N_BF'][i]
    result = 2 * Not * sigma + Ncc * math.log2(Not) + Ncc * math.log2(
        Not) + sigma + Nbf * math.log2(Not) + Nbf * sigma
    result = math.floor(result / 8) / (10 ** 6)
    results_pi.append(result)

# P_0
parties_numbers = [4, 10, 15]
results_p0 = []
for i in range(len(sizes)):
    for number_of_parties in parties_numbers:
        Not, Ncc, Nbf = consts['N_OT'][i], consts['N_CC'][i], consts['N_BF'][
            i]
        result = 2 * number_of_parties * Not * sigma + number_of_parties * \
                 Ncc * math.log2(
            Not) + number_of_parties * Ncc * math.log2(
            Not) + sigma + number_of_parties * Nbf * math.log2(Not)
        result = math.floor(result / 8) / (10 ** 6)
        results_p0.append((number_of_parties, result))

print('Results for client P_i:')
for index_size, size in enumerate(sizes):
    print(f'Set size- {size}, Total result (in MB)- {results_pi[index_size]}')

print('Total result:')
for index_size, size in enumerate(sizes):
    for index_num_parties, number_of_parties in enumerate(parties_numbers):
        print(
            f'Set size- {size}, Number of parties- {number_of_parties}, '
            f'Total result (in MB)- '
            f'{(number_of_parties - 1) * results_pi[index_size] + results_p0[index_size + index_num_parties][1]}')
