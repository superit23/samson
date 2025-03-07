from math import sqrt, pi, log2, e
from samson.math.general import random_int, lcm, ceil, log1p, log, _integer_ring, _real_field, _symbols
from tqdm import tqdm
import functools
import operator as _operator
import json
import difflib as _difflib
import os

RC4_BIAS_MAP = [163, 0, 131, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 240, 17, 18, 0, 20, 21, 22, 0, 24, 25, 26, 0, 28, 29, 0, 31, 224, 33, 0, 0, 0, 0, 38, 0, 0, 0, 0, 0, 0, 0, 0, 0, 208, 0, 0, 0]


def longest_subsequence(seq_a: list, seq_b: list) -> list:
    """
    Finds the longest matching subsequence between two enumerable objects.

    Parameters:
        seq_a (list): First enumerable.
        seq_b (list): Second enumerable.

    Returns:
        list: Longest subsequence.
    """
    seqMatch = _difflib.SequenceMatcher(None, seq_a, seq_b)
    match = seqMatch.find_longest_match(0, len(seq_a), 0, len(seq_b))
    return seq_a[match.a: match.a + match.size]



def hamming_distance(bytes1: bytes, bytes2: bytes) -> int:
    """
    Calculates the Hamming distance between two byte-strings.

    Parameters:
        bytes1 (bytes): First byte-string.
        bytes2 (bytes): Second byte-string.

    Returns:
        int: Hamming distance.
    """
    from samson.encoding.general import bytes_to_bitstring
    assert len(bytes1) == len(bytes2)
    bitstring1 = bytes_to_bitstring(bytes1)
    bitstring2 = bytes_to_bitstring(bytes2)

    distance = 0
    for bit1, bit2 in zip(bitstring1, bitstring2):
        if bit1 != bit2: distance += 1

    return distance


def str_hamming_distance(s1: str, s2: str) -> int:
    """
    Computes the Hamming distance between two equal-length strings

    Parameters:
        s1 (str): First string.
        s2 (str): Second string.

    Returns:
        int: Hamming Distance.
    """
    if len(s1) != len(s2):
        raise ValueError("Strings MUST be equal length")

    return sum(letter1 != letter2 for letter1, letter2 in zip(s1, s2))


def levenshtein_distance(seq_a: list, seq_b: list) -> int:
    """
    Calculates the Levenshtein Distance between two enumerable objects.

    Parameters:
        seq_a (list): First enumerable.
        seq_b (list): Second enumerable.

    Returns:
        int: Levenshtein Distance.
    """
    if len(seq_a) < len(seq_b):
        return levenshtein_distance(seq_b, seq_a)

    if len(seq_b) == 0:
        return len(seq_a)

    previous_row = range(len(seq_b) + 1)

    for i, c1 in enumerate(seq_a):
        current_row = [i + 1]

        for j, c2 in enumerate(seq_b):
            insertions = previous_row[j + 1] + 1 # j+1 instead of j since previous_row and current_row are one character longer
            deletions = current_row[j] + 1       # than seq_b
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))

        previous_row = current_row

    return previous_row[-1]


def hamming_weight(n: int):
    return bin(n).count('1')



def parity(n: int):
    for i in reversed(range(n.bit_length().bit_length())):
        n ^= n >> (2**i)
    return n & 1



def count_items(items: list) -> dict:
    """
    Counts the items in an enumerable object.

    Parameters:
        items (list): Enumerable of items.

    Returns:
        dict: Dictionary of {item, count}.
    """
    item_ctr = {}

    for curr_item in items:
        if curr_item not in item_ctr:
            item_ctr[curr_item] = 0

        item_ctr[curr_item] += 1

    return item_ctr



def chisquare(observed_dict: dict, expected_freq_dict: dict, length_override: int=0) -> float:
    """
    Calculates the Chi-squared score of an `observed_dict` against the `expected_freq_dict`.

    Parameters:
        observed_dict      (dict): Dictionary of observed items and their counts.
        expected_freq_dict (dict): Dictionary of expected items and their counts.

    Returns:
        float: Chi-squared score.
    """
    observed_items = observed_dict.items()
    observed_len = length_override or sum([v for _k, v in observed_items])
    total = 0
    for key, freq_value in expected_freq_dict.items():
        if key in observed_dict:
            obs_val = observed_dict[key]
        else:
            obs_val = 0

        expected_number = observed_len * freq_value
        total += (expected_number - obs_val) ** 2 / expected_number


    for key, obs_value in observed_dict.items():
        if key not in expected_freq_dict:
            obs_val = obs_value
        else:
            obs_val = 0

        total += obs_val ** 2

    return total



def find_repeating_key_size(ciphertext: bytes, key_range: list) -> list:
    """
    Attempts to find the key size of a repeating XOR cipher.

    Parameters:
        ciphertext (bytes): Ciphertext to analyze.
        key_range   (list): List of key sizes to test.

    Returns:
        list: Sorted list of most likely key sizes.
    """
    key_distances = {}

    for size in key_range:
        size_sum = 0
        num_blocks = (len(ciphertext) // size)

        for block in range(num_blocks - 1):
            size_sum += hamming_distance(ciphertext[block * size: (block + 1) * size], ciphertext[(block + 1) * size: (block + 2) * size]) / size

        key_distances[size] = size_sum / num_blocks

    return sorted(key_distances.items(), key=_operator.itemgetter(1))



def birthday_attack_analysis(bits: int, probability: float, prec: int=None) -> float:
    """
    Determines the average number of attempts before a collision occurs against `bits` with `probability`.

    Parameters:
        bits          (int): Number of bits in the keyspace.
        probability (float): Target probability.
        prec          (int): Desired precision. Will be calculated automatically if not specified.

    Returns:
        float: Average number of attempts before collision.

    References:
        https://en.wikipedia.org/wiki/Birthday_attack#Mathematics
    """
    RealField = _real_field.RealField
    RR = RealField(prec or int(bits // 2 + 7))
    return ((2* RR(2)**bits) * RR(-RR(-probability).log1p())).sqrt()


def coupon_collector_analysis(n: int, prec: int=None) -> (float, float):
    """
    Determines the average number of attempts to collect all `n` items from a pseudorandom function.

    Parameters:
        n    (int): Number of items.
        prec (int): Desired precision. Will be calculated automatically if not specified.

    Returns:
        (float, float): Tuple formatted as (average_number, standard_deviation).

    References:
        https://brilliant.org/wiki/coupon-collector-problem/
    """
    RealField = _real_field.RealField
    RR = RealField(prec or (n.bit_length() + n.bit_length().bit_length() + 3))

    average_number     = n * (RR(n).ln() + RR.euler) + 0.5
    standard_deviation = ((RR.pi**2 * n**2) / 6 - average_number - 1).sqrt()
    return (average_number, standard_deviation)


def approximate_ncr(n: int, r: int, prec: int=100) -> int:
    """
    `n` choose `r`.

    Parameters:
        n    (int): Number to choose from.
        r    (int): Number of those to choose.
        prec (int): Desired precision.

    Returns:
        int: Number of elements in nCr.
    """
    RealField = _real_field.RealField
    RR = RealField(prec)

    return RR(RR.ctx.factorial(n)/(RR.ctx.factorial(r)*RR.ctx.factorial(n-r)))


def ncr(n: int, r: int) -> int:
    """
    `n` choose `r`.

    Parameters:
        n (int): Number to choose from.
        r (int): Number of those to choose.

    Returns:
        int: Number of elements in nCr.
    """
    r = min(r, n-r)
    numer = 1

    for i in range(n, n-r, -1):
        numer *= i

    denom = 1
    for i in range(1, r+1):
        denom *= i

    return numer // denom


def num_expected_collisions(bits: int, num_inputs: int) -> float:
    """
    Calculates the number of expected collisions with `num_inputs` over `bits` keyspace.

    Parameters:
        bits       (int): Number of bits in the keyspace.
        num_inputs (int): Hypothetical number of inputs.

    Returns:
        float: Number of expected collisions.
    """
    return 2**(-bits)*ncr(num_inputs, 2)



def probability_of_x_occurences(n: int, x: int, p: float) -> float:
    """
    Calculates the probability of an event with probability `p` occuring exactly `x` times in `n` trials.

    Parameters:
        n   (int): Number of trials.
        x   (int): Number of times for event to occur.
        p (float): Probability event will occur.

    Returns:
        float: Probability of total event.

    References:
        https://math.stackexchange.com/questions/2348827/probability-of-an-event-occurring-x-number-of-times-in-a-sequence-of-events
    """
    return ncr(n, x) * p**x * (1-p)**(n-x)



def probability_of_at_least_x_occurences(n: int, x: int, p: float) -> float:
    """
    Calculates the probability of an event with probability `p` occuring at least `x` times in `n` trials.

    Parameters:
        n   (int): Number of trials.
        x   (int): Number of times for event to occur.
        p (float): Probability event will occur.

    Returns:
        float: Probability of total event.
    """
    return sum(probability_of_x_occurences(n, k, p) for k in range(x, n))


def number_of_attempts_to_reach_probability(p: float, desired_prob: float, prec: int=None) -> int:
    """
    Calculates the minimum number of attempts of an event with probability `p` to occur with `desired_prob` probability.

    Parameters:
        p            (float): Probability event will occur.
        desired_prob (float): Probability to reach.

    Returns:
        int: Number of attempts.

    Examples:
        >>> from samson.analysis.general import number_of_attempts_to_reach_probability, simulate_event
        >>> d = number_of_attempts_to_reach_probability(1/100, 0.5)
        >>> # Note we're checking how many times it happens at least once, not the number of times it happens
        >>> result = sum([simulate_event(1/100, d) > 0 for _ in range(10000)]) / 10000
        >>> d, abs(result - 0.5) < 0.05
        (69, True)

    """
    RealField = _real_field.RealField
    if type(p) is float:
        RR200 = RealField(200)
        n = 1/RR200(p)
    else:
        n = 1/p

    n  = int((n).log(2).ceil())
    RR = RealField(prec or (n + 5))

    return (RR(-desired_prob).log1p()/RR(-p).log1p()).ceil()


def __float_to_discrete_probability(p: float):
    p_frac = _integer_ring.ZZ.fraction_field()(p)
    space  = int(lcm(p_frac.numerator, p_frac.denominator))
    cutoff = int(p_frac*space)
    return space, cutoff


def simulate_event(p: float, attempts: int) -> int:
    """
    Simulates an event with probability `p` for `attempts` attempts and returns the number of times it occured.

    Parameters:
        p        (float): Probability event will occur.
        attempts   (int): Number of attempts.

    Returns:
        int: Number of occurences.
    """
    space, cutoff = __float_to_discrete_probability(p)
    total = 0

    for _ in range(attempts):
        total += random_int(space) < cutoff

    return total


def simulate_until_event(p: float, runs: int, visual: bool=False) -> float:
    """
    Simulates an event with probability `p` for `runs` runs and returns the average number of attempts until it occured.

    Parameters:
        p       (float): Probability event will occur.
        runs      (int): Number of runs.
        visual   (bool): Whether or not to display a progress bar.

    Returns:
        float: Average number of attempts.
    """
    space, cutoff = __float_to_discrete_probability(p)
    total  = 0

    r_iter = range(runs)
    if visual:
        r_iter = tqdm(r_iter)

    for _ in r_iter:
        curr = 0
        while True:
            curr += 1
            if random_int(space) < cutoff:
                break

        total += curr

    return total / runs


def approximate_n_bit_permutations(n: int, prec: int=None) -> float:
    """
    Approximates the number of `n`-bit permutations. Equal to the number of of `n`-bit bijections which are a subset of the `2^2^(n*n)` `n`-bit boolean functions.

    Parameters:
        n    (int): Size of permutation in bits.
        prec (int): Desired precision. Will be calculated automatically if not specified.

    Returns:
        float: Exponent of number of permutations with base 2.
    """
    RealField = _real_field.RealField
    RR = RealField(prec or (n + n.bit_length() + n.bit_length().bit_length()))
    return RR(RR.ctx.factorial(2**n)).log(2)


def approximate_n_to_m_bit_functions(n: int, m: int=1, prec: int=53) -> float:
    """
    Approximates the number of `n-to-m`-bit functions.

    Parameters:
        n    (int): Size of input in bits.
        m    (int): Size of output in bits.
        prec (int): Desired precision.

    Returns:
        float: Exponent of number of functions with base 2.
    """
    RealField = _real_field.RealField
    R = RealField(prec)
    return R(2)**(n*m)


def _approximate_n_bit_permutations(n: int) -> float:
    """
    Approximates the number of `n`-bit permutations.

    Parameters:
        n (int): Size of permutation in bits.

    Returns:
        float: Exponent of number of permutations with base 2.
    """
    a = log2(2*pi)
    b = (2**n/e)
    return a*n/2 + log2(b)*2**n



@functools.lru_cache(None)
def _dickman_phi(k, i, prec):
    R = k.field
    if k <= 1:
        if i == 0:
            return R.one
        else:
            return R.zero
    elif k == 2:
        if i == 0:
            return R.one - R(2).ln()
        else:
            return R.one/R(2**i*i)
    else:
        if i == 0:
            return 1/R(k-1)*sum([_dickman_phi(k, j, prec)/R(j+1) for j in range(1, prec)])
        else:
            return sum([_dickman_phi(k-1, j, prec)/(R(k)**(i-j)*i) for j in range(int(i))])




def approximate_dickman_rho_polynomial(u: int, prec: int=None) -> float:
    """
    Used by Dickman psi to estimate density of smooth numbers.

    Parameters:
        u  (float): `x log y`.
        prec (int): Desired precision.

    Returns:
        float: Approximation of `rho(u)`.

    References:
        https://www.ams.org/journals/mcom/2006-75-254/S0025-5718-05-01798-9/S0025-5718-05-01798-9.pdf
    """
    RealField = _real_field.RealField
    Symbol = _symbols.Symbol

    if not prec and type(u) is _real_field.RealElement:
        R = u.field
    else:
        R = RealField(prec or 53)
        u = R(u)


    if u.ceil() != u:
        raise ValueError('"u" must be an integer')

    P = R[Symbol('x')]
    return P([_dickman_phi(u, i, R.prec) for i in range(R.prec+1)])



def approximate_dickman_rho(u: float, prec: int=None) -> float:
    """
    Used by Dickman psi to estimate density of smooth numbers.

    Parameters:
        u  (float): `x log y`.
        prec (int): Desired precision.

    Returns:
        float: Approximation of `rho(u)`.

    References:
        https://www.ams.org/journals/mcom/2006-75-254/S0025-5718-05-01798-9/S0025-5718-05-01798-9.pdf
    """
    RealField = _real_field.RealField

    if not prec and type(u) is _real_field.RealElement:
        R = u.field
    else:
        R = RealField(prec or 53)
        u = R(u)

    if u < 0:
        return R.zero
    
    if u <= 1:
        return R.one

    R  = u.field
    xi = (-u % 1) or R.one
    k  = u + xi
    return approximate_dickman_rho_polynomial(k, prec)(xi)



def approximate_dickman_psi(x: int, y: int, prec: int=53, ignore_bound: bool=False) -> float:
    """
    Approximates the number of `y`-smooth numbers less than `x` using Dickman psi.

    Parameters:
        x (int): Upper bound of integer range.
        y (int): Upper bound of factor range.

    Returns:
        float: Approximation of `y`-smooth numbers less than `x`.

    References:
        https://en.wikipedia.org/wiki/Dickman_function
        https://www.jstor.org/stable/2000551
    """
    RealField = _real_field.RealField
    R = RealField(prec)

    x, y = R(x), R(y)
    u    = x.log(y)

    if not ignore_bound and u > y.sqrt():
        raise ValueError(f"u ({u}) must be within 1 <= u <= y.sqrt()")

    return x*approximate_dickman_rho(u, prec)



def generate_rc4_bias_map(ciphertexts):
    bias_map = [{} for i in range(256)]

    for c in ciphertexts:
        for i, byte in enumerate(c):
            if byte in bias_map[i]:
                bias_map[i][byte] = bias_map[i][byte] + 1
            else:
                bias_map[i][byte] = 1

    for i,_ in enumerate(bias_map):
        bias_map[i] = sorted(bias_map[i].items(), key=lambda kv: kv[1], reverse=True)

    return bias_map



def generate_random_rc4_bias_map(data=b'\x00' * 51, key_size=128, sample_size=2**20):
    from samson.stream_ciphers.rc4 import RC4
    ciphertexts = []

    for _ in range(sample_size):
        key = os.urandom(key_size // 8)
        cipher = RC4(key)
        ciphertexts.append(cipher.generate(len(data)) ^ data)


    return generate_rc4_bias_map(ciphertexts)



def incremental_rc4_bias_map_gen(filepath, start_idx=0, data=b'\x00' * 51, key_size=128, sample_size=2**30, chunk_size=2**24):
    if sample_size % chunk_size > 0:
        iteration_mod = 1
    else:
        iteration_mod = 0


    iterations = sample_size // chunk_size + iteration_mod

    for i in range(start_idx, iterations):
        if i == iterations - 1 and iteration_mod == 1:
            mod_sample_size = sample_size % chunk_size
        else:
            mod_sample_size = chunk_size

        bias_map = generate_random_rc4_bias_map(data, key_size, mod_sample_size)


        with open(filepath + ".{}".format(i), "w+") as f:
            f.write(json.dumps(bias_map))

        del bias_map



def merge_rc4_bias_map_files(base_path, num):
    bias_maps = []

    for i in range(num):
        with open("{}.{}".format(base_path, i)) as f:
            content = f.read()

        bias_maps.append(json.loads(content))

    return merge_rc4_bias_maps(bias_maps)



def merge_rc4_bias_maps(bias_maps):
    merged_map = [{} for i in range(256)]

    for bias_map in bias_maps:
        for i,_ in enumerate(bias_map):
            for k,v in bias_map[i]:
                if k in merged_map[i]:
                    merged_map[i][k] += v
                else:
                    merged_map[i][k] = v

    for i,_ in enumerate(merged_map):
        merged_map[i] = sorted(merged_map[i].items(), key=lambda kv: kv[1], reverse=True)

    return merged_map
