# http://cryptopals.com
#
# ## Set 1

import numpy as np
import urllib2
import base64


# Challenge 1
# ===========

def convert_hex_to_base64(input_string):
    import base64
    return base64.b64encode(input_string.decode("hex"))

convert_hex_to_base64('49276d206b696c6c696e6720796f757220627261696e206c696b6'
                      '5206120706f69736f6e6f7573206d757368726f6f6d')


# Challenge 2
# ===========

def hex_xor(input1, input2, distance=False):
    try:
        assert len(input1) == len(input2)
    except AssertionError:
        raise ValueError("input1 and input2 should have the same lenght")

    input1_bin = bin(int(input1, 16))[2:]
    input2_bin = bin(int(input2, 16))[2:]

    binlen = np.max((len(input1_bin), len(input2_bin)))

    input1_bin = '{0:0{1}}'.format(int(input1_bin), binlen)
    input2_bin = '{0:0{1}}'.format(int(input2_bin), binlen)

    xor_bin = np.zeros(binlen, dtype='str')

    for i in range(binlen):
        xor_bin[i] = int(np.logical_xor(int(input1_bin[i]),
                                        int(input2_bin[i])))
    xor_bin = ''.join(xor_bin)

    if distance:
        hemming_distance = np.sum([np.int(xor_bin[i]) for i in range(binlen)])
        return hemming_distance
    hex_result = hex(int(xor_bin, 2))[2:-1]

    # Make sure we return an even legth hex string
    if len(hex_result) % 2 == 1:
        hex_result = '0' + hex_result
    return hex_result


hex_xor('1c0111001f010100061a024b53535009181c',
        '686974207468652062756c6c277320657965')

# Challenge 3
# ===========

# Source: https://en.wikipedia.org/wiki/Letter_frequency
# "In English, the space is slightly more frequent than the top letter (e)"
# thus adding it with 13%

FREQUENCY_MAP = dict([('A', 8.167),
                      ('B', 1.492),
                      ('C', 2.782),
                      ('D', 4.253),
                      ('E', 12.702),
                      ('F', 2.228),
                      ('G', 2.015),
                      ('H', 6.094),
                      ('I', 6.966),
                      ('J', 0.153),
                      ('K', 0.772),
                      ('L', 4.025),
                      ('M', 2.406),
                      ('N', 6.749),
                      ('O', 7.507),
                      ('P', 1.929),
                      ('Q', 0.095),
                      ('R', 5.987),
                      ('S', 6.327),
                      ('T', 9.056),
                      ('U', 2.758),
                      ('V', 0.978),
                      ('W', 2.360),
                      ('X', 0.150),
                      ('Y', 1.974),
                      ('Z', 0.074),
                      (' ', 13.0)])


def frequency_scoring(input_text, letter_map=FREQUENCY_MAP, hex_input=True):
    if hex_input:
        input_text = input_text.decode('hex')

    letter_sums = np.sum([letter_map[input_text[j].upper()]
                          for j in range(len(input_text))
                          if input_text[j].upper() in letter_map])

    return letter_sums


def single_xor_decipher(input_hex, frequent=False,
                        frequency_map=FREQUENCY_MAP, full=True):

    from string import printable, ascii_letters

    # Make sure we are not ommitting the leading 0 of the input_hex
    if len(input_hex) % 2 == 1:
        input_hex = '0' + input_hex

    possible_keys = printable
    ascii_texts = ' ' + ascii_letters
    letter_map = dict(zip(ascii_texts, np.ones(len(ascii_texts))))

    if frequent:
        letter_map = frequency_map

    key_length = len(input_hex) / 2
    decipher = np.empty(len(possible_keys),
                        dtype='S{0}'.format(len(input_hex) + 5))
    letter_sums = np.zeros(len(possible_keys))
    for i, cha in enumerate(possible_keys):
        xor_result = hex_xor(input_hex, (cha * key_length).encode('hex'))

        decipher[i] = xor_result.decode('hex')
        letter_sums[i] = frequency_scoring(decipher[i], letter_map=letter_map,
                                           hex_input=False)

    max_ascii_ind = np.argmax(letter_sums)
    max_ascii_letter = possible_keys[max_ascii_ind]
    if full:
        return decipher, letter_sums, max_ascii_letter, max_ascii_ind
    else:
        return decipher[max_ascii_ind]

result1 = single_xor_decipher('1b37373331363f78151b7f2b783431333d783978'
                              '28372d363c78373e783a393b3736')
print ('The deciphered text is "{0}" using "{1}" as encryption key.'
       .format(result1[0][result1[3]], result1[2]))

result2 = single_xor_decipher('1b37373331363f78151b7f2b783431333d7839782'
                              '8372d363c78373e783a393b3736', frequent=True)
print ('The deciphered text is "{0}" using "{1}" as encryption key '
       '(using frequency map).'.format(result2[0][result2[3]], result2[2]))

# Challenge 4
# ===========

input_data = urllib2.urlopen('http://cryptopals.com/static/challenge-data/'
                             '4.txt').read().split("\n")

series_decipher = []

for i in range(len(input_data)):
    series_decipher.append(single_xor_decipher(input_data[i]))

series_decipher = np.array(series_decipher)

max_ascii_letters_ind = np.argmax([np.max(series_decipher[i, 1])
                                   for i in range(len(series_decipher))])
result = series_decipher[max_ascii_letters_ind]

print ('The deciphered text is "{0}" using "{1}" as encryption key in the '
       'line of No {2}.'.format(result[0][result[3]], result[2],
                                max_ascii_letters_ind + 1))


# Challenge 5
# ===========

def repeating_key_XOR(input_text, input_key, hex_input=False):
    if hex_input:
        input_hex = input_text
        key_hex = input_key
    else:
        input_hex = input_text.encode('hex')
        key_hex = input_key.encode('hex')

    input_length = len(input_hex)
    key_length = len(key_hex)
    key_multi = input_length // key_length
    key_mod = input_length % key_length

    full_key = key_hex * key_multi + key_hex[:key_mod]

    result = hex_xor(input_hex, full_key)

    return result

text_in = ("Burning 'em, if you ain't quick and nimble "
           "I go crazy when I hear a cymbal")

print (repeating_key_XOR(text_in, 'ICE'))
print (repeating_key_XOR(text_in.encode('hex'), 'ICE'.encode('hex'),
                         hex_input=True))


# Challenge 6
# ===========

def breakup_string(input_str, length):
    breakup = [input_str[i:length + i]
               for i in range(0, len(input_str), length)]
    return breakup


input_data = urllib2.urlopen('http://cryptopals.com/static/challenge-data/'
                             '6.txt').read()
input_hex = base64.b64decode(input_data).encode('hex')

# Test whether the distance calculation works
st1 = 'this is a test'
st2 = 'wokka wokka!!!'
assert hex_xor(st1.encode('hex'), st2.encode('hex'), distance=True) == 37

keysize_range = range(2, 41)
keysize_norm_distance = np.empty(len(keysize_range))

for i, keysize in enumerate(keysize_range):
    # In hexa string the keys are double in length
    keysize *= 2
    first_key = input_hex[:keysize]
    second_key = input_hex[keysize:keysize * 2]
    third_key = input_hex[keysize * 2:keysize * 3]
    fourth_key = input_hex[keysize * 3:keysize * 4]
    fifth_key = input_hex[keysize * 4:keysize * 5]
    keysize_norm_distance[i] = np.mean([hex_xor(first_key, second_key,
                                                distance=True),
                                        hex_xor(second_key, third_key,
                                                distance=True),
                                        hex_xor(third_key, fourth_key,
                                                distance=True),
                                        hex_xor(fourth_key, fifth_key,
                                                distance=True)]) / keysize

smallest_distances_ind = np.argsort(keysize_norm_distance)[:3]

keep_keysizes = [keysize_range[smallest_distances_ind[i]]
                 for i in range(len(smallest_distances_ind))]

best_keys = []
for keysize in keep_keysizes:
    breakup = breakup_string(input_hex, keysize * 2)

    breakup_trans = []
    single_decipher_result = []

    # In hexa string the characters are double in length
    for i in range(len(breakup[0]) / 2):
        i *= 2
        # The last chunk may be shorter than the other, needs special treatment
        breakup_trans.append(''.join([breakup[j][i:i + 2]
                                      for j in range(len(breakup) - 1)]))
        try:
            breakup_trans[-1] = breakup_trans[-1] + breakup[-1][i:i + 2]
        except:
            pass

        single_decipher_result.append(single_xor_decipher(breakup_trans[-1],
                                                          frequent=True))
    best_keys.append(''.join([single_decipher_result[i][2]
                              for i in range(len(single_decipher_result))]))

# Decide which key is the best

key_scores = [frequency_scoring(repeating_key_XOR(input_hex,
                                                  best_keys[i].encode('hex'),
                                                  hex_input=True))
              for i in range(len(best_keys))]

best_key_ind = np.argmax(key_scores)
best_key = best_keys[best_key_ind]

print('The best key is:\n\t\t "{0}"'.format(best_key))
print('Deciphered text: \n {0}'
      .format(repeating_key_XOR(input_hex, best_key.encode('hex'),
                                hex_input=True).decode('hex')))

# Challenge 7
# ===========
