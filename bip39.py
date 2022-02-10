import hashlib
import hmac
import secrets


def base58(hx):
    chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

    i = int(hx, 16)
    output = str()
    while i > 0:
        rem = i % 58
        i = i // 58
        output = chars[rem] + output
    return output


def calulate_checksum(bits):
    # convert bit-string to int
    dec = int(bits, 2)
    # convert int to raw bytes
    bites = dec.to_bytes(len(bits) // 8, byteorder='big')
    # take sha hash of bytestring
    sha = hashlib.sha256(bites).hexdigest()
    # convert sha hex to bits, grab first bits as appropriate
    return bin(int(sha, 16))[2:].zfill(256)[:len(bits) // 32]


def calulate_indices(bits):
    # make 11-bit chunks
    indices = list()
    while bits:
        indices.append(bits[:11])
        bits = bits[11:]
    # convert bit-chunks to ints (0-2047 map to wordlist)
    return [int(inx, 2) for inx in indices]


def get_random_bits(wordcount):
    # find count of entropy bits required for wordcount
    bitcount = wordcount * 32 // 3
    # find these entropy bits
    bits = secrets.randbits(bitcount)
    # remove python binary header and ensure leading zeroes
    return bin(bits)[2:].zfill(bitcount)


def get_seedphrase(words, indices):
    # use the wordlist and indices to provide the seed phrase
    seed_phrase = str()
    for inx in indices:
        seed_phrase += words[inx] + ' '
    # all words should have a space, but none trailing the phrase
    return seed_phrase.strip()


def get_wordcount():
    wordcount = int()
    # do not proceed without valid wordcount selection
    while not wordcount:
        try:
            wordcount = int(input('How many words? (12/15/18/21/24): '))
        except ValueError:
            continue
        # force user into 12/15/18/21/24 words
        if wordcount not in [12, 15, 18, 21, 24]:
            wordcount = int()
    print()
    return wordcount


def get_wordlist():
    # retrieve full list of english words from file
    with open('english.txt') as f:
        words = f.readlines()
    # remove the new line whitespace
    return [wr.strip() for wr in words]


def get_xprv(seed):
    # extended priv key is just hmac-sha512 of binary seed and 'Bitcoin seed'
    hsh = hmac.digest('Bitcoin seed'.encode(), bytes.fromhex(seed), 'sha512')
    keydata = b'\x00' + hsh[:32]
    chaincode = hsh[32:]

    # serialize the extended priv key
    version = b'\x04\x88\xAD\xE4'
    depth = b'\x00'
    parent = b'\x00\x00\x00\x00'
    child = b'\x00\x00\x00\x00'
    xprv = version + depth + parent + child + chaincode + keydata

    # add checksum
    xprv += hashlib.sha256(hashlib.sha256(xprv).digest()).digest()[:4]
    # convert to base58
    xprv = base58(xprv.hex())
    return xprv


def set_salt():
    # the salt is mnemonic + whatever the passphrase is, no spaces
    salt = 'mnemonic'
    salt += input('Enter passphrase (or blank): ')
    return salt


def main():
    wordcount = get_wordcount()
    entropy = get_random_bits(wordcount)
    entropy += calulate_checksum(entropy)
    indices = calulate_indices(entropy)

    words = get_wordlist()
    ph = get_seedphrase(words, indices)

    print('BIP39 PHRASE:', ph)
    sl = set_salt()
    # derive seed from phrase + salt
    sd = hashlib.pbkdf2_hmac('sha512', ph.encode(), sl.encode(), 2048).hex()
    print('BIP39 SEED:', sd)
    print()
    xprv = get_xprv(sd)
    print('BIP32 KEY:', xprv)
    print()


main()
