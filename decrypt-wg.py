import struct
from Crypto.Cipher import AES
import xml.etree.ElementTree as ET

QUAD = struct.Struct('>Q')

def aes_unwrap_key_and_iv(kek, wrapped):
    n = int(len(wrapped)/8 - 1)
    #NOTE: R[0] is never accessed, left in for consistency with RFC indices
    R = [None]+[wrapped[i*8:i*8+8] for i in range(1, n+1)]
    A = QUAD.unpack(wrapped[:8])[0]
    decrypt = AES.new(kek,AES.MODE_ECB).decrypt
    for j in range(5,-1,-1): #counting down
        for i in range(n, 0, -1): #(n, n-1, ..., 1)
            ciphertext = QUAD.pack(A^(n*j+i)) + R[i]
            B = decrypt(ciphertext)
            A = QUAD.unpack(B[:8])[0]
            R[i] = B[8:]
    R[-1] = R[-1][:-R[-1][-1]]
    #return "".join(R[1:]), A
    return "".join(r.decode('utf-8', errors='ignore') for r in R[1:]), A

#key wrapping as defined in RFC 3394
#http://www.ietf.org/rfc/rfc3394.txt
#def aes_unwrap_key(kek, wrapped, iv=0xa6a6a6a6a6a6a6a6):
#Changed iv for Watchguard
def aes_unwrap_key(kek, wrapped, iv=100085249058027875):
    key, key_iv = aes_unwrap_key_and_iv(kek, wrapped)
    if key_iv != iv:
        raise ValueError("Integrity Check Failed: "+hex(key_iv)+" (expected "+hex(iv)+")")
    #print (key)
    #print key_iv
    return key

# #alternate initial value for aes key wrapping, as defined in RFC 5649 section 3
# #http://www.ietf.org/rfc/rfc5649.txt
# def aes_unwrap_key_withpad(kek, wrapped):
#     if len(wrapped) == 16:
#         plaintext = AES.new(kek,AES.MODE_ECB).decrypt(wrapped)
#         key, key_iv = plaintext[:8], plaintext[8:]
#     else:
#         key, key_iv = aes_unwrap_key_and_iv(kek, wrapped)
#     key_iv = "{0:016X}".format(key_iv)
#     if key_iv[:8] != "A65959A6":
#         raise ValueError("Integrity Check Failed: "+key_iv[:8]+" (expected A65959A6)")
#     key_len = int(key_iv[8:], 16)
#     #print key[:key_len]
#     return key[:key_len]

# def aes_wrap_key(kek, plaintext, iv=0xa6a6a6a6a6a6a6a6):
#     n = len(plaintext)/8
#     R = [None]+[plaintext[i*8:i*8+8] for i in range(0, n)]
#     A = iv
#     encrypt = AES.new(kek,AES.MODE_ECB).encrypt
#     for j in range(6):
#         for i in range(1, n+1):
#             B = encrypt(QUAD.pack(A) + R[i])
#             A = QUAD.unpack(B[:8])[0] ^ (n*j + i)
#             R[i] = B[8:]
#     return QUAD.pack(A) + "".join(R[1:])

# def aes_wrap_key_withpad(kek, plaintext):
#     iv = 0xA65959A600000000 + len(plaintext)
#     plaintext = plaintext + "\0" * ((8 - len(plaintext)) % 8)
#     if len(plaintext) == 8:
#         return AES.new(kek,AES.MODE_ECB).encrypt(QUAD.pack[iv] + plaintext)
#     return aes_wrap_key(kek, plaintext, iv)

def decrypt(psk):
    import binascii
    import sys
    KEK = binascii.unhexlify("1d03f58287982bc701227394e498de23")
    array_kek = [ 29, 3, 245, 130, 135, 152, 43, 199, 1, 34, 115, 148, 228, 152, 222, 35 ]
    CIPHER = binascii.unhexlify(psk)
    return aes_unwrap_key(KEK, CIPHER)

def extract_name_and_psk(xml_file):
    # Parse the XML file
    tree = ET.parse(xml_file)
    root = tree.getroot()

    # Iterate through all ike-policy elements
    for ike_policy in root.findall(".//ike-policy-list/ike-policy"):
        # Extract the 'name' and 'psk' for each ike-policy
        if ike_policy.find("name").text is not None:
            name = ike_policy.find("name").text
        else: 
            print ("missing name")
            continue
        if ike_policy.find(".//local-cert/psk").text is not None:
            psk = ike_policy.find(".//local-cert/psk").text
        else: 
            print (f"NAME: {name}, PSK: missing")
            continue

        # Decrypt key
        key = decrypt(psk.replace('+','')) if psk != "No PSK" else "psk"
        
        # Print or store the extracted values
        print(f"NAME: {name}, PSK: {key}")



xml_file = input("Input file: ")

extract_name_and_psk(xml_file)
