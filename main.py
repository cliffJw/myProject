import binascii


class Ekraal:
    # def __init__(self):
    #     super(Ekraal, self).__init__()

    #     textinput = input("Enter text: ")
    #     passwd = input("Enter password: ")

    #     # self.encrypt(textinput, passwd)
    #     self.decrypt(textinput, passwd)

    def encrypt(self, pt, encpasswd):
        # convert plaintext to binary
        ptbin = bin(int(binascii.hexlify(pt.encode()), 16))[2:]
        print("Binary plaintext: ", ptbin)
        # convert password to binary
        passwdbin = bin(int(binascii.hexlify(encpasswd.encode()), 16))[2:]
        print("Binary password: ", passwdbin)
        # do padding if pt is odd length
        lenptbin = len(ptbin)

        if lenptbin % 2 == 0:
            nptbin = ptbin
        else:
            nptbin = ptbin.zfill(lenptbin + 1)
            print(nptbin)

        # info about the plaintext .... length of pt
        lenptb = len(nptbin)
        lenpt = '{0:08b}'.format(lenptb).zfill(256)
        print("Length of PT: ", lenptb)
        print("Length of PT in bin: ", lenpt)

        # encryption
        # divide pt into two equal chunks
        chunklength = int(lenptb / 2)
        print("Plain text bits: ", nptbin)
        chunk1 = nptbin[:chunklength]

        print("Chunk 1 bits: ", chunk1)
        chunk2 = nptbin[chunklength:]
        print("Chunk 2 bits: ", chunk2)

        # operations on the key
        lenchunk1 = len(chunk1)
        print("Len chunk1: ", lenchunk1)
        lenkey = len(passwdbin)
        print("Len key: ", lenkey)
        if lenkey > lenchunk1:
            keyfin = passwdbin[:lenchunk1]
            print("Truncated key: ", keyfin)
        else:
            nrepskey = int(lenchunk1/lenkey) + 1
            print("Num reps: ", nrepskey)
            keyfin = (passwdbin*nrepskey)[:lenchunk1]
            print("Expanded key: {} -- {}".format(keyfin, len(keyfin)))

        # operations on chunk 1
        # right shift by 3
        chunk1rs3 = chunk1[3:] + chunk1[:3]
        print(chunk1)
        print(chunk1rs3)

        # xor with the key
        chunk1rs3xk = (int(chunk1rs3, 2) ^ int(keyfin, 2))
        print(chunk1rs3xk)
        chunk1xk = format(chunk1rs3xk, 'b').zfill(lenchunk1)
        print("Final chunk 1: ", chunk1xk)

        # reverse bits
        fchunk1 = chunk1xk[::-1]
        print("Final chunk 1 reversed: ", fchunk1)

        # operations on chunk2
        # xor with key
        chunk2xk = (int(chunk2, 2) ^ int(keyfin, 2))
        print(chunk2xk)
        fchunk2xk = format(chunk2xk, 'b').zfill(len(chunk2))
        print("Final chunk 2: ", fchunk2xk)

        # right shift by 2
        chunk2rs2 = fchunk2xk[2:] + fchunk2xk[:2]
        print("Final shifted chunk 2: ", chunk2rs2)

        # concatenate all outputs
        ctbits = fchunk1 + chunk2rs2 + lenpt
        print("Binary cipher text: ", ctbits)

        # store as hex
        cthex = int(ctbits, 2)
        ciphertext = hex(cthex)
        print("Final cipher text: ", ciphertext)

    def decrypt(self, ct, passwd):
        ctbin = bin(int(ct, 16))[2:]
        print("Cipher text binary: ", ctbin)

        passwdbin = bin(int(binascii.hexlify(passwd.encode()), 16))[2:]
        print("Binary password: ", passwdbin)

        # extract info
        infobits = ctbin[len(ctbin)-256:]
        print("Info bits: {} -- {}".format(infobits, len(infobits)))
        ptlen = int(infobits, 2)
        print("Plain text length: ", ptlen)

        ctbits = ctbin[:len(ctbin) - 256]
        print("Cipher text binary: ", ctbits)

        # do some padding
        ctbitsp = ctbits.zfill(ptlen)
        print("Padded cipher text binary: ", ctbitsp)

        # determine chunklength
        chunklength = int(len(ctbitsp)/2)
        print("Chunk length: ", chunklength)

        # divide ct into chunks
        chunk1 = ctbitsp[:chunklength]
        chunk2 = ctbitsp[chunklength:]

        # operations on chunk 1
        # reverse
        chunk1rev = chunk1[::-1]
        # xor with key
        # operations on the key
        lenchunk1 = len(chunk1)
        print("Len chunk1: ", lenchunk1)
        lenkey = len(passwdbin)
        print("Len key: ", lenkey)
        if lenkey > lenchunk1:
            keyfin = passwdbin[:lenchunk1]
            print("Truncated key: ", keyfin)
        else:
            nrepskey = int(lenchunk1 / lenkey) + 1
            print("Num reps: ", nrepskey)
            keyfin = (passwdbin * nrepskey)[:lenchunk1]
            print("Expanded key: {} -- {}".format(keyfin, len(keyfin)))

        chunk1revxk = (int(chunk1rev, 2) ^ int(keyfin, 2))
        print(chunk1revxk)
        fchunk1revxk = format(chunk1revxk, 'b').zfill(len(chunk1))
        print("Chunk 1 xor key: ", fchunk1revxk)

        # left shift by 3
        chunk1ls3 = fchunk1revxk[-3:] + fchunk1revxk[:-3]
        print("Chunk 1 final bits: ", chunk1ls3)

        # operations on chunk 2
        # left shift by 3
        chunk2ls2 = chunk2[-2:] + chunk2[:-2]
        print("Chunk 2 ls bits: ", chunk2ls2)

        # xor with the key
        chunk2xk = (int(chunk2ls2, 2) ^ int(keyfin, 2))
        print(chunk2xk)
        fchunk2xk = format(chunk2xk, 'b').zfill(len(chunk2))
        print("Final bits chunk 2: ", fchunk2xk)

        # concatenate bits
        ptbits = chunk1ls3 + fchunk2xk
        print("Plain text bits: ", ptbits)

        # convert to text
        ptext = int(ptbits, 2)
        message = binascii.unhexlify('%x' % ptext)
        print("Plain text", message)

# if __name__ == "__main__":
#     Ekraal()
