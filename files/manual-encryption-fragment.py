#!/usr/bin/env python

# Python 3.7.6
#
# Auteurs: Adrien Barth, Lionel Burgbacher
# Date:    03.04.2020
#
# Description:
# Chiffre manuellement de 3 fragments avec une clé donnée

import zlib
from scapy.all import *
from rc4 import RC4

#Cle wep AA:AA:AA:AA:AA
key = b'\xaa\xaa\xaa\xaa\xaa'

# Nouveau texte à envoyer de même taille que les données de la trame
plaintext = b'HHHHHeeeeeelllllllllllloooooooo SWI1HHHHHeeeeeelllllllllllloooooooo SWI2HHHHHeeeeeelllllllllllloooooooo SWI3'

arp_array = []

for index in range(0, 3):

    # lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
    arp = rdpcap('arp.cap')[0]

    # On anjoute le numéro de fragment
    arp.SC = index

    # On change le bit a 1 dans le frame control
    if index < 2:
        arp.FCfield = arp.FCfield | 0x04

    # rc4 seed est composé de IV+clé
    seed = arp.iv + key

    # On divise le plaintext pour chaque trame
    plaintext_part = plaintext[index*36:(index+1)*36]

    # calcule de l'icv pour le plaintext
    icv = zlib.crc32(plaintext_part).to_bytes(4, byteorder='little')

    # chiffrement rc4
    cipher = RC4(seed, streaming=False)
    # On concatène le plaintext et l'icv
    ciphertext = cipher.crypt(plaintext_part + icv)

    # On change les données de la trame avec les nouvelles sans l'icv
    arp.wepdata = ciphertext[:-4]
    # On ajoute l'icv
    arp.icv = struct.unpack('!L', ciphertext[-4:])[0]

    arp_array.append(arp)

# On crée une capture avec les nouvelles trames
wrpcap('manual_encryption_fragment.cap', arp_array)