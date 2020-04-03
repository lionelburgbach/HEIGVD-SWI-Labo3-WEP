#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Python 3.7.6
#
# Auteurs: Adrien Barth, Lionel Burgbacher
# Date:    03.04.2020
#
# Description:
# Chiffre manuellement un message wep avec une clé donnée

import zlib
from scapy.all import *
from rc4 import RC4

#Cle wep AA:AA:AA:AA:AA
key = b'\xaa\xaa\xaa\xaa\xaa'

#lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap('arp.cap')[0]

#Nouveau texte à envoyer de même taille que les données de la trame
plaintext = b'HHHHHeeeeeellllllllllllooooooooo SWI'

#rc4 seed est composé de IV+clé
seed = arp.iv+key

#Calcule de l'icv pour le plaintext
icv = zlib.crc32(plaintext).to_bytes(4, byteorder='little')

#Chiffrement rc4
cipher = RC4(seed, streaming=False)
#On concatène le plaintext et l'icv
ciphertext = cipher.crypt(plaintext + icv)

#On change le message de la trame avec le nouveau sans l'icv
arp.wepdata = ciphertext[:-4]
#On ajoute l'icv
arp.icv = struct.unpack('!L', ciphertext[-4:])[0]

#On crée une capture avec la nouvelle trame
wrpcap('manual_encryption.cap', arp)

sendp(arp, iface="wlan0mon", verbose=False)