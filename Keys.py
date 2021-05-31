from Crypto.PublicKey import RSA


def key_Generator(identifier=""):
    keyPair = RSA.generate(1024)

    namePub = "publicKey" if identifier == "" else "publicKey_"+identifier+".pem"
    f = open(namePub, 'wb')

    pubKey = keyPair.publickey()
    pubKeyPEM = pubKey.exportKey()
    f.write(pubKeyPEM)
    f.close()

    namePriv = "privateKey" if identifier == "" else "privateKey_"+identifier+".pem"
    f = open(namePriv, 'wb')
    privKeyPEM = keyPair.exportKey()
    f.write(privKeyPEM)
    f.close()
