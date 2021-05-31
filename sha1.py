from Crypto.Hash import SHA1


class SHA1_:
    def __init__(self) -> None:
        self.sha1 = SHA1.new()

    def makeDigest(self, cadena: str) -> str:
        try:
            self.sha1.update(bytes(cadena, 'utf-8'))
            return self.sha1.hexdigest()
        except Exception:
            print("Error trying to make a digest")


if __name__ == "__main__":
    sha = SHA1_()
    digest = sha.makeDigest("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Bonum incolumis acies: misera caecitas. Neminem videbis ita laudatum, ut artifex callidus comparandarum voluptatum diceretur. An est aliquid per se ipsum flagitiosum, etiamsi nulla comitetur infamia? Quae cum essent dicta, finem fecimus et ambulandi et disputandi. ")
    print("Digest:", digest)
