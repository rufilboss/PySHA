import unittest
from main import SHA1, SHA256, SHA512

class TestPySHA(unittest.TestCase):

    def test_sha1(self):
        sha1 = SHA1()
        self.assertEqual(sha1.digest(b"hello world"), "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed")

    def test_sha256(self):
        sha256 = SHA256()
        self.assertEqual(sha256.digest(b"hello world"), "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")

    def test_sha512(self):
        sha512 = SHA512()
        self.assertEqual(sha512.digest(b"hello world"), "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f")

if __name__ == "__main__":
    unittest.main()
