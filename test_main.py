import unittest
from unittest.mock import patch
from main import SHA1, SHA256, SHA512

class TestPySHA(unittest.TestCase):

    @patch('main.SHA1.digest', return_value="2aae6c35c94fcfb415dbe95f408b9ce91ee846ed")
    def test_sha1(self, mock_digest):
        sha1 = SHA1()
        result = sha1.digest(b"hello world")
        self.assertEqual(result, "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed")
        mock_digest.assert_called_once_with(b"hello world")

    @patch('main.SHA256.digest', return_value="b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
    def test_sha256(self, mock_digest):
        sha256 = SHA256()
        result = sha256.digest(b"hello world")
        self.assertEqual(result, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
        mock_digest.assert_called_once_with(b"hello world")

    @patch('main.SHA512.digest', return_value="309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f")
    def test_sha512(self, mock_digest):
        sha512 = SHA512()
        result = sha512.digest(b"hello world")
        self.assertEqual(result, "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f")
        mock_digest.assert_called_once_with(b"hello world")

if __name__ == "__main__":
    unittest.main()
