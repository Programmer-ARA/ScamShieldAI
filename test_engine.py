import unittest
from scam_engine import analyze_message, extract_urls, investigate, analyze_url

class ScamShieldTests(unittest.TestCase):
    def test_upfront_fee_signal(self):
        result = analyze_message("You won a prize. Pay a processing fee.")
        self.assertGreater(result["signals_found"], 0)

    def test_extract_url(self):
        urls = extract_urls("Visit https://example.com/path for details.")
        self.assertTrue(any("example.com" in url for url in urls))

    def test_no_reputation_claim(self):
        result = investigate("Hello, how are you?")
        self.assertFalse(result["reputation_checked"])

    def test_does_not_open_url(self):
        result = analyze_url("https://example.invalid")
        self.assertEqual(result["reputation"], "not checked")

    def test_empty_message_rejected(self):
        with self.assertRaises(ValueError):
            investigate("   ")

if __name__ == "__main__":
    unittest.main()
