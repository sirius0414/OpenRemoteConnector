"""An intentional failure for checking the recorded nonzero exit code."""
import unittest

class ExpectedFailureFixture(unittest.TestCase):
    def test_nonzero(self):
        self.assertEqual(1, 2, "intentional ORC failure fixture")

if __name__ == "__main__":
    unittest.main()
