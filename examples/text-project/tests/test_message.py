import unittest
from message import greeting

class GreetingTest(unittest.TestCase):
    def test_greeting(self):
        self.assertEqual(greeting("ORC"), "Hello, ORC!")

if __name__ == "__main__":
    unittest.main()
