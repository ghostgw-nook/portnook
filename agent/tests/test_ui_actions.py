"""Every action button in the web UI must be allowed by the API."""
import ast
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


class UiActionsTest(unittest.TestCase):
    def test_buttons_are_allowed(self):
        src = open(os.path.join(HERE, "..", "app", "api.py"), encoding="utf-8").read()
        node = next(n for n in ast.parse(src).body if isinstance(n, ast.Assign)
                    and getattr(n.targets[0], "id", "") == "ACTIONS")
        allowed = set(ast.literal_eval(node.value))
        html = open(os.path.join(HERE, "..", "web", "index.html"), encoding="utf-8").read()
        used = set(re.findall(r'data-action="([a-z-]+)"', html))
        used |= {"speedtest-" + r for r in re.findall(r'testRow\([^\n]*"([a-z0-9-]+)"\)', html)}
        self.assertTrue(used)
        self.assertEqual(set(), used - allowed)


if __name__ == "__main__":
    unittest.main()
