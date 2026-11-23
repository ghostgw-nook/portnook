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
        # 0.29.3: the route must accept every allowed name (digits in "speedtest-active-1" gave a 404)
        rx = re.search(r'_ACTION_RE = re\.compile\(r"(.+?)"\)', src).group(1)
        self.assertEqual([], [a for a in allowed if not re.fullmatch(rx, "/api/action/" + a)])


if __name__ == "__main__":
    unittest.main()
