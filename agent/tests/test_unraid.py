"""The Unraid template (agent/unraid/portnook.xml) matches the compose files."""
import pathlib
import re
import unittest
import xml.etree.ElementTree as ET

AGENT = pathlib.Path(__file__).resolve().parents[1]


class UnraidTemplateTest(unittest.TestCase):
    def setUp(self):
        self.root = ET.parse(AGENT / "unraid" / "portnook.xml").getroot()

    def test_same_image_as_compose(self):
        image = re.search(r"image:\s*(\S+)", (AGENT / "docker-compose.yml").read_text()).group(1)
        self.assertEqual(self.root.findtext("Repository"), image)

    def test_capabilities_and_sysctls(self):
        extra = self.root.findtext("ExtraParams")
        for part in ("--cap-add=NET_ADMIN", "net.ipv4.conf.all.src_valid_mark=1", "net.ipv4.ip_forward=1",
                     "net.ipv6.conf.all.disable_ipv6=1", "com.centurylinklabs.watchtower.enable=false"):
            self.assertIn(part, extra)

    def test_data_and_port(self):
        targets = {c.get("Target"): c.get("Type") for c in self.root.iter("Config")}
        self.assertEqual(targets.get("/data"), "Path")
        self.assertEqual(targets.get("8090"), "Port")

    def test_no_empty_path(self):
        # an empty host path makes Unraid build "-v :/target", which docker rejects
        for c in self.root.iter("Config"):
            if c.get("Type") == "Path":
                with self.subTest(target=c.get("Target")):
                    self.assertTrue((c.text or "").strip())

    def test_starts_with_container(self):
        # no comment or blank line before the root element, as Unraid writes its own templates
        text = (AGENT / "unraid" / "portnook.xml").read_text()
        self.assertTrue(text.startswith('<?xml version="1.0"?>\n<Container version="2">'))

    def test_template_url_is_raw_file(self):
        self.assertEqual(self.root.findtext("TemplateURL"),
                         "https://raw.githubusercontent.com/ghostgw-nook/portnook/main/agent/unraid/portnook.xml")

    def test_example_br0_zoraxy(self):
        # filled-in example as Unraid saves it: LAN entry on br0 with a fixed IP and the Zoraxy folder
        ex = ET.parse(AGENT / "unraid" / "portnook-br0-zoraxy.example.xml").getroot()
        self.assertEqual(ex.findtext("Repository"), self.root.findtext("Repository"))
        self.assertEqual(ex.findtext("ExtraParams"), self.root.findtext("ExtraParams"))
        self.assertEqual(ex.findtext("Network"), "br0")
        self.assertTrue(ex.findtext("MyIP").startswith("192.168.1."))
        self.assertFalse(ex.findtext("DateInstalled"))
        paths = {c.get("Target"): c.text for c in ex.iter("Config") if c.get("Type") == "Path"}
        self.assertEqual(paths["/zoraxy-certs"], "/mnt/user/appdata/zoraxy/conf/certs")


if __name__ == "__main__":
    unittest.main()
