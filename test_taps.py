import unittest
from unittest.mock import patch
from taps import *


class TestTAPS(unittest.TestCase):
    # tests cases for the client input parsing
    def test_parse_client_input(self):
        client_input_example = {
            "Alliances": [{"countries": ["US", "GB"], "trust": 0.1}],
            "Client": "3.3.3.3",
            "Destination": "4.4.4.4"
        }
        alliances, trust, client_ip, dest_ip = parse_client_input(client_input_example)
        self.assertEqual(client_ip, "3.3.3.3")
        self.assertEqual(dest_ip, "4.4.4.4")
        self.assertEqual(alliances, [{"US", "GB"}])
        self.assertEqual(trust, {"US": 0.1, "GB": 0.1})
        #
        client_input_example = {
            "Alliances": [
                {"countries": ["PT", "ES"], "trust": 0.5},
                {"countries": ["PT", "FR"], "trust": 0.3}
            ],
            "Client": "5.5.5.5",
            "Destination": "6.6.6.6"
        }
        alliances, trust, client_ip, dest_ip = parse_client_input(client_input_example)
        self.assertEqual(client_ip, "5.5.5.5")
        self.assertEqual(dest_ip, "6.6.6.6")
        self.assertEqual(alliances, [{"PT", "ES"}, {"PT", "FR"}])
        self.assertEqual(trust, {"PT": 0.5, "ES": 0.5, "FR": 0.3})


    # tests cases for the relay filtering
    @patch('taps.ip_to_country')
    def test_filter_relays(self, mock_ip_to_country):
        relays_example = [
            {"ip": "1.1.1.1", "fingerprint": "A"},
            {"ip": "2.2.2.2", "fingerprint": "B"},
            {"ip": "3.3.3.3", "fingerprint": "C"}
        ]
        trust = {
            "US": 1.0,
            "DE": 0.8
        }
        mock_ip_to_country.side_effect = lambda ip: {
            "1.1.1.1": "US",
            "2.2.2.2": "FR",
            "3.3.3.3": "DE"
        }[ip]
        result = filter_relays(relays_example, trust)
        expected = [
            {"ip": "1.1.1.1", "fingerprint": "A"},
            {"ip": "3.3.3.3", "fingerprint": "C"}
        ]
        self.assertEqual(result, expected)


    # tests cases for the exit policy parsing
    def test_is_relay_exit(self):
        exit_policy_example = [
            "accept *:80, accept *:443, reject *:*",
        ]
        result = is_relay_exit(exit_policy_example[0])
        self.assertEqual(result, True)
        #
        exit_policy_example = [
            "reject *:80, reject *:443, reject *:*",
        ]
        result = is_relay_exit(exit_policy_example[0])
        self.assertEqual(result, False)
        #
        exit_policy_example = [
            "accept *:80, accept *:443, accept *:*",
        ]
        result = is_relay_exit(exit_policy_example[0])
        self.assertEqual(result, True)
        #
        exit_policy_example = [
            "accept *:80, accept *:443, reject *:22, reject *:*",
        ]
        result = is_relay_exit(exit_policy_example[0])
        self.assertEqual(result, True)
        #
        exit_policy_example = [
            "reject *:22, accept *:80, accept *:443, reject *:23, reject *:*",
        ]
        result = is_relay_exit(exit_policy_example[0])
        self.assertEqual(result, True)


    # tests cases for the tor consensus parsing
    def test_parse_tor_consensus(self):
        tor_consensus_example = [{
            "fingerprint": "FBF5C14262DE82E180F0CF69CFB006C6BB08FA9E",
            "nickname": "Bens3rdVPSRelayDE",
            "ip": "178.254.37.2",
            "port": 17500,
            "bandwidth": {
                "measured": 23319777,
                "average": 20480000,
                "burst": 30720000
            },
            "family": [
                "$FBF5C14262DE82E180F0CF69CFB006C6BB08FA9E",
                "$CA675ACBEDADF0C95D62B74240C18B7D918949DD",
                "$6A464FA9012AA0CFD4EDDCF9BD65D79E388FAC47",
                "$C24AE5DB9CFEA75CA0D03D0B4D90672E64E291F2"
            ],
            "asn": "42730",
            "exit": "reject *:*"
        }]
        result = parse_tor_consensus(tor_consensus_example)
        self.assertEqual(result[0]["fingerprint"], "FBF5C14262DE82E180F0CF69CFB006C6BB08FA9E")
        self.assertEqual(result[0]["ip"], "178.254.37.2")
        self.assertEqual(result[0]["bandwidth"], 23319777)
        self.assertEqual(result[0]["family"], [
            "FBF5C14262DE82E180F0CF69CFB006C6BB08FA9E",
            "CA675ACBEDADF0C95D62B74240C18B7D918949DD",
            "6A464FA9012AA0CFD4EDDCF9BD65D79E388FAC47",
            "C24AE5DB9CFEA75CA0D03D0B4D90672E64E291F2"
        ])
        self.assertEqual(result[0]["is_guard"], True)
        self.assertEqual(result[0]["is_exit"], False)


    # tests cases for the IP to country conversion
    def test_ip_to_country(self):
        ip_example = "8.8.8.8"
        result = ip_to_country(ip_example)
        self.assertEqual(result, "US")


    # tests cases for the alliance expansion
    def test_expand_alliance(self):
        alliances = [
            {"DE", "US"},
            {"US", "GB", "CA"},
            {"DE", "FR"}
        ]
        result = expand_alliance({"US"}, alliances)
        self.assertSetEqual(result, {"US", "DE", "GB", "CA", "FR"})
        result = expand_alliance({"FR"}, alliances)
        self.assertSetEqual(result, {"FR", "DE", "US", "GB", "CA"})
        result = expand_alliance({"GB"}, alliances)
        self.assertSetEqual(result, {"GB", "US", "CA", "DE", "FR"})
        result = expand_alliance({"CN"}, alliances)
        self.assertSetEqual(result, {"CN"})


    # tests cases for the guard security calculation
    @patch('taps.ip_to_country')
    def test_guard_security(self, mock_ip_to_country):
        trust = {'US': 1.0, 'GB': 0.8, 'DE': 0.5, 'CN': 0.0}
        alliances = [{'US', 'GB'}, {'DE'}]
        client_ip = "1.1.1.1"
        guards = [{"ip": "2.2.2.2"}]
        mock_ip_to_country.side_effect = lambda ip: {
            client_ip: "US",
            guards[0]["ip"]: "GB",
        }[ip]
        score = guard_security(client_ip, guards, trust, alliances)
        self.assertAlmostEqual(score, 0.2173913043478261) # (0.5 + 0.0) / (1.0 + 0.8 + 0.5 + 0.0)


    # tests cases for the exit security calculation
    @patch('taps.ip_to_country')
    def test_exit_security(self, mock_ip_to_country):
        trust = {'US': 1.0, 'GB': 0.8, 'FR': 0.5, 'CN': 0.0}
        alliances = [{'US', 'GB'}, {'FR'}]
        client_ip = "1.1.1.1"
        guard = {"ip": "2.2.2.2"}
        exit = {"ip": "3.3.3.3"}
        dest_ip = "4.4.4.4"
        mock_ip_to_country.side_effect = lambda ip: {
            client_ip: "US",
            guard["ip"]: "GB",
            exit["ip"]: "FR",
            dest_ip: "FR",
        }[ip]
        score = exit_security(client_ip, dest_ip, guard, exit, trust, alliances)
        self.assertAlmostEqual(score, 1.0)  # (1.0 + 0.8 + 0.5 + 0.0) / (1.0 + 0.8 + 0.5 + 0.0)


    # tests cases for the secure relays selection
    def test_secure_relays(self):
        self.assertFalse(False)


    # tests cases for the path selection
    @patch('taps.ip_to_country')
    def test_select_path(self, mock_ip_to_country):
        mock_ip_to_country.side_effect = lambda ip: {
            "1.1.1.1": "US",  # client
            "8.8.8.8": "DE",  # guard
            "9.9.9.9": "FR",  # middle
            "5.5.5.5": "SE",  # exit
            "2.2.2.2": "SE",  # dest
        }[ip]

        relays = [
            {"fingerprint": "G", "ip": "8.8.8.8", "is_guard": True, "is_exit": False, "bandwidth": 100, "family": []},
            {"fingerprint": "M", "ip": "9.9.9.9", "is_guard": False, "is_exit": False, "bandwidth": 100, "family": []},
            {"fingerprint": "E", "ip": "5.5.5.5", "is_guard": False, "is_exit": True, "bandwidth": 100, "family": []}
        ]

        trust = {"US": 1.0, "DE": 0.9, "FR": 0.5, "SE": 0.8}
        alliances = [{"US", "GB"}, {"FR"}]

        alpha_guard = {
            'safe_upper': 0.9, 'safe_lower': 2.0,
            'accept_upper': 0.5, 'accept_lower': 5.0,
            'bandwidth_frac': 0.2
        }

        alpha_exit = {
            'safe_upper': 0.9, 'safe_lower': 2.0,
            'accept_upper': 0.5, 'accept_lower': 5.0,
            'bandwidth_frac': 0.2
        }

        path = select_path(
            relays, alpha_guard, alpha_exit,
            client_ip="1.1.1.1",
            dest_ip="2.2.2.2",
            trust=trust,
            alliances=alliances
        )

        self.assertIn("guard", path)
        self.assertIn("middle", path)
        self.assertIn("exit", path)
        self.assertEqual(path["guard"], "G")
        self.assertEqual(path["exit"], "E")


if __name__ == '__main__':
    unittest.main()
