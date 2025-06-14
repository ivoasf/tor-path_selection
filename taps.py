import random
import json
import geoip2.database


def parse_client_input(data):
    alliances = []
    trust = {} # max trust associated with each country

    for entry in data["Alliances"]:
        group = set(entry["countries"])
        alliances.append(group)

        for c in group:
            trust[c] = max(trust.get(c, 0), entry["trust"])

    client_ip = data["Client"]
    dest_ip = data["Destination"]

    return alliances, trust, client_ip, dest_ip


def filter_relays(relays, trust):
    filtered = []

    for relay in relays:
        country = ip_to_country(relay["ip"])

        if country in trust:
            filtered.append(relay)

    return filtered


def is_relay_exit(exit_policy):
    if not exit_policy:
        return False
    
    rules = [rule.strip() for rule in exit_policy.lower().split(",")]
    
    for rule in rules:
        if rule.startswith("accept"):
            return True
        if rule == "reject *:*":
            return False
    
    return False


def parse_tor_consensus(data):
    relays = []

    for r in data:
        relay = {
            "fingerprint": r["fingerprint"],
            "ip": r["ip"],
            "bandwidth": r["bandwidth"].get("measured") or r["bandwidth"].get("average"),
            "family": [f.replace("$", "") for f in r["family"]],
            "is_guard": not is_relay_exit(r["exit"]), # assuming guards are not exits
            "is_exit": is_relay_exit(r["exit"])
        }

        relays.append(relay)

    return relays


def ip_to_country(ip):
    # manual IP to country mapping for specific cases (geoip2 not found)
    MANUAL_IP_COUNTRIES = {
        "73.170.126.220": "US",
    }
    if ip in MANUAL_IP_COUNTRIES:
        return MANUAL_IP_COUNTRIES[ip]

    with geoip2.database.Reader('GeoLite2-Country.mmdb') as reader:
        try:
            response = reader.country(ip)
            return response.country.iso_code
        
        except geoip2.errors.AddressNotFoundError:
            print(f"GeoIP country not found for IP: {ip}")
            return None

        except Exception as e:
            print(f"GeoIP error for IP {ip}: {e}")
            return None
        

def expand_alliance(countries, alliances):
    expanded = set(countries)
    changed = True
    
    while changed:
        changed = False

        for group in alliances:
            group_set = set(group)

            if expanded & group_set and not group_set.issubset(expanded):
                expanded |= group_set
                changed = True
                
    return expanded


def guard_security(client_ip, guards, trust, alliances):
    if not trust:
        return 0.0

    client_country  = ip_to_country(client_ip)    
    guard_countries = { ip_to_country(guard["ip"]) for guard in guards }

    compromised = expand_alliance({client_country}, alliances) & expand_alliance(guard_countries, alliances)

    # compute weighted safe fraction of countries
    total_weight = sum(trust.values())
    safe_weight = sum(weight for country, weight in trust.items() if country not in compromised)
    return safe_weight / total_weight if total_weight > 0 else 0.0


def exit_security(client_ip, dest_ip, guard, exit, trust, alliances):
    if not trust:
        return 0.0

    client_country = ip_to_country(client_ip)
    guard_country  = ip_to_country(guard["ip"])
    dest_country   = ip_to_country(dest_ip)
    exit_country   = ip_to_country(exit["ip"])

    # build compromised sets on each side
    left_bad  = expand_alliance({client_country, guard_country}, alliances)
    right_bad = expand_alliance({exit_country, dest_country}, alliances)

    # a country is safe unless it is in *both* left_bad and right_bad
    total_weight = sum(trust.values())
    safe_weight = 0
    for country, weight in trust.items():
        if not (country in left_bad and country in right_bad):
            safe_weight += weight
    return safe_weight / total_weight if total_weight > 0 else 0.0


def secure_relays(alpha, scores, relays, weights):
    R = sorted(relays, key=lambda r: scores[r], reverse=True)
    s = scores[R[0]] # maximum score
    n = len(relays) # number of relays
    S, w, i = set(), 0, 0

    # add all safe relays
    while ((i < n) and
            (scores[R[i]] >= (alpha['safe_upper'] * s)) and 
            ((1 - scores[R[i]]) <= (alpha['safe_lower'] * (1 - s)))):
        S.add(R[i])
        w += weights[R[i]]
        i += 1

    # add all acceptable relays
    while ((i < n) and
            (scores[R[i]] >= (alpha['accept_upper'] * s)) and
            ((1 - scores[R[i]]) <= (alpha['accept_lower'] * (1 - s))) and
            (w < alpha['bandwidth_frac'])):
        S.add(R[i])
        w += weights[R[i]]
        i += 1

    return S


def select_path(relays, alpha_guard, alpha_exit, client_ip, dest_ip, trust, alliances):
    relay_by_fingerprint = {r['fingerprint']: r for r in relays}
    bandwidths = {r['fingerprint']: r['bandwidth'] for r in relays}
    guards = [r for r in relays if r.get("is_guard", False)]
    exits = [r for r in relays if r.get("is_exit", False)]

    # score guards
    score = guard_security(client_ip, guards, trust, alliances)
    guard_scores = {g['fingerprint']: score for g in guards}
    secure_guards = secure_relays(alpha_guard, guard_scores, [g['fingerprint'] for g in guards], bandwidths)
    if not secure_guards:
        raise Exception("No secure guards available!")

    # choose guard (bandwidth-weighted)
    guard_fp = random.choices(
        population=list(secure_guards),
        weights=[bandwidths[f] for f in secure_guards],
        k=1
    )[0]
    guard = relay_by_fingerprint[guard_fp]

    # score exits (using selected guard)
    exit_scores = {
        e['fingerprint']: exit_security(client_ip, dest_ip, guard, e, trust, alliances)
        for e in exits
    }
    secure_exits = secure_relays(alpha_exit, exit_scores, [e['fingerprint'] for e in exits], bandwidths)
    if not secure_exits:
        raise Exception("No secure exits available!")

    # choose exit (bandwidth-weighted)
    exit_fp = random.choices(
        population=list(secure_exits),
        weights=[bandwidths[f] for f in secure_exits],
        k=1
    )[0]
    exit = relay_by_fingerprint[exit_fp]

    # choose middle relay randomly (not guard or exit or same family)
    guard_family = set(guard.get("family", []))
    exit_family = set(exit.get("family", []))
    middle_candidates = [
        r for r in relays if r['fingerprint'] not in [guard_fp, exit_fp]
        and r['fingerprint'] not in guard_family
        and r['fingerprint'] not in exit_family
    ]
    if not middle_candidates:
        raise Exception("No valid middle relays!")
    middle = random.choice(middle_candidates)

    # final path
    return {
        "guard": guard_fp,
        "middle": middle["fingerprint"],
        "exit": exit_fp
    }


if __name__ == "__main__":
    with open("client_input.json") as f:
        client_data = json.load(f)

    with open("tor_consensus.json") as f:
        consensus_data = json.load(f)

    alliances, trust, client_ip, dest_ip = parse_client_input(client_data)
    relays = filter_relays(parse_tor_consensus(consensus_data), trust) # get only relays refered by the client

    alpha_guard = {
    'safe_upper': 0.95, 'safe_lower': 2.0,
    'accept_upper': 0.5, 'accept_lower': 5.0,
    'bandwidth_frac': 0.2
    }
    alpha_exit = {
        'safe_upper': 0.95, 'safe_lower': 2.0,
        'accept_upper': 0.1, 'accept_lower': 10.0,
        'bandwidth_frac': 0.2
    }

    path = select_path(relays, alpha_guard, alpha_exit, client_ip, dest_ip, trust, alliances)
    print("-- Selected Path --\n", path)
    
    print("\n-- Extra Info --")
    relay_by_fingerprint = {r["fingerprint"]: r for r in relays}
    for role in ["guard", "middle", "exit"]:
        fp = path[role]
        relay = relay_by_fingerprint[fp]
        country = ip_to_country(relay["ip"])
        print(f"({role}) - {fp} ({country}) - IP: {relay['ip']}")
