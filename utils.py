def parse_alerts(alerts):
    clean = []
    for a in alerts:
        if a['risk'] == "Informational":
            continue

        clean.append({
            "name": a['alert'],
            "risk": a['risk'],
            "url": a['url']
        })
    return clean


def calculate_score(alerts):
    score = 100
    for a in alerts:
        if a['risk'] == "High":
            score -= 20
        elif a['risk'] == "Medium":
            score -= 10
        elif a['risk'] == "Low":
            score -= 5
    return max(score, 0)