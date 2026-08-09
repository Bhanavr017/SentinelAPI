def calculate_risk(features:dict):
    score=0
    if not features["https"]:
        score+=20
    if features["url_length"]>75:
        score+=15
    if features["has_ip"]:
        score+=30
    if features["has_at_symbol"]:
        score+=15
    if features["dot_count"]>3:
        score+=10
    if features["hyphen_count"]>2:
        score+=10
    score+=features["suspicious_keywords"]*10
    score=min(score,100)
    if score<20:
        label="Safe"
    elif score<50:
        label="Suspicious"
    else:
        label="Malicious"
    return score,label
