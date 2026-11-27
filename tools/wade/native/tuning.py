# SPDX-License-Identifier: AGPL-3.0-or-later
"""Conservative, offline champion/challenger review; never mutates detections."""
from dataclasses import dataclass
from state import digest


@dataclass(frozen=True)
class Case:
    id: str
    label: str
    champion: str
    challenger: str
    protected: bool = False


def review(champion_digest, challenger_digest, cases, *, min_benign=20, min_malicious=10):
    from state import hexid
    hexid(champion_digest); hexid(challenger_digest)
    if champion_digest == challenger_digest or type(min_benign) is not int or type(min_malicious) is not int or min(min_benign, min_malicious) < 1:
        raise ValueError('invalid review policy')
    if len(cases) > 100000:
        raise ValueError('cohort limit')
    unique = {}
    for c in cases:
        if (not isinstance(c, Case) or not isinstance(c.id, str) or not 1 <= len(c.id) <= 1024
                or c.label not in ('BENIGN', 'MALICIOUS', 'UNLABELLED')
                or c.champion not in ('MATCH', 'NO_MATCH', 'UNKNOWN')
                or c.challenger not in ('MATCH', 'NO_MATCH', 'UNKNOWN') or type(c.protected) is not bool):
            raise ValueError('invalid case')
        if c.id in unique:
            raise ValueError('duplicate case ID')
        unique[c.id] = c
    rows = [unique[k] for k in sorted(unique)]
    benign = [c for c in rows if c.label == 'BENIGN']
    malicious = [c for c in rows if c.label == 'MALICIOUS']
    unknown = [c for c in benign + malicious if 'UNKNOWN' in (c.champion, c.challenger)]
    regressions = [c.id for c in malicious if c.champion == 'MATCH' and c.challenger != 'MATCH']
    protected = [c.id for c in rows if c.protected and (c.label != 'MALICIOUS' or c.challenger != 'MATCH')]
    before = sum(c.champion == 'MATCH' for c in benign)
    after = sum(c.challenger == 'MATCH' for c in benign)
    reasons = []
    if len(benign) < min_benign or len(malicious) < min_malicious: reasons.append('INSUFFICIENT_LABELLED_COHORT')
    if unknown: reasons.append('INCOMPLETE_PAIRED_EVALUATION')
    if regressions: reasons.append('MALICIOUS_REGRESSION')
    if protected: reasons.append('PROTECTED_CASE_FAILURE')
    if after >= before: reasons.append('NO_FALSE_POSITIVE_REDUCTION')
    receipt = digest('wade-tuning-review-v1', champion_digest, challenger_digest, str(min_benign), str(min_malicious),
                     *(digest(c.id,c.label,c.champion,c.challenger,str(c.protected)) for c in rows))
    return {'status': 'WITHHELD' if reasons else 'REVIEW_CANDIDATE', 'receipt': receipt,
            'reasons': reasons, 'benign': len(benign), 'malicious': len(malicious),
            'unlabelled': len(rows)-len(benign)-len(malicious), 'unknown': len(unknown),
            'false_positives_before': before, 'false_positives_after': after,
            'malicious_regressions': regressions, 'protected_failures': protected,
            'requires_human_approval': True}
