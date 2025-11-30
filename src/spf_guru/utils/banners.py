"""Fortune-telling style banners for SPF results."""

import random
from typing import List

PASS_BANNERS: List[str] = [
    "The SPF Guru's tarot reveals '{result}' as The Star - hope guides this message.",
    "The SPF Guru's crystal whispers '{result}' into the ethers of deliverability.",
    "From the Guru's cards emerges '{result}' beneath The Sun - clarity shines.",
    "The SPF Guru's I Ching hexagram speaks '{result}' - harmony blesses this mail.",
    "The Guru's pendulum swings to '{result}' - fate smiles upon your e-mail.",
    "Runes inscribed by the SPF Guru etch '{result}' on the scroll of destiny.",
    "Under the Guru's moonlight gaze, '{result}' unfolds - intuition vindicates.",
    "Tea leaves read by the Guru form the symbol '{result}' - prophecy confirmed.",
    "The Guru's astrolabe charts a path marked '{result}' - cosmic winds align.",
    "In the Guru's scrying pool, '{result}' shimmers - mystical forces decree.",
]

FAIL_BANNERS: List[str] = [
    "The SPF Guru's tarot reveals '{result}' as The Tower - caution beckons.",
    "The Guru's crystal cracks with '{result}' - obstacles guard this mail.",
    "From the cards emerges '{result}' under The Moon - shadows heed your caution.",
    "The SPF Guru's I Ching hexagram speaks '{result}' - discord stirs the realm.",
    "The Guru's pendulum swings to '{result}' - fate warns of blocked passage.",
    "Runes inscribed by the SPF Guru carve '{result}' into the dark scroll.",
    "Under the Guru's moonlit scrutiny, '{result}' collapses - intuition urges retreat.",
    "Tea leaves read by the Guru form the omen '{result}' - prophecy halts deliverability.",
    "The Guru's astrolabe indicates '{result}' - cosmic currents oppose this mail.",
    "In the Guru's scrying pool, '{result}' darkens - mystical forces decree rebuke.",
]


def get_banner(result: str) -> str:
    """
    Return a fortune-telling style SPF banner based on the result.

    Args:
        result: The SPF result, e.g., 'PASS' or 'FAIL'.

    Returns:
        A randomly selected mystical banner with the result interpolated.
    """
    key = result.strip().upper()

    if key == "PASS":
        return random.choice(PASS_BANNERS).format(result=result)

    return random.choice(FAIL_BANNERS).format(result=result)
