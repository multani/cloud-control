import random


def random_delay(maximum: int = 30) -> float:
    return random.random() * maximum
