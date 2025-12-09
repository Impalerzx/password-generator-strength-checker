from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List


_DICTIONARY_WORDS = {
    "password",
    "qwerty",
    "admin",
    "letmein",
    "welcome",
    "login",
    "user",
    "root",
    "123456",
    "12345678",
    "iloveyou",
}


@dataclass
class PasswordReport:
    score: int
    category: str
    is_dictionary_like: bool
    recommendations: List[str]


def _count_character_classes(password: str) -> int:
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)

    return sum([has_lower, has_upper, has_digit, has_symbol])


def _penalty_for_repeated_sequences(password: str) -> int:
    """
    Simple penalty for repeated characters in a row.
    For every sequence of length > 2, subtract some points.
    """
    if not password:
        return 0

    penalty = 0
    current_char = password[0]
    current_run = 1

    for ch in password[1:]:
        if ch == current_char:
            current_run += 1
        else:
            if current_run >= 3:
                penalty += (current_run - 2) * 2
            current_char = ch
            current_run = 1

    if current_run >= 3:
        penalty += (current_run - 2) * 2

    return penalty


def _looks_like_single_class(password: str) -> bool:
    """
    Detect simple patterns like:
    - only letters
    - only digits
    - only symbols
    """
    if not password:
        return True

    if password.isdigit():
        return True
    if password.isalpha():
        return True
    if all(not c.isalnum() for c in password):
        return True

    return False


def _strip_edge_digits(value: str) -> str:
    """Remove digits from both ends, keep middle part."""
    return re.sub(r"^\d+|\d+$", "", value)


def _is_dictionary_like(password: str) -> bool:
    """
    Very simple dictionary check:
    - Case-insensitive
    - Remove digits at the start and end
    - Compare against small built-in list
    """
    normalized = password.lower()
    normalized = _strip_edge_digits(normalized)

    if not normalized:
        return False

    for word in _DICTIONARY_WORDS:
        if normalized == word:
            return True
        # Also consider simple leetspeak equivalent like 'password1', 'p@ssword'
        if len(normalized) >= 4 and word in normalized:
            return True

    return False


def _categorize_score(score: int) -> str:
    if score < 20:
        return "very weak"
    if score < 40:
        return "weak"
    if score < 60:
        return "medium"
    if score < 80:
        return "strong"
    return "very strong"


def check_password_strength(password: str) -> PasswordReport:
    """
    Calculate a simple password strength score from 0 to 100.

    The score is based on:
    - Length
    - Variety of character classes (lower/upper/digits/symbols)
    - Penalty for simple patterns and repeated sequences
    - Penalty for dictionary-like passwords
    """
    length = len(password)

    # Base score from length (0–50)
    length_score = min(length * 3, 50)

    # Score from character classes (0–30)
    class_count = _count_character_classes(password)
    class_score = class_count * 8  # 0–32, later capped

    score = length_score + class_score

    # Penalty for repeated sequences
    repeat_penalty = _penalty_for_repeated_sequences(password)
    score -= repeat_penalty

    # Penalty for very simple patterns
    if _looks_like_single_class(password):
        score -= 15

    is_dict_like = _is_dictionary_like(password)
    if is_dict_like:
        score -= 35

    # Clamp score to [0, 100]
    score = max(0, min(100, score))

    category = _categorize_score(score)

    recommendations: List[str] = []
    if length < 12:
        recommendations.append("Increase password length to at least 12 characters.")
    if class_count <= 2:
        recommendations.append(
            "Add more character types (uppercase, lowercase, digits, symbols)."
        )
    if _looks_like_single_class(password):
        recommendations.append(
            "Avoid passwords that use only letters, only digits, or only symbols."
        )
    if repeat_penalty > 0:
        recommendations.append("Avoid long runs of the same character.")
    if is_dict_like:
        recommendations.append(
            "Avoid passwords that look like common words or simple phrases."
        )
    if not recommendations and category != "very strong":
        recommendations.append(
            "Consider using a longer passphrase with multiple unrelated words."
        )

    return PasswordReport(
        score=score,
        category=category,
        is_dictionary_like=is_dict_like,
        recommendations=recommendations,
    )
