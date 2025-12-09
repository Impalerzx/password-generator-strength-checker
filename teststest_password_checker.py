from __future__ import annotations

from password_checker import check_password_strength


def test_very_weak_password():
    report = check_password_strength("123456")
    assert report.score < 30
    assert report.category in {"very weak", "weak"}


def test_medium_password():
    report = check_password_strength("Abcdef1234")
    assert report.score >= 40
    assert report.score <= 80


def test_strong_password():
    report = check_password_strength("Ab!9zP#2kLmQ")
    assert report.score >= 60


def test_dictionary_like_penalty():
    report_plain = check_password_strength("password")
    report_complex = check_password_strength("P@ssw0rd!123")
    assert report_plain.score < report_complex.score
    assert report_plain.is_dictionary_like
