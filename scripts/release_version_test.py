#!/usr/bin/env python3
import unittest

from scripts.release_version import allocate_version


class ReleaseVersionTests(unittest.TestCase):
    day = "2026-10-24"

    def test_allocates_the_first_tag_of_a_day(self) -> None:
        self.assertEqual(allocate_version([], self.day, []), self.day)

    def test_allocates_a_suffix_after_a_collision(self) -> None:
        self.assertEqual(allocate_version([self.day], self.day, []), f"{self.day}.1")

    def test_increments_the_largest_numeric_suffix(self) -> None:
        self.assertEqual(
            allocate_version([self.day, f"{self.day}.1", f"{self.day}.9"], self.day, []),
            f"{self.day}.10",
        )

    def test_starts_a_new_sequence_on_the_next_day(self) -> None:
        self.assertEqual(
            allocate_version([self.day, f"{self.day}.3"], "2026-10-25", []),
            "2026-10-25",
        )

    def test_reuses_a_dated_tag_already_pointing_at_the_commit(self) -> None:
        self.assertEqual(
            allocate_version([self.day, f"{self.day}.1"], self.day, [f"{self.day}.1"]),
            f"{self.day}.1",
        )

    def test_reuses_the_highest_existing_suffix_for_a_reexecution(self) -> None:
        self.assertEqual(
            allocate_version([self.day, f"{self.day}.9", f"{self.day}.10"], self.day, [f"{self.day}.9", f"{self.day}.10"]),
            f"{self.day}.10",
        )

    def test_serial_allocations_choose_distinct_versions(self) -> None:
        first = allocate_version([self.day], self.day, [])
        second = allocate_version([self.day, first], self.day, [])
        self.assertEqual((first, second), (f"{self.day}.1", f"{self.day}.2"))


if __name__ == "__main__":
    unittest.main()
