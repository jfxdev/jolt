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

    def test_reuses_the_first_publication_version_after_midnight(self) -> None:
        self.assertEqual(
            allocate_version([self.day], "2026-10-25", [self.day]),
            self.day,
        )

    def test_concurrent_collision_retries_with_the_next_version(self) -> None:
        # Two publishers can observe the same snapshot. The workflow reserves
        # with an atomic ref creation; the loser reloads this updated snapshot.
        first = allocate_version([self.day], self.day, [])
        colliding_attempt = allocate_version([self.day], self.day, [])
        retry = allocate_version([self.day, first], self.day, [])
        self.assertEqual((first, colliding_attempt, retry), (f"{self.day}.1", f"{self.day}.1", f"{self.day}.2"))


if __name__ == "__main__":
    unittest.main()
