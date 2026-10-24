"""
test_group_mapping module.

Tests for :func:`load_group_mapping`.

:author: Ron Webb
:since: 1.6.0
"""

from java_dependency_analyzer.util.group_mapping import load_group_mapping

__author__ = "Ron Webb"
__since__ = "1.6.0"


class TestLoadGroupMapping:
    """Tests for ``load_group_mapping``."""

    def test_reads_group_and_artifact(self, tmp_path):
        """Each ``<group>:<artifact>`` line should map the artifact to its group."""
        mapping_file = tmp_path / "mapping.txt"
        mapping_file.write_text(
            "org.apache.logging.log4j:log4j-core\ncom.google.guava:guava\n",
            encoding="utf-8",
        )

        assert load_group_mapping(str(mapping_file)) == {
            "log4j-core": ["org.apache.logging.log4j"],
            "guava": ["com.google.guava"],
        }

    def test_ignores_blank_comment_and_bom(self, tmp_path):
        """Blank lines, comments and a UTF-8 BOM should be tolerated."""
        mapping_file = tmp_path / "mapping.txt"
        mapping_file.write_bytes(b"\xef\xbb\xbf# note\n\n  g1 : a1  \n")

        assert load_group_mapping(str(mapping_file)) == {"a1": ["g1"]}

    def test_keeps_all_groups_in_order_without_duplicates(self, tmp_path):
        """An artifact under several groups should keep them in file order."""
        mapping_file = tmp_path / "mapping.txt"
        mapping_file.write_text("g1:a\ng2:a\ng1:a\n", encoding="utf-8")

        assert load_group_mapping(str(mapping_file)) == {"a": ["g1", "g2"]}

    def test_skips_malformed_lines(self, tmp_path):
        """Lines without exactly a group and an artifact should be skipped."""
        mapping_file = tmp_path / "mapping.txt"
        mapping_file.write_text(
            "no-colon\n:artifact-only\ngroup-only:\ng:a:extra\ng:ok\n",
            encoding="utf-8",
        )

        assert load_group_mapping(str(mapping_file)) == {"ok": ["g"]}
