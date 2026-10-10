"""Check the function-value zero-fold transformer and its refusals.

The fixture is a structural stand-in for the guard `rac2_reg_live_after_store_p`
and the three anchors of `rac2_fold_zero_ti_store`; it carries the shapes the
transformer searches for and nothing else. It is not a compiler source and is
not evidence of instruction-level matching.
"""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/compiler/fold_zero_ti_return_value.py"


def fixture() -> str:
    """The qualified guard and the three pass anchors, before the transform."""
    return "".join((
        "void\nmachine_dependent_reorg (first)\n{\n  return;\n}\n",
        "\nstatic int\nrac2_reg_live_after_store_p (insn, reg)\n",
        "     rtx insn;\n     rtx reg;\n{\n",
        "  rtx scan;\n\n",
        "  for (scan = NEXT_INSN (insn); scan; scan = NEXT_INSN (scan))\n    {\n",
        "      rtx pat, set;\n\n",
        "      if (reg_referenced_p (reg, pat))\n\treturn 1;\n",
        "    }\n\n  return 0;\n}\n",
        "\nvoid\nrac2_fold_zero_ti_store (first)\n     rtx first;\n{\n",
        "  for (insn = first; insn; insn = NEXT_INSN (insn))\n    {\n",
        "      rtx set, prev, pset, reg;\n      int steps;\n\n",
        "      if (rac2_reg_live_after_store_p (insn, reg))\n\tcontinue;\n\n",
        "      validate_change (insn, &SET_SRC (set), gen_rtx_REG (TImode, 0), 1);\n",
        "      if (! apply_change_group ())\n\tcontinue;\n\n",
        "      delete_insn (pset);\n    }\n}\n",
    ))


def run(gcc: Path, *flags: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, *flags, "-I", str(SCRIPT), str(gcc)],
                          capture_output=True, text=True)


def place(gcc: Path, source: str) -> Path:
    """Write the fixture where the transformer looks for it: config/mips/mips.c."""
    path = gcc / "config/mips/mips.c"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8", newline="")
    return path


class ZeroReturnValueFoldTests(unittest.TestCase):
    def transform(self, source: str, *flags: str) -> str:
        with tempfile.TemporaryDirectory() as directory:
            gcc = Path(directory)
            path = place(gcc, source)
            result = run(gcc, *flags)
            self.assertEqual(result.returncode, 0, result.stderr)
            return path.read_text(encoding="utf-8")

    def test_the_guard_becomes_three_state_and_keeps_the_original_rule(self):
        out = self.transform(fixture())
        # the original refusal and the rewritten-register end-of-life survive
        self.assertIn("return 1;", out)
        self.assertEqual(out.count("return rac2_fvu_insn != 0 ? 2 : 0;"), 2)
        self.assertIn("rac2_fvu_insn = scan;", out)
        self.assertIn("rac2_fvu_reg = used;", out)
        # the region was rebuilt, everything outside it is untouched
        self.assertIn("void\nmachine_dependent_reorg (first)\n{\n  return;\n}\n", out)
        self.assertIn("void\nrac2_fold_zero_ti_store (first)\n", out)

    def test_case_two_is_bounded_by_four_conditions(self):
        out = self.transform(fixture())
        start = out.index("static int\nrac2_reg_live_after_store_p")
        end = out.index("void\nrac2_fold_zero_ti_store")
        guard = out[start:end]
        # exact `(use (reg/i ...))` shape, same register, value-return flag,
        # straight line and a single use
        self.assertIn("GET_CODE (pat) == USE ? XEXP (pat, 0) : 0", guard)
        self.assertIn("REGNO (used) == REGNO (reg)", guard)
        self.assertIn("REG_FUNCTION_VALUE_P (used)", guard)
        self.assertIn("past_control == 0", guard)
        self.assertIn("rac2_fvu_insn == 0", guard)
        # a jump or a call between the store and the use disqualifies the case
        self.assertIn("GET_CODE (scan) == JUMP_INSN || GET_CODE (scan) == CALL_INSN", guard)
        self.assertIn("past_control = 1;", guard)

    def test_the_two_changes_go_into_one_change_group(self):
        out = self.transform(fixture())
        fold = out.index("validate_change (insn, &SET_SRC (set), gen_rtx_REG (TImode, 0), 1);")
        remat = out.index("if (live == 2)", fold)
        second = out.index("validate_change (rac2_fvu_insn, &PATTERN (rac2_fvu_insn),", remat)
        apply_at = out.index("if (! apply_change_group ())", second)
        self.assertLess(fold, remat)
        self.assertLess(remat, second)
        self.assertLess(second, apply_at)
        # the fold is only skipped for the living case, never for case 2
        self.assertIn("live = rac2_reg_live_after_store_p (insn, reg);", out)
        self.assertIn("if (live == 1)", out)
        self.assertNotIn("if (rac2_reg_live_after_store_p (insn, reg))", out)
        # the re-materialised return is the plain set form of the pre-reload RTL
        self.assertIn("gen_rtx (SET, VOIDmode, copy_rtx (rac2_fvu_reg),", out)
        self.assertIn("const0_rtx)", out)

    def test_reapplication_is_a_no_op_that_leaves_the_file_alone(self):
        once = self.transform(fixture())
        with tempfile.TemporaryDirectory() as directory:
            gcc = Path(directory)
            path = place(gcc, once)
            for flags in ([], ["-O"]):
                again = run(gcc, *flags)
                self.assertEqual(again.returncode, 0, again.stderr)
                self.assertIn("deja applique", again.stdout)
                self.assertEqual(path.read_text(encoding="utf-8"), once)

    def test_a_missing_guard_anchor_stops_the_transform(self):
        broken = fixture().replace(
            "static int\nrac2_reg_live_after_store_p (insn, reg)",
            "static int\nrac2_reg_live_after_store_p (insn, other)")
        with tempfile.TemporaryDirectory() as directory:
            gcc = Path(directory)
            path = place(gcc, broken)
            result = run(gcc)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(path.read_text(encoding="utf-8"), broken)

    def test_a_missing_pass_anchor_stops_the_transform(self):
        broken = fixture().replace(
            "      validate_change (insn, &SET_SRC (set), gen_rtx_REG (TImode, 0), 1);\n",
            "      validate_change (insn, &SET_SRC (set), gen_rtx_REG (TImode, 0), 0);\n")
        with tempfile.TemporaryDirectory() as directory:
            gcc = Path(directory)
            path = place(gcc, broken)
            result = run(gcc)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(path.read_text(encoding="utf-8"), broken)

    def test_the_annotation_states_the_rule_it_extends(self):
        out = self.transform(fixture())
        self.assertIn("RAC2 : le zero TImode materialise peut aussi etre lu par la valeur de", out)
        self.assertIn("rematerialise en clair dans l'insn de retour", out)


if __name__ == "__main__":
    unittest.main()
