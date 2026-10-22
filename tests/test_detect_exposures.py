import sys
import unittest
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import detect_exposures as detector


class DetectionTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.input_path = ROOT / "authorized_exposure_input.csv"
        cls.source = pd.read_csv(cls.input_path, dtype=str)

    def test_expected_findings_are_generated(self):
        data = detector.validate_input(self.source.copy())
        findings, skipped = detector.build_findings(data)

        self.assertEqual(len(findings), 8)
        self.assertEqual(skipped["unconfirmed"], 2)
        self.assertEqual(
            int((findings["severity"] == "Critical").sum()), 3
        )

    def test_raw_password_column_is_rejected(self):
        data = self.source.copy()
        data["password"] = "NEVER-USE-REAL-SECRETS"

        with self.assertRaisesRegex(ValueError, "prohibited raw-secret"):
            detector.validate_input(data)

    def test_unconfirmed_records_are_not_findings(self):
        data = detector.validate_input(self.source.copy())
        findings, _ = detector.build_findings(data)

        self.assertNotIn("R-004", findings["finding_id"].values)
        self.assertNotIn("R-007", findings["finding_id"].values)


if __name__ == "__main__":
    unittest.main(verbosity=2)
