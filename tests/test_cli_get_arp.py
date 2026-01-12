# Copyright 2024
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# This file was created or modified with the assistance of an AI (Large Language Model).
# Review required for correctness, security, and licensing.

import json
import logging

from switchmap_py.cli import get_arp


def test_get_arp_invalid_rows(tmp_path, caplog):
    csv_path = tmp_path / "maclist.csv"
    csv_path.write_text(
        "\n".join(
            [
                "# comment row",
                "aa:bb:cc:dd:ee:ff,192.0.2.10,example-host",
                "11:22:33:44:55:66,",
                "not-a-mac,192.0.2.11",
                "22:33:44:55:66:77,999.999.999.999",
                "missing-columns",
            ]
        )
    )
    maclist_path = tmp_path / "maclist.json"
    config_path = tmp_path / "site.yml"
    config_path.write_text(f"maclist_file: {maclist_path}\n")

    caplog.set_level(logging.WARNING)

    get_arp(source="csv", csv_path=csv_path, config=config_path, logfile=None)

    saved = json.loads(maclist_path.read_text())
    assert len(saved) == 1
    assert saved[0]["mac"] == "aa:bb:cc:dd:ee:ff"
    assert saved[0]["ip"] == "192.0.2.10"
    assert any("Skipping CSV row" in record.message for record in caplog.records)
