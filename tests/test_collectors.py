# Copyright 2025 OpenAI Codex
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

from switchmap_py.config import SwitchConfig
from switchmap_py.snmp import collectors, mibs


class StubSession:
    def __init__(self, tables):
        self._tables = tables

    def get_table(self, oid):
        return self._tables.get(oid, {})


def test_collect_switch_state_falls_back_to_descr_or_ifindex(monkeypatch):
    switch = SwitchConfig(
        name="sw1",
        management_ip="192.0.2.1",
        community="public",
        trunk_ports=["Gi1/0/1"],
    )
    tables = {
        mibs.IF_NAME: {
            f"{mibs.IF_NAME}.1": "",
            f"{mibs.IF_NAME}.2": "",
        },
        mibs.IF_DESCR: {
            f"{mibs.IF_DESCR}.1": "Gi1/0/1",
            f"{mibs.IF_DESCR}.2": "",
        },
        mibs.IF_ADMIN_STATUS: {
            f"{mibs.IF_ADMIN_STATUS}.1": "1",
            f"{mibs.IF_ADMIN_STATUS}.2": "1",
        },
        mibs.IF_OPER_STATUS: {
            f"{mibs.IF_OPER_STATUS}.1": "1",
            f"{mibs.IF_OPER_STATUS}.2": "2",
        },
        mibs.IF_SPEED: {
            f"{mibs.IF_SPEED}.1": "1000",
            f"{mibs.IF_SPEED}.2": "1000",
        },
    }

    monkeypatch.setattr(
        collectors,
        "build_session",
        lambda *_args, **_kwargs: StubSession(tables),
    )
    monkeypatch.setattr(collectors, "_collect_macs", lambda _session: {})

    state = collectors.collect_switch_state(switch, timeout=1, retries=0)
    assert state.ports[0].name == "Gi1/0/1"
    assert state.ports[0].is_trunk is True
    assert state.ports[1].name == "2"
