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

from datetime import datetime, timezone
from pathlib import Path

from switchmap_py.model.port import Port
from switchmap_py.model.switch import Switch
from switchmap_py.render.build import build_site
from switchmap_py.storage.idlesince_store import IdleSinceStore
from switchmap_py.storage.maclist_store import MacListStore


def test_build_site_copies_binary_assets(tmp_path):
    template_dir = Path(__file__).resolve().parents[1] / "switchmap_py" / "render" / "templates"
    static_dir = tmp_path / "static"
    static_dir.mkdir()

    binary_data = b"\x00\x01\xffbinary"
    (static_dir / "asset.bin").write_bytes(binary_data)

    nested_dir = static_dir / "nested"
    nested_dir.mkdir()
    nested_data = b"\x10\x11nested"
    (nested_dir / "nested.bin").write_bytes(nested_data)

    output_dir = tmp_path / "output"
    build_site(
        switches=[
            Switch(
                name="sw1",
                management_ip="192.0.2.1",
                vendor="test",
            )
        ],
        failed_switches=[],
        output_dir=output_dir,
        template_dir=template_dir,
        static_dir=static_dir,
        idlesince_store=IdleSinceStore(tmp_path / "idlesince"),
        maclist_store=MacListStore(tmp_path / "maclist.json"),
        build_date=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )

    assert (output_dir / "asset.bin").read_bytes() == binary_data
    assert (output_dir / "nested" / "nested.bin").read_bytes() == nested_data


def test_build_site_escapes_xss_in_user_controlled_data(tmp_path):
    """
    Regression test for XSS vulnerability in Jinja2 autoescape configuration.
    
    Previously, templates with .html.j2 extension were NOT autoescaped because
    select_autoescape(["html"]) did not match the .j2 extension.
    
    This test ensures that XSS-prone data from SNMP, CSV, or user input
    (switch names, port descriptions, failed switch names) is properly escaped
    in the generated HTML to prevent stored XSS attacks.
    """
    template_dir = Path(__file__).resolve().parents[1] / "switchmap_py" / "render" / "templates"
    static_dir = tmp_path / "static"
    static_dir.mkdir()
    
    # XSS payload that should be escaped
    xss_payload = '<script>alert("XSS")</script>'
    xss_port_descr = f'Infected Port {xss_payload}'
    xss_vendor = f'Evil Vendor {xss_payload}'
    xss_failed_switch = f'bad-switch{xss_payload}'
    
    output_dir = tmp_path / "output"
    build_site(
        switches=[
            Switch(
                name="test-switch",  # Safe filename, but vendor will have XSS
                management_ip="192.0.2.10",
                vendor=xss_vendor,
                ports=[
                    Port(
                        name="eth0",
                        descr=xss_port_descr,
                        admin_status="up",
                        oper_status="up",
                        speed=1000,
                        vlan="1",
                    )
                ],
            )
        ],
        failed_switches=[xss_failed_switch],
        output_dir=output_dir,
        template_dir=template_dir,
        static_dir=static_dir,
        idlesince_store=IdleSinceStore(tmp_path / "idlesince"),
        maclist_store=MacListStore(tmp_path / "maclist.json"),
        build_date=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )
    
    # Check index.html - should escape failed switch name
    index_html = (output_dir / "index.html").read_text()
    assert xss_payload not in index_html, "XSS payload should not appear unescaped in index.html"
    assert "&lt;script&gt;" in index_html, "Script tags should be HTML-escaped in index.html"
    
    # Check switch page - should escape port description
    switch_html = (output_dir / "switches" / "test-switch.html").read_text()
    assert xss_payload not in switch_html, "XSS payload should not appear unescaped in switch.html"
    assert "&lt;script&gt;" in switch_html, "Script tags should be HTML-escaped in switch.html"
    
    # Check ports page - should escape port description
    ports_html = (output_dir / "ports" / "index.html").read_text()
    assert xss_payload not in ports_html, "XSS payload should not appear unescaped in ports.html"
    assert "&lt;script&gt;" in ports_html, "Script tags should be HTML-escaped in ports.html"
