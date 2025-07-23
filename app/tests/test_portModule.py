from types import SimpleNamespace

def test_port_resolver_roundtrip(monkeypatch, pano_stub):
    from ruleGenerator.core import PanoramaInventory, build_port_maps

    inv = PanoramaInventory(pano_stub)

    # Patch minimal stub app svc so build_port_maps has data
    app = SimpleNamespace(name="web-http", default_port=["tcp/80"])
    svc = SimpleNamespace(name="svc_www", protocol="tcp", destination_port="8080")
    monkeypatch.setattr(inv, "applicationObjects", [app])
    monkeypatch.setattr(inv, "_predefAppObjects", {})
    monkeypatch.setattr(inv, "serviceObjects", [svc])
    monkeypatch.setattr(inv, "_predefServiceObjects", {})

    resolver = build_port_maps(inv)
    out = resolver.enrich_rule_with_ports(
        apps=["web-http"], services=["svc_www"], service_field_raw=["application-default", "svc_www"]
    )
    assert set(out["resolvedPorts"]) == {"tcp/80", "tcp/8080"}
