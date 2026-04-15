# 06_custom_oid.rego
#
# Matching on custom certificate extensions.
#
# The plugin walks every X509 extension whose OID is unknown to OpenSSL
# and emits an entry in input.cert.custom_extensions[]:
#
#   [
#     {"oid":"1.3.6.1.4.1.99999.1", "critical":false,
#      "value_type":"utf8string", "value":"fleet-a",
#      "value_hex":"0c076669656c652d61"}
#   ]
#
# The decoder tries UTF8/Printable/IA5/BMP/T61/Universal/Visible strings,
# OCTET STRING (recursive unwrap), and a raw-ASCII fallback. Whatever it
# recovers is at `value` with `value_type` naming the ASN.1 flavour.
#
# Chain freshness is checked alongside — a cert with a recognised fleet
# tag but an expired intermediate still gets rejected.

package mqtt

fleet_oid        := "1.3.6.1.4.1.99999.1"
device_class_oid := "1.3.6.1.4.1.99999.2"

# Value for a given OID, or undefined if absent / not decodable.
ext_value(oid) := v {
    some i
    input.cert.custom_extensions[i].oid == oid
    v := input.cert.custom_extensions[i].value
    v != null
}

client_fleet := v { v := ext_value(fleet_oid) }
client_class := v { v := ext_value(device_class_oid) }

# Every cert in the chain within its validity window.
now_sec := input.now_unix_ms / 1000
chain_currently_valid { not chain_validity_breach_exists }
chain_validity_breach_exists {
    some i
    input.cert.chain[i].not_before_unix > now_sec
}
chain_validity_breach_exists {
    some i
    input.cert.chain[i].not_after_unix <= now_sec
}

default connect := false
default acl := false

connect {
    input.cert.chain_ok
    input.cert.cn != ""
    client_fleet == "fleet-a"
    chain_currently_valid
}

connect {
    input.cert.chain_ok
    input.cert.cn != ""
    client_fleet == "fleet-b"
    chain_currently_valid
}

# Fleet clients are scoped to their own fleet subtree.
acl {
    client_fleet == "fleet-a"
    startswith(input.acl.topic, "fleet-a/")
}

acl {
    client_fleet == "fleet-b"
    startswith(input.acl.topic, "fleet-b/")
}

# Gateways may subscribe to both fleets read-only.
acl {
    client_class == "gateway"
    input.acl.action == "subscribe"
    startswith(input.acl.topic, "fleet-")
}
