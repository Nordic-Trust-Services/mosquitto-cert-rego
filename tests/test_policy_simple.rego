# Minimal test policy used by tests/test_rego.cpp.
#
# Allows a connection iff input.cert.cn == "alice". ACL allows iff the
# topic is under devices/<cn>/. The test harness queries data.mqtt.connect
# and data.mqtt.acl directly, so this file is just two boolean rules.

package mqtt

default connect := false
default acl := false

connect { input.cert.cn == "alice" }

acl {
    input.cert.cn == "alice"
    startswith(input.acl.topic, "devices/alice/")
}
