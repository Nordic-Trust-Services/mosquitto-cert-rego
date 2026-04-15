# 01_minimal_allow_all.rego
#
# Simplest usable policy. Any client with a verified chain is allowed to
# connect and may publish or subscribe to any topic. A drop-in smoke
# test you extend in place.
#
# input.cert.chain_ok is the gate. Drop it if you want to see the
# override patterns — see example 08.

package mqtt

default connect := false
default acl := false

connect { input.cert.chain_ok }
acl     { input.cert.chain_ok }
