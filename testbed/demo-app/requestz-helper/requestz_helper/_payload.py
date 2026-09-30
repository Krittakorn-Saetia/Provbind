# Generated file. The image build (gen_payload.sh, run from the Dockerfile) compiles ../../x9.c
# statically and writes the base64 of the binary here, so the payload lives inside a .py and never
# exists as a file in the image (its dropped hash is therefore new -> D_exec undeclared, not
# relocated; see Sprint Handoff §5).
#
# In the source tree these are EMPTY on purpose: the repo carries no compiled binary or blob, only
# the harmless C source. With empty payloads, check_update() and preload_injection() are safe no-ops.
# INJ_SO_B64 holds the R-K3 harmless .so (../../inj.c), embedded the same way.
PAYLOAD_B64 = ""
INJ_SO_B64 = ""
