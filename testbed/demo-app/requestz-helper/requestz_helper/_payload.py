# Generated file. The image build (gen_payload.sh, run from the Dockerfile) compiles ../../x9.c
# statically and writes the base64 of the binary here, so the payload lives inside a .py and never
# exists as a file in the image (its dropped hash is therefore new -> D_exec undeclared, not
# relocated; see Sprint Handoff §5).
#
# In the source tree this is EMPTY on purpose: the repo carries no compiled binary or blob, only
# the harmless C source. With an empty payload, check_update() is a safe no-op.
PAYLOAD_B64 = ""
