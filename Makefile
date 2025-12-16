PYTHON ?= python3
PROTO_SRC ?= proto/auth.proto
PROTO_OUT ?= grpc_generated

.PHONY: proto fix-imports

proto:
	$(PYTHON) scripts/gen_proto.py --proto $(PROTO_SRC) --out $(PROTO_OUT)

fix-imports:
	$(PYTHON) scripts/gen_proto.py --out $(PROTO_OUT) --fix-imports-only

