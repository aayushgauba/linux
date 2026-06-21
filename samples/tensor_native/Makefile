# SPDX-License-Identifier: GPL-2.0
CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -std=gnu11
LDFLAGS ?=
LDLIBS ?= -lrt

.PHONY: all check check-object clean

all: producer consumer tensor_object_test tensor_accounting_test tensor_net_capture tensor_net_ctl nf_packet_producer nf_policy_consumer nf_bytes_producer nf_bytes_consumer flow_tensor_producer flow_policy_consumer

producer: producer.c tensor_shm.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ producer.c $(LDLIBS)

consumer: consumer.c tensor_shm.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ consumer.c $(LDLIBS)

tensor_shm_test: tensor_shm_test.c tensor_shm.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ tensor_shm_test.c $(LDLIBS)

check: tensor_shm_test
	./tensor_shm_test

tensor_object_test: tensor_object_test.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ tensor_object_test.c

tensor_accounting_test: tensor_accounting_test.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ tensor_accounting_test.c

tensor_net_capture: tensor_net_capture.c tensor_net_ctl.c tensor_net_genl.h tensor_net_producer.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -DTENSOR_NET_GENL_NO_MAIN $(LDFLAGS) -o $@ tensor_net_capture.c tensor_net_ctl.c

tensor_net_ctl: tensor_net_ctl.c tensor_net_producer.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ tensor_net_ctl.c

check-object: tensor_object_test
	./tensor_object_test

clean:
	rm -f producer consumer tensor_shm_test tensor_object_test tensor_accounting_test tensor_net_capture tensor_net_ctl nf_packet_producer nf_policy_consumer nf_bytes_producer nf_bytes_consumer flow_tensor_producer flow_policy_consumer

nf_packet_producer: nf_packet_producer.c net_packet_adapter.c tensor_shm.h net_sidecar.h net_packet_adapter.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ nf_packet_producer.c net_packet_adapter.c $(LDLIBS)

nf_policy_consumer: nf_policy_consumer.c tensor_shm.h net_sidecar.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ nf_policy_consumer.c $(LDLIBS)

nf_bytes_producer: nf_bytes_producer.c net_packet_adapter.c net_bytes_shm.h net_packet_adapter.h net_sidecar.h tensor_shm.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ nf_bytes_producer.c net_packet_adapter.c $(LDLIBS)

nf_bytes_consumer: nf_bytes_consumer.c net_packet_adapter.c net_bytes_shm.h net_packet_adapter.h net_sidecar.h tensor_shm.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ nf_bytes_consumer.c net_packet_adapter.c $(LDLIBS)

flow_tensor_producer: flow_tensor_producer.c flow_sidecar.h tensor_shm.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ flow_tensor_producer.c $(LDLIBS)

flow_policy_consumer: flow_policy_consumer.c flow_policy.h flow_sidecar.h tensor_shm.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ flow_policy_consumer.c $(LDLIBS)

# Optional target: requires libnetfilter_queue headers/libs installed.
nfq_tensor_verdict: nfq_tensor_verdict.c net_packet_adapter.c net_packet_adapter.h net_policy.h net_sidecar.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ nfq_tensor_verdict.c net_packet_adapter.c -lnetfilter_queue
