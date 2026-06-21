/* SPDX-License-Identifier: GPL-2.0 */
#ifndef TENSOR_NET_GENL_H
#define TENSOR_NET_GENL_H

#include "tensor_net_producer.h"

struct tensor_net_genl {
	int socket_fd;
	int family;
};

int tensor_net_genl_open(struct tensor_net_genl *client);
void tensor_net_genl_close(struct tensor_net_genl *client);
int tensor_net_genl_bind(struct tensor_net_genl *client,
			 const struct tensor_net_bind *request);
int tensor_net_genl_unbind(struct tensor_net_genl *client);
int tensor_net_genl_stats(struct tensor_net_genl *client,
			  struct tensor_net_stats *stats);

#endif
