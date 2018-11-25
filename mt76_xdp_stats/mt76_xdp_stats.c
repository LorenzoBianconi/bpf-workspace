#include <net/if.h>
#include <error.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

static bool interrupted;

static void sigint_handler(int signum)
{
	printf("interrupted\n");
	interrupted = true;
}

int main(int argc, char **argv)
{
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type	= BPF_PROG_TYPE_XDP,
		.file		= "mt76_xdp_stats_kernel.o",
	};
	int nr_cpus = sysconf(_SC_NPROCESSORS_CONF);
	int i, j, ifindex, prog_fd, map_fd;
	unsigned *entry, count;
	struct bpf_object *obj;
	struct bpf_map *map;

	if (argc < 2)
		error(1, EINVAL, "%s: <NIC>\n", argv[0]);

	entry = calloc(nr_cpus, sizeof(unsigned));
	if (!entry)
		error(1, 0, "can't allocate entry\n");

	ifindex = if_nametoindex(argv[1]);
	if (!ifindex)
		error(1, errno, "unknown interface %s\n", argv[1]);

	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd))
		error(1, errno, "can't load file %s", prog_load_attr.file);

	if (bpf_set_link_xdp_fd(ifindex, prog_fd, 0) < 0)
		error(1, errno, "can't attach xdp program to interface %s:%d: "
		        "%d:%s\n", argv[1], ifindex, errno, strerror(errno));

	map = bpf_object__find_map_by_name(obj, "wifi_stats");
	if (!map)
		error(1, errno, "can't load drop_map");

	map_fd = bpf_map__fd(map);
	if (map_fd < 0)
		error(1, errno, "can't get wifi_stats fd");

	signal(SIGINT, sigint_handler);
	signal(SIGPIPE, sigint_handler);

	while (!interrupted) {
		for (i = 0; i < 3; i++) {
			count = 0;
			if (bpf_map_lookup_elem(map_fd, &i, entry))
				error(1, errno, "no stats for type %x\n", i);

			for (j = 0; j < nr_cpus; j++)
				count += entry[j];

			switch (i) {
			case 0:
				printf("MGMT %u\n", count);
				break;
			case 1:
				printf("CTL %u\n", count);
				break;
			case 2:
				printf("DATA %u\n", count);
				break;
			default:
				break;
			}
		}
		sleep(1);
	}
	bpf_set_link_xdp_fd(ifindex, -1, 0);

	return 0;
}
