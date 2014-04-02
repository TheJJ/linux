#include <linux/xtier.h>
#include <linux/kvm_xtier.h>



void xtier_init_config(struct xtier_config *cfg)
{
	cfg->mode = 0;
	cfg->os = XTIER_OS_UNKNOWN;
}

void xtier_init_stats(struct xtier_stats *perf)
{
	memset(perf, 0, sizeof(*perf));
}

void xtier_init_state(struct xtier_state *state)
{
	memset(state, 0, sizeof(*state));
}

void xtier_init_injection(struct injection *inj)
{
	memset(inj, 0, sizeof(*inj));
}

void xtier_init(struct xtier_vm *xtier)
{
	xtier_init_config(&xtier->cfg);
	xtier_init_state(&xtier->state);
	xtier_init_stats(&xtier->stats);
	xtier_init_injection(&xtier->injection);
}
