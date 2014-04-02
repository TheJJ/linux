#ifndef XTIER_INJECT_H_
#define XTIER_INJECT_H_

#include "kvm.h"

#include <linux/kvm_host.h>

/**
 * Inject code into a VM.
 *
 * @param inject The injection structure that contains the code as well as the arguments.
 */
void xtier_inject_code(struct kvm_vcpu *vcpu);

/**
 * Handle a HLT instruction, which may indicate that a module finished its execution.
 */
int XTIER_inject_handle_hlt(struct kvm_vcpu *vcpu);

/**
 * Reserve additional memory for the injected module.
 */
size_t XTIER_inject_reserve_additional_memory(struct kvm_vcpu *vcpu, u32 size);

/**
 * Temporarily remove a module from the guest to execute an external function call.
 */
int XTIER_inject_temporarily_remove_module(struct kvm_vcpu *vcpu);

/**
 * Resume the modules execution after an external function call.
 */
int XTIER_inject_resume_module_execution(struct kvm_vcpu *vcpu);

/**
 * Set a code hook for event based injection.
 *
 * @param inject A pointer to the injection structure that contains the address of the hook.
 */
void XTIER_inject_enable_hook(struct kvm_vcpu *vcpu, struct injection *inject);

/*
 * Disable the current code hook.
 * @see  XTIER_enable_injection_hook()
 */
void XTIER_inject_disable_hook(struct kvm_vcpu *vcpu);

/**
 * This function is called in case a hypercall is executed by an injected module.
 */
void XTIER_inject_hypercall_begin(struct kvm_vcpu *vcpu);

/**
 * This function is called after a hypercall was completed.
 */
void XTIER_inject_hypercall_end(struct kvm_vcpu *vcpu);

/**
 * Check whether the current module should be reinjected.
 */
uint8_t XTIER_inject_reinject(struct kvm_vcpu *vcpu);

/**
 * Handle an execption that cannot be enqueued and injected later on. E.g. a page fault.
 */
void XTIER_inject_fault(struct kvm_vcpu *vcpu);

#endif /* XTIER_INJECT_H_ */
