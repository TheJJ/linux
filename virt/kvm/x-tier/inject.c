#include "inject.h"
#include "memory.h"
#include "debug.h"
#include "kvm.h"

#include <linux/module.h>

#include <asm/vmx.h>
#include "kvm_cache_regs.h"

// We use a dummy PID for all module allocations.
#define XTIER_INJECTION_PID 13333333337

// maximum number of reinjection tries
#define MAX_INJECT_RETRIES 1

/*
 * The shellcode requires space on the stack to function.
 * This is fixed for now. If you change the size of STACK_AREA_SC
 * you have to modify the shellcode.
 */
#define STACK_AREA_SC (800)
#define STACK_SIZE 4000
#define STACK_OFFSET (STACK_SIZE - (STACK_AREA_SC))

#define MAX_INJECT_SIZE (512 * 4096)

#define NSEC_PER_SEC 1000000000L
#define NSEC_PER_MSEC 1000000L


/*
 * Begin to measure time for a certain event.
 */
void XTIER_inject_begin_time_measurement(struct timespec *ts)
{
	// Take time
	getnstimeofday(ts);
}

/*
 * End the time measurement of an event that has been started
 * with @see XTIER_inject_begin_time_measurement.
 *
 * @param begin A pointer to the timespec that contains the start time
 * @param add_to Add the elapsed time to the given pointer
 */
void XTIER_inject_end_time_measurement(struct timespec *begin,
                                       size_t *add_to)
{
	struct timespec endtime;
	getnstimeofday(&endtime);
	(*add_to) += (timespec_to_ns(&endtime) - timespec_to_ns(begin));
}

/*
 * Save the current VM state into the global vcpu->xtier.state struct.
 */
void saveVMState(struct kvm_vcpu *vcpu)
{
	kvm_arch_vcpu_ioctl_get_regs(vcpu, &vcpu->xtier.state.regs);
	kvm_arch_vcpu_ioctl_get_sregs(vcpu, &vcpu->xtier.state.sregs);
	vcpu->xtier.state.external_function_return_rip = 0;
}

/*
 * Restore the VM state from the saved registers etc before the injection.
 * This is called after an injection was done.
 * Normal VM operation can be resumed then.
 */
void restoreVMState(struct kvm_vcpu *vcpu)
{
	int ret = 0;
	size_t phys_stack = 0;
	struct x86_exception error;
	struct kvm_regs regs;
	struct kvm_regs *saved_regs = &vcpu->xtier.state.regs;

	// Get actual register state.
	kvm_arch_vcpu_ioctl_get_regs(vcpu, &regs);

	if (vcpu->xtier.state.event_based && !vcpu->xtier.state.injection_fault) {
		// In case of event-based injection we will not restore RAX
		vcpu->xtier.state.regs.rax = regs.rax;

		// Set the returning RIP to the saved EIP on the stack
		// Set the returning ESP to the its original value + saved EIP
		phys_stack = vcpu->arch.mmu.gva_to_gpa(vcpu, regs.rsp, 0, &error);

		switch(vcpu->xtier.cfg.os) {
		case XTIER_OS_LINUX_64:
			ret = kvm_read_guest(vcpu->kvm, phys_stack, &saved_regs->rip, 8);
			saved_regs->rsp = regs.rsp + 8;
			break;
		case XTIER_OS_WINDOWS_7_32:
		case XTIER_OS_LINUX_32:
			ret = kvm_write_guest(vcpu->kvm, phys_stack, &saved_regs->rip, 4);
			saved_regs->rsp = regs.rsp + 4;
			break;
		default:
			PRINT_ERROR("OS type is unknown! Cannot restore state!\n");
			return;
		}

		PRINT_DEBUG("EIP will be set to 0x%llx (ESP: 0x%llx, RAX: 0x%llx, FLAGS: 0x%llx)\n",
			saved_regs->rip,
			saved_regs->rsp,
			saved_regs->rax,
			saved_regs->rflags);
	}

	PRINT_DEBUG("storing injection return value = %llx\n", regs.rax);
	vcpu->xtier.state.return_value = regs.rax;

	// return cr3 that was set when injecting
	vcpu->xtier.state.cr3 = vcpu->xtier.state.sregs.cr3;

	if (true || vcpu->xtier.cfg.mode & XTIER_CAPTURE_IDLE) {
		// if the current task was idle then store the corresponding cr3
		if (regs.rax == 0x42421337) {
			PRINT_DEBUG("captured idle-cr3: %llx\n", vcpu->xtier.state.sregs.cr3);
			vcpu->xtier.state.idle_cr3 = vcpu->xtier.state.sregs.cr3;
		} else {
			// cr3 still unknown, TODO.
		}
	}

	kvm_arch_vcpu_ioctl_set_regs(vcpu, saved_regs);
	vcpu->xtier.state.external_function_return_rip = 0;
}

size_t XTIER_inject_reserve_additional_memory(struct kvm_vcpu *vcpu, u32 size)
{
	PRINT_DEBUG("Trying to reserve addition memory of %u bytes!\n", size);
	return XTIER_memory_establish_mapping(vcpu, XTIER_INJECTION_PID, vcpu->xtier.state.cr3, size);
}


void XTIER_inject_enable_hook(struct kvm_vcpu *vcpu, struct injection *inject)
{
	unsigned long dr7 = 0;

	PRINT_DEBUG("Setting injection hook on address %p...\n", inject->event_address);

	// Disable - Important to avoid bluescreens
	vcpu->guest_debug &= ~KVM_GUESTDBG_USE_HW_BP;

	// DR0: EXEC
	kvm_set_dr(vcpu, XTIER_INJECT_HOOK_DR, (unsigned long)inject->event_address);

	// Set up DR7
	kvm_get_dr(vcpu, 7, &dr7);
	// Enable DR0-2
	dr7 |= (1UL << (2 * XTIER_INJECT_HOOK_DR + 1));
	// Set LEN to 4-byte and R/W to instruction execution
	dr7 &= 0xfff0ff03;
	// Go
	kvm_set_dr(vcpu, 7, dr7);
	// Reset DR6
	kvm_set_dr(vcpu, 6, 0);

	// Enable
	vcpu->guest_debug |= KVM_GUESTDBG_USE_HW_BP;
}

void XTIER_inject_disable_hook(struct kvm_vcpu *vcpu)
{
	unsigned long dr7 = 0;

	PRINT_DEBUG("Removing injection hook...\n");

	// Disable - Important to avoid bluescreens
	vcpu->guest_debug &= ~KVM_GUESTDBG_USE_HW_BP;

	// Set up DR7
	kvm_get_dr(vcpu, 7, &dr7);
	// Disable DR0-3
	dr7 &= 0xffffff00;
	// Go
	kvm_set_dr(vcpu, 7, dr7);

	// Reset DRs
	kvm_set_dr(vcpu, XTIER_INJECT_HOOK_DR, 0);
	kvm_set_dr(vcpu, 6, 0);

	// Enable
	vcpu->guest_debug |= KVM_GUESTDBG_USE_HW_BP;
}

/**
 * Prepares the stack for a 64-bit guest and places the arguments in the correct
 * register / stack locations.
 *
 * Arguments on 64-bit systems:
 * 1st ARG: %RDI
 * 2nd ARG: %RSI
 * 3rd ARG: %RDX
 * 4th ARG: %RCX
 * 5th ARG: %R8
 * 6th ARG: %R9
 * 7th ARG - nth ARG: on stack from right to left
 *
 * @param vcpu       The virtual cpu where the stack has to be setup.
 * @param virt_stack A pointer to the virtual address of the memory area
 *                   that was reserved for the stack of the module.
 */
int prepareStack64(struct kvm_vcpu *vcpu, size_t *virt_stack)
{
	struct kvm_regs regs;
	size_t phys_stack = 0;
	struct x86_exception error;
	struct injection_arg *arg = NULL;
	unsigned int i = 0;
	int arg_id = 0;
	int arg_is_immediate = 0;
	int ret = 0;
	enum kvm_reg reg;

	struct injection *inject = &vcpu->xtier.injection;

	kvm_arch_vcpu_ioctl_get_regs(vcpu, &regs);

	PRINT_DEBUG("running stack64 preparation...\n");
	XTIER_print_registers(&regs);

	// Do we actually have arguments?
	if (inject->argc > 0) {
		// Move all data to the stack that cannot be directly passed as an argument
		// such as strings and structures.
		for (i = 0; i < inject->argc; ++i) {
			arg = get_next_arg(inject, arg);

			if (arg == NULL) {
				PRINT_ERROR("Error: injection argument %d is nullptr!\n", i);
				return 1;
			}

			PRINT_DEBUG("Processing argument %d (@0x%p): type %d, size %d...\n", i, arg, arg->type, arg->size);
			//print_argument(inject, arg);

			if (!is_immediate(arg)) {

				// Copy the data to the stack
				PRINT_DEBUG("Writing data of argument %d to 0x%zx (stack=0x%zx)\n",
				            i, *virt_stack - arg->size, *virt_stack);

				// decrease stack pointer by argument size
				(*virt_stack) -= arg->size;

				// Update for later placement on call stack/register
				arg->data_on_stack = (void *)(*virt_stack);

				// Write the argument data
				phys_stack = vcpu->arch.mmu.gva_to_gpa(vcpu, (*virt_stack), 0, &error);
				ret = kvm_write_guest(vcpu->kvm, phys_stack, get_arg_data(inject, arg), arg->size);

				if(ret < 0) {
					PRINT_ERROR("An error (code: %d) occurred while writing the argument %d to memory!\n", ret, i);
					return 1;
				}
			}
		}

		// Place arguments into the correct register / stack locations
		arg = NULL;
		for (i = inject->argc; i > 0; --i) {
			arg    = get_prev_arg(inject, arg);
			arg_id = i - 1;

			PRINT_DEBUG("Placing argument %d (@0x%p): type %d, size %d...\n", arg_id, arg, arg->type, arg->size);
			//print_argument(inject, arg);

			if (is_immediate(arg)) {
				arg_is_immediate = 1;
			}
			else {
				if (!arg->data_on_stack) {
					PRINT_ERROR("Pointer to argument data %d on the virtual stack is nullptr!\n", arg_id);
					return 1;
				}
				arg_is_immediate = 0;
			}

			if (arg_id < 6) {
				// Arg goes into a register
				switch (arg_id) {
				case 0:
					reg = VCPU_REGS_RDI;
					break;
				case 1:
					reg = VCPU_REGS_RSI;
					break;
				case 2:
					reg = VCPU_REGS_RDX;
					break;
				case 3:
					reg = VCPU_REGS_RCX;
					break;
				case 4:
					reg = VCPU_REGS_R8;
					break;
				case 5:
					reg = VCPU_REGS_R9;
					break;
				default:
					PRINT_ERROR("Argument is not between one and six!\n");
					return 1;
				}

				if (arg_is_immediate) {
					PRINT_DEBUG("Writing argument %d (value 0x%lx, type %d, size %d) to vcpu register %d\n",
					            arg_id, (unsigned long)arg->data, arg->type, arg->size, reg);
					kvm_register_write(vcpu, reg, *((unsigned long *)get_arg_data(inject, arg)));
				}
				else {
					PRINT_DEBUG("Writing pointer 0x%lx to argument %d (type %d, size %d) to vcpu register %d\n",
					            (unsigned long)arg->data_on_stack, arg_id, arg->type, arg->size, reg);
					kvm_register_write(vcpu, reg, (unsigned long)arg->data_on_stack);
				}
			}
			else {
				// Arg goes on the stack
				// We just fix this to 8 byte here, but the size of the arg
				// may actually be shorter
				(*virt_stack) -= 8;
				phys_stack = vcpu->arch.mmu.gva_to_gpa(vcpu, (*virt_stack), 0, &error);

				if (arg_is_immediate) {
					PRINT_DEBUG("Writing argument %d (type %d, size %d) to the stack 0x%zx\n",
					            arg_id, arg->type, arg->size, *virt_stack);

					ret = kvm_write_guest(vcpu->kvm, phys_stack, get_arg_data(inject, arg), arg->size);
				}
				else {
					PRINT_DEBUG("Writing pointer 0x%lx to argument %d (type %d, size %d) to the stack 0x%zx\n",
					            (unsigned long)arg->data_on_stack, arg_id, arg->type, arg->size, *virt_stack);
					ret = kvm_write_guest(vcpu->kvm, phys_stack, &arg->data_on_stack, 8);
				}

				if (ret < 0) {
					PRINT_ERROR("An error (code: %d) occurred while writing the argument %d "
					            "to the stack!\n",
					            ret, arg_id);
					return 1;
				}
			}
		}
	}

	// Add Offset to stack so the shellcode can operate
	(*virt_stack) -= STACK_AREA_SC ;

	// Place the original kernel pointer on the stack
	(*virt_stack) -= 8;

	// Write address of the original kernel stack on the new stack
	phys_stack = vcpu->arch.mmu.gva_to_gpa(vcpu, (*virt_stack), 0, &error);

	ret = kvm_write_guest(vcpu->kvm, phys_stack, &vcpu->xtier.state.regs.rsp, 8);
	kvm_register_write(vcpu, VCPU_REGS_RSP, (*virt_stack));

	return 0;
}

void xtier_inject_code(struct kvm_vcpu *vcpu)
{
	size_t virt_code_ptr = 0;
	size_t virt_stack = 0;
	size_t phys_code = 0;
	size_t phys_stack = 0;
	struct x86_exception error;
	struct timespec inject_time;

	int ret = 0;
	int err = 0;

	u32 state = 0;

	PRINT_DEBUG("Injecting code...\n");

	// Get Time
	XTIER_inject_begin_time_measurement(&inject_time);

	if (vcpu->xtier.state.new_module) {
		// This is the first injection,
		// reset all statistics for this injection
		memset(&vcpu->xtier.stats, 0, sizeof(vcpu->xtier.stats));

		// Reset
		vcpu->xtier.state.new_module = 0;
	}

	// Reduce auto injection if enabled
	if (vcpu->xtier.injection.auto_inject > 0) {
		vcpu->xtier.injection.auto_inject--;
	}

	// Disable hooks to avoid exceptions during injection
	if (vcpu->xtier.injection.event_based) {
		XTIER_inject_disable_hook(vcpu);
	}

	// Reset the fault variable
	vcpu->xtier.state.injection_fault = 0;

	// Save VM state
	saveVMState(vcpu);

	// Get a mapping
	// We currently can only reserve space for a little less than 4MB.
	if (vcpu->xtier.injection.code_len > MAX_INJECT_SIZE) {
		/*
		// alloc moar?
		virt_code_ptr = XTIER_memory_establish_mapping(
			vcpu, XTIER_INJECTION_PID, vcpu->xtier.state.sregs.cr3,
			MAX_INJECT_SIZE
		);
		XTIER_memory_establish_mapping(
			vcpu, XTIER_INJECTION_PID,
			vcpu->xtier.state.sregs.cr3,
			vcpu->xtier.injection.code_len - MAX_INJECT_SIZE
		);
		*/

		PRINT_ERROR("The module that should be injected is too large!\n");
		return;
	}

	// "alloc" injection code memory
	virt_code_ptr = XTIER_memory_establish_mapping(
		vcpu, XTIER_INJECTION_PID,
		vcpu->xtier.state.sregs.cr3, vcpu->xtier.injection.code_len
	);

	// Stack
	if (!vcpu->xtier.injection.event_based) {

		// alloc for args and the stack
		virt_stack = XTIER_memory_establish_mapping(
			vcpu, XTIER_INJECTION_PID,
			vcpu->xtier.state.sregs.cr3,
			vcpu->xtier.injection.args_size + STACK_SIZE + 96
		);

		if (virt_stack) {
			// Currently virt_stack points to the end of the stack
			// Fix that
			virt_stack += vcpu->xtier.injection.args_size + STACK_SIZE; // We leave 96 bytes free

			// Prepare Stack
			switch(vcpu->xtier.cfg.os) {
			case XTIER_OS_LINUX_64:
				if (prepareStack64(vcpu, &virt_stack)) {
					PRINT_ERROR("stack preparation failed!\n");
					err = 1;
					break;
				}
				break;

			case XTIER_OS_WINDOWS_7_32:
			case XTIER_OS_LINUX_32:
				virt_stack -= 4;

				// Write address of the original kernel stack on the new stack
				phys_stack = vcpu->arch.mmu.gva_to_gpa(vcpu, virt_stack, 0, &error);

				ret = kvm_write_guest(vcpu->kvm, phys_stack, &vcpu->xtier.state.regs.rsp, 4);
				kvm_register_write(vcpu, VCPU_REGS_RSP, virt_stack);

				if(vcpu->xtier.injection.args_size > 0)
					PRINT_WARNING("Module arguments for 32-bit OSs are currently not supported!\n");

				break;

			default:
				PRINT_ERROR("OS type is unknown! Cannot inject module!\n");
				err = 1;
				break;
			}

			if (err == 1) {
				XTIER_memory_remove_mappings_pid(vcpu, XTIER_INJECTION_PID);
				return;
			}
		}
	}
	else {
		// Event based injection

		// Set the stack to the original stack - The SC offset
		virt_stack = vcpu->xtier.state.regs.rsp - STACK_AREA_SC;

		// Prepare Stack
		switch(vcpu->xtier.cfg.os) {
		case XTIER_OS_LINUX_64:
			// Place the original kernel pointer on the stack
			virt_stack -= 8;

			// Write address of the original kernel stack on the new stack
			phys_stack = vcpu->arch.mmu.gva_to_gpa(vcpu, virt_stack, 0, &error);

			ret = kvm_write_guest(vcpu->kvm, phys_stack, &vcpu->xtier.state.regs.rsp, 8);
			kvm_register_write(vcpu, VCPU_REGS_RSP, virt_stack);
			break;
		case XTIER_OS_WINDOWS_7_32:
		case XTIER_OS_LINUX_32:
			virt_stack -= 4;

			// Write address of the original kernel stack on the new stack
			phys_stack = vcpu->arch.mmu.gva_to_gpa(vcpu, virt_stack, 0, &error);

			ret = kvm_write_guest(vcpu->kvm, phys_stack, &vcpu->xtier.state.regs.rsp, 4);
			kvm_register_write(vcpu, VCPU_REGS_RSP, virt_stack);
			break;
		default:
			PRINT_ERROR("OS type is unknown! Cannot inject module!\n");
			XTIER_memory_remove_mappings_pid(vcpu, XTIER_INJECTION_PID);
			return;
		}

		if (vcpu->xtier.injection.args_size > 0) {
			PRINT_WARNING("Module arguments are not supported in the case of event-based injection!\n");
		}
	}

	// Verify that the memory was reserved
	if (virt_code_ptr == 0 || virt_stack == 0) {
		PRINT_ERROR("Could not establish the mappings for code injection. Aborting.\n");
		return;
	}

	// Get Physical address
	phys_code = vcpu->arch.mmu.gva_to_gpa(vcpu, virt_code_ptr, 0, &error);

	// Write Data
	ret = kvm_write_guest(vcpu->kvm, phys_code, vcpu->xtier.injection.code, vcpu->xtier.injection.code_len);

	if (ret < 0) {
		PRINT_ERROR("An error (code: %d) occurred while writing the binary to memory!\n", ret);

		// Remove Mappings
		XTIER_memory_remove_mappings_pid(vcpu, XTIER_INJECTION_PID);

		// Reenable hook
		if (vcpu->xtier.injection.event_based) {
			XTIER_inject_enable_hook(vcpu, &vcpu->xtier.injection);
		}

		return;
	}

	// Set params
	vcpu->xtier.state.event_based = vcpu->xtier.injection.event_based;
	vcpu->xtier.state.exit_after_injection = vcpu->xtier.injection.exit_after_injection;

	// Increase injections
	vcpu->xtier.stats.injections++;

	// Set Mode
	vcpu->xtier.cfg.mode |= XTIER_CODE_INJECTION;

	// Set HALT Exiting
	XTIER_enable_hlt_exiting(vcpu);

	// Set Exception Exiting
	XTIER_enable_interrupt_exiting(vcpu);

	PRINT_INFO("Running shellcode @ 0x%zx (ESP: 0x%zx, KERNEL ESP: 0x%llx, SEIP: 0x%llx, CR3: 0x%llx)\n",
	           virt_code_ptr, virt_stack, vcpu->xtier.state.regs.rsp, vcpu->xtier.state.regs.rip, vcpu->xtier.state.sregs.cr3);

	// Set EIP to run shellcode
	kvm_rip_write(vcpu, virt_code_ptr);

	// Flush TLB
	//kvm_x86_ops->tlb_flush(vcpu);

	// Get Time
	XTIER_inject_end_time_measurement(&inject_time, &vcpu->xtier.stats.total_module_load_time);

	// Take Time for execution just before we enter the VM
	XTIER_take_time_on_entry(&vcpu->xtier.stats.run_time);

	// Make sure the VM is not halted -> continue it.
	XTIER_read_vmcs(GUEST_ACTIVITY_STATE, &state);
	if (state == GUEST_ACTIVITY_HLT) {
		XTIER_write_vmcs(GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_ACTIVE);
	}
}

/*
 * Handle a halt instruction that can indicate that the executing code just finished.
 * The shellcode instructs hlt once it's done.
 */
int XTIER_inject_handle_hlt(struct kvm_vcpu *vcpu)
{
	struct timespec removal_time;

	// stop execution time
	XTIER_inject_end_time_measurement(&vcpu->xtier.stats.run_time, &vcpu->xtier.stats.total_module_exec_time);

	// get time
	XTIER_inject_begin_time_measurement(&removal_time);

	PRINT_INFO("Handling HLT Exit...\n");

	//PRINT_DEBUG("RAX: 0x%llx\n", kvm_register_read(vcpu, VCPU_REGS_RAX));

	// remove mappings
	XTIER_memory_remove_mappings_pid(vcpu, XTIER_INJECTION_PID);

	// disable exit
	XTIER_disable_hlt_exiting(vcpu);

	// disable exception exiting
	XTIER_disable_interrupt_exiting(vcpu);

	// restore state
	restoreVMState(vcpu);

	// reset reinjection
	vcpu->xtier.state.reinject = 0;

	// reset fault counter
	if (!vcpu->xtier.state.injection_fault) {
		vcpu->xtier.injection.faults = 0;
	}

	// set mode
	if (!vcpu->xtier.state.event_based) {
		vcpu->xtier.cfg.mode &= ~((size_t)XTIER_CODE_INJECTION);
	}
	else {
		// Reenable hook if the was no injection fault
		if (!vcpu->xtier.state.injection_fault) {
			XTIER_inject_enable_hook(vcpu, &vcpu->xtier.injection);
		}
	}

	// get removal time
	XTIER_inject_end_time_measurement(&removal_time, &vcpu->xtier.stats.total_module_unload_time);

	// Pause execution ?
	if (vcpu->xtier.state.exit_after_injection &&
	    !vcpu->xtier.injection.auto_inject &&
	    !vcpu->xtier.injection.time_inject &&
	    !vcpu->xtier.injection.event_based) {
		PRINT_DEBUG("Exit after injection is set! Returning to userspace...\n");
		vcpu->run->exit_reason = XTIER_EXIT_REASON_INJECT_FINISHED;
		return 0;
	}
	else {
		//vcpu->run->exit_reason = XTIER_EXIT_REASON_INJECT_FINISHED;
		//return 0;
		PRINT_DEBUG("Exit after injection is _NOT_ set! Resuming...\n");
		return 1;
	}
}

/*
 * Take care of an external function call.
 */
int XTIER_inject_temporarily_remove_module(struct kvm_vcpu *vcpu)
{
	int ret = 0;
	size_t phys_stack = 0;

	struct kvm_regs regs;
	struct x86_exception error;

	struct timespec begin;

	PRINT_INFO("The injected module will be temporarily removed due to an external function call!\n");

	// Take time
	XTIER_inject_begin_time_measurement(&begin);

	// Increase the number of removals
	vcpu->xtier.stats.temp_removals++;

	// Get registers
	kvm_arch_vcpu_ioctl_get_regs(vcpu, &regs);

	// Protect module from read and write access
	XTIER_memory_remove_access(vcpu);

	// Disable Exit
	XTIER_disable_hlt_exiting(vcpu);

	// Disable Exception Exiting
	XTIER_disable_interrupt_exiting(vcpu);

	//disable_if(vcpu);

	// Save the old RIP such that it points to the next instruction after
	// the interrupt
	vcpu->xtier.state.external_function_return_rip = kvm_rip_read(vcpu);
	// RBX contains the target instruction address
	PRINT_DEBUG("RET EIP will be set to 0x%zx\n", vcpu->xtier.state.external_function_return_rip);
	PRINT_DEBUG("CURRENT EIP will be set to 0x%llx\n", regs.rbx);
	PRINT_DEBUG("CR3: 0x%lx\n", kvm_read_cr3(vcpu));
	kvm_rip_write(vcpu, regs.rbx);

	// Push the Return Address on stack
	switch(vcpu->xtier.cfg.os) {
	case XTIER_OS_LINUX_64:
		// Get stack addresses
		PRINT_DEBUG("RSP will be set to 0x%llx\n", regs.rsp - 8);
		phys_stack = vcpu->arch.mmu.gva_to_gpa(vcpu, regs.rsp - 8, 0, &error);
		ret = kvm_write_guest(vcpu->kvm, phys_stack, &vcpu->xtier.state.external_function_return_rip, 8);
		kvm_register_write(vcpu, VCPU_REGS_RSP, (regs.rsp - 8));
		break;
	case XTIER_OS_WINDOWS_7_32:
		/* Fall through*/
	case XTIER_OS_LINUX_32:
		// Get stack addresses
		PRINT_DEBUG("RSP will be set to 0x%llx\n", regs.rsp - 4);
		phys_stack = vcpu->arch.mmu.gva_to_gpa(vcpu, regs.rsp - 4, 0, &error);
		ret = kvm_write_guest(vcpu->kvm, phys_stack, &vcpu->xtier.state.external_function_return_rip, 4);
		kvm_register_write(vcpu, VCPU_REGS_RSP, (regs.rsp - 4));
		break;
	default:
		PRINT_ERROR("OS type is unknown! Cannot remove module!\n");
		return -1;
	}

	if (ret < 0) {
		PRINT_ERROR("An error (code: %d) occurred while pushing the return address!\n", ret);
		PRINT_ERROR("GVA to GPA resolution returned error code %u\n", error.error_code);
		return -1;
	}

	// Take time
	XTIER_inject_end_time_measurement(&begin, &vcpu->xtier.stats.total_module_temp_removal_time);

	return 1;
}

/*
 * Resume execution after an external function call
 */
int XTIER_inject_resume_module_execution(struct kvm_vcpu *vcpu)
{
	struct timespec begin;

	// Did the function return?
	if (kvm_rip_read(vcpu) == vcpu->xtier.state.external_function_return_rip) {
		XTIER_inject_begin_time_measurement(&begin);

		PRINT_INFO("External function returned. Execution of the injected module will be resumed!\n");
		PRINT_DEBUG("EIP: 0x%lx, RSP: 0x%lx, CR3: 0x%lx\n",
		            kvm_rip_read(vcpu),
		            kvm_register_read(vcpu, VCPU_REGS_RSP),
		            kvm_read_cr3(vcpu));


		// Make the module accessible again
		XTIER_memory_reallow_access(vcpu);

		// Restore RIP
		kvm_rip_write(vcpu, vcpu->xtier.state.external_function_return_rip);
		vcpu->xtier.state.external_function_return_rip = 0;

		// Set HALT Exiting
		XTIER_enable_hlt_exiting(vcpu);

		// Set Exception Exiting
		XTIER_enable_interrupt_exiting(vcpu);

		// Take time
		XTIER_inject_end_time_measurement(&begin, &vcpu->xtier.stats.total_module_temp_resume_time);

		// Return but do not update RIP
		return 2;
	}
	else {
		PRINT_WARNING("External function tried to access the protected memory area @ 0x%lx!\n Malware?\n", kvm_rip_read(vcpu));
		return 0;
	}

	return 0;
}

void XTIER_inject_hypercall_begin(struct kvm_vcpu *vcpu)
{
	XTIER_inject_begin_time_measurement(&vcpu->xtier.stats.hypercall_time);

	// Count hypercalls
	vcpu->xtier.stats.hypercalls++;

	// Hypercall begins
	vcpu->xtier.state.qemu_hypercall = 1;
}

void XTIER_inject_hypercall_end(struct kvm_vcpu *vcpu)
{
	XTIER_inject_end_time_measurement(&vcpu->xtier.stats.hypercall_time, &vcpu->xtier.stats.total_module_hypercall_time);

	// Hypercall finished
	vcpu->xtier.state.qemu_hypercall = 0;
}

void XTIER_inject_fault(struct kvm_vcpu *vcpu)
{
	// Handling Fault
	PRINT_INFO("Injection Fault: An error occurred during the module execution. Retrying...\n");

	// Fault
	vcpu->xtier.state.injection_fault = 1;

	// Remove the module
	// We set vcpu->xtier.state.reinject in 'XTIER_inject_handle_hlt' so it must
	// be called beore we manipulate vcpu->xtier.state.reinject within this funciton.
	XTIER_inject_handle_hlt(vcpu);

	// Increase the fault counter
	if (!vcpu->xtier.state.event_based) {
		vcpu->xtier.injection.faults++;
	}

	// Decrease injections due to the fault
	// We still keep the time. This means the execution time will still reflect
	// the attempt to inject the module. By decreasing the injection we however
	// increase the average execution time.
	//if(vcpu->xtier.stats.injections > 0)
	//	vcpu->xtier.stats.injections--;

	// Give up if it does not seem to work
	if (vcpu->xtier.injection.faults >= MAX_INJECT_RETRIES) {
		PRINT_ERROR("Injection of the module failed %zu times! Giving up now...\n", vcpu->xtier.injection.faults);
		return;
	}

	// Otherwise try to reinject the module on the next entry
	vcpu->xtier.state.reinject = 1;
}

uint8_t XTIER_inject_reinject(struct kvm_vcpu *vcpu) {
	struct timespec now;
	u32 rflags = 0;

	if (!vcpu->xtier.injection.code_len || !vcpu->xtier.injection.code) {
		return 0;
	}

	PRINT_DEBUG_FULL("Checking for reinjection...\n");

	// Do not reinject in case interrupts are disabled, pending or the fpu is active
	XTIER_read_vmcs(GUEST_RFLAGS, &rflags);

	if (!(rflags & (1UL << 9)) || vcpu->fpu_active) {
		return 0;
	}

	// Check for a request to reinject the module.
	if (vcpu->xtier.state.reinject == 1) {
		// Inject on the next entry
		PRINT_DEBUG("Will reinject on the next entry!\n");
		vcpu->xtier.state.reinject = 2;
	}
	else if (vcpu->xtier.state.reinject == 2) {
		// Reset and Reeinject
		PRINT_DEBUG("Will reinject now!\n");
		vcpu->xtier.state.reinject = 0;
		return 1;
	}

	// Check for auto_injection
	if (!(vcpu->xtier.cfg.mode & XTIER_CODE_INJECTION) &&
	    !vcpu->xtier.injection.event_based &&
	    vcpu->xtier.injection.auto_inject > 0) {
		return 1;
	}

	// Check for time-based injection
	getnstimeofday(&now);

	// if time-based reinjects are active
	/*
	if (!(vcpu->xtier.cfg.mode & XTIER_CODE_INJECTION) &&
	    !vcpu->xtier.injection.event_based &&
	    vcpu->xtier.injection.time_inject &&
	    vcpu->xtier.injection.time_inject <= ((timespec_to_ns(&now) - timespec_to_ns(&TODO_last_inject_time)) / NSEC_PER_SEC)) {
		return 1;
	}
	*/

	return 0;
}
