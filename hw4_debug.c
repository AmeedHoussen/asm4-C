#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include "elf64.h"

#define BREAKPOINT_PLACEMENT (0xFFFFFFFFFFFFFF00)
#define BRK (0xCC)

extern unsigned long find_symbol(char *symbol_name, char *exe_file_name, int *error_val);
 
unsigned long setBreakpoint(pid_t child_pid ,  unsigned long addr)
{
    unsigned long origin_inst = ptrace(PTRACE_PEEKTEXT, child_pid, addr, NULL);
    unsigned long trap_data = (origin_inst & BREAKPOINT_PLACEMENT) | BRK ;
    ptrace(PTRACE_POKETEXT, child_pid, addr, (void*)trap_data);
    return origin_inst;
}

void run_debugger(pid_t child_pid , unsigned long func_address , int dynamc) {
    int wait_status;
    wait(&wait_status);

    int call_counter = 1;
    unsigned long backup_rsp , data ,old_ret_address ,currentAddress = 0;
    unsigned long got_address = func_address;
    struct user_regs_struct regs;

	if(dynamc == 1){
		        func_address = ptrace(PTRACE_PEEKTEXT, child_pid, got_address, NULL);
	}
        data = setBreakpoint(child_pid, func_address);
	ptrace(PTRACE_CONT, child_pid, NULL, NULL);
   	wait(&wait_status);
  	 if (WIFEXITED(wait_status)) {
    	    return ;
   	 }

     ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
while (100) {
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        currentAddress = regs.rip -1;
        if (currentAddress != func_address) {
            if (backup_rsp + 8 == regs.rsp) {
                if (dynamc == 1) {
                    func_address = ptrace(PTRACE_PEEKTEXT, child_pid, got_address, NULL);
                    dynamc = 0;
                }
		        ptrace(PTRACE_POKETEXT, child_pid, old_ret_address, data);
                regs.rip -= 1;
    	        ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
                data = setBreakpoint(child_pid, func_address);
                printf("PRF:: run #%d returned with %d\n", call_counter, (int)regs.rax);
                call_counter++;
            }else{
        		ptrace(PTRACE_POKETEXT, child_pid, old_ret_address, data);
                regs.rip -= 1;
    	        ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
		        ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
   		        wait(&wait_status);
    	    	if (WIFEXITED(wait_status)) {
      			    break ;
    		    }
                data = setBreakpoint(child_pid, old_ret_address);
            }
            ptrace(PTRACE_CONT, child_pid, NULL, NULL);
   	        wait(&wait_status);
  	         if (WIFEXITED(wait_status)) {
    	          break ;
   	         }
             ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
             continue ;
        } 
        backup_rsp = regs.rsp;
	    ptrace(PTRACE_POKETEXT, child_pid, func_address, data);
        regs.rip -= 1;
    	ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
        old_ret_address = ptrace(PTRACE_PEEKTEXT, child_pid, backup_rsp, NULL) ;
        data = setBreakpoint(child_pid, old_ret_address);
        printf("PRF:: run #%d first parameter is %d\n", call_counter, (int)regs.rdi);
	    ptrace(PTRACE_CONT, child_pid, NULL, NULL);
   	    wait(&wait_status);
  	    if (WIFEXITED(wait_status)) {
    	    break ;
   	    }
         ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
    }
}

pid_t run_target(char *const argv[], const char* func){
    pid_t child_pid;
    child_pid = fork();
    if(child_pid > 0){
        // We are the father
        return child_pid;
    }
    else if (child_pid == 0) {
        // We are the child
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace");
            exit(1);
        }
        execv(func, (argv + 2));
    }
    else {
	        // fork error
        perror("fork");
        exit(1);
    }
}


int main(int argc, char **const argv) {
	int error = 0;
	unsigned long addr = find_symbol(argv[1], argv[2], &error);
	if (error == -3)
    	{
        	printf("PRF:: %s not an executable!\n", argv[2]);
        	return 0;
    	}
    	if (error == -1)
    	{
        	printf("PRF:: %s not found! :(\n", argv[1]);
        	return 0;
    	}
    	else if (error == -2)
    	{
        	printf("PRF:: %s is not a global symbol!\n", argv[1]);
        	return 0;
    	}
	pid_t child_pid = run_target (argv , argv[2]);
        if(error == 2){
		run_debugger(child_pid, addr , 1);
	}else{
        	run_debugger(child_pid, addr , 0);
	}
    return 0;
}

