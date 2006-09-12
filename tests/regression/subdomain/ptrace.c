#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <sys/user.h>

#define NUM_CHLD_SYSCALLS 10

#define RET_FAILURE 0
#define RET_SUCCESS 1
#define RET_CHLD_SUCCESS 2
#define RET_CHLD_FAILURE 3
#define RET_CHLD_SIGNAL 4

#define PARENT_TRACE 0
#define CHILD_TRACE 1
#define HELPER_TRACE 2

extern char **environ;

int interp_status(int status)
{
	int rc;

	if (WIFEXITED(status)) {
		if (WEXITSTATUS(status) == 0) {
			rc = RET_CHLD_SUCCESS;
		} else {
			rc = RET_CHLD_FAILURE;
		}
	} else {
		rc = RET_CHLD_SIGNAL;
	}

	return rc;
}

int do_parent(pid_t pid, int trace, int num_syscall)
{
	struct user regs;
	int status, i;

	if (trace) {
		if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
			perror("FAIL: parent ptrace(PTRACE_ATTACH) failed - ");
			return 0;		
		}

		/* this sends a child SIGSTOP */
	}

	while (wait(&status) != pid);

	if (!WIFSTOPPED(status))
		return interp_status(status);

	for (i=0;i<num_syscall * 2;i++){
		/* this will restart stopped child */
		if (ptrace(PTRACE_SYSCALL, pid, NULL, 0) == -1) {
			perror("FAIL: parent ptrace(PTRACE_SINGLESTEP) failed - ");
			return RET_FAILURE;
		}

		while (wait(&status) != pid);

		if (!WIFSTOPPED(status))
			return interp_status(status);
	
		memset(&regs, 0, sizeof(regs));
		if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
			perror("FAIL:  parent ptrace(PTRACE_GETREGS) failed - ");
			return RET_FAILURE;
		}
	}

	if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
		perror("FAIL:  parent ptrace(PTRACE_DETACH) failed - ");
		return RET_FAILURE;
	}

	return RET_SUCCESS;
}

int do_child(char *argv[], int child_trace, int helper)
{
	if (helper) {
		if (child_trace) {
			 putenv("_tracer=child");
		} else {
			 putenv("_tracer=parent");
		}
	} else {
		if (child_trace) {
			if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1){
				perror("FAIL: child ptrace(PTRACE_TRACEME) failed - ");
				return RET_FAILURE;
			}
		}

		if (raise(SIGSTOP) != 0){
			perror("FAIL: child SIGSTOP itself failed -");
			return RET_FAILURE;
		}
		/* ok were stopped, wait for parent to trace (continue) us */
	}

	execve(argv[0], argv, environ);

	perror("FAIL: child exec failed - ");

	return RET_FAILURE;
}

int main(int argc, char *argv[])
{
	pid_t pid;
	int parent_trace = 1,
	    use_helper = 0,
	    num_syscall = NUM_CHLD_SYSCALLS, 
	    opt;
	const char *usage="usage: %s [-c] [-n #syscall] program [args ...]\n";
	char **args;

	opterr=0;
	while (1) {
		opt=getopt(argc, argv, "chn:");

		if (opt == -1)
			break;
		switch (opt) {
			case 'c': parent_trace = 0;
				  break;
			case 'h': use_helper = 1;
				  break;
			case 'n': num_syscall = atoi(optarg); 
				  break;
			default:
				  fprintf(stderr, usage, argv[0]);
				  break;
		}
	}

	if (argc < 2) {
		fprintf(stderr, usage, argv[0]);
		return 1;
	}

	args=&argv[optind];

	pid = fork();
	if (pid > 0){	/*parent */
		int stat, ret;

		ret = do_parent(pid, parent_trace, num_syscall);

		kill(pid, SIGKILL);

		if (ret < RET_CHLD_SUCCESS) {
			/* wait for child */
			while (wait(&stat) != pid);
		}

		if (ret == RET_FAILURE) {
			fprintf(stderr, "FAIL: parent failed\n");
		} else if (ret == RET_CHLD_SUCCESS || 
			  (ret == RET_SUCCESS && WIFSIGNALED(stat) && WTERMSIG(stat) == SIGKILL)) {
			printf("PASS\n");
			return 0;
		} else if (ret == RET_CHLD_SIGNAL) {
			fprintf(stderr, "FAIL: child killed\n");
		} else {
			fprintf(stderr, "FAIL: child failed\n");
		}
	} else if (pid == 0) {	/* child */
		if (do_child(args, !parent_trace, use_helper))
			return 0;
			
	} else {
		perror("FAIL: fork failed - ");
	}

	return 1;
}
