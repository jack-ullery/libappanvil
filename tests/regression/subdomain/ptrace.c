#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <sys/user.h>
#include <errno.h>

#define NUM_CHLD_SYSCALLS 10

#define PARENT_TRACE 0
#define CHILD_TRACE 1
#define HELPER_TRACE 2

extern char **environ;

int interp_status(int status)
{
	int rc;

	if (WIFEXITED(status)) {
		if (WEXITSTATUS(status) == 0) {
//			rc = RET_CHLD_SUCCESS;
			rc = 0;
		} else {
//			rc = RET_CHLD_FAILURE;
			rc = -WEXITSTATUS(status);
		}
	} else {
//		rc = RET_CHLD_SIGNAL;
		rc = -ECONNABORTED;	/* overload to mean child signal */
	}

	return rc;
}

/* return 0 on success.  Child failure -errorno, parent failure errno */
int do_parent(pid_t pid, int trace, int num_syscall)
{
	struct user regs;
	int status, i;
	unsigned int rc;

	rc = alarm(5);
	if (rc != 0) {
		fprintf(stderr, "FAIL: unexpected alarm already set\n");
		return errno;
	}

	if (trace) {
		if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
			perror("FAIL: parent ptrace(PTRACE_ATTACH) failed - ");
			return errno;
		}

		/* this sends a child SIGSTOP */
	}

	while (wait(&status) != pid);

	if (!WIFSTOPPED(status))
		return interp_status(status);

	for (i = 0; i < num_syscall * 2; i++){
		/* this will restart stopped child */
		if (ptrace(PTRACE_SYSCALL, pid, NULL, 0) == -1) {
			perror("FAIL: parent ptrace(PTRACE_SINGLESTEP) failed - ");
			return errno;
		}

		while (wait(&status) != pid);

		if (!WIFSTOPPED(status))
			return interp_status(status);
	
		memset(&regs, 0, sizeof(regs));
		if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
			perror("FAIL:  parent ptrace(PTRACE_GETREGS) failed - ");
			return errno;
		}
	}

	if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
		perror("FAIL:  parent ptrace(PTRACE_DETACH) failed - ");
		return errno;
	}

	return 0;
}

/* returns 0 on success or error code of failure */
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
				return errno;
			}
		}

		if (raise(SIGSTOP) != 0){
			perror("FAIL: child SIGSTOP itself failed -");
			return errno;
		}
		/* ok were stopped, wait for parent to trace (continue) us */
	}

	execve(argv[0], argv, environ);

	perror("FAIL: child exec failed - ");

	return errno;
}

void sigalrm_handler(int sig) {
	fprintf(stderr, "FAIL: parent timed out waiting for child\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	pid_t pid;
	int parent_trace = 1,
	    use_helper = 0,
	    num_syscall = NUM_CHLD_SYSCALLS, 
	    opt,
	    ret = 0;
	const char *usage = "usage: %s [-c] [-n #syscall] program [args ...]\n";
	char **args;

	if (signal(SIGALRM, sigalrm_handler) == SIG_ERR) {
		perror ("FAIL - signal failed: ");
		return(1);
        }

	opterr = 0;
	while (1) {
		opt = getopt(argc, argv, "chn:");

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

	args = &argv[optind];

	pid = fork();
	if (pid > 0){	/*parent */
		int stat;

		ret = do_parent(pid, parent_trace, num_syscall);

		kill(pid, SIGKILL);

		if (ret >= 0) {
			/* wait for child */
			while (wait(&stat) != pid);
		}

		if (ret > 0) {
			perror("FAIL: parent failed: ");
		} else if (ret == 0) { //||
//			  (ret == RET_SUCCESS && WIFSIGNALED(stat) && WTERMSIG(stat) == SIGKILL)) {
			printf("PASS\n");
			return 0;
		} else if (ret == -ECONNABORTED) {
			errno = -ret;
			perror("FAIL: child killed: ");
		} else {
			errno = -ret;
			perror("FAIL: child failed: ");
		}
	} else if (pid == 0) {	/* child */
		if (do_child(args, !parent_trace, use_helper))
			return 0;
			
	} else {
		perror("FAIL: fork failed - ");
	}

	return ret;
}
