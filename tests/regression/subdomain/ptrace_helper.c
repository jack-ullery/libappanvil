#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

#define RET_FAILURE 0

int main(int argc, char *argv[])
{
char **args=&argv[1];
char *tracer = getenv("_tracer");
extern char **environ;
int child_traces;

	if (tracer && strcmp(tracer, "parent") == 0) {
		child_traces = 0;
	} else if (tracer && strcmp(tracer, "child") == 0) {
		child_traces = 1;
	} else {
		fprintf(stderr, "No/invalid _tracer in environ\n");
		return RET_FAILURE;
	}

	if (child_traces == 1 && 
	    ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1){
		perror("FAIL: child/helper ptrace(PTRACE_TRACEME) failed - ");
		return RET_FAILURE;
	}

	if (raise(SIGSTOP) != 0){
		perror("FAIL: child/helper SIGSTOP itself failed -");
		return RET_FAILURE;
	}
	/* ok were stopped, wait for parent to trace (continue) us */

	if (*args) {
		execve(args[0], args, environ);
	} else {
		for (;;) kill(getpid(), 0);
	}

	return RET_FAILURE;
}
