#define DBUS_API_SUBJECT_TO_CHANGE 
#include <stdio.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <locale.h>
#include <libaudit.h>
#include <dbus/dbus.h>
#include <pcre.h>

// Local data
static volatile int signaled = 0;
static int pipe_fd;
static const char *pgm = "AppArmorDBUS";

// Local functions
static int event_loop(void);
static int is_reject(char *data);

// SIGTERM handler
static void term_handler( int sig )
{
	signaled = 1;
}


/*
 * main is started by auditd. See dispatcher in auditd.conf
 */
int main(int argc, char *argv[])
{
	struct sigaction sa;
	
	setlocale (LC_ALL, "");
	
#ifndef DEBUG
	// Make sure we are root
	if (getuid() != 0) {
		printf("You must be root to run this program.\n");
		return 4;
	}
#endif

	// register sighandlers
	sa.sa_flags = 0 ;
	sa.sa_handler = term_handler;
	sigemptyset( &sa.sa_mask ) ;
	sigaction( SIGTERM, &sa, NULL );
	sa.sa_handler = term_handler;
	sigemptyset( &sa.sa_mask ) ;
	sigaction( SIGCHLD, &sa, NULL );
	sa.sa_handler = SIG_IGN;
	sigaction( SIGHUP, &sa, NULL );
	(void)chdir("/");

	// change over to pipe_fd
	pipe_fd = dup(0);
	close(0);
	open("/dev/null", O_RDONLY);
	fcntl(pipe_fd, F_SETFD, FD_CLOEXEC);

	// Start the program
	return event_loop();
}

static int is_reject (char *data)
{
	int ret = -1;
	/* Look for the first space */
	char *start = strchr(data, ' ');
	if ((start != NULL) && (strlen(start) > 9))
	{
		if (strncmp(start + 1, "REJECTING", 9) == 0)
		{
			ret = 0;
		}
	}

	return ret;
}

static int event_loop(void)
{
	void* data;
	struct iovec vec[2];
	struct audit_dispatcher_header hdr;
	DBusError		error;		/* Error, if any */
	DBusMessage		*message;	/* Message to send */
	DBusMessageIter		iter;		/* Iterator for message data */
	const char		*what;		/* What to send */
	static DBusConnection	*con = NULL;	/* Connection to DBUS server */
	pcre *reject_regex;
	const char *pcre_error, *matched_mode, *matched_resource, *matched_program, *matched_pid, *matched_profile, *matched_active;
	int pcre_reject_vector[30];
	int pcre_reject_vector_size = 30;
	int pcre_erroffset, pcre_exec_return;
	char *line;

	char *pcre_reject_string = "^audit\\(\\d+\\.\\d+:\\d+\\): REJECTING (\\D+) access to (\\S+) \\((\\D+)\\((\\d+)\\) profile (\\S+) active (\\S+)\\)";
	if (con && !dbus_connection_get_is_connected(con))
	{
		dbus_connection_unref(con);
		con = NULL;
	}
	
	if (!con)
	{
		dbus_error_init(&error);
		con = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
		if (!con)
		{
			dbus_error_free(&error);
			return 1;
		}
	}


 	//message = dbus_message_new_signal("/com/Novell/AppArmor","com.novell.apparmor", "Reject");

	/* allocate data structures */
	data = malloc(MAX_AUDIT_MESSAGE_LENGTH);
	if (data == NULL) 
	{
		printf("Cannot allocate buffer\n");
		return 1;
	}

	/* Compile the regular expression */
	reject_regex = pcre_compile(pcre_reject_string, 0, &pcre_error, &pcre_erroffset, NULL);
	if (reject_regex == NULL)
	{
		printf("Could not compile the reject regular expression.\n");
		printf("The error message was: %s\n", pcre_error);
		return 1;
	}

	memset(data, 0, MAX_AUDIT_MESSAGE_LENGTH);
	memset(&hdr, 0, sizeof(hdr));
	do
	{
		int rc;
		struct timeval tv;
		fd_set fd;
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		FD_ZERO(&fd);
		FD_SET(pipe_fd, &fd);
		rc = select(pipe_fd+1, &fd, NULL, NULL, &tv);
		if (rc == 0) 
			continue;
		 else if (rc == -1)
			break;

		/* Get header first. it is fixed size */
		vec[0].iov_base = (void*)&hdr;
		vec[0].iov_len = sizeof(hdr);

		memset(data, 0, MAX_AUDIT_MESSAGE_LENGTH);
        	// Next payload 
		vec[1].iov_base = data;
		vec[1].iov_len = MAX_AUDIT_MESSAGE_LENGTH; 

		rc = readv(pipe_fd, vec, 2);
		if (rc == 0 || rc == -1) {
			printf("rc == %d(%s)\n", rc, strerror(errno));
			break;
		}
		/* Handle the AppArmor events */
		if ((hdr.type >= 1500) && (hdr.type <= 1599)) 
		{
			line = (char *) data;
			/* We only care about REJECTING messages */
			if (is_reject(line) == 0)
			{
				pcre_exec_return = pcre_exec(reject_regex,
								NULL,
								line,
								strlen(line),
								0,
								0,
								pcre_reject_vector,
								pcre_reject_vector_size);
				if (pcre_exec_return > 0)
				{
					pcre_get_substring(line, pcre_reject_vector, pcre_exec_return, 1, &matched_mode);
					pcre_get_substring(line, pcre_reject_vector, pcre_exec_return, 2, &matched_resource);
					pcre_get_substring(line, pcre_reject_vector, pcre_exec_return, 3, &matched_program);
					pcre_get_substring(line, pcre_reject_vector, pcre_exec_return, 4, &matched_pid);
					pcre_get_substring(line, pcre_reject_vector, pcre_exec_return, 5, &matched_profile);
					pcre_get_substring(line, pcre_reject_vector, pcre_exec_return, 6, &matched_active);
					message = dbus_message_new_signal("/com/Novell/AppArmor","com.novell.apparmor", "REJECT");
					dbus_message_iter_init_append(message, &iter);
					dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &data);
					dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &matched_mode);
					dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &matched_resource);
					dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &matched_program);
					dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &matched_pid);
					dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &matched_profile);
					dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &matched_active);
					dbus_connection_send(con, message, NULL);
  					dbus_connection_flush(con);
					dbus_message_unref(message);
					pcre_free_substring(matched_mode);
					pcre_free_substring(matched_resource);
					pcre_free_substring(matched_program);
					pcre_free_substring(matched_pid);
					pcre_free_substring(matched_profile);
					pcre_free_substring(matched_active);

				}
			}
		}

	} while(!signaled);
	//dbus_message_unref(message);

	if (con)
	        dbus_connection_disconnect (con);
	pcre_free(reject_regex);
	return 0;
}

