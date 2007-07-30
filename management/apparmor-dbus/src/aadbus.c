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
#include <aalogparse/aalogparse.h>

#define NULLSPACE(x) (x == NULL) ? &empty_string : &x

// Local data
static volatile int signaled = 0;
static int pipe_fd;

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
/*	Make sure we are root */
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

/* This function is needed for "old" messages which lumped
 * everything together under one audit ID.
 */
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
	char *empty_string = " "; /* This is a quick way to indicate a 'null' value in our DBUS message */

	struct iovec vec[2];
	struct audit_dispatcher_header hdr;

	DBusError		error;		/* Error, if any */
	DBusMessage		*message;	/* Message to send */
	DBusMessageIter		iter;		/* Iterator for message data */
	static DBusConnection	*con = NULL;	/* Connection to DBUS server */

	char *line = NULL, *parsable_line = NULL;
	int real_data_size;
	aa_log_record *record;
	int is_rejection = 0;

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

	memset(data, 0, MAX_AUDIT_MESSAGE_LENGTH);
	memset(&hdr, 0, sizeof(hdr));
	do
	{
		int rc;
		parsable_line = NULL;
		is_rejection = 0;
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

		/* Handle the AppArmor events.
		 * 1500 is used for "old" style messages.
		 * 1503 is used for APPARMOR_DENIED messages. 
		 */
		if ((hdr.type == 1500) || (hdr.type == 1503))
		{
			line = (char *) data;
			record = NULL;
			if (hdr.type == 1503)
				is_rejection = 1;
			if ((hdr.type == 1500) && (is_reject(line) == 0))
				is_rejection = 1;

			/* We only care about REJECTING messages */
 			if (is_rejection == 1)
 			{
				printf("It's rejection\n");
				/* parse_record expects things like they appear in audit.log -
				 * which means we need to prepend TYPE=APPARMOR (if hdr.type is 1500)
				 * or type=APPARMOR_DENIED (if hdr.type is 1503).  This is not ideal.
				 */
				real_data_size = strlen(line);
				if (hdr.type == 1500)
				{
					printf("malloc\n");
					parsable_line = (char *) malloc(real_data_size + 20);
					snprintf(parsable_line, real_data_size + 19, "type=APPARMOR msg=%s", line);
					printf("printed\n");
				}
				else
				{
					parsable_line = (char *) malloc(real_data_size + 27);
					snprintf(parsable_line, real_data_size + 26, "type=APPARMOR_REJECT msg=%s", line);
				}

				record = parse_record(parsable_line);
				message = dbus_message_new_signal("/com/Novell/AppArmor","com.novell.apparmor", "REJECT");
				dbus_message_iter_init_append(message, &iter);

				/*
				 * The message has a number of fields appended to it,
				 * all of which map to the aa_log_record struct that we get back from
				 * parse_record().  If an entry in the struct is NULL or otherwise invalid,
				 * the field is still appended as a single blank space (in the case of strings), or a 
				 * 0 in case of integers (which are all PIDs and unlikely to ever be 0).
				 *
				 * TODO: Pass a bitmask int along for the denied & requested masks
				 *
				 * 1 - The full string - DBUS_TYPE_STRING
				 * 2 - The PID (record->pid)  - DBUS_TYPE_INT64
				 * 3 - The task (record->task) - DBUS_TYPE_INT64
				 * 4 - The audit ID (record->audit_id) - DBUS_TYPE_STRING
				 * 5 - The operation (record->operation: "Exec" "ptrace" etc) - DBUS_TYPE_STRING
				 * 6 - The denied mask (record->denied_mask: "rwx" etc) - DBUS_TYPE_STRING
				 * 7 - The requested mask (record->requested_mask) - DBUS_TYPE_STRING
				 * 8 - The name of the profile (record->profile) - DBUS_TYPE_STRING
				 * 9 - The first name field (record->name) - DBUS_TYPE_STRING
				 * 10- The second name field (record->name2) - DBUS_TYPE_STRING
				 * 11- The attribute (record->attribute) - DBUS_TYPE_STRING
				 * 12- The parent task (record->parent) - DBUS_TYPE_STRING
				 * 13- The magic token (record->magic_token) - DBUS_TYPE_STRING
				 * 14- The info field (record->info) - DBUS_TYPE_STRING
				 * 15- The active hat (record->active_hat) - DBUS_TYPE_STRING
				 */

				dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &data);
 				if (record != NULL)
 				{
					dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT64, &record->pid);
					dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT64, &record->task);	
					// Please note: NULLSPACE is defined at the top of this file, and will expand to
					// a ternary conditional:
					// (record->audit_id == NULL) ? &empty_string : &record->audit_id
					// for example.
					dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, NULLSPACE(record->audit_id));
					dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, NULLSPACE(record->operation));
					dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, NULLSPACE(record->denied_mask));
					dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, NULLSPACE(record->requested_mask));
					dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, NULLSPACE(record->profile));
					dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, NULLSPACE(record->name));
					dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, NULLSPACE(record->name2));
					dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, NULLSPACE(record->attribute));
					dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, NULLSPACE(record->parent));
					dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, NULLSPACE(record->magic_token));
					dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, NULLSPACE(record->info));
					dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, NULLSPACE(record->active_hat));
				}
				dbus_connection_send(con, message, NULL);
				dbus_connection_flush(con);
				dbus_message_unref(message);
  				free_record(record);

				if (parsable_line != NULL)
					free(parsable_line);
 			}
		}
	} while(!signaled);

	if (con)
	        dbus_connection_unref(con);
	free(data);
	return 0;
}
