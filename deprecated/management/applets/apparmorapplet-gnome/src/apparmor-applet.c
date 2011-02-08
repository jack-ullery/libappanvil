#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <glib.h>
#include <panel-applet.h>
#include <gtk/gtk.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <regex.h>
#include <stdlib.h>
#include <string.h>
#include <glib/gi18n.h>
#include <libgnome/gnome-program.h>
#include "preferences_dialog.h"
#include "reject_list.h"
#include "apparmor-applet.h"

struct _apparmor_applet *apparmor_applet = NULL;

static const BonoboUIVerb apparmor_menu_verbs[] = {
	BONOBO_UI_UNSAFE_VERB("apparmor_applet_about", applet_about),
/*	BONOBO_UI_UNSAFE_VERB("apparmor_applet_preferences", applet_prefs),*/
	BONOBO_UI_VERB_END
};

// We don't really have any "preferences" to set yet.

// static const char Context_menu_xml [] =
//    "<popup name=\"button3\">\n"
//    "   <menuitem name=\"About AppArmor Applet\" "
//    "             verb=\"apparmor_applet_about\" "
//    "           _label=\"_About...\"\n"
//    "          pixtype=\"stock\" "
//    "          pixname=\"gnome-stock-about\"/>\n"
//    "   <menuitem name=\"Preferences\" "
//    "		verb=\"apparmor_applet_preferences\" "
//    "          _label=\"_Preferences...\"\n"
//    "         pixtype=\"stock\" "
//    "         pixname=\"gtk-preferences\"/>\n"
//    "</popup>\n";

static const char Context_menu_xml [] =
   "<popup name=\"button3\">\n"
   "   <menuitem name=\"About AppArmor Applet\" "
   "             verb=\"apparmor_applet_about\" "
   "           _label=\"_About...\"\n"
   "          pixtype=\"stock\" "
   "          pixname=\"gnome-stock-about\"/>\n"
   "</popup>\n";

void
insert_into_list(char *name)
{
	GtkTreeIter iter, listIter;
	gboolean exists, row_found;

	row_found = FALSE;
	exists = gtk_tree_model_get_iter_first (GTK_TREE_MODEL(apparmor_applet->program_store), &iter);
	/* Check to see if it exists already and increment the rejection count if it is */
	while (exists)
	{
		gchar *str_data;
		gint int_data;

		gtk_tree_model_get (GTK_TREE_MODEL(apparmor_applet->program_store), &iter, 
					0, &str_data,
					1, &int_data,
					-1);


		if (g_strcasecmp(str_data, name) == 0)
		{
			int_data++;
			gtk_list_store_set (apparmor_applet->program_store, &iter, 0, str_data, 1, int_data, -1);
			row_found = TRUE;
			g_free (str_data);
			break;
		}

		g_free (str_data);
		exists = gtk_tree_model_iter_next (GTK_TREE_MODEL(apparmor_applet->program_store), &iter);
	}

	if (row_found == FALSE)
	{
		gtk_list_store_append (apparmor_applet->program_store, &listIter);
		gtk_list_store_set (apparmor_applet->program_store, &listIter, 0, name, 1,  1, -1);
	}
}

static DBusHandlerResult signal_filter 
	(DBusConnection *connection, DBusMessage *message, void *user_data)
{
	GtkTreePath *path;
	GtkTreeIter listIter;
	DBusMessageIter	iter, subIter;
	char *program_name;
	int arrayLen;
	/* We are about to be kicked off */
	if (dbus_message_is_signal
		(message, DBUS_PATH_LOCAL, "Disconnected"))
	{
		return DBUS_HANDLER_RESULT_HANDLED;
	}
	else if (dbus_message_is_signal (message, "com.novell.apparmor", "REJECT"))
	{
		apparmor_applet->alert_count++;
		apparmor_applet->uncleared_alerts = TRUE;
		dbus_message_iter_init(message, &iter);
	/*
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
		dbus_message_iter_next(&iter);
		dbus_message_iter_next(&iter);
		dbus_message_iter_next(&iter);
		dbus_message_iter_next(&iter);
		dbus_message_iter_next(&iter);
		dbus_message_iter_next(&iter);
		dbus_message_iter_next(&iter);
//		dbus_message_iter_get_basic(&iter, &program_name);
		dbus_message_iter_recurse(&iter, &subIter);
		dbus_message_iter_get_fixed_array(&subIter, &program_name, &arrayLen);
		
		if (program_name == NULL)
		{
			return DBUS_HANDLER_RESULT_HANDLED;
		}

		insert_into_list(program_name);
		set_tooltip();
		set_appropriate_icon();
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

/* The applet display */
static gboolean apparmor_applet_fill(PanelApplet * applet,
					const gchar * iid,
					gpointer data)
{
	if (strcmp(iid, "OAFIID:AppArmorApplet") != 0) 
	{
		return FALSE;
	}

	GError *error = NULL;
	DBusConnection *bus;
	DBusError dbus_error;

	apparmor_applet = g_new(struct _apparmor_applet, 1);
	apparmor_applet->uncleared_alerts = FALSE;
	apparmor_applet->reject_dialog = NULL;
	apparmor_applet->alert_icon_displayed = FALSE;
	apparmor_applet->alert_count = 0;
	apparmor_applet->tooltips = gtk_tooltips_new();
	apparmor_applet->program_store = gtk_list_store_new(2, G_TYPE_STRING, G_TYPE_UINT);
	apparmor_applet->applet = GTK_WIDGET(applet);
	gtk_widget_realize(apparmor_applet->applet);

	/* Set up the icons */
	apparmor_applet->icon =
		gdk_pixbuf_new_from_file(
			gnome_program_locate_file
				(NULL, GNOME_FILE_DOMAIN_PIXMAP,
				"apparmor_default.png", FALSE, NULL), &error);	

	apparmor_applet->icon_alert =
		gdk_pixbuf_new_from_file(
			gnome_program_locate_file
				(NULL, GNOME_FILE_DOMAIN_PIXMAP,
				"apparmor_alert.png", FALSE, NULL), &error);

	/* Get the panel height in order to resize the icon */

	apparmor_applet->panel_height =
		panel_applet_get_size(PANEL_APPLET(apparmor_applet->applet));
	
	apparmor_applet->icon_resized =
		gdk_pixbuf_scale_simple(apparmor_applet->icon,
					apparmor_applet->panel_height,
					apparmor_applet->panel_height,
					GDK_INTERP_BILINEAR);
	
	apparmor_applet->icon_alert_resized =
		gdk_pixbuf_scale_simple(apparmor_applet->icon_alert,
					apparmor_applet->panel_height,
					apparmor_applet->panel_height,
					GDK_INTERP_BILINEAR);
	
	apparmor_applet->panel_image = g_object_new(GTK_TYPE_IMAGE,
						"pixbuf",
						apparmor_applet->icon_resized,
						"storage-type", GTK_IMAGE_PIXBUF,
						NULL);
	panel_applet_setup_menu (PANEL_APPLET (apparmor_applet->applet),
                         	Context_menu_xml,
                         	apparmor_menu_verbs,
                         	NULL);

	gtk_container_add(GTK_CONTAINER(apparmor_applet->applet),
					apparmor_applet->panel_image);

	g_signal_connect(G_OBJECT(apparmor_applet->applet),
				"button-press-event", G_CALLBACK(on_button_press),
				NULL);

	gtk_widget_show_all(GTK_WIDGET(apparmor_applet->applet));
	set_tooltip();
	gtk_tooltips_enable(apparmor_applet->tooltips);

	dbus_error_init (&dbus_error);
	bus = dbus_bus_get (DBUS_BUS_SYSTEM, &dbus_error);
	if (!bus)
	{
		dbus_error_free (&dbus_error);
		return FALSE;
	}

	dbus_connection_setup_with_g_main (bus, NULL);

	/* listening to messages from all objects as no path is specified */
	dbus_bus_add_match (bus, "type='signal',interface='com.novell.apparmor'", &dbus_error);
	dbus_connection_add_filter (bus, signal_filter, NULL, NULL);

	return TRUE;
}

void set_tooltip (void)
{
	GString *apparmor_tooltip = g_string_sized_new(255);
	g_string_printf(apparmor_tooltip, "There are %i AppArmor alerts", apparmor_applet->alert_count);

	gtk_tooltips_set_tip(apparmor_applet->tooltips,
				apparmor_applet->applet,
				apparmor_tooltip->str, NULL);
}

void set_appropriate_icon (void)
{
	GdkPixbuf *pixbuf = NULL;

	if ((apparmor_applet->uncleared_alerts == TRUE) && (apparmor_applet->alert_icon_displayed == FALSE))
	{
		pixbuf = gdk_pixbuf_copy(apparmor_applet->icon_alert_resized);
		gtk_image_set_from_pixbuf(GTK_IMAGE(apparmor_applet->panel_image), pixbuf);
		apparmor_applet->alert_icon_displayed = TRUE;
	}
	else if ((apparmor_applet->uncleared_alerts == FALSE) && (apparmor_applet->alert_icon_displayed == TRUE))
	{
		pixbuf = gdk_pixbuf_copy(apparmor_applet->icon_resized);
		gtk_image_set_from_pixbuf(GTK_IMAGE(apparmor_applet->panel_image), pixbuf);
		apparmor_applet->alert_icon_displayed = FALSE;
	}

	if (pixbuf != NULL)
		g_object_unref(pixbuf);

}


void applet_about(BonoboUIComponent * uic)
{
	const gchar *license =
		_("AppArmorApplet is free software; you can redistribute it and/or modify\n"
		 "it under the terms of the GNU General Public License, version 2, as published by\n"
		 "the Free Software Foundation.");

	const gchar *authors[] = {
		"Matt Barringer <mbarringer@suse.de>",
		NULL
	};

	GtkWidget *about_apparmor_applet=
		g_object_new(GTK_TYPE_ABOUT_DIALOG, 
				"authors", authors,
				"logo", GDK_PIXBUF(apparmor_applet->icon),
				"copyright", ("Copyright (C) 2007 Novell"),
				"name", ("AppArmor Alert Applet"),
				"version", VERSION,
				"license", license,
				NULL);

       g_signal_connect (about_apparmor_applet, "response",
                         G_CALLBACK (gtk_widget_destroy),
                         about_apparmor_applet);

       g_signal_connect (about_apparmor_applet, "destroy",
                         G_CALLBACK (gtk_widget_destroyed),
                         NULL);

       gtk_widget_show(about_apparmor_applet);
}

void applet_prefs (BonoboUIComponent *uic)
{
	GtkWidget *prefs_dialog;
	prefs_dialog = create_preferences_dialog();
	gtk_widget_show(prefs_dialog);
}

gboolean on_button_press (GtkWidget *event_box, 
				GdkEventButton *event,
				gpointer data)
{
	if (event->button != 1)
		return FALSE;
	
	if (apparmor_applet->reject_dialog == NULL)
	{
		apparmor_applet->reject_dialog = create_reject_dialog(apparmor_applet->program_store);
		gtk_widget_show(apparmor_applet->reject_dialog);

	}
	else
	{
		gtk_widget_show(apparmor_applet->reject_dialog);
	}

	return TRUE;
}

/* Decrement the event count and reset the icon/tooltip state if necessary */
void decrement_event_count(gint decrement)
{
	apparmor_applet->alert_count = apparmor_applet->alert_count - decrement;

	if (apparmor_applet->alert_count <= 0)
	{
		apparmor_applet->alert_count= 0;
		apparmor_applet->uncleared_alerts = FALSE;
		set_appropriate_icon();
		set_tooltip();
	}
}

PANEL_APPLET_BONOBO_FACTORY("OAFIID:AppArmorApplet_Factory",
			PANEL_TYPE_APPLET, "AppArmor Desktop Alerts", "0",
			apparmor_applet_fill, NULL);

