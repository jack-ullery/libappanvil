#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <gdk/gdkkeysyms.h>
#include <gtk/gtk.h>
#include <glib/gi18n.h>
#include <gconf/gconf-client.h>
#include "preferences_dialog.h"
#include "apparmor-applet.h"

GtkWidget *profile_combobox;

GtkWidget*
create_preferences_dialog (void)
{
	GtkWidget *preferences_dialog;
	GtkWidget *preferences_vbox;
	GtkWidget *layout_table;
	GtkWidget *profile_label;
	GtkWidget *path_label;
	GtkWidget *preferences_buttonbox;
	GtkWidget *cancel_button;
	GtkWidget *ok_button;
	GtkWidget *path_entry;

	GConfClient *client;
	int active_combo;
	client = gconf_client_get_default();
	active_combo = gconf_client_get_int(client, CONF_PROFILE_KEY, NULL);

	preferences_dialog = gtk_dialog_new ();
	gtk_widget_set_name (preferences_dialog, "preferences_dialog");
	gtk_window_set_title (GTK_WINDOW (preferences_dialog), _("AppArmor Desktop Preferences"));
	gtk_window_set_position (GTK_WINDOW (preferences_dialog), GTK_WIN_POS_CENTER);
	gtk_window_set_modal (GTK_WINDOW (preferences_dialog), TRUE);
	gtk_window_set_type_hint (GTK_WINDOW (preferences_dialog), GDK_WINDOW_TYPE_HINT_DIALOG);
	
	preferences_vbox = GTK_DIALOG (preferences_dialog)->vbox;
	gtk_widget_set_name (preferences_vbox, "preferences_vbox");
	gtk_widget_show (preferences_vbox);
	
	layout_table = gtk_table_new (2, 2, FALSE);
	gtk_widget_set_name (layout_table, "layout_table");
	gtk_widget_show (layout_table);
	gtk_box_pack_start (GTK_BOX (preferences_vbox), layout_table, FALSE, TRUE, 0);
	gtk_table_set_col_spacings (GTK_TABLE (layout_table), 10);
	
	profile_label = gtk_label_new (_("Profile Generation"));
	gtk_widget_set_name (profile_label, "profile_label");
	gtk_widget_show (profile_label);
	gtk_table_attach (GTK_TABLE (layout_table), profile_label, 0, 1, 0, 1,
			(GtkAttachOptions) (GTK_FILL),
			(GtkAttachOptions) (0), 0, 0);
	gtk_misc_set_alignment (GTK_MISC (profile_label), 0, 0.5);
	
	path_label = gtk_label_new (_("Path"));
	gtk_widget_set_name (path_label, "path_label");
	gtk_widget_show (path_label);
	gtk_table_attach (GTK_TABLE (layout_table), path_label, 0, 1, 1, 2,
			(GtkAttachOptions) (GTK_FILL),
			(GtkAttachOptions) (0), 0, 0);
	gtk_misc_set_alignment (GTK_MISC (path_label), 0, 0.5);
	
	path_entry = gtk_entry_new ();
	gtk_widget_set_name (path_entry, "path_entry");
	gtk_widget_show (path_entry);
	gtk_table_attach (GTK_TABLE (layout_table), path_entry, 1, 2, 1, 2,
			(GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
			(GtkAttachOptions) (0), 0, 0);
	gtk_entry_set_invisible_char (GTK_ENTRY (path_entry), 9679);
	
	
	profile_combobox = gtk_combo_box_new_text ();
	gtk_widget_set_name (profile_combobox, "profile_combobox");
	gtk_widget_show (profile_combobox);
	gtk_table_attach (GTK_TABLE (layout_table), profile_combobox, 1, 2, 0, 1,
			(GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
			(GtkAttachOptions) (GTK_FILL), 0, 0);
	gtk_combo_box_append_text (GTK_COMBO_BOX (profile_combobox), _("YAST"));
	gtk_combo_box_append_text (GTK_COMBO_BOX (profile_combobox), _("genprof"));
	gtk_combo_box_set_active(GTK_COMBO_BOX(profile_combobox), active_combo);

	preferences_buttonbox = GTK_DIALOG (preferences_dialog)->action_area;
	gtk_widget_set_name (preferences_buttonbox, "preferences_buttonbox");
	gtk_widget_show (preferences_buttonbox);
	gtk_button_box_set_layout (GTK_BUTTON_BOX (preferences_buttonbox), GTK_BUTTONBOX_END);
	
	cancel_button = gtk_button_new_from_stock ("gtk-cancel");
	gtk_widget_set_name (cancel_button, "cancel_button");
	gtk_widget_show (cancel_button);
	gtk_dialog_add_action_widget (GTK_DIALOG (preferences_dialog), cancel_button, GTK_RESPONSE_CANCEL);
	GTK_WIDGET_SET_FLAGS (cancel_button, GTK_CAN_DEFAULT);
	
	ok_button = gtk_button_new_from_stock ("gtk-ok");
	gtk_widget_set_name (ok_button, "ok_button");
	gtk_widget_show (ok_button);
	gtk_dialog_add_action_widget (GTK_DIALOG (preferences_dialog), ok_button, GTK_RESPONSE_OK);
	GTK_WIDGET_SET_FLAGS (ok_button, GTK_CAN_DEFAULT);
	
	g_signal_connect(preferences_dialog, "response",
				G_CALLBACK(button_press),
				NULL);
	return preferences_dialog;
}

void
button_press (GtkDialog * dialog, gint answer, gpointer data)
{
	if (answer == GTK_RESPONSE_OK || answer == GTK_RESPONSE_CANCEL)
	{
		if (answer == GTK_RESPONSE_OK)
		{
			int active = gtk_combo_box_get_active (GTK_COMBO_BOX(profile_combobox));
			if (active <= -1)
				active = 0;

			GConfClient *client;
			client = gconf_client_get_default();
			gconf_client_set_int(client, CONF_PROFILE_KEY, active, NULL);
		}
		gtk_widget_destroy(GTK_WIDGET(dialog));
	}
}
