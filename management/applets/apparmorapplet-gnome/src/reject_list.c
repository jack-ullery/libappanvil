#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <gconf/gconf-client.h>
#include <stdio.h>
#include <panel-applet.h>
#include <libgnome/libgnome.h>
#include <glib/gi18n.h>
#include <gdk/gdkkeysyms.h>
#include <gtk/gtk.h>
#include "reject_list.h"
#include "apparmor-applet.h"

static void
add_columns (GtkTreeView *treeview)
{
	GtkCellRenderer *renderer;
	GtkTreeViewColumn *column;
	GtkTreeModel *model = gtk_tree_view_get_model (treeview);
	
	/* column for fixed toggles */
	renderer = gtk_cell_renderer_text_new ();
	
	column = gtk_tree_view_column_new_with_attributes ("Program Name",
							renderer,
							"text", 0,
							NULL);
	gtk_tree_view_column_set_sort_column_id (column, 0);
	gtk_tree_view_append_column (treeview, column);
	
	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes ("Rejection Count",
							renderer,
							"text", 1,
							NULL);
	gtk_tree_view_column_set_sort_column_id (column, 1);
	gtk_tree_view_append_column (treeview, column);

}

GtkWidget*
create_reject_dialog (GtkListStore *store)
{
	GtkWidget *reject_dialog;
	GtkWidget *reject_vbox;
	GtkWidget *reject_list_scrolledwindow;
	GtkWidget *program_list;
	GtkWidget *reject_button_area;
	GtkWidget *cancel_button;
	GtkWidget *ok_button;
	GtkTreeIter listIter;
	
	reject_dialog = gtk_dialog_new ();
	gtk_widget_set_name (reject_dialog, "reject_dialog");
	gtk_window_set_title (GTK_WINDOW (reject_dialog), _("AppArmor Rejections"));
	gtk_window_set_type_hint (GTK_WINDOW (reject_dialog), GDK_WINDOW_TYPE_HINT_DIALOG);
	gtk_window_set_modal(GTK_WINDOW(reject_dialog), TRUE);
	
	reject_vbox = GTK_DIALOG (reject_dialog)->vbox;
	gtk_widget_set_name (reject_vbox, "reject_vbox");
	gtk_widget_show (reject_vbox);
	
	reject_list_scrolledwindow = gtk_scrolled_window_new (NULL, NULL);
	gtk_widget_set_name (reject_list_scrolledwindow, "reject_list_scrolledwindow");
	gtk_widget_show (reject_list_scrolledwindow);
	gtk_box_pack_start (GTK_BOX (reject_vbox), reject_list_scrolledwindow, TRUE, TRUE, 0);
	gtk_scrolled_window_set_shadow_type (GTK_SCROLLED_WINDOW (reject_list_scrolledwindow), GTK_SHADOW_IN);
	
	program_list = gtk_tree_view_new_with_model(GTK_TREE_MODEL(store));
	gtk_widget_set_name (program_list, "program_list");
	gtk_widget_show (program_list);
	gtk_container_add (GTK_CONTAINER (reject_list_scrolledwindow), program_list);
	gtk_tree_view_set_headers_visible (GTK_TREE_VIEW (program_list), TRUE);
	add_columns (GTK_TREE_VIEW (program_list));
	
	reject_button_area = GTK_DIALOG (reject_dialog)->action_area;
	gtk_widget_set_name (reject_button_area, "reject_button_area");
	gtk_widget_show (reject_button_area);
	gtk_button_box_set_layout (GTK_BUTTON_BOX (reject_button_area), GTK_BUTTONBOX_END);
	
	cancel_button = gtk_button_new_from_stock ("gtk-cancel");
	gtk_widget_set_name (cancel_button, "cancel_button");
	gtk_widget_show (cancel_button);
	gtk_dialog_add_action_widget (GTK_DIALOG (reject_dialog), cancel_button, GTK_RESPONSE_CANCEL);
	GTK_WIDGET_SET_FLAGS (cancel_button, GTK_CAN_DEFAULT);
	
	ok_button = gtk_button_new_from_stock ("gtk-ok");
	gtk_widget_set_name (ok_button, "ok_button");
	gtk_widget_show (ok_button);
	gtk_dialog_add_action_widget (GTK_DIALOG (reject_dialog), ok_button, GTK_RESPONSE_OK);
	GTK_WIDGET_SET_FLAGS (ok_button, GTK_CAN_DEFAULT);
	
	g_signal_connect(reject_dialog,
			"response",
			G_CALLBACK(reject_button_press),
			NULL);
	
	g_signal_connect(reject_dialog,
			"delete-event",
			G_CALLBACK(reject_window_close),
			NULL);

	g_signal_connect(program_list, 
			"button-press-event",
			G_CALLBACK(popup_button_pressed),
			NULL);

	g_signal_connect(program_list,
			"popup-menu",
			G_CALLBACK(view_on_popup_menu),
			NULL);
	
	gtk_widget_grab_focus (program_list);
	gtk_window_set_default_size(GTK_WINDOW(reject_dialog), 500, 400);
	return reject_dialog;
}


void reject_button_press (GtkDialog * dialog, gint answer, gpointer data)
{
	if (answer == GTK_RESPONSE_OK || answer == GTK_RESPONSE_CANCEL)
	{
		gtk_widget_hide(GTK_WIDGET(dialog));
	}
}

void reject_window_close (GtkDialog * dialog, gpointer data)
{
		gtk_widget_hide(GTK_WIDGET(dialog));
}

void
handle_popup_profile (GtkWidget *menuitem, gpointer userdata)
{
	GtkTreeView *treeview = GTK_TREE_VIEW(userdata);
	GConfClient *client = gconf_client_get_default();

	int profiler_type = gconf_client_get_int(client, CONF_PROFILE_KEY, NULL);
	char *cmdline;

	GtkTreeSelection *selection = gtk_tree_view_get_selection(treeview);
	GtkTreeIter iter;
	GtkTreeModel *model = gtk_tree_view_get_model(treeview);
	gchar *str_data = NULL;

	if (gtk_tree_selection_get_selected(selection, &model, &iter) == TRUE)
	{
		
		gint int_data;
		GtkListStore *store = GTK_LIST_STORE(model);

		gtk_tree_model_get (model, &iter, 
					0, &str_data,
					1, &int_data,
					-1);
	}

	// 0 is YAST, 1 is genprof
	if ((profiler_type == 0) && (str_data != NULL))
	{
		cmdline = "/opt/gnome/bin/gnomesu /sbin/yast2 LogProf";
		gnome_execute_terminal_shell(NULL, cmdline);
	}
	else if ((profiler_type == 1) && (str_data != NULL))
	{
		/* /usr/sbin/genprof */
		cmdline = (char *) malloc(41 + strlen(str_data));
		strcpy(cmdline, "/opt/gnome/bin/gnomesu /usr/sbin/genprof ");
		strcat(cmdline, str_data);
		gnome_execute_terminal_shell(NULL, cmdline);
		free(cmdline);
	}

	if (str_data != NULL)
		g_free (str_data);
}

void
handle_popup_remove (GtkWidget *menuitem, gpointer userdata)
{ 
	GtkTreeView *treeview = GTK_TREE_VIEW(userdata);
	GtkTreeSelection *selection = gtk_tree_view_get_selection(treeview);
	GtkTreeIter iter;
	GtkTreeModel *model = gtk_tree_view_get_model(treeview);
	if (gtk_tree_selection_get_selected(selection, &model, &iter) == TRUE)
	{
		gchar *str_data;
		gint int_data;
		GtkListStore *store = GTK_LIST_STORE(model);

		gtk_tree_model_get (model, &iter, 
					0, &str_data,
					1, &int_data,
					-1);
		g_free (str_data);
		decrement_event_count(int_data);
		gtk_list_store_remove(store, &iter);
	}
}

void
display_popup_menu (GtkWidget *treeview, GdkEventButton *event, gpointer userdata)
{
	GtkWidget *menu, *remove_item, *profile_item;
	
	menu = gtk_menu_new();
	
	profile_item = gtk_menu_item_new_with_label(_("Profile application"));
	remove_item = gtk_menu_item_new_with_label(_("Remove from list"));

	g_signal_connect(remove_item,
			"activate",
			G_CALLBACK(handle_popup_remove),
			treeview);
	g_signal_connect(profile_item,
			"activate",
			G_CALLBACK(handle_popup_profile),
			treeview);

	gtk_menu_shell_append(GTK_MENU_SHELL(menu), profile_item);
	gtk_menu_shell_append(GTK_MENU_SHELL(menu), remove_item);

	gtk_widget_show_all(menu);
	
	gtk_menu_popup(GTK_MENU(menu), NULL, NULL, NULL, NULL,
			(event != NULL) ? event->button : 0,
			gdk_event_get_time((GdkEvent*)event));
}


gboolean
popup_button_pressed (GtkWidget *treeview, GdkEventButton *event, gpointer userdata)
{
	if (event->type == GDK_BUTTON_PRESS  &&  event->button == 3)
	{

		GtkTreeSelection *selection;
		selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(treeview));

		if (gtk_tree_selection_count_selected_rows(selection)  <= 1)
		{
			GtkTreePath *path;
			if (gtk_tree_view_get_path_at_pos(GTK_TREE_VIEW(treeview),
						(gint) event->x, 
						(gint) event->y,
						&path, NULL, NULL, NULL))
			{
				gtk_tree_selection_unselect_all(selection);
				gtk_tree_selection_select_path(selection, path);
				gtk_tree_path_free(path);
			}
		}
		display_popup_menu(treeview, event, userdata);
		return TRUE;
	}
	
	return FALSE;
}


gboolean
view_on_popup_menu (GtkWidget *treeview, gpointer userdata)
{
	display_popup_menu(treeview, NULL, userdata);
	return TRUE; 
}

