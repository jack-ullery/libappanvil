#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <panel-applet.h>
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

   g_signal_connect(reject_dialog, "response",
				G_CALLBACK(reject_button_press),
				NULL);

   g_signal_connect(reject_dialog, "delete-event",
				G_CALLBACK(reject_window_close),
				NULL);

  gtk_widget_grab_focus (program_list);
  return reject_dialog;
}
