#ifndef REJECT_LIST_H
#define REJECT_LIST_H

GtkWidget* create_reject_dialog (GtkListStore *store);
void reject_button_press (GtkDialog * dialog, gint answer, gpointer data);
void reject_window_close (GtkDialog * dialog, gpointer data);
void handle_popup_profile (GtkWidget *menuitem, gpointer userdata);
void handle_popup_remove (GtkWidget *menuitem, gpointer userdata);
void display_popup_menu (GtkWidget *treeview, GdkEventButton *event, gpointer userdata);
gboolean popup_button_pressed (GtkWidget *treeview, GdkEventButton *event, gpointer userdata);
gboolean view_on_popup_menu (GtkWidget *treeview, gpointer userdata);

#endif
