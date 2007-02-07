#ifndef __APPARMOR_APPLET_H
#define __APPARMOR_APPLET_H

#include <panel-applet.h>

#define CONF_PATH "/apps/AppArmor/apparmor-applet"
#define CONF_PROFILE_KEY "/apps/AppArmor/apparmor-applet/profiler"
#define CONF_PATH_KEY "/apps/AppArmor/apparmor-applet/path"

struct _apparmor_applet 
{
	GtkWidget *applet;
	GtkWidget *reject_dialog;
	gboolean uncleared_alerts;
	gboolean alert_icon_displayed;
	GtkWidget *panel_image;
	GdkPixbuf *icon;		/* Default icon */
	GdkPixbuf *icon_resized;	/* The resized default icon */
	GdkPixbuf *icon_alert;		/* Alert icon */
	GdkPixbuf *icon_alert_resized;	/* Resized alert icon */
	gint panel_height;
	gint alert_count;
	GtkTooltips *tooltips;
	GtkListStore *program_store;
};

void applet_about(BonoboUIComponent *uic);
void applet_prefs(BonoboUIComponent *uic);
void set_tooltip(void);
void set_appropriate_icon();
gboolean on_button_press (GtkWidget *event_box, 
				GdkEventButton *event,
				gpointer data);
void insert_into_list(char *name);
void decrement_event_count(gint decrement);

#endif
