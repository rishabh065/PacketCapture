#include <gtk/gtk.h>
#include "pcat.h"
/* Our callback.
 * The data passed to this function is printed to stdout */

/* This callback quits the program */
static gboolean delete_event( GtkWidget *widget,
                              GdkEvent  *event,
                              gpointer   data )
{
    gtk_main_quit ();
    return FALSE;
}

static void trigger( GtkWidget *widget,
                              GdkEvent  *event,
                              gpointer   data )
{
    initiateCapture();
}

void button_clicked(GtkWidget *widget, gpointer data)
{
  printf("%d\n",(int)data );
}

int main( int   argc,
          char *argv[] )
{

    GtkWidget *window,*scrolled_window,*table2;
    GtkWidget *button,*text;
    GtkWidget *table;

    gtk_init (&argc, &argv);

    /* Create a new window */
    window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
    gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);
    gtk_widget_set_size_request (window, 1100, 700);
    gtk_window_fullscreen ((GtkWindow *)window);

    /* Set the window title */
    gtk_window_set_title (GTK_WINDOW (window), "P.C.A.T.");

    /* Set a handler for delete_event that immediately
     * exits GTK. */
    g_signal_connect (window, "delete-event",
                      G_CALLBACK (delete_event), NULL);

    /* Sets the border width of the window. */
    gtk_container_set_border_width (GTK_CONTAINER (window), 10);

    /* Create a 2x2 table */
    table = gtk_table_new (27, 23, TRUE);

    /* Put the table in the main window */
    gtk_container_add (GTK_CONTAINER (window), table);

    gtk_widget_show (table);
    scrolled_window = gtk_scrolled_window_new (NULL, NULL);
    
    gtk_container_set_border_width (GTK_CONTAINER (scrolled_window), 5);

    gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scrolled_window),
                                    GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS);

    gtk_table_attach(GTK_TABLE(table), scrolled_window, 21, 24, 0, 25, 
        GTK_FILL, GTK_FILL, 0, 0);
    gtk_widget_show (scrolled_window);
    table2 = gtk_table_new (1000, 1, FALSE);
    
    /* set the spacing to 10 on x and 10 on y */
    gtk_table_set_row_spacings (GTK_TABLE (table2), 5);
    // gtk_table_set_col_spacings (GTK_TABLE (table2), 5);
    
    /* pack the table into the scrolled window */
    gtk_scrolled_window_add_with_viewport (GTK_SCROLLED_WINDOW (scrolled_window), table2);
    gtk_widget_show (table2);
    /* Insert button 1 into the upper left quadrant of the table */
    
    for(int i=0;i<5;i++)
    {
        GtkWidget* scrolled_window = gtk_scrolled_window_new (NULL, NULL);
        gtk_container_set_border_width (GTK_CONTAINER (scrolled_window), 5);

        gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scrolled_window),
                                    GTK_POLICY_ALWAYS, GTK_POLICY_ALWAYS);
        gtk_table_attach(GTK_TABLE(table), scrolled_window,  0, 21, i*5, 5*i+5, 
        GTK_FILL, GTK_FILL, 0, 0);
        gtk_widget_show (scrolled_window);
        text=gtk_text_view_new();
        gtk_text_view_set_editable(GTK_TEXT_VIEW(text), TRUE);
        gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(text), TRUE);
        // gtk_table_attach(GTK_TABLE(table), text, 0, 10, i*2, 2*i+2, 
        // GTK_FILL | GTK_EXPAND, GTK_FILL | GTK_EXPAND, 1, 1);
        gtk_scrolled_window_add_with_viewport (GTK_SCROLLED_WINDOW (scrolled_window), text);
        gtk_widget_show (text);
    }
    char buffer[10];
    for (int i = 0; i < 1000; i++){
       // for (j = 0; j < 10; j++) {
          sprintf (buffer, "Packet %d\n", i+1);
          button = gtk_toggle_button_new_with_label (buffer);
          gtk_table_attach(GTK_TABLE(table2), button,0,1, i, i+1, GTK_FILL | GTK_EXPAND, GTK_FILL | GTK_EXPAND, 2, 1);
          g_signal_connect (G_OBJECT(button), "clicked",
                      G_CALLBACK (button_clicked),(void*)i);
          gtk_widget_show (button);
       }
    /* Create second button */
       text=gtk_text_view_new();
        gtk_text_view_set_editable(GTK_TEXT_VIEW(text), FALSE);
        gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(text), FALSE);
        // gtk_table_attach(GTK_TABLE(table), text, 0, 10, i*2, 2*i+2, 
        // GTK_FILL | GTK_EXPAND, GTK_FILL | GTK_EXPAND, 1, 1);
        gtk_table_attach_defaults (GTK_TABLE (table), button, 0, 24, 26,27);
        gtk_widget_show (text);


    /* Create "Quit" button */
    button = gtk_button_new_with_label ("Quit");
   
    /* When the button is clicked, we call the "delete-event" function
     * and the program exits */
    g_signal_connect (button, "clicked",G_CALLBACK (delete_event), NULL);

    /* Insert the quit button into the both 
     * lower quadrants of the table */
    gtk_table_attach_defaults (GTK_TABLE (table), button, 21, 24, 26,27);
    gtk_widget_show (button);
    button = gtk_button_new_with_label ("Start");
    g_signal_connect (button, "clicked",G_CALLBACK (trigger), NULL);
    gtk_table_attach_defaults (GTK_TABLE (table), button, 12, 15, 26,27);
    gtk_widget_show (button);

    gtk_widget_show (table);
    gtk_widget_show (window);

    gtk_main ();

    return 0;
}