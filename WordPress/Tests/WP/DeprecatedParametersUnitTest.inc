<?php

// All will be OK as the default value is used.

wp_title_rss( '&#8211;' ); // 1st.
wp_get_sidebars_widgets( true ); // 1st.
wp_new_user_notification( '', null, '' ); // 2nd.
the_attachment_link( '', false, false, false ); // 3rd.
update_blog_option( '', '', '', null ); // 4th.
wp_install( '', '', '', '', '' ); // 5th.
get_category_parents( '', '', '', '', array() ); // 5th.
get_category_parents( '', '', '', '', [] ); // 5th.

// Method names within a class should be fine.

Theme_Object::wp_title_rss( 'home' ); // Ok.
$this->wp_title_rss( 'siteurl' ); // Ok.
$theme_object->wp_title_rss( 'text_direction' ); // Ok.

// All will give an Error even though they have a dynamic variable.

wp_new_user_notification( '', $variable );
wp_new_user_notification( '', function_name() );
wp_new_user_notification( '', $this->method_name() );

/*
 * Test support for named parameters.
 */
// OK: Parameter is not passed.
wp_install( blog_title: '', user_name: '', user_email: '', is_public: '' );
// OK: Another (optional) parameter is passed as the 5th param.
wp_install( blog_title: '', user_name: '', user_email: '', is_public: '', language: '' );
// OK: Parameter is passed with correct default, mixed positional and named params, unconventional order.
wp_install( '', '', deprecated: '', user_email: '', is_public: '' );
// OK: Parameter is passed with correct default, all named params, unconventional order.
wp_install( user_name: '', deprecated: '', user_email: '', blog_title: '', is_public: '' );
// Error: Parameter is passed with incorrect default, unconventional order.
wp_install( is_public: '', user_name: '', user_email: '', deprecated: 'should be empty', blog_title: '' );

// All will give an ERROR. The functions are ordered alphabetically.

add_option( '', '', [] );
add_option( '', '', 1.23 );
add_option( '', '', 10 );
add_option( '', '', false );
add_option( '', '', 'deprecated' );
comments_link( 'deprecated', 'deprecated' );
convert_chars( '', 'deprecated' );
discover_pingback_server_uri( '', 'deprecated' );
get_category_parents( '', '', '', '', array( 'deprecated') );
get_delete_post_link( '', 'deprecated' );
get_last_updated( 'deprecated' );
get_the_author( 'deprecated' );
get_user_option( '', '', 'deprecated' );
get_wp_title_rss( 'deprecated' );
is_email( '', 'deprecated' );
is_email( '', 'false' ); // False as a string not bool.
load_plugin_textdomain( '', 'deprecated' );
safecss_filter_attr( '', 'deprecated' );
the_attachment_link( '', '', 'deprecated' );
the_author( 'deprecated', 'deprecated' );
the_author_posts_link( 'deprecated' );
trackback_rdf( 'deprecated' );
trackback_url( 'deprecated' );
unregister_setting( '', '', 'deprecated' );
update_blog_option( '', '', '', 'deprecated' );
update_user_status( '', '', '', 'deprecated' );
wp_get_http_headers( '', 'deprecated' );
wp_get_sidebars_widgets( 'deprecated' );
wp_install( '', '', '', '', 'deprecated', 'password', 'language' );
wp_new_user_notification( '', 'deprecated' );
wp_notify_postauthor( '', 'deprecated' );
wp_notify_postauthor( '', 'null' ); // Null as a string not null.
wp_title_rss( 'deprecated' );
wp_upload_bits( '', 'deprecated' );
xfn_check( '', '', 'deprecated' );
_future_post_hook( 10, $post );

// All will give an WARNING as they have been deprecated after WP 5.8.
_load_remote_block_patterns( $value );
