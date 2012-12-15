<?php
/**
 * Plugin Name: EDD Signed URLs
 * Plugin URI: https://github.com/bradyvercher/EDD-Signed-URLs
 * Description: Properly signed URLs for Easy Digital Downloads for more security.
 * Version: 1.0
 * Author: Blazer Six, Inc.
 * Author URI: http://www.blazersix.com/
 * License: GPLv2 or later
 * License URI: http://www.gnu.org/licenses/gpl-2.0.html
 *
 * @package EDD_Signed_Urls
 * @author Brady Vercher <brady@blazersix.com>
 * @copyright Copyright (c) 2012, Blazer Six, Inc.
 * @license http://www.gnu.org/licenses/gpl-2.0.html
 *
 * Signing URLs ensures that they can't be tampered with, allowing
 * non-sensitive data to be passed in the clear without needing to obfuscate
 * it, creating shorter and more secure URLs.
 *
 * This method only ensures the URL is valid and hasn't been tampered with,
 * so any further restrictions, such as expiration date or access rules based
 * on purchases or license keys needs to be done independently.
 */

/**
 * Load the plugin.
 */
add_action( 'plugins_loaded', 'eddsurl_load' );

/**
 * Attach hooks to EDD filters to change their behavior.
 *
 * @since 1.0.0
 */
function eddsurl_load() {
	// Determines if the request is for file.
	add_filter( 'edd_process_download_args', 'eddsurl_process_download_args' );
	
	// Filters secure URL generation to create signed URLs.
	add_filter( 'edd_download_file_url_args', 'eddsurl_download_file_url_args', 999 );
}

/**
 * Determine if a request is for a secure file.
 *
 * Check the query string to determine if the current request is for a secure
 * file. If it is, the URL the token was generated against is regenerated and
 * the token is verified. If the token can be verified, the information needed
 * by EDD is extracted from the URL and passed back to EDD so the expiration
 * date can be checked and the download sent.
 *
 * Typically the URL wouldn't be generated and the current URL would be used
 * when verifying the token.
 *
 * @since 1.0.0
 *
 * @param array $args EDD download args.
 * @return array
 */
function eddsurl_process_download_args( $args ) {
	if ( isset( $_GET['eddfile'] ) && isset( $_GET['ttl'] ) && isset( $_GET['token'] ) ) {
		// Kinda hacky method to generate the URL to test.
		$parts = parse_url( add_query_arg() );
		wp_parse_str( $parts['query'], $query_args );
		$url = add_query_arg( $query_args, home_url() );
		
		// Bail if the token isn't valid.
		// The request should pass through EDD, or custom handling can be enabled with the action.
		if ( ! eddsurl_is_token_valid( $url ) ) {
			// Do a wp_die() or redirect to an error page.
			do_action( 'eddsurl_invalid_download_request', $url, $args );
			
			return $args;
		}
		
		$order_parts = explode( ':', rawurldecode( $_GET['eddfile'] ) );
		
		$args['download'] = $order_parts[1];
		$args['email'] = get_post_meta( $order_parts[0], '_edd_payment_user_email', true );
		$args['expire'] = $_GET['ttl'];
		$args['file_key'] = $order_parts[2];
		$args['key'] = get_post_meta( $order_parts[0], '_edd_payment_purchase_key', true );
		
		do_action( 'eddsurl_valid_download_request', $url, $args );
	}
	
	return $args;
}

/**
 * Filter EDD's secure URL generation to return custom args.
 *
 * Replaces the default args for smaller and more secure URLs.
 *
 * Setting an expiration far in the future limits the usefulness of any
 * "protected" URL, no matter how many "limiting" args are added. They just
 * make it harder to guess, but if the URL published, it can no longer be
 * restricted except on the server side.
 *
 * @since 1.0.0
 *
 * @param array $args List of variables to append to the URL as a query string.
 * @return array
 */
function eddsurl_download_file_url_args( $args ) {
	global $wpdb;
	
	if ( empty( $args['download_key'] ) ) {
		return $args;
	}
	
	// Look up the payment ID.
	$payment_id = $wpdb->get_var( $wpdb->prepare( "SELECT post_id FROM $wpdb->postmeta WHERE meta_key='_edd_payment_purchase_key' AND meta_value=%s", $args['download_key'] ) );
	
	if ( $payment_id ) {
		$edd_args = $args;
		
		// Simply the URL by concatenating required data using a colon as a delimiter.
		$args = array(
			'eddfile' => rawurlencode( sprintf( '%d:%d:%d', $payment_id, $args['download'], $args['file'] ) )
		);
		
		// Decode the expiration date.
		if ( isset( $edd_args['expire'] ) ) {
			$args['ttl'] = base64_decode( rawurldecode( $edd_args['expire'] ) );
		}
		
		$args = apply_filters( 'eddsurl_download_file_url_args', $args, $payment_id, $edd_args );
		
		$args['token'] = eddsurl_get_token( add_query_arg( $args, home_url() ) );
	}
	
	return $args;
}

/**
 * Sign a URL to prevent it from being tampered with.
 *
 * @since 1.0.0
 *
 * @param string $url The URL to sign.
 * @param array $args Optional. List of query args to add to the URL before signing.
 * @return string Signed URL.
 */
function eddsurl_sign_url( $url, $args = array() ) {
    $args['token'] = false; // Removes a token if present.
   
    $url = add_query_arg( $args, $url );
    $token = eddsurl_get_token( $url );
    $url = add_query_arg( 'token', $token, $url );
   
    return $url;
}

/**
 * Generates a token for a given URL.
 *
 * An 'o' query parameter on a URL can include optional variables to test
 * against when verifying a token without passing those variables around in
 * the URL. For example, downloads can be limited to the IP that the URL was
 * generated for by adding 'o=ip' to the query string.
 *
 * Or suppose when WordPress requested a URL for automatic updates, the user
 * agent could be tested to ensure the URL is only valid for requests from
 * that user agent.
 *
 * @since 1.0.0
 *
 * @param string $url The URL to generate a token for.
 * @return string The token for the URL.
 */
function eddsurl_get_token( $url ) {
    $secret = apply_filters( 'eddsurl_get_token_secret', rawurlencode( base64_encode( wp_salt() ) ) );
	
	// Add additional args to the URL for generating the token.
	// Allows for restricting access to IP and/or user agent.
	$parts = parse_url( $url );
	$options = array();
	
	if ( isset( $parts['query'] ) ) {
		wp_parse_str( $parts['query'], $query_args );
		
		// o = option checks (ip, user agent).
		if ( ! empty( $query_args['o'] ) ) {
			// Multiple options can be checked by separating them with a colon in the query parameter.
			$options = explode( ':', rawurldecode( $query_args['o'] ) );
			
			if ( in_array( 'ip', $options ) ) {
				$args['ip'] = edd_get_ip();
			}
			
			if ( in_array( 'ua', $options ) ) {
				$args['user_agent'] = rawurlencode( $_SERVER['HTTP_USER_AGENT'] );
			}
		}
	}
	
	// Filter to modify arguments and allow custom options to be tested.
	// Be sure to rawurlencode any custom options for consistent results.
	$args = apply_filters( 'eddsurl_get_token_args', $args, $url, $options );
	
	$args['secret'] = $secret;
	$args['token'] = false; // Removes a token if present.
	
	$url = add_query_arg( $args, $url );
	$parts = parse_url( $url );
	$token = md5( $parts['path'] . '?' . $parts['query'] );
	
	return $token;
}

/**
 * Generate a token for a URL and match it against the existing token to make
 * sure the URL hasn't been tampered with.
 *
 * @since 1.0.0
 *
 * @param string $url URL to test.
 * @return bool
 */
function eddsurl_is_token_valid( $url ) {
    $parts = parse_url( $url );
   
    if ( isset( $parts['query'] ) ) {
        wp_parse_str( $parts['query'], $query_args );
       
        if ( isset( $query_args['token'] ) && $query_args['token'] == eddsurl_get_token( $url ) ) {
            return true;
        }
    }
   
    return false;
}
?>