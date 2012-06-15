<?php
/*
Plugin Name: Minimal LDAP Login
Plugin URI: http://blogs.valpo.edu/systems/ 
Description:  Barebones LDAP Authentication for Wordpress.
Version: 1.0
Author: Richard Orelup
Author URI: http://blogs.valpo.edu/systems/
*/

function ldap_authenticate($user, $username, $password) {
	if ( is_a($user, 'WP_User') ) { return $user; }

	//  Uncomment to only allow users to authenticate with LDAP and not against the default WP U/P
	//remove_filter('authenticate', 'wp_authenticate_username_password', 20, 3);

	if ( empty($username) ) {
                return new WP_Error('empty_username', __('<strong>ERROR</strong>: The username field is empty.'));
        }

        if ( empty($password) ) {
                return new WP_Error('empty_password', __('<strong>ERROR</strong>: The password field is empty.'));
        }
	
	// VU LDAP Credentials
	$ldapSettings = array();

	$ldapSettings['ldapHost'] = 'ldaps://123.123.123.123';
	$ldapSettings['ldapPort'] = 637;
	$ldapSettings['ldapUser'] = 'adminUser';
	$ldapSettings['ldapPass'] = 'adminPass';
	$ldapSettings['searchbase'] = 'DC=valpo,DC=edu';
	$ldapSettings['filter'] = '(sAMAccountName='.$username.')';
	
	$ds = ldap_connect($ldapSettings['ldapHost'], $ldapSettings['ldapPort'])
          or die("There was a problem connecting to LDAP Server - ".$ldapSettings['ldapHost']);
	ldap_set_option($ds, LDAP_OPT_PROTOCOL_VERSION, 3);
	ldap_set_option($ds, LDAP_OPT_REFERRALS, 0);

	$r = ldap_bind($ds,$ldapSettings['ldapUser'],$ldapSettings['ldapPass']);
	$sr = ldap_search($ds, $ldapSettings['searchbase'], $ldapSettings['filter']);
	$userInfo = ldap_get_entries($ds, $sr);
	if (isset($userInfo[0]['dn'])) {
		$userdn = $userInfo[0]['dn'];

		$dsVerify = ldap_connect($ldapSettings['ldapHost'], $ldapSettings['ldapPort'])
		  or die("There was a problem connecting to LDAP Server - ".$ldapSettings['ldapHost']);
		$rVerify=@ldap_bind($dsVerify,$userdn,$password);
	} else {
		return new WP_Error('invalid_username', __('<strong>Login Error</strong>: LDAP user not found.'));
	}

	if (!$rVerify) {
		return new WP_Error('invalid_password', __('<strong>Login Error</strong>: Password incorrect.'));
	} else {
		$user = get_userdatabylogin($username);
		if ( !$user || (strtolower($user->user_login) != strtolower($username)) ) {
			return new WP_Error('invalid_username', __('<strong>Login Error</strong>: LDAP credentials are correct but not added to Wordpress. Contact IMC to be properly setup.'));

		} else {
			return new WP_User($user->ID);	
		}
	} 
}

//Add filter
add_filter('authenticate', 'ldap_authenticate', 1, 3);

?>
