<?php
/*
Plugin Name: WP Access Password
Description: Non-authenticated users can only access your site with a password. Logged-in users can access the site without the password.
Version: 0.1
Author: r-a-y
Author URI: http://profiles.wordpress.org/r-a-y
*/

add_action( 'plugins_loaded', array( 'WP_Access_Password', 'init' ) );

class WP_Access_Password {
	/**
	 * @var string The blog visibility setting.
	 */
	public static $visibility  = '';

	/**
	 * @var string The blog access password.
	 */
	protected static $password = '';

	/**
	 * Static init method.
	 */
	public static function init() {
		return new self();
	}

	/**
	 * Constructor.
	 */
	public function __construct() {
		self::$visibility = get_option( 'blog_public' );
		self::$password   = $this->get_password();

		$this->setup_hooks();
	}

	/**
	 * Setup hooks.
	 */
	public function setup_hooks() {
		// add setting field
		add_action( 'blog_privacy_selector',         array( $this, 'add_password_field' ), 20 );
		add_action( 'signup_blogform',               array( $this, 'add_password_field' ), 20 );

		// save settings
		add_filter( 'pre_update_option_blog_public', array( $this, 'save_options_reading' ) );
		add_action( 'wpmu_new_blog',                 array( $this, 'save_on_new_blog' ),   20 );

		// redirect
		add_action( 'template_redirect',             array( $this, 'redirect' ), 0 );

		// custom login page
		add_action( 'login_form_access-pwd',         array( $this, 'custom_login' ) );

		// dashboard visibility text
		add_filter( 'privacy_on_link_title',         array( $this, 'dashboard_privacy_text' ) );
		add_filter( 'privacy_on_link_text',          array( $this, 'dashboard_privacy_text' ) );

		// some built-in whitelist conditions
		add_filter( 'wp_access_password_whitelist',  array( $this, 'default_whitelist' ) );
	}

	/**
	 * Adds our custom setting and password fields.
	 *
	 * Fields are added to "Settings > Reading" and on multisite's signup blog
	 * form.
	 */
	public function add_password_field() {
		if ( ! is_admin() ) {
			$visibility = '';
			$password   = '';
		} else {
			$visibility = self::$visibility;
			$password   = self::$password;
		}

	?>
		<br />
		<label class="checkbox" for="wp-blog-privacy-pwd">
			<input id="wp-blog-privacy-pwd" type="radio" name="blog_public" value="-4" <?php checked( $visibility, -4 ); ?> />
			<?php _e( 'All registered users can view the site without a password.  Non-logged-in users can only access the site with the following password:', 'wp-access-pwd' ); ?>
		</label>

		<label class="checkbox" for="blog_access_pwd">
			<input type="text" id="blog_access_pwd" name="blog_access_pwd" class="regular-text" value="<?php echo strip_tags( $password ); ?>"  />
		</label>
	<?php
	}

	/**
	 * Save the password when submitting from "Settings > Reading" page.
	 *
	 * @param string $retval The blog public setting
	 */
	public function save_options_reading( $retval = '' ) {
		$this->save();
		return $retval;
	}

	/**
	 * Save the password when creating a new blog.
	 *
	 * Untested... should work when user already has an account.
	 *
	 * @todo Need to add support on new user + blog signup
	 *
	 * @param int $blog_id The blog ID
	 */
	public function save_on_new_blog( $blog_id ) {
		$this->save( $blog_id );
	}

	/**
	 * Handles redirection.
	 *
	 * If a visitor isn't authenticated, the user gets redirected to the password
	 * access form.
	 */
	public function redirect() {
		// check if site is password protected; if not, stop now!
		if ( ! self::is_password_protected() ) {
			return;
		}

		// logged-in users don't need this, so stop!
		if ( is_user_logged_in() ) {
			return;
		}

		// Check if on the wp-signup page, if so, stop!
		if ( ! empty( $_SERVER['SCRIPT_NAME'] ) && false !== strpos( $_SERVER['SCRIPT_NAME'], 'wp-signup.php' ) ) {
			return;
		}

		// Do some other checks with this filter
		// Make sure to return true in your override function!
		if ( apply_filters( 'wp_access_password_whitelist', false ) ) {
			return;
		}

		// visitor has already authenticated, so stop!
		if ( self::is_visitor_authenticated() ) {
			return;
		}

		$host = is_ssl() ? 'https://' : 'http://';

		$login_url = site_url( 'wp-login.php', 'login' );

                $login_url = add_query_arg( 'action',      'access-pwd', $login_url );
                $login_url = add_query_arg( 'redirect_to', urlencode( "{$host}{$_SERVER['HTTP_HOST']}{$_SERVER['REQUEST_URI']}" ), $login_url );

		// redirect to custom login page
		wp_redirect( $login_url );
		exit();
	}

	/**
	 * Sets up our custom login page for visitors.
	 *
	 * This is almost exactly the same as the conditional block for wp-login.php's
	 * 'lostpassword' action.
	 */
	public function custom_login() {
		$redirect_to = ! empty( $_REQUEST['redirect_to'] ) ? $_REQUEST['redirect_to'] : home_url();

		// this part is pretty much a copy of wp-login.php's 'postpass' block
		if ( ( 'POST' == $_SERVER['REQUEST_METHOD'] ) ) {
			require_once ABSPATH . 'wp-includes/class-phpass.php';
			$hasher = new PasswordHash( 8, true );

			$blog_id = get_current_blog_id();

			/**
			 * Filter the life span of the access password cookie.
			 *
			 * By default, the cookie expires 10 days from creation. To turn this
			 * into a session cookie, return 0.
			 *
			 * @param int $expires The expiry time, as passed to setcookie().
			 */
			$expire = apply_filters( 'wp_access_password_expires', time() + 10 * DAY_IN_SECONDS );
			setcookie( "wp-accesspwd_{$blog_id}_" . COOKIEHASH, $hasher->HashPassword( wp_unslash( $_POST['access-pwd'] ) ), $expire, COOKIEPATH );

			wp_safe_redirect( $redirect_to );
			exit();
		}

		/**
		 * Fires before the access password form.
		 */
		do_action( 'access_pwd' );

		login_header(
			__( 'Enter password' ),
			'<p class="message">' . __( 'Please enter the site password to access the site.', 'wp-access-pwd' ) . '<br /><br />' .
			 sprintf( __( 'If you already have an account, <a href="%s">login now</a>.', 'wp-access-pwd' ), wp_login_url( $redirect_to ) ) . '</p>'
		);

	?>

	<form name="access-pwd-form" id="access-pwd-form" action="<?php echo esc_url( site_url( 'wp-login.php?action=access-pwd', 'login_post' ) ); ?>" method="post">
		<p>
			<label for="access-pwd" ><?php _e( 'Password:', 'wp-access-pwd' ); ?><br />
			<input type="text" name="access-pwd" id="access-pwd" class="input" value="" size="20" /></label>
		</p>
		<?php
		/**
		 * Fires inside the <form> tags, before the hidden fields.
		 */
		do_action( 'access_pwd_form' ); ?>
		<input type="hidden" name="redirect_to" value="<?php echo esc_attr( $redirect_to ); ?>" />
		<p class="submit"><input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Submit', 'wp-access-pwd' ); ?>" /></p>
	</form>

	<p id="nav">
	<a href="<?php echo esc_url( wp_login_url( $redirect_to ) ); ?>"><?php _e( 'Log in', 'wp-access-pwd' ) ?></a>
	<?php
	if ( get_option( 'users_can_register' ) ) :
		$registration_url = sprintf( '<a href="%s">%s</a>', esc_url( wp_registration_url() ), __( 'Register', 'wp-access-pwd' ) );
		echo ' | ' . apply_filters( 'register', $registration_url );
	endif;
	?>
	</p>

	<?php
		login_footer( 'user_login' );
		die();
	}

	/**
	 * Modifies the dashboard's site visibility anchor text.
	 *
	 * @param string $retval
	 */
	public function dashboard_privacy_text( $retval ) {
		if ( ! self::is_password_protected() ) {
			return $retval;
		}

		return __( 'Visible to all registered users.  Also visible to non-logged-in users with a password.', 'wp-access-pwd' );
	}

	/**
	 * Whitelist certain pages from redirecting to the password page.
	 *
	 * Currently whitelists BuddyPress' register and activation pages.
	 */
	public function default_whitelist( $retval ) {
		// check for BuddyPress
		if ( defined( 'BP_VERSION' ) ) {
			// allow registration and activation pages to be shown
			if ( bp_is_register_page() || bp_is_activation_page() ) {
				return true;
			}
		}

		return $retval;
	}

	/** UTILITY ************************************************************/

	/**
	 * Save method.
	 *
	 * @param int $blog_id The blog ID.
	 */
	protected function save( $blog_id = 0 ) {
		if ( ! empty( $_REQUEST['blog_public'] ) && $_REQUEST['blog_public'] == -4 ) {
			if ( ! empty( $_REQUEST['blog_access_pwd'] ) ) {
				if ( (int) $blog_id > 0 ) {
					update_blog_option( (int) $blog_id, 'blog_access_pwd', $_REQUEST['blog_access_pwd'] );
				} else {
					update_option( 'blog_access_pwd', $_REQUEST['blog_access_pwd'] );
				}
			}
		}
	}

	/**
	 * Get our access password.
	 *
	 * If a password doesn't exist, try to look for the password from WPMUDev's
	 * Sitewide Privacy Options plugin as a fallback.
	 *
	 * @return string
	 */
	protected function get_password() {
		$password = get_option( 'blog_access_pwd' );

		// support password from WPMUDev's Sitewide Privacy Options plugin as a
		// fallback
		if ( empty( $password ) ) {
			$spo_options = get_option( 'spo_settings' );
			$password    = isset( $spo_options['blog_pass'] ) ? $spo_options['blog_pass'] : '';
		}

		return $password;
	}

	/** STATIC METHODS *****************************************************/

	/**
	 * Check if a visitor is authenticated.
	 *
	 * A visitor is not a registered user.  However, a visitor can gain access to
	 * the site by entering the site's access password correctly.
	 *
	 * This is the same algorithm used by {@link post_password_required()}.
	 */
	protected static function is_visitor_authenticated() {
		if ( empty( self::$password ) ) {
			return false;
		}

		$blog_id = get_current_blog_id();

		if ( ! isset( $_COOKIE["wp-accesspwd_{$blog_id}_" . COOKIEHASH] ) ) {
			return false;
		}

		require_once ABSPATH . 'wp-includes/class-phpass.php';
		$hasher = new PasswordHash( 8, true );

		$hash = wp_unslash( $_COOKIE[ "wp-accesspwd_{$blog_id}_" . COOKIEHASH ] );
		if ( 0 !== strpos( $hash, '$P$B' ) ) {
			return false;
		}

		return $hasher->CheckPassword( self::$password, $hash );
	}

	/**
	 * Check if the current site has toggled the password protection setting.
	 */
	public static function is_password_protected() {
		return self::$visibility == -4;
	}
}