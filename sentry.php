<?php
/**
 * Part of the Sentry package for Laravel.
 *
 * @package    Sentry
 * @version    1.0
 * @author     Cartalyst LLC
 * @license    MIT License
 * @copyright  (c) 2011 - 2012, Cartalyst LLC
 * @link       http://cartalyst.com
 */

namespace Sentry;

use Config;
use Cookie;
use DB;
use Request;
use Session;
use Lang;
use Str;

class SentryException extends \Exception {}
class SentryConfigException extends SentryException {}

/**
 * Sentry Auth class
 */
class Sentry extends \Laravel\Auth\Drivers\Driver
{

	/**
	 * @var  Sentry_Attempts  Holds the Sentry_Attempts object
	 */
	protected $attempts = null;

	/**
	 * @var  array  Caches all users accessed
	 */
	protected $user_cache = array();

	/**
	 * Gets either the currently logged in user or the specified user by id or Login
	 * Column value.
	 *
	 * @param   int|string  User id or Login Column value to find.
	 * @throws  SentryException
	 * @return  Sentry_User
	 */
	public function retrieve($id = null, $recache = false)
	{
		if ($id === null and $recache === false and $this->user !== null)
		{
			return $this->user;
		}
		elseif ($id !== null and $recache === false and isset($this->user_cache[$id]))
		{
			return $this->user_cache[$id];
		}

		try
		{
			if ($id)
			{
				return $this->user_cache[$id] = new Sentry_User($id);
			}
			// if session exists - default to user session
			elseif ($this->token)
			{
				return new Sentry_User($this->token);
			}

			// else return empty user
			//return new Sentry_User();
			return null;
		}
		catch (SentryUserException $e)
		{
			throw new SentryException($e->getMessage());
		}
	}

	/**
	 * Get's either the currently logged in user's group object or the
	 * specified group by id or name.
	 *
	 * @param   int|string  Group id or or name
	 * @return  Sentry_User
	 */
	public function group($id = null)
	{
		if ($id)
		{
			return new Sentry_Group($id);
		}

		return new Sentry_Group();
	}

	/**
	 * Gets the Sentry_Attempts object
	 *
	 * @return  Sentry_Attempts
	 */
	 public function attempts($login_id = null, $ip_address = null)
	 {
	 	return new Sentry_Attempts($login_id, $ip_address);
	 }

	/**
	 * Attempt to log a user in.
	 *
	 * @param   string  Login column value
	 * @param   string  Password entered
	 * @param   bool    Whether to remember the user or not
	 * @return  bool
	 * @throws  SentryException
	 */
	public function attempt($arguments = array(), $password = null, $remember = false)
	{
		$login_column = Config::get('auth.username');
		$suspend = Config::get('auth.sentry.suspend');

		// Leave explicit parameters for backwards compatibility
		if ( ! is_array($arguments))
		{
			$arguments = array(
				$login_column => $arguments,
				'password' => $password,
				'remember' => $remember,
			);
		}

		// log the user out if they hit the login page
		$this->logout();

		// get login attempts
		if ($suspend)
		{
			$attempts = $this->attempts($arguments['username'], Request::ip());

			// if attempts > limit - suspend the login/ip combo
			if ($attempts->get() >= $attempts->get_limit())
			{
				try
				{
					$attempts->suspend();
				}
				catch(SentryUserSuspendedException $e)
				{
					throw new SentryException($e->getMessage());
				}
			}
		}

		// make sure vars have values
		if (empty($arguments[$login_column]) or empty($arguments['password']))
		{
			return false;
		}

		// if user is validated
		if ($user = $this->validate_user($arguments[$login_column], $arguments['password'], 'password'))
		{
			if ($suspend)
			{
				// clear attempts for login since they got in
				$attempts->clear();
			}

			// set update array
			$update = array();

			// if there is a password reset hash and user logs in - remove the password reset
			if ($user->get('password_reset_hash'))
			{
				$update['password_reset_hash'] = '';
				$update['temp_password'] = '';
			}

			$update['last_login'] = time();
			$update['ip_address'] = Request::ip();

			// update user
			if (count($update))
			{
				$user->update($update, false);
			}

			// set session vars
			$this->login((int) $user->get('id'), array_get($arguments, 'remember'));

			return true;
		}

		return false;
	}

	/**
	 * Force Login
	 *
	 * @param   int|string  user id or login value
	 * @param   provider    what system was used to force the login
	 * @return  bool
	 * @throws  SentryException
	 */
	public function force_login($id, $provider = 'Sentry-Forced')
	{
		// check to make sure user exists
		if ( ! $this->user = $this->retrieve($id))
		{
			throw new SentryException(__('sentry::sentry.user_not_found'));
		}

		$this->login($id, $remember = false, $provider);

		return true;
	}

	/**
	 * Logs the specified user in.
	 *
	 * @param   int   
	 * @return  void
	 */
	public function login($token, $remember = false, $provider = 'Sentry')
	{
		parent::login($token, $remember);

		Session::put(Config::get('sentry::sentry.session.provider'), $provider);

		return true;
	}

	/**
	 * Logs the current user out.  Also invalidates the Remember Me setting.
	 *
	 * @return  void
	 */
	public function logout()
	{
		parent::logout();
		Session::forget(Config::get('sentry::sentry.session.provider'));
	}

	/**
	 * Activate a user account
	 *
	 * @param   string  Encoded Login Column value
	 * @param   string  User's activation code
	 * @return  bool|array
	 * @throws  SentryException
	 */
	public function activate_user($login_column_value, $code, $decode = true)
	{
		// decode login column
		if ($decode)
		{
			$login_column_value = base64_decode($login_column_value);
		}

		// make sure vars have values
		if (empty($login_column_value) or empty($code))
		{
			return false;
		}

		// if user is validated
		if ($user = $this->validate_user($login_column_value, $code, 'activation_hash'))
		{
			// update pass to temp pass, reset temp pass and hash
			$user->update(array(
				'activation_hash' => '',
				'activated' => 1
			), false);

			return $user;
		}

		return false;
	}

	/**
	 * Starts the reset password process.  Generates the necessary password
	 * reset hash and returns the new user array.  Password reset confirm
	 * still needs called.
	 *
	 * @param   string  Login Column value
	 * @param   string  User's new password
	 * @return  bool|array
	 * @throws  SentryException
	 */
	public function reset_password($login_column_value, $password)
	{
		// make sure a user id is set
		if (empty($login_column_value) or empty($password))
		{
			return false;
		}

		// check if user exists
		$user = $this->retrieve($login_column_value);

		// create a hash for reset_password link
		$hash = Str::random(24);

		// set update values
		$update = array(
			'password_reset_hash' => $hash,
			'temp_password' => $password,
			'remember_me' => '',
		);

		// if database was updated return confirmation data
		if ($user->update($update))
		{
			$update = array(
				'email' => $user->get('email'),
				'password_reset_hash' => $hash,
				'link' => base64_encode($login_column_value).'/'.$update['password_reset_hash']
			);

			return $update;
		}
		else
		{
			return false;
		}
	}

	/**
	 * Confirms a password reset code against the database.
	 *
	 * @param   string  Login Column value
	 * @param   string  Reset password code
	 * @return  bool
	 * @throws  SentryException
	 */
	public function reset_password_confirm($login_column_value, $code, $decode = true)
	{
		// decode login column
		if ($decode)
		{
			$login_column_value = base64_decode($login_column_value);
		}

		// make sure vars have values
		if (empty($login_column_value) or empty($code))
		{
			return false;
		}

		if (Config::get('auth.sentry.suspend'))
		{
			// get login attempts
			$attempts = $this->attempts($login_column_value, Request::ip());

			// if attempts > limit - suspend the login/ip combo
			if ($attempts->get() >= $attempts->get_limit())
			{
				$attempts->suspend();
			}
		}

		// if user is validated
		if ($user = $this->validate_user($login_column_value, $code, 'password_reset_hash'))
		{
			// update pass to temp pass, reset temp pass and hash
			$user->update(array(
				'password' => $user->get('temp_password'),
				'password_reset_hash' => '',
				'temp_password' => '',
				'remember_me' => '',
			), false);

			return true;
		}

		return false;
	}

	/**
	 * Checks if a user exists by Login Column value
	 *
	 * @param   string|id  Login column value or Id
	 * @return  bool
	 */
	public function user_exists($login_column_value)
	{
		try
		{
			$user = new Sentry_User($login_column_value, true);

			if ($user)
			{
				return true;
			}

			// this should never happen
			return false;
		}
		catch (SentryUserException $e)
		{
			return false;
		}
	}

	/**
	 * Checks if the group exists
	 *
	 * @param   string|int  Group name|Group id
	 * @return  bool
	 */
	public function group_exists($group)
	{
		try
		{
			$group_exists = new Sentry_Group($group, true);

			if ($group_exists)
			{
				return true;
			}

			// this should never happen
			return false;
		}
		catch(SentryException $e)
		{
			$group_exists = false;
		}
	}

	/**
	 * Validates a Login and Password.  This takes a password type so it can be
	 * used to validate password reset hashes as well.
	 *
	 * @param   string  Login column value
	 * @param   string  Password to validate with
	 * @param   string  Field name (password type)
	 * @return  bool|Sentry_User
	 */
	protected function validate_user($login_column_value, $password, $field)
	{
		// get user
		$user = $this->retrieve($login_column_value);

		// check activation status
		if ($user->activated != 1 and $field != 'activation_hash')
		{
			throw new SentryException(__('sentry::sentry.account_not_activated'));
		}

		// check user status
		if ($user->status != 1)
		{
			throw new SentryException(__('sentry::sentry.account_is_disabled'));
		}

		// check password
		if ( ! $user->check_password($password, $field))
		{
			if ($this->$suspend and ($field == 'password' or $field == 'password_reset_hash'))
			{
				$this->attempts($login_column_value, Request::ip())->add();
			}
			return false;
		}

		return $user;
	}

}
