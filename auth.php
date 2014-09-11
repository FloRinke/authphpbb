<?php
// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

define('IN_PHPBB', true);
global $phpbb_root_path;
global $db;
global $cache;
global $phpEx;
global $user;
global $config;
global $conf;
global $table_prefix;
global $phpbb_auth;

$phpEx = substr(strrchr(__FILE__, '.'), 1);

if(strpos($_SERVER['PHP_SELF'], "/lib/plugins/") !== false) { $phpbb_root_path = '../../../'.$phpbb_root_path; }
if(strpos($_SERVER['PHP_SELF'], "/lib/exe/") !== false) { $phpbb_root_path = '../../'.$phpbb_root_path; }

require_once($phpbb_root_path.'common.'.$phpEx);

//$user->session_begin();

//$auth will be used by DokuWiki, so copy phpBB's $auth to another variable
$phpbb_auth = $auth;
//$phpbb_auth->acl($user->data);

/**
 * PHPBB authentication backend
 *
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author     Andreas Gohr <andi@splitbrain.org>
 * @author     Chris Smith <chris@jalakai.co.uk>
 * @author     Matthias Grimm <matthias.grimmm@sourceforge.net>
 * @author     Jan Schumann <js@schumann-it.com>
 * @author     Florian Rinke <github+authphpbb@florianrinke.de>
 */
class auth_plugin_authphpbb extends auth_plugin_authmysql {
    /**
     * Constructor
     *
     * calls constructor of parent class and sets additional options
     *
     * @author Florian Rinke <florian.rinke@fs-eit.de>
     */
    public function __construct() {
        //global $user;
        //global $phpbb_auth;
        parent::__construct();

	$this->cando['external'] = true;
	session_destroy();
	//$user->session_begin();
	//$phpbb_auth->acl($user->data);
    }

    public function trustExternal($username, $password, $sticky = false) {
        global $USERINFO;
	global $conf;
	global $user;
        global $phpbb_auth;
        $sticky ? $sticky = true : $sticky = false; // sanity check
        $user->session_begin();
        $phpbb_auth->acl($user->data);

        // someone used the login form
        if(!empty($username)) {
            // run phpBB's login function
            define('IN_LOGIN', true);
            $login = $phpbb_auth->login($username, $password, $sticky);
	    if($login['status'] != LOGIN_SUCCESS) { 
		    $this->_debug("Login fehlgeschlagen", -1, __LINE__, __FILE__);
		    return false; 
	    }
	    $this->_debug("Login erfolgreich", 1, __LINE__, __FILE__);
	}

        if(!$user->data['is_registered']) { return false; }
	
        $USERINFO['name'] = $user->data['username'];
        $USERINFO['mail'] = $user->data['user_email'];
        if($this->_openDB()) {
            $USERINFO['grps'] = $this->_getGroups($USERINFO['name']);
        }
	
        $_SERVER['REMOTE_USER'] = $user->data['username'];
        $_SESSION[DOKU_COOKIE]['auth']['user'] = $user->data['username'];
        $_SESSION[DOKU_COOKIE]['auth']['pass'] = $user->data['user_password'];
        $_SESSION[DOKU_COOKIE]['auth']['info'] = $USERINFO;
	
        return true;
    }

    public function logOff() {
        global $user;
        $user->session_kill();
    }
}
