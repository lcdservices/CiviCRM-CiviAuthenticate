<?php
/**
 * Joomla/CiviCRM Authentication plugin
 *
 * This plugin authenticates against the Joomla user table and
 * then checks with CiviCRM that the user has a valid current 
 * membership record
 *
 * @author      Henry Bennett <henry@bec-cave.org.uk>
 *              Brian Shaughnessy <brian@lcdservices.biz>
 * @version     2.1.0
 * @package     Joomla
 * @subpackage  JFramework
 * @since       Joomla 1.6
 * @copyright   
 *
 * version 1.0.4 by Brian Shaughnessy
 * version 1.0.5 by Brian Shaughnessy
 * version 1.1.0 by Brian Shaughnessy
 * version 2.0.0 by Henry Bennett (added Joomla ACL and username or email login)
 * version 2.1.0 by Brian Shaughnessy
 * version 2.5.0 by Brian Shaughnessy
 * version 2.6.0 by Brian Shaughnessy (CiviCRM 4.4/Joomla 2.5.18 compatibility)
 * 
 * For updates, see: https://github.com/lcdservices/CiviCRM-CiviAuthenticate
 */

defined('_JEXEC') or die;

/**
 * Joomla/CiviCRM Authentication plugin
 *
 * @package     Joomla.Plugin
 * @subpackage  Authentication.joomla
 * @since       1.5
 */
class plgAuthenticationCiviCRM extends JPlugin
{
  /**
   * This method should handle any authentication and report back to the subject
   *
	 * @param   array   $credentials  Array holding the user credentials
	 * @param   array   $options      Array of extra options
	 * @param   object  &$response    Authentication response object
	 *
   * @return  boolean
	 *
   * @since 1.5
   */
	public function onUserAuthenticate($credentials, $options, &$response)
  {
    $response->type = 'Joomla';

    // Joomla does not like blank passwords
		if (empty($credentials['password']))
		{
      $response->status = JAuthentication::STATUS_FAILURE;
      $response->error_message = JText::_('JGLOBAL_AUTH_EMPTY_PASS_NOT_ALLOWED');

			return false;
    }

    // Initialise variables.
    $conditions = '';

    //CiviCRM: construct redirection urls
    $redirectURLs = self::_getRedirectionURLs();

    //CiviCRM: JLog
    $response->type = 'CiviCRM';

    // Get a database object
    $db = JFactory::getDbo();
	  $query = $db->getQuery(true);

    $query->select('id, password');
    $query->from('#__users');

    //CiviCRM: accommodate username OR email
    if ( $this->params->get('username_email') ) {
      $query->where('username='.$db->quote($credentials['username']).' OR email='.$db->quote($credentials['username']));
    }
    else {
      $query->where('username='.$db->quote($credentials['username']));
    }

    $db->setQuery( $query );
    $result = $db->loadObject();

    if ($result)
    {
      $match = JUserHelper::verifyPassword($credentials['password'], $result->password, $result->id);

      if ($match === true)
      {
				// Bring this in line with the rest of the system
				$user = JUser::getInstance($result->id);
        $response->email = $user->email;
        $response->fullname = $user->name;

        if (JFactory::getApplication()->isAdmin())
        {
          $response->language = $user->getParam('admin_language');
        }
        else
        {
          $response->language = $user->getParam('language');
        }

        //CiviCRM: bypass member check for Joomla admins
        //CiviCRM: use JFactory::getUser to get the object for authorise() function
        $adminTestUser = JFactory::getUser($result->id);
        if ($adminTestUser->authorise('core.login.admin')) {
          $response->status = JAuthentication::STATUS_SUCCESS;
          $response->error_message = '';
        }
        //CiviCRM: run through membership checks
        else {
          self::_checkMembership($redirectURLs, $user, $response, $result);
        }
      }
      else
      {
				// Invalid password
        $response->status = JAuthentication::STATUS_FAILURE;
        $response->error_message = JText::_('JGLOBAL_AUTH_INVALID_PASS');

        //CiviCRM: redirection
        $app =& JFactory::getApplication();
        $app->redirect($redirectURLs['bad_password']);
      }
    }
    else {
			// Invalid user
      $response->status = JAuthentication::STATUS_FAILURE;
      $response->error_message = JText::_('JGLOBAL_AUTH_NO_USER');

      //CiviCRM: no username found
      $app =& JFactory::getApplication();
      $app->redirect($redirectURLs['no_match']);
    }

    // Check the two factor authentication
		if ($response->status == JAuthentication::STATUS_SUCCESS)
		{
			require_once JPATH_ADMINISTRATOR . '/components/com_users/helpers/users.php';

			$methods = UsersHelper::getTwoFactorMethods();

			if (count($methods) <= 1)
			{
				// No two factor authentication method is enabled
				return;
			}

			require_once JPATH_ADMINISTRATOR . '/components/com_users/models/user.php';

			$model = new UsersModelUser;

			// Load the user's OTP (one time password, a.k.a. two factor auth) configuration
			if (!array_key_exists('otp_config', $options))
			{
				$otpConfig = $model->getOtpConfig($result->id);
				$options['otp_config'] = $otpConfig;
			}
			else
			{
				$otpConfig = $options['otp_config'];
			}

			// Check if the user has enabled two factor authentication
			if (empty($otpConfig->method) || ($otpConfig->method == 'none'))
			{
				// Warn the user if he's using a secret code but he has not
				// enabed two factor auth in his account.
				if (!empty($credentials['secretkey']))
				{
					try
					{
						$app = JFactory::getApplication();

						$this->loadLanguage();

						$app->enqueueMessage(JText::_('PLG_AUTH_JOOMLA_ERR_SECRET_CODE_WITHOUT_TFA'), 'warning');
					}
					catch (Exception $exc)
					{
						// This happens when we are in CLI mode. In this case
						// no warning is issued
						return;
					}
				}

				return;
			}

			// Load the Joomla! RAD layer
			if (!defined('FOF_INCLUDED'))
			{
				include_once JPATH_LIBRARIES . '/fof/include.php';
			}

			// Try to validate the OTP
			FOFPlatform::getInstance()->importPlugin('twofactorauth');

			$otpAuthReplies = FOFPlatform::getInstance()->runPlugins('onUserTwofactorAuthenticate', array($credentials, $options));

			$check = false;

			/*
			 * This looks like noob code but DO NOT TOUCH IT and do not convert
			 * to in_array(). During testing in_array() inexplicably returned
			 * null when the OTEP begins with a zero! o_O
			 */
			if (!empty($otpAuthReplies))
			{
				foreach ($otpAuthReplies as $authReply)
				{
					$check = $check || $authReply;
				}
			}

			// Fall back to one time emergency passwords
			if (!$check)
			{
				// Did the user use an OTEP instead?
				if (empty($otpConfig->otep))
				{
					if (empty($otpConfig->method) || ($otpConfig->method == 'none'))
					{
						// Two factor authentication is not enabled on this account.
						// Any string is assumed to be a valid OTEP.

						return true;
					}
					else
					{
						/*
						 * Two factor authentication enabled and no OTEPs defined. The
						 * user has used them all up. Therefore anything he enters is
						 * an invalid OTEP.
						 */
						return false;
					}
				}

				// Clean up the OTEP (remove dashes, spaces and other funny stuff
				// our beloved users may have unwittingly stuffed in it)
				$otep = $credentials['secretkey'];
				$otep = filter_var($otep, FILTER_SANITIZE_NUMBER_INT);
				$otep = str_replace('-', '', $otep);

				$check = false;

				// Did we find a valid OTEP?
				if (in_array($otep, $otpConfig->otep))
				{
					// Remove the OTEP from the array
					$otpConfig->otep = array_diff($otpConfig->otep, array($otep));

					$model->setOtpConfig($result->id, $otpConfig);

					// Return true; the OTEP was a valid one
					$check = true;
				}
			}

			if (!$check)
			{
				$response->status = JAuthentication::STATUS_FAILURE;
				$response->error_message = JText::_('JGLOBAL_AUTH_INVALID_SECRETKEY');
			}
		}
  }//onUserAuthenticate

  /*
   * backward compatibility
   */
  function onAuthenticate($credentials, $options, &$response){
    $this->onUserAuthenticate($credentials, $options, $response);
  }

  function _getRedirectionURLs() {
    // experimental method for creating the URL redirect options.
    // old method was unreliable.
    // use 0 = path constructor lookup
    // use 1 = itemid constructor lookup

    $url_creat_method = 0;
    $menu =& JApplication::getMenu('site');
    $redirectURLs = array();

    $redirectURLs['old_membership_itemid'] = $this->params->get('redirect_old_membership');
    $redirectURLs['old_membership_item'] = $menu->getItem( $redirectURLs['old_membership_itemid'] );
    $redirectURLs['old_membership'] = JRoute::_($redirectURLs['old_membership_item']->link
      .'&Itemid='
      .$redirectURLs['old_membership_itemid'], FALSE);

    $redirectURLs['bad_password_itemid'] = $this->params->get('redirect_bad_password');
    $redirectURLs['bad_password_item'] = $menu->getItem( $redirectURLs['bad_password_itemid'] );
    $redirectURLs['bad_password'] = JRoute::_($redirectURLs['bad_password_item']->link
      .'&Itemid='
      .$redirectURLs['bad_password_itemid'], FALSE);

    $redirectURLs['no_match_itemid'] = $this->params->get('redirect_no_match');
    $redirectURLs['no_match_item'] = $menu->getItem( $redirectURLs['no_match_itemid'] );
    $redirectURLs['no_match'] = JRoute::_($redirectURLs['no_match_item']->link
      .'&Itemid='
      .$redirectURLs['no_match_itemid'], FALSE);

    //determine how expired redirection will be handled
    $redirectURLs['expired_method'] = $this->params->get('expired_method');
    $redirectURLs['expired_itemid'] = $this->params->get('redirect_expired_menu');
    $redirectURLs['expired_item'] = $menu->getItem( $redirectURLs['expired_itemid'] );
    $redirectURLs['expired'] = JRoute::_($redirectURLs['expired_item']->link
      .'&Itemid='
      .$redirectURLs['expired_itemid'], FALSE);
    $redirectURLs['expired_contribpageid'] = $this->params->get('redirect_expired_contribpage');
    $redirectURLs['expired_contribpage'] = 'index.php?option=com_civicrm&task=civicrm/contribute/transact&reset=1&id='
      .$redirectURLs['expired_contribpageid'];

    return $redirectURLs;
  }//_getRedirectionURLs

  function _buildGroups() {
    // Get a list of User Groups to work with
    // we will use these to check against and set the users main group level
    // if a user belongs to another group then that will not be changed
    $groups = array();

    // First cyle thru the assignments for membership STATUS
    // By default we have enabled 8 levels of membership STATUS. If you have more
    // than 8 then you need to modify the section below.
    if ( $this->params->get('advanced_features') ) {
      for ( $i = 1; $i <= 8; $i++ ) {
        $groups[] = $this->params->get( 'user_group_'.$i );
      }
    }

    // Then cycle thru the assignment for membership TYPE
    // By default we have enabled 8 levels of membership TYPE. If you have more
    // than 8 then you need to modify the section below.
    if ( $this->params->get('advanced_membership_features') ) {
      for ( $i = 1; $i <= 8; $i++ ) {
        $groups[] = $this->params->get( 'TACL_user_group_'.$i );
      }
    }

    return array_unique($groups);
  }

  function _checkMembership($redirectURLs, $user, $response, $result) {
    //CiviCRM: build groups array
    $group_array = self::_buildGroups();

    //CiviCRM: retrieve parameter values
    $civicrm_use_current = $this->params->get('use_current');
    $civicrm_is_current = $this->params->get('is_current_CiviMember');
    $civicrm_useAdvancedStatus = $this->params->get('advanced_features_status');
    $civicrm_useAdvancedType = $this->params->get('advanced_features_type');

    $contactID = $this->_getCiviContact($user);
    $contactID = $contactID+0; //ensure integer type conversion

    $membership = $this->_getContactMembership($contactID);
    //CRM_Core_Error::debug_var('redirectURLs', $redirectURLs);
    //CRM_Core_Error::debug_var('membership', $membership);

    // Make sure there is a membership record.
    if ( empty($membership) ){
      //if blocking access, fail
      if ( $this->params->get('block_access') ) {
        $response->status = JAuthentication::STATUS_FAILURE;
        $response->error_message = 'No current membership records for this contact.';

        $app =& JFactory::getApplication();
        $app->redirect($redirectURLs['old_membership']);
      }
      //if not blocking, proceed
      else {
        $response->status = JAuthentication::STATUS_SUCCESS;
        $response->error_message = '';
      }
    }

    // LCD revised membership status check mechanism
    // Cycle through membership records. If a current record is found, authenticate.
    // Else reject and send to old membership redirection page.
    $membership_status_old = TRUE;
    $status_expired = FALSE;
    foreach ($membership as $mem) {
      $membership_status = $mem['status_id'];
      $membership_status_params = array( 'id' => $membership_status );
      $membership_status_details = $this->_getMembershipStatuses( $membership_status_params );
      $membership_status_iscurrent = $membership_status_details[$membership_status]['is_current_member'];

      //CRM_Core_Error::debug_var('mem',$mem);

      // If they are are a current member then proceed with login.
      // use status_id instead of _status_calc function as the latter does not account for manual overrides
      // or use status rule configured current flag (option found in plugin parameter)
      // Also proceed if we are not blocking access
      if (
        ( $civicrm_use_current && $membership_status_iscurrent ) ||
        ( !$civicrm_use_current && $membership_status <= $civicrm_is_current ) ||
        ( !$this->params->get('block_access') )
      ) {
        $response->status = JAuthentication::STATUS_SUCCESS;
        $response->error_message = '';
        $membership_status_old = FALSE;
        $user = JFactory::getUser($result->id);
        $JUserID = $result->id;
        $correct_group = '';

        //CRM_Core_Error::debug_var('$user',$user);
        //CRM_Core_Error::debug_var('$JUserID',$JUserID);
        //CRM_Core_Error::debug_var('$membership_status_iscurrent',$membership_status_iscurrent);

        // get the array of Joomla Usergroups that the user belongs to
        $current_groups = JUserHelper::getUserGroups($result->id);
        //CRM_Core_Error::debug_var('$current_groups',$current_groups);

        //membership status
        if ( $civicrm_useAdvancedStatus ){
          $correct_group = $this->params->get( 'user_group_'.$membership_status);
          //CRM_Core_Error::debug_var('$correct_group1',$correct_group);
        }
        //membership type
        elseif ( $civicrm_useAdvancedType ) {
          $correct_group = $this->params->get( 'TACL_user_group_'.$mem[membership_type_id]);
          //CRM_Core_Error::debug_var('$correct_group2',$correct_group);
        }

        if ( $correct_group ) {
          if (!JUserHelper::addUserToGroup($JUserID, $correct_group)){
            return new JException(JText::_('Error Adding user to group'));
          }
        }

        // remove the user from any groups they shouldn't belong to
        // cycle thru the groups that the user belongs to against the list of groups
        // that we have specified in the plugin Advanced Options that we've already
        // placed in $groups_array.
        // this method ignores any other group that a user may belong to (eg Administrators, Super User)
        foreach ( $current_groups as $key => $value ) {
          if ( in_array($value, $group_array, TRUE) ) {
            // group was found in array
            // let's now check that the group we are asigned is the correct level
            if ( $value !== $this->params->get( 'user_group_'.$membership_status ) ){
              // and remove it if it isn't the right level
              plgAuthenticationCiviCRM::_removeUserFromGroup($value, $JUserID);
            }
          }
        }
      }
      elseif ( $membership_status_details[$membership_status]['is_current_member'] == FALSE ) {
        $status_expired = TRUE;
      }
    }

    //process based on status IF a membership record exists
    //if we have chosen not to block access, we need to skip this when the user has no mem records at all
    if ( !empty($membership) ) {
      //we now know if the membership is current, expired, or other
      if ( $membership_status_old && $status_expired ) { //expired

        //need to decide if we're redirecting to a menu or contrib page
        if ( $redirectURLs['expired_method'] == 1 ) { //menu
          $expired_redirect = $redirectURLs['expired'];
        }
        elseif ( $redirectURLs['expired_method'] == 0 ) { //contrib page
          //generate token
          $checksumValue = $this->_generateToken($contactID);

          //build url; append contact id and checksum
          $expired_redirect = $redirectURLs['expired_contribpage'].'&id='.$redirectURLs['expired_contribpageid'];
          $expired_redirect = $expired_redirect.'&cs='.$checksumValue.'&cid='.$contactID;
          $expired_redirect = JRoute::_( $expired_redirect, FALSE );
        }
        //echo $expired_redirect; exit();
        $response->status = JAuthentication::STATUS_FAILURE;
        $response->error_message = 'Membership has expired.';

        $app =& JFactory::getApplication();
        $app->redirect($expired_redirect);
      }
      //not current, not expired, and we are blocking access
      elseif ( $membership_status_old && $this->params->get('block_access') ) {
        $response->status = JAuthentication::STATUS_FAILURE;
        $response->error_message = 'Membership is not valid.';

        $app =& JFactory::getApplication();
        $app->redirect($redirectURLs['old_membership']);
      }
    }
    //LCD end revised mechanism
  }//_checkMembership

  function _getCiviContact($user) {
    // We have now authenticated against the Joomla user table. From here we 
    // need to find the CiviCRM user ID by using UFMatch
    // Initiate CiviCRM
    require_once JPATH_ROOT.'/'.'administrator/components/com_civicrm/civicrm.settings.php';
    require_once 'CRM/Core/Config.php';
    $civiConfig =& CRM_Core_Config::singleton( );

    // Find the CiviCRM ContactID
    require_once 'CRM/Core/BAO/UFMatch.php';
    CRM_Core_BAO_UFMatch::synchronizeUFMatch( $user->name, $user->id, $user->email, 'Joomla' );
    $contactID = CRM_Core_BAO_UFMatch::getContactId( $user->id );
    return $contactID;
  }
  
  function _getContactMembership($contactID) {
    // Find the membership records for the ContactID
    require_once 'api/api.php';
    $params = array(
      'version' => 3,
      'contact_id' => $contactID,
    );
    $membership = civicrm_api('membership', 'get', $params);

    return $membership['values'];
  }
  
  function _generateToken($contactID) {
    require_once 'CRM/Contact/BAO/Contact/Utils.php';
    require_once 'CRM/Utils/Date.php';
    $checksumValue = NULL;
    $checksumValue = CRM_Contact_BAO_Contact_Utils::generateChecksum( $contactID, NULL, 1 );
    return $checksumValue;    
  }
  
  function  _getMembershipStatuses( $params ) {
    require_once 'api/api.php';
    $params['version'] = 3;
    $statusDetails = civicrm_api('membership_status', 'get', $params);
    return  $statusDetails['values'];
  }
  
  function _getReturnURL($itemid, $method){
    $link = '';
    if ($method == 0) {
      $db  = JFactory::getDbo();
        $query  = $db->getQuery(TRUE);
        $query->select('id, path');
        $query->from('#__menu');
        $query->where('id=' . $itemid);
        $db->SetQuery($query);
        $menuItem = $db->loadObject();
      $link = JURI::base().'index.php/'.JRoute::_($menuItem->path);
    } else {
      //$redirect_item = $menu->getItem( $itemid );
      //$link = JRoute::_($redirect_item->link.'&Itemid='.$itemid, FALSE);
    }
    return $link;
  }

  function _removeUserFromGroup($groupId, $userId){
    // Get the user object.
    $R_user = & JUser::getInstance((int) $userId);

    echo "UserId = ".$userId."<br>";
    echo "GroupId = ".$groupId."<br>";
    $key = array_search($groupId, $R_user->groups);
    echo "key = ".$key."<br>";
    //print("<pre>".print_r($R_user->groups, TRUE)."</pre>");

    //Remove the user from the group if necessary.
    if (array_key_exists($key, $R_user->groups)) {
      // Remove the user from the group.
      unset($R_user->groups[$key]);

      // Store the user object.
      if (!$R_user->save()) {
        return new JException($R_user->getError());
      }
    }

    // Set the group data for any preloaded user objects.
    $temp = & JFactory::getUser((int) $userId);
    $temp->groups = $R_user->groups;

    // Set the group data for the user object in the session.
    $temp = & JFactory::getUser();
    if ($temp->id == $userId) {
      $temp->groups = $R_user->groups;
    }

    return TRUE;
  }//_removeUserFromGroup
}
