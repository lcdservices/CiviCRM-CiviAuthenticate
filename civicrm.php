<?php

/**
 * @package     Joomla.Plugin
 * @subpackage  Authentication.joomla
 */

/**
 * Joomla/CiviCRM Authentication plugin
 *
 * This plugin authenticates against the Joomla user table and
 * then checks with CiviCRM that the user has a valid current
 * membership record
 *
 * @author      Henry Bennett <henry@bec-cave.org.uk>
 *              Brian Shaughnessy <brian@lcdservices.biz>
 * @version     5.0.0
 * @package     Joomla
 * @subpackage  JFramework
 * @since       Joomla 1.6
 * @copyright
 * @license        GNU General Public License version 2 or later; see LICENSE.txt
 *
 * version 1.0.4 by Brian Shaughnessy
 * version 1.0.5 by Brian Shaughnessy
 * version 1.1.0 by Brian Shaughnessy
 * version 2.0.0 by Henry Bennett (added Joomla ACL and username or email login)
 * version 2.1.0 by Brian Shaughnessy
 * version 2.5.0 by Brian Shaughnessy
 * version 2.6.0 by Brian Shaughnessy (CiviCRM 4.4/Joomla 2.5.18 compatibility)
 * version 5.0.0 by Aidan Saunders (CiviCRM 5.56/Joomla 4 compatibility)
 *
 * see current notes in the README.md file
 *
 * For updates, see: https://github.com/lcdservices/CiviCRM-CiviAuthenticate
 *
 * Based on Joomla Core authentication:
 * @copyright   (C) 2006 Open Source Matters, Inc. <https://www.joomla.org>
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 *
 * @phpcs:disable PSR1.Classes.ClassDeclaration.MissingNamespace
 */

use Joomla\CMS\Authentication\Authentication;
use Joomla\CMS\Helper\AuthenticationHelper;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Plugin\CMSPlugin;
use Joomla\CMS\Plugin\PluginHelper;
use Joomla\CMS\User\User;
use Joomla\CMS\User\UserHelper;
use Joomla\CMS\Router\Route;
use Joomla\CMS\Uri\Uri;

// phpcs:disable PSR1.Files.SideEffects
\defined('_JEXEC') or die;
// phpcs:enable PSR1.Files.SideEffects

/**
 * Joomla/CiviCRM Authentication plugin
 *
 * @since  1.5
 */
class PlgAuthenticationCiviCRM extends CMSPlugin
{
    /**
     * Application object
     *
     * @var    \Joomla\CMS\Application\CMSApplication
     * @since  4.0.0
     */
    protected $app;

    /**
     * Database object
     *
     * @var    \Joomla\Database\DatabaseDriver
     * @since  4.0.0
     */
    protected $db;

    /**
     * This method should handle any authentication and report back to the subject
     *
     * @param   array   $credentials  Array holding the user credentials
     * @param   array   $options      Array of extra options
     * @param   object  &$response    Authentication response object
     *
     * @return  void
     *
     * @since   1.5
     */
    public function onUserAuthenticate($credentials, $options, &$response)
    {
        //CiviCRM: construct redirection urls
        $redirectURLs = self::_getRedirectionURLs();

        //CiviCRM: JLog
        $response->type = 'CiviCRM';

        // Joomla does not like blank passwords
        if (empty($credentials['password'])) {
            $response->status        = Authentication::STATUS_FAILURE;
            $response->error_message = Text::_('JGLOBAL_AUTH_EMPTY_PASS_NOT_ALLOWED');

            return;
        }

        $db    = $this->db;
        $query = $db->getQuery(true)
            ->select($db->quoteName(['id', 'password']))
            ->from($db->quoteName('#__users'));

        //CiviCRM: accommodate username OR email
        if ($this->params->get('username_email')) {
            $query->where($db->quoteName('username') . ' = :username' . ' OR ' . $db->quoteName('email') . ' = :email');
            $query->bind(':username', $credentials['username']);
            $query->bind(':email', $credentials['username']);
        } else {
          $query->where($db->quoteName('username') . ' = :username');
          $query->bind(':username', $credentials['username']);
        }

        $db->setQuery($query);
        $result = $db->loadObject();

        if ($result) {
            //CiviCRM: set credentials username as it may have been passed as the email
            if ($this->params->get('username_email')) {
                $credentials['username'] = $response->username = $result->username;
            }

            $match = UserHelper::verifyPassword($credentials['password'], $result->password, $result->id);

            if ($match === true) {
                // Bring this in line with the rest of the system
                $user               = User::getInstance($result->id);
                $response->email    = $user->email;
                $response->fullname = $user->name;

                if ($this->app->isClient('administrator')) {
                    $response->language = $user->getParam('admin_language');
                } else {
                    $response->language = $user->getParam('language');
                }

                //CiviCRM: bypass member check for Joomla admins
                //CiviCRM: use JFactory::getUser to get the object for authorise() function
                $adminTestUser = JFactory::getUser($result->id);
                if ($adminTestUser->authorise('core.login.admin')) {
                    $response->status = Authentication::STATUS_SUCCESS;
                    $response->error_message = '';
                }
                //CiviCRM: run through membership checks
                else {
                   self::_checkMembership($redirectURLs, $user, $response, $result);
                }

            } else {
                // Invalid password
                $response->status        = Authentication::STATUS_FAILURE;
                $response->error_message = Text::_('JGLOBAL_AUTH_INVALID_PASS');
                // CiviCRM: redirection
                $this->app->redirect($redirectURLs['bad_password']);
            }
        } else {
            // Let's hash the entered password even if we don't have a matching user for some extra response time
            // By doing so, we mitigate side channel user enumeration attacks
            UserHelper::hashPassword($credentials['password']);

            // Invalid user
            $response->status        = Authentication::STATUS_FAILURE;
            $response->error_message = Text::_('JGLOBAL_AUTH_NO_USER');
            // CiviCRM: redirect
            $this->app->redirect($redirectURLs['no_match']);
        }
    }

  // Everything below here is CiviCRM stuff

  function _getRedirectionURLs() {

    // experimental method for creating the URL redirect options.
    // old method was unreliable.
    // use 0 = path constructor lookup
    // use 1 = itemid constructor lookup

    $url_creat_method = 0;
    $menu = $this->app->getMenu('site');
    $redirectURLs = [];

    $redirectURLs['old_membership_itemid'] = $this->params->get('redirect_old_membership');
    $redirectURLs['old_membership_item'] = $menu->getItem($redirectURLs['old_membership_itemid']);
    $redirectURLs['old_membership'] = Route::_($redirectURLs['old_membership_item']->link
      . '&Itemid='
      . $redirectURLs['old_membership_itemid'], FALSE);

    $redirectURLs['bad_password_itemid'] = $this->params->get('redirect_bad_password');
    $redirectURLs['bad_password_item'] = $menu->getItem($redirectURLs['bad_password_itemid']);
    $redirectURLs['bad_password'] = Route::_($redirectURLs['bad_password_item']->link
      . '&Itemid='
      . $redirectURLs['bad_password_itemid'], FALSE);

    $redirectURLs['no_match_itemid'] = $this->params->get('redirect_no_match');
    $redirectURLs['no_match_item'] = $menu->getItem($redirectURLs['no_match_itemid']);
    $redirectURLs['no_match'] = Route::_($redirectURLs['no_match_item']->link
      . '&Itemid='
      . $redirectURLs['no_match_itemid'], FALSE);

    //determine how expired redirection will be handled
    $redirectURLs['expired_method'] = $this->params->get('expired_method');
    $redirectURLs['expired_itemid'] = $this->params->get('redirect_expired_menu');
    $redirectURLs['expired_item'] = $menu->getItem($redirectURLs['expired_itemid']);
    $redirectURLs['expired'] = Route::_($redirectURLs['expired_item']->link
      . '&Itemid='
      . $redirectURLs['expired_itemid'], FALSE);
    $redirectURLs['expired_contribpageid'] = $this->params->get('redirect_expired_contribpage');
    $redirectURLs['expired_contribpage'] = 'index.php?option=com_civicrm&task=civicrm/contribute/transact&reset=1&id='
      . $redirectURLs['expired_contribpageid'];

    return $redirectURLs;
  }//_getRedirectionURLs

  /**
   * @return array
   *
   * get a list of user groups to work with, organized by status/type config set
   * we will use these to check against and set the users main group level
   * if a user belongs to another group then that will not be changed
   */
  function _buildGroups() {
    //CRM_Core_Error::debug_var('$this->params', $this->params);

    $groups = [
      'status' => [],
      'type' => [],
    ];

    //when cycling through options, check for existence of type/status

    // cycle through the assignments for membership STATUS
    // by default we have enabled 8 levels of membership STATUS. If you have more
    // than 8 then you need to modify the section below.
    if ($this->params->get('advanced_features_status')) {
      for ($i = 1; $i <= 8; $i++) {
        if ($this->params->get('CiviMember_Level_' . $i)) {
          $groups['status'][$this->params->get('CiviMember_Level_' . $i)] = $this->params->get('user_group_' . $i);
        }
      }
    }

    // cycle through the assignment for membership TYPE
    // by default we have enabled 8 levels of membership TYPE. If you have more
    // than 8 then you need to modify the section below.
    if ($this->params->get('advanced_features_type')) {
      for ($i = 1; $i <= 28; $i++) {
        if ($this->params->get('CiviMember_TACL_Level_' . $i)) {
          $groups['type'][$this->params->get('CiviMember_TACL_Level_' . $i)] = $this->params->get('TACL_user_group_' . $i);
        }
      }
    }

    //remove duplicates
    //$groups['status'] = array_unique($groups['status']);
    //$groups['type'] = array_unique($groups['type']);

    //jdbg::p($groups);
    return $groups;
  }

  function _checkMembership($redirectURLs, $user, $response, $result) {
    $this->_initializeCiviCRM();

    //CiviCRM: build groups array
    $configuredGroups = $this->_buildGroups();

    //CRM_Core_Error::debug_var('$configuredGroups', $configuredGroups);

    //CiviCRM: retrieve parameter values
    $civicrm_use_current = $this->params->get('use_current');
    $civicrm_is_current = $this->params->get('is_current_CiviMember');
    $civicrm_useAdvancedStatus = $this->params->get('advanced_features_status');
    $civicrm_useAdvancedType = $this->params->get('advanced_features_type');

    $contactID = (int) $this->_getCiviContact($user);
    // $contactID = $contactID + 0; //ensure integer type conversion
    $JUserID = $result->id;

    $memberships = $this->_getContactMemberships($contactID);
    //CRM_Core_Error::debug_var('membership', $membership);

    //current ACL groups for user
    $userACLGroups = UserHelper::getUserGroups($JUserID);
    //CRM_Core_Error::debug_var('$userACLGroups', $userACLGroups);

    // Make sure there is a membership record.
    if (empty($memberships)) {
      //if blocking access, fail
      if ($this->params->get('block_access')) {
        $response->status = Authentication::STATUS_FAILURE;
        $response->error_message = 'No current membership records for this contact.';

        $this->app->redirect($redirectURLs['old_membership']);
      }
      //if not blocking, proceed
      else {
        //if no membership, remove any groups assigned via status/type
        if ($civicrm_useAdvancedStatus || $civicrm_useAdvancedType) {
          foreach ($userACLGroups as $JGroupID) {
            if (
              ($civicrm_useAdvancedStatus && in_array($JGroupID, $configuredGroups['status'], TRUE)) ||
              ($civicrm_useAdvancedType && in_array($JGroupID, $configuredGroups['type'], TRUE))
            ) {
              // group was found; remove
              //$this->_removeUserFromGroup($value, $JUserID);
              UserHelper::removeUserFromGroup($JUserID, $JGroupID);
            }
          }
        }
        $response->status = Authentication::STATUS_SUCCESS;
        $response->error_message = '';
      }
    }

    // Cycle through membership records. If a current record is found, authenticate.
    // Else reject and send to 'old membership' redirection page.
    $membership_status_old = TRUE;
    $statusCurrent = FALSE;

    //track the mem status weight as we cycle; only apply the status rule for the earliest weight status type
    $memStatusWeight = NULL;

    //array of groups the user should be assigned to
    $assignedGroups = [];

    //cycle through and determine what groups the user should be assigned
    foreach ($memberships as $mem) {
      $membership_status = $mem['status_id'];
      $membership_status_details = $this->_getMembershipStatuses($membership_status);
      $membership_status_iscurrent = $membership_status_details[$membership_status]['is_current_member'];

      //CRM_Core_Error::debug_var('mem',$mem);
      //CRM_Core_Error::debug_var('$membership_status_details',$membership_status_details);

      // if current member, process status/type rules and flag for login
      if (
        ($civicrm_use_current && $membership_status_iscurrent) ||
        (!$civicrm_use_current && $membership_status <= $civicrm_is_current)
      ) {
        $response->status = Authentication::STATUS_SUCCESS;
        $response->error_message = '';
        $membership_status_old = FALSE;
        $statusCurrent = TRUE;

        //CRM_Core_Error::debug_var('$JUserID',$JUserID);
        //CRM_Core_Error::debug_var('$membership_status_iscurrent',$membership_status_iscurrent);
      }

      //assign groups based on status/type

      //membership status
      if ($civicrm_useAdvancedStatus) {
        if (!$memStatusWeight ||
          $membership_status_details[$membership_status]['weight'] < $memStatusWeight
        ) {
          $assignedGroups[] = $configuredGroups['status'][$membership_status];
        }
        $memStatusWeight = $membership_status_details[$membership_status]['weight'];
        //CRM_Core_Error::debug_var('$memStatusWeight', $memStatusWeight);
      }

      //membership type
      if ($civicrm_useAdvancedType) {
        //if limiting to current, check status
        if (!$this->params->get('typeacl_limittocurrent') ||
          ($this->params->get('typeacl_limittocurrent') && $statusCurrent)
        ) {
          if ($configuredGroups['type'][$mem['membership_type_id']]) {
            $assignedGroups[] = $configuredGroups['type'][$mem['membership_type_id']];
          }
        }
      }
      //CRM_Core_Error::debug_var('$assignedGroups', $assignedGroups);
    }

    //cycle through and assign groups
    foreach ($assignedGroups as $JGroupID) {
      JLog::add("Adding user $JUserID to group $JGroupID: ", JLog::INFO);
      if (!UserHelper::addUserToGroup($JUserID, $JGroupID)) {
        return new \Exception(JText::_('Error Adding user to group'));
      }
    }

    /*Civi::log()->debug('_checkMembership', array(
    '$userACLGroups' => $userACLGroups,
    '$configuredGroups' => $configuredGroups,
    '$assignedGroups' => $assignedGroups,
    ));*/

    // remove the user from any groups they shouldn't belong to
    // cycle through the groups that the user belongs to against the list of groups
    // that we have specified in the plugin Advanced Options that we've already
    // placed in $configuredGroups.
    // this method ignores any other group that a user may belong to (eg Administrators, Super User)
    foreach ($userACLGroups as $JGroupID) {
      if (in_array($JGroupID, $configuredGroups['status']) ||
        in_array($JGroupID, $configuredGroups['type'])
      ) {
        // group was found in array; let's now check that the group we are assigned is the correct level
        // check based on both status and type option; remove if not;
        if (!in_array($JGroupID, $assignedGroups)) {
          JLog::add("Removing user $JUserID from group $JGroupID: ", JLog::INFO);
          //$this->_removeUserFromGroup($JGroupID, $JUserID);
          UserHelper::removeUserFromGroup($JUserID, $JGroupID);
        }
      }
    }

    //process based on status IF a membership record exists and we are blocking access
    if (!empty($memberships) && $this->params->get('block_access')) {
      //expired and blocking
      if ($membership_status_old && !$statusCurrent) { //expired

        //need to decide if we're redirecting to a menu or contrib page
        if ($redirectURLs['expired_method'] == 1) { //menu
          $expired_redirect = $redirectURLs['expired'];
        }
        elseif ($redirectURLs['expired_method'] == 0) { //contrib page
          //generate token
          $checksumValue = $this->_generateToken($contactID);

          //build url; append contact id and checksum
          $expired_redirect = $redirectURLs['expired_contribpage'] . '&id=' . $redirectURLs['expired_contribpageid'];
          $expired_redirect = $expired_redirect . '&cs=' . $checksumValue . '&cid=' . $contactID;
          $expired_redirect = Route::_($expired_redirect, FALSE);
        }
        //echo $expired_redirect; exit();
        $response->status = Authentication::STATUS_FAILURE;
        $response->error_message = 'Membership has expired.';

        $this->app->redirect($expired_redirect);
      }
      //not current, not expired, and we are blocking access
      elseif ($membership_status_old) {
        $response->status = Authentication::STATUS_FAILURE;
        $response->error_message = 'Membership is not valid.';

        $this->app->redirect($redirectURLs['old_membership']);
      }
    }

    //if we are not blocking, always set status success
    if (!$this->params->get('block_access')) {
      $response->status = Authentication::STATUS_SUCCESS;
    }
  }//_checkMembership

  function _getCiviContact($user) {
    // We have now authenticated against the Joomla user table. From here we
    // need to find the CiviCRM user ID by using UFMatch
    $this->_initializeCiviCRM();

    // Find the CiviCRM ContactID
    require_once 'CRM/Core/BAO/UFMatch.php';
    CRM_Core_BAO_UFMatch::synchronizeUFMatch($user->name, $user->id, $user->email, 'Joomla');
    $contactID = CRM_Core_BAO_UFMatch::getContactId($user->id);
    return $contactID;
  }

  function _getContactMemberships($contactID) {
    // Find the membership records for the ContactID
    $params = [
      'version' => 3,
      'contact_id' => $contactID,
    ];
    $memberships = civicrm_api('membership', 'get', $params);

    return $memberships['values'];
  }

  function _generateToken($contactID) {
    $checksumValue = NULL;
    $checksumValue = CRM_Contact_BAO_Contact_Utils::generateChecksum($contactID, NULL, 1);

    return $checksumValue;
  }

  function  _getMembershipStatuses($memStatusId) {
    $statusDetails = civicrm_api('membership_status', 'get', [
      'version' => 3,
      'id' => $memStatusId,
    ]);

    return $statusDetails['values'];
  }

  function _getReturnURL($itemid, $method){
    $link = '';
    if ($method == 0) {
      $query = $this->db->getQuery(TRUE)
        ->select('id, path')
        ->from($db->quoteName('#__menu'))
        ->where($db->quoteName('id') . ' = :id')
        ->bind(':id', $itemid);
      $db->setQuery($query);
      $menuItem = $db->loadObject();
      $link = Uri::base() . 'index.php/' . Route::_($menuItem->path);
    }
    else {
      //$redirect_item = $menu->getItem($itemid);
      //$link = Route::_($redirect_item->link.'&Itemid='.$itemid, FALSE);
    }

    return $link;
  }

  /*
   * @deprecated Use UserHelper::removeUserFromGroup
  */
  function _removeUserFromGroup($groupId, $userId) {
    // Get the user object.
    $user = new User($userId);
    $key = array_search($groupId, $user->groups);
    //Civi::log()->debug('_removeUserFromGroup', array('user' => $user, 'key' => $key));

    //Remove the user from the group if necessary.
    if (array_key_exists($key, $user->groups)) {
      // Remove the user from the group.
      unset($user->groups[$key]);

      //Joomla doesn't allow a user with no groups; check if that's the case and add Public/Guest
      if (empty($user->groups)) {
        //Civi::log()->debug('user has no groups', array('user' => $user));
        if ($grpPublicId = $this->_getGroupId('Public')) {
          $user->groups[$grpPublicId] = $grpPublicId;
        }

        if ($grpGuestId = $this->_getGroupId('Guest')) {
          $user->groups[$grpGuestId] = $grpGuestId;
        }
      }

      // Store the user object.
      if (!$user->save()) {
        return new \Exception($user->getError());
      }
    }

    // Set the group data for any preloaded user objects.
    // Ummm - what's happening here?
    $temp = new User($userId);
    $temp->groups = $user->groups;
    //Civi::log()->debug('_removeUserFromGroup', array('$temp' => $temp));

    // Set the group data for the user object in the session.
    $temp = JFactory::getUser();
    if ($temp->id == $userId) {
      $temp->groups = $user->groups;
    }

    return TRUE;
  }//_removeUserFromGroup

  function _getGroupId($groupName) {
    $db = $this->db;
    $query = $db->getQuery(TRUE)
      ->select('id')
      ->from($db->quoteName('#__usergroups'))
      ->where($db->quoteName('title') . ' = :title')
      ->bind(':title', $groupName);

    $db->setQuery($query);

    $group = $db->loadObject();

    if (!$group) {
      return FALSE;
    }

    return $group->id;;
  }

  /**
   * @return mixed
   *
   * initialize CiviCRM and return config object
   */
  function _initializeCiviCRM() {
    require_once JPATH_ROOT . '/administrator/components/com_civicrm/civicrm.settings.php';
    require_once 'CRM/Core/Config.php';
    $config = CRM_Core_Config::singleton();

    return $config;
    // return civicrm_initialize();
  }

}
