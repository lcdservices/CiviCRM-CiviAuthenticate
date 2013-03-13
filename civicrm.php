<?php
/**
 * Joomla CiviCRM Authentication plugin
 *
 * This plugin authenticates against the Joomla user table and
 * then checks with CiviCRM that the user has a valid current 
 * membership record
 *
 * @author 	Henry Bennett <henry@bec-cave.org.uk>
 * @version	2.0.0
 * @package	Joomla
 * @subpackage	JFramework
 * @since 	Joomla 1.6
 * @copyright	Copyleft 
 *
 * version 1.0.4 by Brian Shaughnessy
 * version 1.0.5 by Brian Shaughnessy
 * version 1.1.0 by Brian Shaughnessy
 * version 2.0.0 by Henry Bennett (added Joomla ACL and username or email login)
 * brian@lcdservices.biz // www.lcdservices.biz
 */

/**
 * Notes on this using this plugin
 * 1. the civicrm_membership_status_calc() function does not handle admin status overides [corrected in v.1.0.4]
 * 2. not tested with multiple memberships per contact [corrected in v1.0.4]
 * 3. Once installed change the parameters via Joomla Admin to meet your requirements.
 */


// Check to ensure this file is included in Joomla!
defined('_JEXEC') or die;

jimport( 'joomla.event.plugin' );

class plgAuthenticationCiviCRM extends JPlugin
{

	/**
	 * Constructor
	 *
	 * For php4 compatability we must not use the __constructor as a constructor for plugins
	 * because func_get_args ( void ) returns a copy of all passed arguments NOT references.
	 * This causes problems with cross-referencing necessary for the observer design pattern.
	 *
	 * @param object $subject The object to observe
	 * @param array  $config  An array that holds the plugin configuration
	 * @since 1.5
	 */
	function plgAuthenticationCiviCRM(& $subject, $config) {
		parent::__construct($subject, $config);
	}

	/**
	 * This method should handle any authentication and report back to the subject
	 *
	 * @access	public
	 * @param   array 	$credentials Array holding the user credentials
	 * @param 	array   $options     Array of extra options
	 * @param	object	$response	Authentication response object
	 * @return	boolean
	 * @since 1.5
	 */
	function onAuthenticate( $credentials, $options, &$response )
	{
		jimport('joomla.user.helper');
		require_once( JPATH_SITE.DS.'includes'.DS.'application.php' );

		// Joomla does not like blank passwords
		if (empty($credentials['password']))
		{
			$response->status = JAUTHENTICATE_STATUS_FAILURE;
			$response->error_message = JText::_('JGLOBAL_AUTH_EMPTY_PASS_NOT_ALLOWED');
			return false;
		}
		// Initialize variables
		$conditions = '';

		// experimental method for creating the URL redirect options.
		// old method was unreliable.
		// use 0 = path constructor lookup
		// use 1 = itemid constructor lookup
		$url_creat_method = 0;

		// construct redirection urls
		$menu =& JApplication::getMenu('site');

		$civicrm_redirect_old_membership_itemid 	= $this->params->get('redirect_old_membership');
		$civicrm_redirect_old_membership_item 		= $menu->getItem( $civicrm_redirect_old_membership_itemid );
		$civicrm_redirect_old_membership 		= 'Location: '.JRoute::_($civicrm_redirect_old_membership_item->link.'&Itemid='.$civicrm_redirect_old_membership_itemid, false);
			
		$civicrm_redirect_bad_password_itemid 		= $this->params->get('redirect_bad_password');
		$civicrm_redirect_bad_password_item 		= $menu->getItem( $civicrm_redirect_bad_password_itemid );
		$civicrm_redirect_bad_password 			= 'Location: '.JRoute::_($civicrm_redirect_bad_password_item->link.'&Itemid='.$civicrm_redirect_bad_password_itemid, false);
			
		$civicrm_redirect_no_match_itemid 		= $this->params->get('redirect_no_match');
		$civicrm_redirect_no_match_item 		= $menu->getItem( $civicrm_redirect_no_match_itemid );
		$civicrm_redirect_no_match 			= 'Location: '.JRoute::_($civicrm_redirect_no_match_item->link.'&Itemid='.$civicrm_redirect_no_match_itemid, false);

		//determine how expired redirection will be handled
		$civicrm_redirect_expired_method 		= $this->params->get('expired_method');
		
		$civicrm_redirect_expired_itemid 		= $this->params->get('redirect_expired_menu');
		$civicrm_redirect_expired_item 			= $menu->getItem( $civicrm_redirect_expired_itemid );
		$civicrm_redirect_expired 			= 'Location: '.JRoute::_($civicrm_redirect_expired_item->link.'&Itemid='.$civicrm_redirect_expired_itemid, false);
		
		$civicrm_redirect_expired_contribpageid		= $this->params->get('redirect_expired_contribpage');
		$civicrm_redirect_expired_contribpage		= 'index.php?option=com_civicrm&task=civicrm/contribute/transact&reset=1&Itemid=170';


		// Get a list of User Groups to work with
		// we will use these to check against and set the users main group level
		// if a user belongs to another group then that will not be changed
		//
		// First cyle thru the assignments for membership STATUS
		// By default we have enabled 8 levels of membership STATUS. If you have more 
		// than 8 then you need to modify the section below.
		// 		
		$i=1;
		while ( $i <= 8 ) {
			$group_array_temp[] = $this->params->get( 'user_group_'.$i );
			$i++ ;
			}

		// Then cycle thru the assignment for membership TYPE
		// By default we have enabled 8 levels of membership TYPE. If you have more 
		// than 8 then you need to modify the section below.
		// 		
		$i=1;
		while ( $i <= 8 ) {
			$group_array_temp[] = $this->params->get( 'TACL_user_group_'.$i );
			$i++ ;
			}

		$group_array = array_unique($group_array_temp);


		// Get the parameter values
		// load plugin params info
		$civicrm_use_current 	= $this->params->get('use_current');
		$civicrm_is_current  	= $this->params->get('is_current_CiviMember');
		$Civicrm_use_advanced_membership_features = $this->params->get('advanced_membership_features');

		// For JLog
		$response->type = 'CiviCRM';



		// Get a database object
		$db	= JFactory::getDbo();
		$query	= $db->getQuery(true);

		$query->select('id, password');
		$query->from('#__users');
		$query->where('username=' . $db->Quote($credentials['username']). 'OR email=' . $db->Quote($credentials['username'])) ;

		$db->setQuery( $query );
		$result = $db->loadObject();

		if($result)
		{
			$parts	= explode( ':', $result->password );
			$crypt	= $parts[0];
			$salt	= @$parts[1];
			$testcrypt = JUserHelper::getCryptedPassword($credentials['password'], $salt);

			if ($crypt == $testcrypt) {
				$user = JUser::getInstance($result->id); // Bring this in line with the rest of the system
				$response->username = $user->username;
				$response->email = $user->email;
				$response->fullname = $user->name;

				// bypass CiviMember check for Joomla admins
				// We need to use JFactory::getUser to get the object for authorise() function
				//				
				$adminTestUser = JFactory::getUser($result->id);
				if ($adminTestUser->authorise('core.login.admin'))
					{
					$response->status = JAUTHENTICATE_STATUS_SUCCESS;
					$response->error_message = '';
					}
				else {
					// We have now authenticated against the Joomla user table. From here we 
					// need to find the CiviCRM user ID by using UFMatch
					// Initiate CiviCRM
					require_once JPATH_ROOT.'/'.'administrator/components/com_civicrm/civicrm.settings.php';
					require_once 'CRM/Core/Config.php';
					$civiConfig =& CRM_Core_Config::singleton( );

					// Find the CiviCRM ContactID
					require_once 'CRM/Core/BAO/UFMatch.php';
					CRM_Core_BAO_UFMatch::synchronizeUFMatch( $user->name, $result->id, $user->email, 'Joomla' );
					$contactID = CRM_Core_BAO_UFMatch::getContactId( $result->id );
					$contactID = $contactID+0; //ensure integer type conversion

					// Find the membership records for the ContactID
					require_once 'api/v2/Membership.php';
					$membership = civicrm_contact_memberships_get($contactID);

					// Make sure there is a membership record.
					if ($membership['is_error'] == 1){
						$response->status = JAUTHENTICATE_STATUS_FAILURE;
						$response->error_message = 'no memberships for this contact';
						ob_end_clean();
						header($civicrm_redirect_old_membership); 
						exit;
					}

					// the $membership array is a three level array we need to get to 
					// the bottom level strip the top level off the array
					$membership1 = $membership[$contactID];
				
					// LCD revised membership status check mechanism
					// Cycle through membership records. If a current record is found, authenticate.
					// Else reject and send to old membership redirection page.
					$membership_status_old = 'true';
					$status_expired = 'false';
					foreach ($membership1 as $a) {
						$membership2 = $a;
						$membership_status = $membership2[status_id];
						$membership_status_params = array( 'id' => $membership_status );
						$membership_status_details = civicrm_membership_statuses_get( $membership_status_params );
						$membership_status_iscurrent = $membership_status_details[$membership_status]['is_current_member'];

						// print("<pre>".print_r($membership2,true)."</pre>");
						// print("<pre>".print_r($membership_status_details,true)."</pre>");
						// jexit();


						// If they are a a current member then proceed with login.
						//
						// use status_id instead of _status_calc function as the latter does not account for manual overrides 
						// or use status rule configured current flag (option found in plugin parameter)
						if ( ( $civicrm_use_current && $membership_status_iscurrent ) ||
							 ( !$civicrm_use_current && $membership_status <= $civicrm_is_current ) ) {
							$response->status = JAUTHENTICATE_STATUS_SUCCESS;
							$response->error_message = '';
							$membership_status_old = 'false';
							$user = JFactory::getUser($result->id);
							$JUserID = $result->id;

							// get the array of Joomla Usergroups that the user belongs to
							$current_groups = JUserHelper::getUserGroups($result->id);

							// define $user_matches_group
							//  1 = the users group matches in both CiviCRM and Joomla = proceed with login
							//  0 = the user does not match 
							//      set the Joomla group to match CiviCRM level 
							//      according to their membership status
							$user_matches_group = 0;
								
							// Set the correct Joonla Access Level for the user
							//
							// Have tried checking first and then adding but had *issues*
							// which I believe are down to being an instance of the user object
							if ($membership_status_iscurrent == true  && $Civicrm_use_advanced_membership_features == true){
								$correct_group =  $this->params->get( 'TACL_user_group_'.$membership2[membership_type_id]);
								// print("<pre>".print_r($membership2,true)."</pre>");
								// print("<pre>".print_r($membership_status_details,true)."</pre>");
								// print "<br>correct group = ".$correct_group; 
								// jexit();

							} else {
								$correct_group =  $this->params->get( 'user_group_'.$membership_status);
							}
							
							if (!JUserHelper::addUserToGroup($JUserID, $correct_group)){
								return new JException(JText::_('Error Adding user to group'));
							}

							// Then remove the user from any groups they shouldn't belong to
							//
							// cycle thru the groups that the user belongs to against the list of groups
							// that we have specified in the plugin Advanced Options that we've already 
							// placed in $groups_array. 
							//
							// This method ignores any other group that a user may belong to (eg Administrators, Super User)
							foreach ($current_groups as $key=>$value) {
								if (in_array($value, $group_array, true)) {
									// group was found in array
									// Let's now check that the group we are asigned is the correct level
									if ($value !== $this->params->get( 'user_group_'.$membership_status )){
										// and remove it if it isn't the right level
										plgAuthenticationCiviCRM::RemoveUserFromGroup($value, $JUserID);
									} 
								}

							}
						} elseif ( $membership_status_details[$membership_status]['is_current_member'] == false ) {
							$status_expired = 'true';
						}
					}				
					//we now know if the membership is current, expired, or other
					if ( $membership_status_old == 'true' && $status_expired == 'true' ) { //expired
						
						//need to decide if we're redirecting to a menu or contrib page
						if ( $civicrm_redirect_expired_method == 1 ) { //menu
							$expired_redirect = $civicrm_redirect_expired;
						} elseif ( $civicrm_redirect_expired_method == 0 ) { //contrib page
							//generate token
							require_once 'CRM/Contact/BAO/Contact/Utils.php';
							require_once 'CRM/Utils/Date.php';
							$checksumValue = null;
							$checksumValue = CRM_Contact_BAO_Contact_Utils::generateChecksum( $contactID, null, 1 );
							
							//build url; append contact id and checksum
							$expired_redirect = $civicrm_redirect_expired_contribpage.'&id='.$civicrm_redirect_expired_contribpageid;
							$expired_redirect = $expired_redirect.'&cs='.$checksumValue.'&cid='.$contactID;
							$expired_redirect = 'Location: '.JRoute::_( $expired_redirect, false );
						}
						//echo $expired_redirect; exit();
						$response->status = JAUTHENTICATE_STATUS_FAILURE;
						$response->error_message = 'Membership has expired.';
						ob_end_clean();
						header($expired_redirect); 
						exit;
						
					} elseif ( $membership_status_old == 'true' ) { //not current, not expired
					
						$response->status = JAUTHENTICATE_STATUS_FAILURE;
						$response->error_message = 'Membership is not valid.';
						ob_end_clean();
						header($civicrm_redirect_old_membership); 
						exit;
						
					}
				//LCD end revised mechanism					
				}
			} else {
				$response->status = JAUTHENTICATE_STATUS_FAILURE;
				$response->error_message = 'Invalid username and password';
				ob_end_clean();
				header($civicrm_redirect_bad_password); 
				exit;
			}
		} else { //No username found
			$response->status = JAUTHENTICATE_STATUS_FAILURE;
			$response->error_message = 'Invalid username and password';
			ob_end_clean();
			header($civicrm_redirect_no_match); 
			exit;
		
		}

	}

	function onUserAuthenticate($credentials, $options, &$response){
		$this->onAuthenticate($credentials, $options, $response);
	}

	function GetReturnURL($itemid, $method){
		$link = '';
		if ($method == 0) {
			$db	= JFactory::getDbo();
				$query	= $db->getQuery(true);
				$query->select('id, path');
				$query->from('#__menu');
				$query->where('id=' . $itemid);
				$db->SetQuery($query);
				$menuItem = $db->loadObject();
			$link = 'Location: '.JURI::base().'index.php/'.JRoute::_($menuItem->path);
		} else {
			$redirect_item = $menu->getItem( $itemid );
			$link = 'Location: '.JRoute::_($redirect_item->link.'&Itemid='.$itemid, false);
		}
		return $link;
	}

	function RemoveUserFromGroup($groupId, $userId){
      		// Get the user object.
        	$R_user = & JUser::getInstance((int) $userId);

		echo "UserId  = ".$userId."<br>";
		echo "GroupId = ".$groupId."<br>";
		$key = array_search($groupId, $R_user->groups);
		echo "key     = ".$key."<br>";
		print("<pre>".print_r($R_user->groups,true)."</pre>");

		// Remove the user from the group if necessary.
        	if (array_key_exists($key, $R_user->groups))
	        {
        	        // Remove the user from the group.
	                unset($R_user->groups[$key]);
 
        	        // Store the user object.
                	if (!$R_user->save()) {
                        	return new JException($user->getError());
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
 
        	return true;
	}
}
