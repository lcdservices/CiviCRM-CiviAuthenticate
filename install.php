<?php
/*
 * CiviAuthenticate installation routine
 * @license		GNU General Public License version 2 or later; see LICENSE.txt
 */

// No direct access to this file
defined('_JEXEC') or die('Restricted access');

/**
 * Script file of CiviCRM plugin
 */
class plgauthenticationcivicrmInstallerScript {
  /**
   * method to install the plugin
   *
   * @return void
   */
  function install($parent) {
    // $parent is the class calling this method
  }

  /**
   * method to uninstall the plugin
   *
   * @return void
   */
  function uninstall($parent) {
    // $parent is the class calling this method
    echo '<p>' . JText::_('PLG_CIVICRM_UNINSTALL_TEXT') . '</p>';
    $filename = 'civimembershiplevels.php';
    $path = JPATH_SITE . '/administrator/components/com_civicrm/civicrm/joomla/site/elements';
    echo '<p>Removing file from: ' . $path . '/' . $filename . '</p>';

    JFile::delete($path . '/' . $filename);

    $filename = 'civimembershiptypes.php';
    echo '<p>Removing file from: ' . $path . '/' . $filename . '</p>';

    JFile::delete($path . '/' . $filename);

    echo '<p>Important! Failure to enable an authentication module will likely result in your being locked out of your site!</p>';

  }

  /**
   * method to update the plugin
   *
   * @return void
   */
  function update($parent) {
    // $parent is the class calling this method
    // echo '<p>' . JText::_('PLG_CIVICRM_UPDATE_TEXT') . '</p>';
  }

  /**
   * method to run before an install/update/uninstall method
   *
   * @return void
   */
  function preflight($type, $parent) {
    // $parent is the class calling this method
    // $type is the type of change (install, update or discover_install)
  }

  /**
   * method to run after an install/update/uninstall method
   *
   * @return void
   */
  function postflight($type, $parent) {
    // $parent is the class calling this method
    // $type is the type of change (install, update or discover_install)
    // File move is in post flight as we have to wait on the installer having installed it first.
    //
    if ($type == "install") {

      $path1 = JPATH_SITE . '/plugins/authentication/civicrm';
      $path2 = JPATH_SITE . '/administrator/components/com_civicrm/civicrm/joomla/site/elements';

      $filename = 'civimembershiplevels.php';
      echo '<p>Move from: ' . $path1 . '/' . $filename . '</p>';
      echo '<p>To: ' . $path2 . '/' . $filename . '</p>';
      JFile::copy($path1 . '/' . $filename, $path2 . '/' . $filename);

      $filename = 'civimembershiptypes.php';
      echo '<p>Move from: ' . $path1 . '/' . $filename . '</p>';
      echo '<p>To: ' . $path2 . '/' . $filename . '</p>';
      JFile::copy($path1 . '/' . $filename, $path2 . '/' . $filename);

      echo '<p>' . JText::_('Done dealing with files injected into CiviCRM ') . '</p>';
      echo '<p>' . JText::_('PLG_CIVICRM_POSTFLIGHT_' . strtoupper($type) . '_TEXT') . '</p>';
    }
  }

}
