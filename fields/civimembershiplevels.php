<?php
/**
 * @version      $Id: list.php 20196 2011-01-09 02:40:25Z ian $
 * @package      Joomla.Framework
 * @subpackage   Form
 * @copyright    Copyright (C) 2005 - 2011 Open Source Matters, Inc. All rights reserved.
 * @license      GNU General Public License version 2 or later; see LICENSE.txt
 */

defined('JPATH_BASE') or die;

jimport('joomla.html.html');
jimport('joomla.form.formfield');

/**
 * Form Field class for the Joomla Framework.
 *
 * @package      Joomla.Framework
 * @subpackage   Form
 * @since        1.6
 */
class JFormFieldCiviMembershipLevels extends JFormField {
  /**
   * The form field type.
   *
   * @var      string
   * @since    1.6
   */
  protected $type = 'List';
  var    $_name = 'CiviMembershipLevels';

  /**
   * Method to get the field input markup.
   *
   * @return   string    The field input markup.
   * @since    1.6
   */
  protected function getInput() {
    // Initialize variables.
    $html = [];
    $attr = '';

    // Initiate CiviCRM
    require_once JPATH_ROOT . '/administrator/components/com_civicrm/civicrm.settings.php';
    require_once 'CRM/Core/Config.php';
    $config = CRM_Core_Config::singleton();

    // Initialize some field attributes.
    $attr .= $this->element['class'] ? ' class="' . (string) $this->element['class'] . '"' : '';

    // To avoid user's confusion, readonly="true" should imply disabled="true".
    if ((string) $this->element['readonly'] == 'true' || (string) $this->element['disabled'] == 'true') {
      $attr .= ' disabled="disabled"';
    }

    $attr .= $this->element['size'] ? ' size="' . (int) $this->element['size'] . '"' : '';
    $attr .= $this->multiple ? ' multiple="multiple"' : '';

    // Initialize JavaScript field attributes.
    $attr .= $this->element['onchange'] ? ' onchange="' . (string) $this->element['onchange'] . '"' : '';

    // Get the field options.
    $options = [];
    $options[] = JHTML::_('select.option', '0', JText::_('- Select Membership Status -'));

    $membershipStatuses = \Civi\Api4\MembershipStatus::get(FALSE)
      ->addSelect('name')
      ->addWhere('is_active', '=', TRUE)
      ->addOrderBy('id', 'ASC')
      ->execute();
    foreach ($membershipStatuses as $membershipStatus) {
      $options[] = JHTML::_('select.option', $membershipStatus['id'], $membershipStatus['name']);
    }

    // Create a read-only list (no name) with a hidden input to store the value.
    if ((string) $this->element['readonly'] == 'true') {
      $html[] = JHtml::_('select.genericlist', $options, '', trim($attr), 'value', 'text', $this->value, $this->name);
      $html[] = '<input type="hidden" name="' . $this->name . '" value="' . $this->value . '"/>';
    }
    // Create a regular list.
    else {
      $html[] = JHtml::_('select.genericlist', $options, $this->name, trim($attr), 'value', 'text', $this->value, $this->name);
    }

    return implode($html);
  }

}
