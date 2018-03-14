<?php
/**
 * @version      $Id: list.php 20196 2011-01-09 02:40:25Z ian $
 * @package      Joomla.Framework
 * @subpackage   Form
 * @copyright    Copyright (C) 2005 - 2014 Open Source Matters, Inc. All rights reserved.
 * @license      GNU General Public License version 2 or later; see LICENSE.txt
 */

defined('JPATH_BASE') or die;

jimport('joomla.html.html');
jimport('joomla.form.formfield');

/**
 * Form Field class for the Joomla Framework.
 *
 * @package    Joomla.Framework
 * @subpackage Form
 * @since      1.6
 */
class JFormFieldCiviContributionPages extends JFormField {
  /**
   * The form field type.
   *
   * @var    string
   * @since  1.6
   */
  protected $type = 'List';
  var  $_name = 'CiviContributionPages';

  /**
   * Method to get the field input markup.
   *
   * @return  string  The field input markup.
   * @since   1.6
   */
  protected function getInput() {
    // Initialize variables.
    $html = array();

    // Initiate CiviCRM
    require_once JPATH_ROOT . '/administrator/components/com_civicrm/civicrm.settings.php';
    require_once 'CRM/Core/Config.php';
    $config = CRM_Core_Config::singleton();

    // Initialize some field attributes.
    $attr = $this->element['class'] ? ' class="' . (string) $this->element['class'] . '"' : '';
    $attr .= $this->element['size'] ? ' size="' . (int) $this->element['size'] . '"' : '';
    $attr .= $this->multiple ? ' multiple="multiple"' : '';

    // Get the field options.
    $options = array();
    $options[] = JHTML::_('select.option', '0', JText::_('- Select Contribution Page -'));
    $query = 'SELECT id, title FROM civicrm_contribution_page WHERE is_active = 1 ORDER BY title';
    $dao = CRM_Core_DAO::executeQuery($query);
    while ($dao->fetch()) {
      $options[] = JHTML::_('select.option', $dao->id, $dao->title);
    }

    $html[] = JHtml::_('select.genericlist', $options, $this->name, trim($attr), 'value', 'text', $this->value, $this->name);

    return implode($html);
  }

}
