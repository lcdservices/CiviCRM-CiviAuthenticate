<?php
/**
 * @version      $Id: mobile.php 20196 2011-01-09 02:40:25Z ian $
 * @package      Joomla.Framework
 * @subpackage   Form
 * @license      GNU General Public License version 2 or later; see LICENSE.txt
 */

defined('JPATH_BASE') or die;

jimport('joomla.form.formrule');

/**
 * Form Rule class for the Joomla Framework.
 *
 * @package      Joomla.Framework
 * @since        1.6
 */
class JFormRuleCiviMembershipTypes extends JFormRule {
  /**
   * Method to test the username for uniqueness.
   *
   * @param    object $element  The JXMLElement object representing the <field /> tag for the
   *                                 form field object.
   * @param    mixed $value     The form field value to validate.
   * @param    string $group    The field name group control value. This acts as as an array
   *                            container for the field. For example if the field has name="foo"
   *                            and the group value is set to "bar" then the full field name
   *                            would end up being "bar[foo]".
   * @param    object $input    An optional JRegistry object with the entire data set to validate
   *                            against the entire form.
   * @param    object $form     The form object for which the field is being tested.
   *
   * @return   boolean          True if the value is valid, false otherwise.
   * @since    1.6
   * @throws   JException on invalid rule.
   */
  public function test(&$element, $value, $group = NULL, &$input = NULL, &$form = NULL) {
    /*
     * Here we match the value with a specific format. You may also use any kind of validation,
     * If you need a value of another field as well from the same form then use the following method:
     * $userId = ($input instanceof JRegistry) ? $input->get('id') : '0';
     * this gived you the value of the Id field
     */

    require_once JPATH_ROOT . '/administrator/components/com_civicrm/civicrm.settings.php';
    require_once 'CRM/Core/Config.php';
    $config =& CRM_Core_Config::singleton();

    //CRM_Core_Error::debug_var('test: $element', $element);
    //CRM_Core_Error::debug_var('test: $value', $value);
    //CRM_Core_Error::debug_var('test: $group', $group);
    //CRM_Core_Error::debug_var('test: $input', $input);
    //CRM_Core_Error::debug_var('test: $form', $form);

    $fldBase = substr($element['name'], 0, strrpos($element['name'], '_'));
    //CRM_Core_Error::debug_var('test: $fldBase', $fldBase);

    $unique = TRUE;
    $params = $input->get('params');
    for ($x = 1; $x <= 8; $x++) {
      $fldName = "{$fldBase}_{$x}";
      $fld = $params->$fldName;
      //CRM_Core_Error::debug_var("test: $fldName", $fld);

      if ($element['name'] != $fldName &&
        !empty($value) &&
        $value == $fld
      ) {
        $unique = FALSE;

        JFactory::getApplication()->enqueueMessage(
          'You must select a unique membership type for each option.',
          'warning'
        );
      }
      //CRM_Core_Error::debug_log_message("$fldName : $unique");
    }
    //CRM_Core_Error::debug_var('test: $unique', $unique);

    return $unique;
  }

}
