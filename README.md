CiviCRM CiviAuthenticate Plugin
===============================

Authentication plugin for Joomla which allows you to restrict frontend login access based on whether the user is a member in good standing and various other criteria.

In addition to creating membership-status-based access criteria, the user can configure the plugin to assign a Joomla Access Level based on the membership status or type, allow login using username (standard) or email address (alternate), and control where the user is redirected based on various status combinations.

See also: http://wiki.civicrm.org/confluence/display/CRMDOC/Joomla+CiviCRM+Membership+Authentication+and+ACL+Plugin

Version Notes
-------------

* v2.6.0 provides compatibility with Joomla 2.5.18. The Joomla authentication routine was modified in this revision (a new method for password hashing is now used). If you are using a version of Joomla prior to v2.5.18 you will need to use v2.0.x of the plugin.
