CiviCRM CiviAuthenticate Plugin
===============================

Authentication plugin for Joomla which allows you to restrict frontend login access based on whether the user is a member in good standing and various other criteria.

In addition to creating membership-status-based access criteria, the user can configure the plugin to assign a Joomla Access Level based on the membership status or type, allow login using username (standard) or email address (alternate), and control where the user is redirected based on various status combinations.

See also: http://wiki.civicrm.org/confluence/display/CRMDOC/Joomla+CiviCRM+Membership+Authentication+and+ACL+Plugin

Major Version Notes
-------------

* v3.0.x :: updates for Joomla 3.x compatibility. Also compatible with Joomla 2.5.18+.
* v2.5.x :: use this version if you are using a version of Joomla prior to v2.5.18 (before Joomla implemented enhanced password hashing).

Minor Version Notes
-------------

* v3.0.5 :: releases the lock on membership type levels in the advanced level option tab. Note that you may only select a membership level and apply the ACL group once (i.e. you may not apply multiple ACL groups to a single membership type).

To access an earlier version, use the branch dropdown, switch to the tags tab, and select the desired version.
