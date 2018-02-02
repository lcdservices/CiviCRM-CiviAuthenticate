CiviCRM CiviAuthenticate Plugin
===============================

Authentication plugin for Joomla which allows you to restrict frontend login access based on whether the user is a member in good standing and various other criteria.

In addition to creating membership-status-based access criteria, the user can configure the plugin to assign a Joomla Access Level based on the membership status or type, allow login using username (standard) or email address (alternate), and control where the user is redirected based on various status combinations.

See also: http://wiki.civicrm.org/confluence/display/CRMDOC/Joomla+CiviCRM+Membership+Authentication+and+ACL+Plugin

Major Version Notes
-------------

* v4.0.x :: significant restructuring to status/type handling. we now consider both sets of options separately, and outside of the master status check. this allows users to assign based on status and type at the same time. care should be taken to avoid logical conflicts (i.e. where assignments based on type and status would conflict). because this introduces some changes in behavior, please test thoroughly when implementing.
* v3.5.x :: support multiple mappings per user
* v3.4.x :: bug fixes: in membership type mapping, support selecting memberships in any order; fix condition structure when determine what groups to remove
* v3.3.x :: implement extension update path
* v3.2.x :: fixes contrib page parameter selection
* v3.0.x :: updates for Joomla 3.x compatibility. Also compatible with Joomla 2.5.18+.
* v2.5.x :: use this version if you are using a version of Joomla prior to v2.5.18 (before Joomla implemented enhanced password hashing).

Minor Version Notes
-------------

* v3.2.1 :: fix pass by reference error affecting session headers.
* v3.0.7 :: when cycling through memberships to apply status rules, only apply a rule for the lowest weight status. This addresses the situation where a person has an active membership and an expired membership, and the expired membership is inadvertently applied last (thus assigning a lower group than desired).
* v3.0.5 :: releases the lock on membership type levels in the advanced level option tab. Note that you may only select a membership level and apply the ACL group once (i.e. you may not apply multiple ACL groups to a single membership type).

To access an earlier version, use the branch dropdown, switch to the tags tab, and select the desired version.
