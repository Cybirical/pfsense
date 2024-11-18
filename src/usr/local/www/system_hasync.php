<?php
/*
 * system_hasync.php
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2004-2013 BSD Perimeter
 * Copyright (c) 2013-2016 Electric Sheep Fencing
 * Copyright (c) 2014-2024 Rubicon Communications, LLC (Netgate)
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

##|+PRIV
##|*IDENT=page-system-hasync
##|*NAME=System: High Availability Sync
##|*DESCR=Allow access to the 'System: High Availability Sync' page.
##|*MATCH=system_hasync.php*
##|-PRIV

require_once("guiconfig.inc");

$a_hasync = config_get_path('hasync', []);

if ($_POST['act'] == "del") {
	if (config_get_path('hasync/xmlrpcclients/' . $_POST['id'])) {
		config_del_path('hasync/xmlrpcclients/' . $_POST['id']);
		write_config(gettext("Client deleted from XMLRPC Sync."));
		mark_subsystem_dirty('hasync');
		header("Location: system_hasync.php");
		exit;
	}
}

if ($_POST) {
	$pconfig = $_POST;
	$a_hasync[$name] = $pconfig['pfsyncenabled'] ? $pconfig['pfsyncenabled'] : false;
	$old_pfhostid = isset($a_hasync['pfhostid']) ? $a_hasync['pfhostid'] : '';
	$a_hasync['pfhostid'] = strtolower(trim($pconfig['pfhostid']));
	$a_hasync['pfsyncpeerip'] = $pconfig['pfsyncpeerip'];
	$a_hasync['pfsyncinterface'] = $pconfig['pfsyncinterface'];

	if ((!empty($pconfig['pfhostid']) &&
	    !(ctype_xdigit($pconfig['pfhostid']) &&
	    (strlen($pconfig['pfhostid']) <= 8))) ||
	    ($pconfig['pfhostid'] === "0")) {
		$input_errors[] = gettext("Invalid Host ID. Must be a non-zero hexadecimal string 8 characters or less.");
	}

	if (!empty($pconfig['pfsyncpeerip']) && !is_ipaddrv4($pconfig['pfsyncpeerip'])) {
		$input_errors[] = gettext("pfsync Synchronize Peer IP must be an IPv4 IP.");
	}

	if (!$input_errors) {
		config_set_path('hasync', $a_hasync);
		write_config("Updated High Availability Sync configuration");
		interfaces_sync_setup();
		if ($old_pfhostid != $a_hasync['pfhostid']) {
			filter_configure();
		}
		header("Location: system_hasync.php");
		exit();
	}
}

$pconfig['pfsyncenabled']	= $a_hasync['pfsyncenabled'];
$pconfig['pfhostid']	= $a_hasync['pfhostid'];
$pconfig['pfsyncpeerip']	= $a_hasync['pfsyncpeerip'];
$pconfig['pfsyncinterface'] = $a_hasync['pfsyncinterface'];

$ifaces = get_configured_interface_with_descr();
$ifaces["lo0"] = "loopback";

$pgtitle = array(gettext('System'), gettext('High Availability'));
$shortcut_section = 'carp';

// Build a list of available interfaces
$iflist = array();
foreach ($ifaces as $ifname => $iface) {
	$iflist[$ifname] = $iface;
}

include("head.inc");

if ($input_errors) {
	print_input_errors($input_errors);
}

$form = new Form;

$section = new Form_Section(gettext('State Synchronization Settings (pfsync)'));

$section->addInput(new Form_Checkbox(
	'pfsyncenabled',
	gettext('Synchronize states'),
	gettext('pfsync transfers state insertion, update, and deletion messages between firewalls.'),
	($pconfig['pfsyncenabled'] === 'on'),
	'on'
))->setHelp(gettext('Each firewall sends these messages out via multicast on a specified interface, using the PFSYNC protocol (IP Protocol 240).' .
			' It also listens on that interface for similar messages from other firewalls, and imports them into the local state table.%1$s' .
			'This setting should be enabled on all members of a failover group.%1$s' .
			'Clicking "Save" will force a configuration sync if it is enabled! (see Configuration Synchronization Settings below)'), '<br />');

$section->addInput(new Form_Select(
	'pfsyncinterface',
	gettext('Synchronize Interface'),
	$pconfig['pfsyncinterface'],
	$iflist
))->setHelp(gettext('If Synchronize States is enabled this interface will be used for communication.%1$s' .
			'It is recommended to set this to an interface other than LAN! A dedicated interface works the best.%1$s' .
			'An IP must be defined on each machine participating in this failover group.%1$s' .
			'An IP must be assigned to the interface on any participating sync nodes.'), '<br />');

$section->addInput(new Form_Input(
	'pfhostid',
	gettext('Filter Host ID'),
	'text',
	$pconfig['pfhostid'],
	['placeholder' => substr(system_get_uniqueid(), -8)]
))->setHelp(gettext('Custom pf host identifier carried in state data to uniquely identify which host created a firewall state.%1$s' .
		'Must be a non-zero hexadecimal string 8 characters or less (e.g. 1, 2, ff01, abcdef01).%1$s' .
		'Each node participating in state synchronization must have a different ID.'), '<br />');

$section->addInput(new Form_Input(
	'pfsyncpeerip',
	gettext('pfsync Synchronize Peer IP'),
	'text',
	$pconfig['pfsyncpeerip'],
	['placeholder' => 'IP Address']
))->setHelp(gettext('Setting this option will force pfsync to synchronize its state table to this IP address. The default is directed multicast.'));

$form->add($section);

print($form);

?>
<div class="panel panel-default">
        <div class="panel-heading"><h2 class="panel-title"><?=gettext('XMLRPC Synchronization Clients')?></h2></div>
        <div class="panel-body">
                <div class="table-responsive">
                        <table class="table table-striped table-hover table-condensed sortable-theme-bootstrap" data-sortable>
                                <thead>
                                        <tr>
                                                <th><?=gettext("Name")?></th>
                                                <th><?=gettext("IP")?></th>
                                                <th><?=gettext("Description")?></th>
                                                <th><?=gettext("Actions")?></th>
                                        </tr>
                                </thead>
                                <tbody>
<?php
foreach (config_get_path('hasync/xmlrpcclients', []) as $idx => $client):
?>
                                        <tr ondblclick="document.location='system_hasync_xmlrpc_client_edit.php?id=<?=$idx?>'">
                                                <td>
                                                        <?=htmlspecialchars($client['name'])?>
                                                </td>
                                                <td>
                                                        <?=htmlspecialchars($client['synchronizetoip'])?>
                                                </td>
                                                <td>
                                                        <?=htmlspecialchars($client['description'])?>
                                                </td>
                                                <td>
                                                        <a class="fa fa-pencil"   title="<?=gettext("Edit Client")?>" href="system_hasync_xmlrpc_client_edit.php?id=<?=$idx?>"></a>
                                                        <a class="fa fa-trash"        title="<?=gettext("Delete Client")?>" href="?act=del&amp;id=<?=$idx?>" usepost></a>
                                                </td>
                                        </tr>
<?php endforeach?>
                                </tbody>
                        </table>
                </div>
        </div>
</div>

<nav class="action-buttons">
	<a href="system_hasync_xmlrpc_client_edit.php" role="button" class="btn btn-success btn-sm">
		<i class="fa fa-plus icon-embed-btn"></i>
		<?=gettext("Add");?>
	</a>
</nav>
<?php

include("foot.inc");
