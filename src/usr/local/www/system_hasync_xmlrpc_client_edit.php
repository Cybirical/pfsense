<?php 
/*
 * system_hasync_xmlrpc_client_edit.php
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
##|*NAME=System: High Availability Sync: Edit XMLRPC Sync Client
##|*DESCR=Allow access to the 'System: High Availability Sync: Edit XMLRPC Sync Client' page.
##|*MATCH=system_hasync_xmlrpc_client_edit.php*
##|-PRIV

require_once("guiconfig.inc");

$checkbox_names = array(
        'adminsync',
        'synchronizeusers',
        'synchronizeauthservers',
        'synchronizecerts',
        'synchronizerules',
        'synchronizeschedules',
        'synchronizealiases',
        'synchronizenat',
        'synchronizeipsec',
        'synchronizeopenvpn',
        'synchronizedhcpd',
        'synchronizedhcrelay',
        'synchronizekea6',
        'synchronizedhcrelay6',
        'synchronizewol',
        'synchronizestaticroutes',
        'synchronizevirtualip',
        'synchronizetrafficshaper',
        'synchronizetrafficshaperlimiter',
        'synchronizednsforwarder',
        'synchronizecaptiveportal');

$id = is_numericint($_REQUEST['id']) ? $_REQUEST['id'] : null;

$pconfig = [];
$client_sync_entry = [];


if (isset($id) &&
    config_get_path('hasync/xmlrpcclients/' . $id)) {
	$pconfig = config_get_path('hasync/xmlrpcclients/' . $id);
	$client_sync_entry = config_get_path('hasync/xmlrpcclients/' . $id);
	$pconfig['passwordfld'] = $pconfig['password'];
}

if ($_POST['save']) {
	unset($input_errors);
	$pconfig = $_POST;

	/* input validation */
	$reqdfields = explode(" ", "name synchronizetoip username passwordfld");
	$reqdfieldsn = array(gettext("Name"), gettext("Synchronize Config to IP"), gettext("Remote System Username"), gettext("Remote System Password"));

	do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);

	$client_sync_entry['name'] = $pconfig['name'];
	$client_sync_entry['description'] = $pconfig['description'];
	$client_sync_entry['synchronizetoip'] = $pconfig['synchronizetoip'];
	$client_sync_entry['username'] = $pconfig['username'];

	if ($pconfig['passwordfld'] == $pconfig['passwordfld_confirm']) {
		if ($pconfig['passwordfld'] != DMYPWD) {
			$client_sync_entry['password'] = $pconfig['passwordfld'];
		}
	} else {
		$input_errors[] = gettext("Password and confirmation must match.");
	}

	foreach ($checkbox_names as $name) {
		$client_sync_entry[$name] = $pconfig[$name];
	}

	if (!is_ipaddr($pconfig['synchronizetoip'])) {
		$input_errors[] = gettext("Synchronize Config to IP must be a valid IP address.");
	}

	/* check for overlaps */
	foreach (config_get_path('hasync/xmlrpcclients/', []) as $client_entry) {
		if (isset($id) && (config_get_path('hasync/xmlrpcclients/' . $id) === $client_entry)) {
			continue;
		}

		if ($client_entry['synchronizetoip'] == $_POST['synchronizetoip']) {
			$input_errors[] = gettext("This address is already being used by another sync client.");
			break;
		}
	}

	if (!$input_errors) {
		if (isset($id) && config_get_path('hasync/xmlrpcclients/' . $id)) {
			config_set_path('hasync/xmlrpcclients/' . $id, $client_sync_entry);	
		} else {
			config_set_path('hasync/xmlrpcclients/' . count(config_get_path('hasync/xmlrpcclients/', [])) + 1, $client_sync_entry);
		}

		mark_subsystem_dirty('hasync');

		write_config(gettext("Client configured for XMLRPC Sync."));

		header("Location: system_hasync.php");
		exit;
	}
}

$pgtitle = array(gettext("System"), gettext("High Availability"), gettext("Edit XMLRPC Sync Client"));
$pglinks = array("", "system_hasync.php", "@self");
$shortcut_section = 'carp';
include("head.inc");

if ($input_errors) {
	print_input_errors($input_errors);
}

$form = new Form;

$section = new Form_Section(gettext('Configuration Synchronization Settings (XMLRPC Sync)'));

$section->addInput(new Form_Input(
        'name',
        gettext('Name'),
        'text',
        $pconfig['name']
));

$section->addInput(new Form_Input(
        'description',
        gettext('Description'),
        'text',
        $pconfig['description']
));

$section->addInput(new Form_Input(
	'synchronizetoip',
	gettext('Synchronize Config to IP'),
	'text',
	$pconfig['synchronizetoip'],
	['placeholder' => 'IP Address']
))->setHelp(gettext('Enter the IP address of the firewall to which the selected configuration sections should be synchronized.%1$s%1$s' .
			'XMLRPC sync is currently only supported over connections using the same protocol and port as this system - make sure the remote system\'s port and protocol are set accordingly!%1$s' .
			'Do not use the Synchronize Config to IP and password option on backup cluster members!'), '<br />');

$section->addInput(new Form_Input(
        'username',
        gettext('Remote System Username'),
        'text',
        $pconfig['username'],
        ['autocomplete' => 'new-password']
))->setHelp(gettext('Enter the webConfigurator username of the system entered above for synchronizing the configuration.%1$s' .
                        'Do not use the Synchronize Config to IP and username option on backup cluster members!'), '<br />');

$section->addPassword(new Form_Input(
        'passwordfld',
        gettext('Remote System Password'),
        'password',
        $pconfig['passwordfld']
))->setHelp(gettext('Enter the webConfigurator password of the system entered above for synchronizing the configuration.%1$s' .
                        'Do not use the Synchronize Config to IP and password option on backup cluster members!'), '<br />');

$section->addInput(new Form_Checkbox(
        'adminsync',
        gettext('Synchronize admin'),
        gettext('synchronize admin accounts and autoupdate sync password.'),
        ($pconfig['adminsync'] === 'on'),
        'on'
))->setHelp(gettext('By default, the admin account does not synchronize, and each node may have a different admin password.%1$s' .
                        'This option automatically updates XMLRPC Remote System Password when the password is changed on
                        the Remote System Username account.'), '<br />');

$group = new Form_MultiCheckboxGroup(gettext('Select options to sync'));

$group->add(new Form_MultiCheckbox(
        'synchronizeusers',
        gettext('Synchronize Users and Groups'),
        gettext('User manager users and groups'),
        ($pconfig['synchronizeusers'] === 'on'),
        'on'
));

$group->add(new Form_MultiCheckbox(
        'synchronizeauthservers',
        gettext('Synchronize Auth Servers'),
        gettext('Authentication servers (e.g. LDAP, RADIUS)'),
        ($pconfig['synchronizeauthservers'] === 'on'),
        'on'
));

$group->add(new Form_MultiCheckbox(
        'synchronizecerts',
        gettext('Synchronize Certificates'),
        gettext('Certificate Authorities, Certificates, and Certificate Revocation Lists'),
        ($pconfig['synchronizecerts'] === 'on'),
        'on'
));

$group->add(new Form_MultiCheckbox(
        'synchronizerules',
        gettext('Synchronize Rules'),
        gettext('Firewall rules'),
        ($pconfig['synchronizerules'] === 'on'),
        'on'
));

$group->add(new Form_MultiCheckbox(
        'synchronizeschedules',
        gettext('Synchronize Firewall schedules'),
        gettext('Firewall schedules'),
        ($pconfig['synchronizeschedules'] === 'on'),
        'on'
));

$group->add(new Form_MultiCheckbox(
        'synchronizealiases',
        gettext('Synchronize Firewall aliases'),
        gettext('Firewall aliases'),
        ($pconfig['synchronizealiases'] === 'on'),
        'on'
));

$group->add(new Form_MultiCheckbox(
        'synchronizenat',
        gettext('Synchronize NAT'),
        gettext('NAT configuration'),
        ($pconfig['synchronizenat'] === 'on'),
        'on'
));

$group->add(new Form_MultiCheckbox(
        'synchronizeipsec',
        gettext('Synchronize IPsec'),
        gettext('IPsec configuration'),
        ($pconfig['synchronizeipsec'] === 'on'),
        'on'
));

$group->add(new Form_MultiCheckbox(
                'synchronizeopenvpn',
                gettext('Synchronize OpenVPN'),
                gettext('OpenVPN configuration (Implies CA/Cert/CRL Sync)'),
                ($pconfig['synchronizeopenvpn'] === 'on'),
                'on'
));

$group->add(new Form_MultiCheckbox(
        'synchronizedhcpd',
        gettext('Synchronize DHCPD'),
        gettext('DHCP Server settings'),
        ($pconfig['synchronizedhcpd'] === 'on'),
        'on'
));

$group->add(new Form_MultiCheckbox(
        'synchronizedhcrelay',
        gettext('Synchronize DHCP Relay'),
        gettext('DHCP Relay settings'),
        ($pconfig['synchronizedhcrelay'] === 'on'),
        'on'
));

if (dhcp_is_backend('kea')) {
        $group->add(new Form_MultiCheckbox(
                'synchronizekea6',
                gettext('Synchronize Kea DHCPv6'),
                gettext('DHCPv6 Server settings'),
                ($pconfig['synchronizekea6'] === 'on'),
                'on'
        ));
}

$group->add(new Form_MultiCheckbox(
        'synchronizedhcrelay6',
        gettext('Synchronize DHCPv6 Relay'),
        gettext('DHCPv6 Relay settings'),
        ($pconfig['synchronizedhcrelay6'] === 'on'),
        'on'
));

$group->add(new Form_MultiCheckbox(
        'synchronizewol',
        gettext('Synchronize Wake-on-LAN'),
        gettext('WoL Server settings'),
        ($pconfig['synchronizewol'] === 'on'),
        'on'
));

$group->add(new Form_MultiCheckbox(
        'synchronizestaticroutes',
        gettext('Synchronize Static Routes'),
        gettext('Static Route configuration'),
        ($pconfig['synchronizestaticroutes'] === 'on'),
        'on'
));

$group->add(new Form_MultiCheckbox(
        'synchronizevirtualip',
        gettext('Synchronize Virtual IPs'),
        gettext('Virtual IPs'),
        ($pconfig['synchronizevirtualip'] === 'on'),
        'on'
));

$group->add(new Form_MultiCheckbox(
        'synchronizetrafficshaper',
        gettext('Synchronize traffic shaper (queues)'),
        gettext('Traffic Shaper configuration'),
        ($pconfig['synchronizetrafficshaper'] === 'on'),
        'on'
));

$group->add(new Form_MultiCheckbox(
        'synchronizetrafficshaperlimiter',
        gettext('Synchronize traffic shaper (limiter)'),
        gettext('Traffic Shaper Limiters configuration'),
        ($pconfig['synchronizetrafficshaperlimiter'] === 'on'),
        'on'
));

$group->add(new Form_MultiCheckbox(
        'synchronizednsforwarder',
        gettext('Synchronize DNS (Forwarder/Resolver)'),
        gettext('DNS Forwarder and DNS Resolver configurations'),
        ($pconfig['synchronizednsforwarder'] === 'on'),
        'on'
));

$group->add(new Form_MultiCheckbox(
        'synchronizecaptiveportal',
        gettext('Synchronize Captive Portal'),
        gettext('Captive Portal'),
        ($pconfig['synchronizecaptiveportal'] === 'on'),
        'on'
));

$section->add($group);

$form->add($section);

print($form);

include("foot.inc");
