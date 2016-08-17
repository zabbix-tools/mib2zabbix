# mib2zabbix

This Perl script will generate a Zabbix v3 Template in XML format from an OID
tree in a SNMP MIB file.

### Usage

    mib2zabbix.pl -o <OID> [OPTIONS]...
        
    Export loaded SNMP MIB OIDs to Zabbix Template XML

        -f, --filename=PATH         output filename (default: stdout)
       
        -N, --name=STRING           template name (default: OID label)
        -G, --group=STRING          template group (default: 'Templates')
        -e, --enable-items          enable all template items (default: disabled)
        
        -o, --oid=STRING            OID tree root to export (must start with '.')
        
        -v, --snmpver=1|2|3         SNMP version (default: 2)
        -p, --port=PORT             SNMP UDP port number (default: 161)
        
    SNMP Version 1 or 2c specific

        -c, --community=STRING      SNMP community string (default: 'public')
        
    SNMP Version 3 specific

        -L, --level=LEVEL           security level (noAuthNoPriv|authNoPriv|authPriv)
        -n, --context=CONTEXT       context name
        -u, --username=USERNAME     security name
        -a, --auth=PROTOCOL         authentication protocol (MD5|SHA)
        -A, --authpass=PASSPHRASE   authentication protocol passphrase
        -x, --privacy=PROTOCOL      privacy protocol (DES|AES)
        -X, --privpass=PASSPHRASE   privacy passphrase

    Zabbix item configuration

        --check-delay=SECONDS       check interval in seconds (default: 60)
        --disc-delay=SECONDS        discovery interval in seconds (default: 3600)
        --history=DAYS              history retention in days (default: 7)
        --trends=DAYS               trends retention in days (default: 365)
        
        -h, --help                  print this message

### Requirements

* Zabbix v3+
* Perl v5
* Pod::Usage
* XML::Simple
* Net-SNMP
* Correctly configured [MIB files](http://net-snmp.sourceforge.net/tutorial/tutorial-5/commands/mib-options.html)

### Installation

Install from GitHub:

    # install prerequisites on Ubuntu: 
    apt-get install perl libxml-simple-perl libsnmp-perl

    # assumes ~/bin exists and is in $PATH, so adjust accordingly!
    curl -sL -o ~/bin/mib2zabbix https://raw.githubusercontent.com/cavaliercoder/mib2zabbix/master/mib2zabbix.pl
    chmod +x ~/bin/mib2zabbix


### Translations

This table describes how MIB elements are translated into Zabbix template
elements:

* Scalar OID -> Zabbix SNMP Item
* Table OID -> Zabbix SNMP Discovery Rule
* Table Column OID -> Zabbix Discovery Prototype
* Trap/Notification OID -> Zabbix SNMP Trap Item 
* OID Enums -> Zabbix Value Maps

### License

mib2zabbix - SNMP Template Generator for Zabbix
Copyright (C) 2016 - Ryan Armstrong <ryan@cavaliercoder.com>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
