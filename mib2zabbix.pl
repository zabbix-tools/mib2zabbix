#!/usr/bin/perl

=pod

=head1 NAME

mib2zabbix.pl - SNMP MIB to Zabbix Template

=head1 SYNOPSIS

mib2zabbix.pl -o <OID> [OPTIONS]...

Export loaded SNMP MIB OIDs to Zabbix Template XML

    -f, --filename=PATH         output filename (default: stdout)

    -N, --name=STRING           template name (default: OID label)
    -G, --group=STRING          template group (default: 'Templates')
    -e, --enable-items          enable all template items (default: disabled)

    -o, --oid=STRING            OID tree root to export

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

=head1 DESCRIPTION

B<mib2zabbix.pl> will export a loaded MIB tree into a Zabbix Template starting
from the OID root specified.

Requires: Zabbix v3, Perl v5, Pod::Usage, XML::Simple, Net-SNMP

=head1 AUTHOR

Ryan Armstrong <ryan@cavaliercoder.com>

=head1 SEE ALSO

Guidelines for Authors and Reviewers of MIB Documents
https://www.ietf.org/rfc/rfc4181.txt

Next Generation Structure of Management Information (SMIng) Mappings to the
Simple Network Management Protocol (SNMP)
https://tools.ietf.org/html/rfc3781

SNMP Table Basics
http://www.webnms.com/snmp/help/snmpapi/snmpv3/table_handling/snmptables_basics.html

=head1 SUBROUTINES

=cut

use strict;
#use warnings;

use Cwd 'abs_path';
use Data::Dumper;
use Date::Format;
use Encode qw(decode encode);
use File::Basename;
use Pod::Usage;
use Getopt::Long;
use SNMP;
use XML::Simple;

# Get path info as constants
use constant SCRIPT_NAME    => basename($0);
use constant BASE_PATH      => dirname(abs_path($0));

use constant ZBX_SERVER_CONF    => '/etc/zabbix/zabbix_server.conf';
use constant ZBX_WEB_CONF       => '/etc/zabbix/web/zabbix.conf.php';

# For Zabbix type constants see:
# https://www.zabbix.com/documentation/3.0/manual/api/reference/item/object
# Zabbix Item status
use constant ZBX_ITEM_ENABLED       => 0;
use constant ZBX_ITEM_DISABLED      => 1;

# Zabbix Item Type IDs
use constant ZBX_ITEM_TYPE_SNMPV1   => 1;
use constant ZBX_ITEM_TYPE_SNMPV2   => 4;
use constant ZBX_ITEM_TYPE_SNMPV3   => 6;
use constant ZBX_ITEM_TYPE_SNMPTRAP => 17;

# Zabbix Item Value Type IDs
use constant ZBX_VAL_TYPE_FLOAT     => 0;
use constant ZBX_VAL_TYPE_CHAR      => 1;
use constant ZBX_VAL_TYPE_LOG       => 2;
use constant ZBX_VAL_TYPE_UINT      => 3;
use constant ZBX_VAL_TYPE_TEXT      => 4;

# Zabbix Item Storage types (delta)
use constant ZBX_ITEM_STORE_ASIS        => 0; # Store value as is
use constant ZBX_ITEM_STORE_SPEED       => 1; # Delta, speed per second
use constant ZBX_ITEM_STORE_CHANGE      => 2; # Delta, simple change

# Zabbix Item SNMPv3 constants
use constant ZBX_V3_PRIV_DES            => 0;
use constant ZBX_V3_PRIV_AES            => 1;
use constant ZBX_V3_AUTH_MD5            => 0;
use constant ZBX_V3_AUTH_SHA            => 1;
use constant ZBX_V3_SEC_NOAUTHNOPRIV    => 0;
use constant ZBX_V3_SEC_AUTHNOPRIV      => 1;
use constant ZBX_V3_SEC_AUTHPRIV        => 2;

# SNMP Type -> Zabbix type mapping
my $type_map = {
    'BITS'          => ZBX_VAL_TYPE_TEXT,       # Zabbix 'Text' value type
    'COUNTER'       => ZBX_VAL_TYPE_UINT,       # Zabbix 'Numeric Unsigned' value type for an unsigned integer
    'COUNTER32'     => ZBX_VAL_TYPE_UINT,       # Zabbix 'Numeric Unsigned' value type for an unsigned integer
    'COUNTER64'     => ZBX_VAL_TYPE_UINT,       # Zabbix 'Numeric Unsigned' value type for an unsigned integer
    'GAUGE'         => ZBX_VAL_TYPE_UINT,       # Zabbix 'Numeric Unsigned' value type for an unsigned integer
    'GAUGE32'       => ZBX_VAL_TYPE_UINT,       # Zabbix 'Numeric Unsigned' value type for an unsigned integer
    'INTEGER'       => ZBX_VAL_TYPE_FLOAT,      # Zabbix 'Numeric Float' value type for a signed integer
    'INTEGER32'     => ZBX_VAL_TYPE_FLOAT,      # Zabbix 'Numeric Float' value type for a signed 32 bit integer
    'IPADDR'        => ZBX_VAL_TYPE_TEXT,       # Zabbix 'Text' value type for an IP address
    'NETADDDR'      => ZBX_VAL_TYPE_TEXT,       # Zabbix 'Text' value type for a network address
    'NOTIF'         => ZBX_ITEM_TYPE_SNMPTRAP,  # Zabbix 'SNMP Trap' item type
    'TRAP'          => ZBX_ITEM_TYPE_SNMPTRAP,  # Zabbix 'SNMP Trap' item type
    'OBJECTID'      => ZBX_VAL_TYPE_TEXT,       # Zabbix 'Text' value type for an OID
    'OCTETSTR'      => ZBX_VAL_TYPE_TEXT,       # Zabbix 'Text' value type
    'OPAQUE'        => ZBX_VAL_TYPE_TEXT,       # Zabbix 'Text' value type
    'TICKS'         => ZBX_VAL_TYPE_UINT,       # Zabbix 'Numeric Unsigned' for a Module 232 timestamp
    'UNSIGNED32'    => ZBX_VAL_TYPE_UINT        # Zabbix 'Numeric Unsigned' value type for an unsigned 32bit integer
};

# SNMP Version -> Zabbix item type mapping
my $snmpver_map = {
    1               => ZBX_ITEM_TYPE_SNMPV1, # Zabbix SNMPv1 Agent type for SNMPv1
    2               => ZBX_ITEM_TYPE_SNMPV2, # Zabbix SNMPv2 Agent type for SNMPv2
    3               => ZBX_ITEM_TYPE_SNMPV3  # Zabbix SNMPv3 Agent type for SNMPv3
};

# SNMP Auth config -> Zabbix item auth config
my $snmpv3_auth_level_map = {
    'noauthnopriv'  => ZBX_V3_SEC_NOAUTHNOPRIV,
    'authnopriv'    => ZBX_V3_SEC_AUTHNOPRIV,
    'authpriv'      => ZBX_V3_SEC_AUTHPRIV
};

my $snmpv3_auth_protocol_map = {
    'md5'           => ZBX_V3_AUTH_MD5,
    'sha'           => ZBX_V3_AUTH_SHA
};

my $snmpv3_sec_protocol_map = {
    'des'           => ZBX_V3_PRIV_DES,
    'aes'           => ZBX_V3_PRIV_AES
};

# Default command line options
my $opts =  {
    delay               => 60,              # 1 minute check interval
    disc_delay          => 3600,            # Hourly discovery
    enableitems         => 0,               # Disable items
    group               => 'Templates',
    history             => 7,
    trends              => 365,
    list                => 0,
    maxdepth            => -1,
    oid                 => '.1',
    use_macros          => 0,
    snmpcomm            => 'public',
    snmpport            => 161,
    snmpver             => 2,
    v3auth_level        => 'noAuthNoPriv',
    v3context           => '',
    v3user              => '',
    v3auth_protocol     => 'md5',
    v3auth_pass         => '',
    v3sec_protocol      => 'des',
    v3sec_pass          => ''
};

# Capture calling args
my $cmd = basename($0) . " @ARGV";

# Get command line options
Getopt::Long::Configure ("posix_default", "bundling");
GetOptions(
    'f|filename=s'          => \$opts->{ filename },        # Filename to output

    'N|name=s'              => \$opts->{ name },            # Template name
    'G|group=s'             => \$opts->{ group },           # Template group
    'o|oid=s'               => \$opts->{ oid },             # Root OID to export

    'e|enable-items'        => \$opts->{ enableitems },     # Enable template items

    'v|snmpver=i'           => \$opts->{ snmpver },         # SNMP Version
    'p|port=i'              => \$opts->{ snmpport },        # SNMP Port

    'c|community=s'         => \$opts->{ snmpcomm },        # SNMP Community string

    'L|level=s'             => \$opts->{ v3auth_level },    # SNMPv3 Authentication level
    'n|context=s'           => \$opts->{ v3context },       # SNMPv3 Security Context
    'u|username=s'          => \$opts->{ v3user },          # SNMPv3 Authentication username
    'a|auth=s'              => \$opts->{ v3auth_protocol }, # SNMPv3 Authentication protocol
    'A|authpass=s'          => \$opts->{ v3auth_pass },     # SNMPv3 Authentication passphrase
    'x|privacy=s'           => \$opts->{ v3sec_protocol },  # SNMPv3 Privacy protocol
    'X|privpass=s'          => \$opts->{ v2sec_pass},       # SNMPv3 Privacy passphrase

    'check-delay=i'         => \$opts->{ delay },           # Update interval in seconds
    'disc-delay=i'          => \$opts->{ disc_delay },      # Update interval in seconds
    'history=i'             => \$opts->{ history },         # History retention in days
    'trends=i'              => \$opts->{ trends },          # Trends retention in days

    'h|help'            => \$opts->{ help }
) || pod2usage();

# Print usage if requested
pod2usage({ -exitval => 0 }) if ($opts->{ help });

# Validate SNMPv3 settings
if ($opts->{ snmpver } == 3) {
    $opts->{ snmpcomm } = '';
    if (defined $snmpv3_auth_level_map->{ lc($opts->{ v3auth_level }) }) {
        $opts->{ v3auth_level } = $snmpv3_auth_level_map->{ lc($opts->{ v3auth_level }) }
    }
    else {
        die("Unknown authentication level '$opts->{ v3auth_level }'");
    }
    if (defined $snmpv3_auth_protocol_map->{ lc($opts->{ v3auth_protocol }) }) {
        $opts->{ v3auth_protocol } = $snmpv3_auth_protocol_map->{ lc($opts->{ v3auth_protocol }) }
    }
    else {
        die("Unknown authentication protocol '$opts->{ v3auth_protocol }'");
    }
    if (defined $snmpv3_sec_protocol_map->{ lc($opts->{ v3sec_protocol }) }) {
        $opts->{ v3sec_protocol } = $snmpv3_sec_protocol_map->{ lc($opts->{ v3sec_protocol }) }
    }
    else {
        die("Unknown privacy protocol '$opts->{ v3sec_protocol }'");
    }
}

# Base template for Template Items, Discovery Rules and Item Prototypes
# See: https://www.zabbix.com/documentation/2.2/manual/api/reference/item/object
my %item_base_template = (
    allowed_hosts           => '',
    applications            => [],
    authtype                => '0',
    delay_flex              => '',
    ipmi_sensor             => '',
    params                  => '',
    password                => '',
    port                    => '{$SNMP_PORT}',                                              # Use macro for SNMP UDP Port
    privatekey              => '',
    publickey               => '',
    snmp_community          => $opts->{ snmpver } < 3 ? '{$SNMP_COMMUNITY}' : '',           # Use macro for SNMP Community string
    snmpv3_authpassphrase   => $opts->{ snmpver } == 3 ? '{$SNMP_AUTHPASS}' : '',           # Use macro for SNMPv3 Authentication passphrase
    snmpv3_authprotocol     => $opts->{ snmpver } == 3 ? $opts->{ v3auth_protocol } : '0',
    snmpv3_contextname      => $opts->{ snmpver } == 3 ? '{$SNMP_CONTEXT}' : '',            # Use macro for SNMPv3 context name
    snmpv3_privpassphrase   => $opts->{ snmpver } == 3 ? '{$SNMP_PRIVPASS}' : '',           # Use macro for SNMPv3 Privacy passphrase
    snmpv3_privprotocol     => $opts->{ snmpver } == 3 ? $opts->{ v3sec_protocol } : '0',
    snmpv3_securitylevel    => $opts->{ snmpver } == 3 ? $opts->{ v3auth_level } : '0',
    snmpv3_securityname     => $opts->{ snmpver } == 3 ? '{$SNMP_USER}' : '',               # Use macro for SNMPv3 Username
    status                  => ($opts->{ enableitems } ? ZBX_ITEM_ENABLED : ZBX_ITEM_DISABLED), # Enabled (0) | Disabled (1)
    username                => '',
);

# Item template for standard Template items
my %item_template = (
    data_type               => '0',
    delay                   => $opts->{ delay },        # Update internal seconds
    delta                   => '0',                     # Change delta
    formula                 => '1',                     # Multiplier factor
    history                 => $opts->{ history },      # History retention in days
    inventory_link          => '0',
    multiplier              => '0',                     # Enable multiplier
    trends                  => $opts->{ trends },       # Trends retention in days
    units                   => '',
    valuemap                => '',
    logtimefmt              => '',
);
%item_template = (%item_base_template, %item_template);

# Discovery rule template
my %disc_rule_template = (
    delay                   => $opts->{ disc_delay },
    lifetime                => '30',
    filter                  => {
        evaltype            => 0,
        formula             => undef,
        conditions          => undef
    },

    # The following items must be created as unique refs for each item
    host_prototypes         => [],
    item_prototypes         => [],
    graph_prototypes        => [],
    trigger_prototypes      => []
);
%disc_rule_template = (%item_base_template, %disc_rule_template);

# SNMP Trap template
my %trap_template = (
    allowed_hosts           => '',
    applications            => [],
    authtype                => 0,
    data_type               => 0,
    delay                   => '0',
    delay_flex              => '',
    delta                   => 0,
    description             => '',
    formula                 => 1,
    history                 => $opts->{ history },
    inventory_link          => 0,
    ipmi_sensor             => '',
    logtimefmt              => 'hh:mm:ss dd/MM/yyyy',
    multiplier              => '0',
    params                  => '',
    password                => '',
    port                    => '',
    privatekey              => '',
    publickey               => '',
    snmp_community          => '',
    snmp_oid                => '',
    snmpv3_authpassphrase   => '',
    snmpv3_authprotocol     => 0,
    snmpv3_contextname      => '',
    snmpv3_privpassphrase   => '',
    snmpv3_privprotocol     => 0,
    snmpv3_securitylevel    => 0,
    snmpv3_securityname     => '',
    status                  => ($opts->{ enableitems } ? ZBX_ITEM_ENABLED : ZBX_ITEM_DISABLED),
    trends                  => $opts->{ trends },
    type                    => ZBX_ITEM_TYPE_SNMPTRAP,
    units                   => '',
    username                => '',
    value_type              => ZBX_VAL_TYPE_LOG,
    valuemap                => ''
);

# Item prototype template
my %item_proto_template = (
    application_prototypes  => undef,
);
%item_proto_template = (%item_template, %item_proto_template);

# Global value maps array
my $valuemaps = {};

=head2 utf8_santize

Parameters      : (string) $malformed_utf8
Returns         : (string) $wellformed_utf8
Description     : Returns a sanitized UTF8 string, removing incompatable characters

=cut
sub utf8_sanitize {
    my ($malformed_utf8) = @_;

    my $octets = decode('UTF-8', $malformed_utf8, Encode::FB_DEFAULT);
    return encode('UTF-8', $octets, Encode::FB_CROAK);
}

=head2 oid_path

Parameters  : SNMP::MIB::Node   $oid
Returns     : (String) $oid_path
Description : Returns the fully qualified textual path of a MIB node by
                  traversing the node's parents.

=cut
sub oid_path {
    my ($oid) = @_;

    my $path = $oid->{ label };
    my $node = $oid;
    while ($node = $node->{ parent }) {
        $path = "$node->{ label }.$path";
    }

    return $path;
}

=head2 node_to_item

Parameters  : SNMP::MIB::Node   $node
                  (Hash)            $template
Returns     : (Hash)            $item
Description : Returns a Zabbix Item hash derived from the specified MIB OID

=cut
sub node_to_item {
    my ($node, $template) = @_;
    $template = $template || \%item_template;

    # Create item hash
    my $item = { %{ $template } };

    $item->{ name } = $node->{ label };
    $item->{ snmp_oid } = $node->{ objectID };
    if ($node->{ units }) {
        # Convert unit to Zabbix postfix
        # See 'Units' section of https://www.zabbix.com/documentation/3.0/manual/config/items/item
        if ($node->{ units } =~ /^seconds$/) {
            $item->{ units } = 's';
        } elsif ($node->{ units } =~ /^(hundreds of seconds)$/i) {
            $item->{ units } = 's';
            $item->{ multiplier } = '1';
            $item->{ formula } = '100';
        } elsif ($node->{ units } =~ /^(milliseconds|milli-seconds)$/i) {
            $item->{ units } = 's';
            $item->{ multiplier } = '1';
            $item->{ formula } = '.001';
        } elsif ($node->{ units } =~ /^microseconds$/i) {
            $item->{ units } = 's';
            $item->{ multiplier } = '1';
            $item->{ formula } = '.000001';
        } elsif ($node->{ units } =~ /^(octets|bytes)$/i) {
            $item->{ units } = 'B';
        } elsif ($node->{ units } =~ /^(k-octets|kbytes|kb)$/i) {
            $item->{ units } = 'B';
            $item->{ multiplier } = '1';
            $item->{ formula } = '.001';
        } elsif ($node->{ units } =~ /^(bits per second)$/i) {
            $item->{ units } = 'b';
        } elsif ($node->{ units } =~ /^(kbps|kilobits per second)$/i) {
            $item->{ units } = 'b';
            $item->{ multiplier } = '1';
            $item->{ formula } = '.001';
        } elsif ($node->{ units } =~ /^percent$/i) {
            $item->{ units } = '%';
        } elsif ($node->{ units } =~ /\/s$/i) {
            # truncate /s (/sec will be added later)
            $item->{ units } = substr($node->{ units }, 0, -2) . "/sec";
        } else {
            # default to original
            $item->{ units } = $node->{ units };
        }
    }

    # Merge in item defaults
    %{ $item } = (%{ $template }, %{ $item } );

    # Create SNMP Agent item
    $item->{ type } = $snmpver_map->{ $opts->{ snmpver } };

    # Item key
    $item->{ key } = "$node->{ moduleID }.$node->{ label }";

    # Map value type (Ignore for OID Table Entry Rows)
    if ($node->{ type }) {
        $item->{ value_type } = $type_map->{ $node->{ type } };
        if (!defined($item->{ value_type })) {
            print STDERR "No type mapping found for type $node->{ type } in $node->{ objectID }\n";
        }
    }

    # Set storage type to Delta for MIB counter types
    if ( $node->{ type } ~~ ['COUNTER', 'COUNTER32', 'COUNTER64']) {
        $item->{ delta } = ZBX_ITEM_STORE_SPEED;

        if ($item->{ units } =~ /^s$/) {
            $item->{ units } = '/sec';
        } elsif ($item->{ units } =~ /^b$/i) {
            $item->{ units } .= 'ps';
        } else {
            $item->{ units } .= '/sec';
        }
    }

    # Translate SNMP Ticks
    if ($node->{ type } eq 'TICKS') {
        $item->{ multiplier } = '1';
        $item->{ formula } = '.01';
        $item->{ units } = 'uptime';
    }

    # Parse item desciption
    $item->{ description } = utf8_sanitize($node->{ description });
    if ($item->{ description }) {
        $item->{ description } =~ s/^\s+|\s+$|\n//g;    # Trim left/right whitespace and newlines
        $item->{ description } =~ s/\s{2,}/ /g;         # Remove padding
    }

    # Process value maps
    if (scalar keys % {$node->{ enums } }) {
        my $map_name = "$node->{ moduleID }::$node->{ label }";

        # If the map_name is longer than 64 characters truncate to 64 characters
        # to match maximum database field length.
        if (length($map_name) > 64) {
            $map_name = substr($map_name,0,61) . "...";
        }

        # add template value map
        $valuemaps->{ $map_name }->{ 'mappings' } = [];
        foreach(keys %{ $node->{ enums } }) {
            push(@{ $valuemaps->{ $map_name }->{ 'mappings' } }, {
                'value'     => $node->{ enums }->{ $_ },
                'newvalue'  => $_
            });
        }

         # Assign value map to item
        $item->{ valuemap } = { name => $map_name };
    }

    return $item;
}

=head2 node_to_trapitem

Parameters  : SNMP::MIB::Node   $node
                  (Hash)            $template
Returns     : (Hash)            $item
Description : Returns a Zabbix SNMP Trap Item hash derived from the
                  specified MIB OID

=cut
sub node_to_trapitem {
    my ($node, $template) = @_;
    $template = $template || \%trap_template;

    # Create item hash
    my $item = { %{ $template } };

    $item->{ name } = "SNMP Trap: $node->{ moduleID }::$node->{ label }";

    # Merge in item defaults
    %{ $item } = (%{ $template }, %{ $item } );

    # Create trap key
    my $oid = $node->{ objectID };
    $oid =~ s/\./\\./g;
    $item->{ key } = "snmptrap[\"\\s$oid\\s\"]";

    # Parse item desciption
    my $desc = '';
    if ($node->{ description }) {
        $desc = $node->{ description };
        $desc =~ s/^\s+|\s+$|\n//g;        # Trim left/right whitespace and newlines
        $desc =~ s/\s{2,}/ /g;          # Remove padding
    }

    # Append varbinds to description
    if (defined($node->{ varbinds }) && scalar @{ $node->{ varbinds } }) {
        my $varcount = scalar @{ $node->{ varbinds } };

        if ($desc ne '') {
            $desc .= "\n\n";
        }

        $desc .= "Varbinds:\n";

        for(my $i = 0; $i < $varcount; $i++) {
            my $varbind_label = $node->{ varbinds }[$i];
            $desc .= "$i. $varbind_label";

            # Try to find OID for each varbind
            my $varbind_path = "$node->{ moduleID }::$varbind_label";
            my $varbind = $SNMP::MIB{ $varbind_path };

            if (defined($varbind)) {
                $desc .= " ($varbind->{ type })\n" if $varbind->{ type };

                if ($varbind->{ description }) {
                    my $vbdesc = $varbind->{ description };
                    $vbdesc =~ s/[ \t]+/ /g;        # Replace long whitespace with single space
                    $vbdesc =~ s/^ ?/      /mg;       # Prepend indent to each description line
                    $desc .= "$vbdesc\n\n";
                }
            } else {
                $desc .= "\n";
            }
        }
    }
    $item->{ description } = $desc;

    return $item;
}

=head2 node_is_current

Parameters  : SNMP::MIB::Node   $node
Returns     : (int)             0|1
Description : Returns true if the specified OID is not obsolete

=cut
sub node_is_current {
    my ($node) = @_;

    return (
        node_is_valid_trap($node)
        || (defined($node->{ status }) && $node->{ status } ne 'Obsolete')
    );
}

=head2 node_is_valid_scalar

Parameters  : SNMP::MIB::Node   $node
Returns     : (int)             0|1
Description : Returns true if the specified OID is current, readable and
                  defines a valid value type.

=cut
sub node_is_valid_scalar {
    my ($node) = @_;

    return (
        node_is_current($node)
        && $node->{ type }
        && (
            $node->{ type } eq 'NOTIF' || $node->{ type } eq 'TRAP'
            || ($node->{ access } eq 'ReadOnly' || $node->{ access } eq 'ReadWrite')
        )

    );
}

=head2 node_is_valid_trap

Parameters  : SNMP::MIB::Node   $node
Returns     : (int)             0|1
Description : Returns true if the specified OID is an SNMP Trap

=cut
sub node_is_valid_trap {
    my ($node) = @_;

    return (
        defined($node->{ type }) && ($node->{ type } eq 'NOTIF' || $node->{ type } eq 'TRAP')
    );
}

=head2 node_is_valid_table

Parameters  : SNMP::MIB::Node   $node
Returns     : (int)             0|1
Description : Returns true if the specified OID is a valid table which is
                  current, readable and contains a single child (row
                  definition)

=cut
sub node_is_valid_table {
    my ($node) = @_;

    # The MIB will define a 'SEQUENCE OF' attribute for tables but
    # SNMP::MIB::NODE does not expose this value. Instead, a table
    # node must be 'NoAccess' and have a single 'NoAccess' child
    return (
        node_is_current($node)

        # Table is NoAccess
        && $node->{ access } eq 'NoAccess'

        # Table has one child (row definition)
        && (scalar @{ $node->{ children } }) == 1

        # Table row is NoAccess
        && $node->{ children }[0]->{ access } eq 'NoAccess'

        # Table row defines atleast one index
        && (scalar @{ $node->{ children }[0]->{ indexes } })
    );
}

=head2 build_template

Parameters  : (hash)            $template
                  SNMP::MIB::NODE   $node
Returns     : (void)
Description : Traverses a loaded MIB tree from the specified OID node
                  a populates a Zabbix Template hash with items, discovery
                  rules, item prototypes, groups and macros.

=cut
sub build_template {
    my ($template, $node) = @_;

    # Ignore obsolete OIDs
    if (node_is_current($node)) {
        # Create an Item Application name for this node
        my $appname = "$node->{ moduleID }::$node->{ parent }->{ label }";

        # Is this a scalar value OID?
        if (node_is_valid_trap($node)) {
            # Convert the SNMP::MIB::Node to a Zabbix Template SNMP Trap Item
            my $item = node_to_trapitem($node);

            # Add item applications to template application list
            $item->{ applications } = [{ name => $appname }];
            $template->{ apptags }->{ $appname } = 1;

            # Add item to template
            push(@{ $template->{ items } }, $item );

            # If the snmptrap has children.
            foreach(@{ $node->{ children } }) {

                # Convert the SNMP::MIB::Node to a Zabbix Template SNMP Trap Item
                my $item = node_to_trapitem($_);

                # Add item applications to template application list
                $item->{ applications } = [{ name => $appname }];
                $template->{ apptags }->{ $appname } = 1;

                # Add item to template
                push(@{ $template->{ items } }, $item );

            }

        } elsif (node_is_valid_scalar($node)) {

            # Convert the SNMP::MIB::Node to a Zabbix Template Item hash
            my $item = node_to_item($node);

            # Append '.0' to normal SNMP OIDS
            $item->{ snmp_oid } = "$item->{ snmp_oid }.0";

            # Add item applications to template application list
            $item->{ applications } = [{ name => $appname }];
            $template->{ apptags }->{ $appname } = 1;

            # Add item to template
            push(@{ $template->{ items } }, $item );

        } elsif (node_is_valid_table($node)) {
            # Get row OID
            my $table = $node;
            my $row = $node->{ children }[0];

            # Validate naming standard
            if ($table->{ label } !~ /Table/) {
                print STDERR "Warning: $table->{ moduleID }:: $table->{ label } appears to be a table but does not have the 'Table' suffix\n";
            }

            if ($row->{ label } !~ /Entry/) {
                print STDERR "Warning: $row->{ moduleID }:: $row->{ label } appears to be a table entry but does not have the 'Entry; suffix\n";
            }

            # This is a table. Build a discovery rule
            my $disc_rule = {};
            $disc_rule = node_to_item($row, \%disc_rule_template);

            # Update discovery rule name
            $disc_rule->{ name } = "$disc_rule->{ name } Discovery";
            $disc_rule->{ snmp_oid } = "discovery[";

            # find any *Descr column
            my $index = '{#SNMPINDEX}';
            foreach my $column(@{ $row->{ children } }) {
                if (node_is_valid_scalar($column)) {
                    if($column->{ label } =~ m/Descr$/) {
                        $disc_rule->{ snmp_oid } .= "{#SNMPVALUE},$column->{ objectID },";
                        $index = '{#SNMPVALUE}';
                    }
                }
            }

            # Define macros in discovery key up to 255 chars
            # See: https://www.zabbix.com/documentation/3.0/manual/discovery/low_level_discovery#discovery_of_snmp_oids
            foreach my $column(@{ $row->{ children } }) {
                if (node_is_valid_scalar($column)) {
                    my $new_snmp_oid = $disc_rule->{ snmp_oid } . "{#" . uc($column->{ label }) . "}," . $column->{ objectID } . ",";
                    if (length($new_snmp_oid) <= 255) {
                        $disc_rule->{ snmp_oid } = $new_snmp_oid;
                    }
                }
            }
            $disc_rule->{ snmp_oid } = substr($disc_rule->{ snmp_oid }, 0, -1) . "]";

            # Fetch an arbitrary column OID for Zabbix to use for discovery
            my $index_oid = $row->{ children }[0];
            if (!defined($index_oid)) {
                print STDERR "No index found for table $table->{ moduleID}::$table->{ label } ($table->{ objectID })\n";
            } else {
                # Remove unrequired fields
                delete($disc_rule->{ applications });
                delete($disc_rule->{ data_type });

                # Create new array for prototypes
                $disc_rule->{ item_prototypes } = [];

                # Add prototypes for each row column
                foreach my $column(@{ $row->{ children } }) {
                    if (node_is_valid_scalar($column)) {
                        if (my $proto = node_to_item($column, \%item_proto_template)) {
                            $proto->{ name } = "$proto->{ name } for $index";
                            $proto->{ key } = "$column->{ label }\[$index]";
                            $proto->{ snmp_oid } = "$proto->{ snmp_oid }.{#SNMPINDEX}";

                            # Add item applications to template application list
                            $proto->{ applications } = [{ name => $appname }];
                            $template->{ apptags }->{ $appname } = 1;

                            push(@{ $disc_rule->{ item_prototypes } }, $proto);
                        }
                    }
                }

                # Add discovery rule to template
                push(@{ $template->{ discovery_rules } }, $disc_rule);
            }
        }
    } else {
        # Parse children
        foreach(@{ $node->{ children } }) {
            build_template($template, $_);
        }
    }
}

# Initialize net-snmp
$SNMP::save_descriptions = 1;
SNMP::initMib();

# Verify the specified OID exists
if ($opts->{ oid } !~ m/^\./) {
    $opts->{ oid } = "." . $opts->{ oid }
}

my $oid_root = $SNMP::MIB{ $opts->{ oid } };
if (!$oid_root || $oid_root->{ objectID } ne $opts->{ oid }) {
    print STDERR "OID $opts->{ oid } not found in MIB tree.\n";
    exit 1;

# Build a Zabbix template
} else {
    my $suffix = $opts->{ snmpver } > 2 ? " v$opts->{ snmpver }" : '';
    my $template_name = $opts->{ name } || "Template SNMP $oid_root->{ moduleID } - $oid_root->{ label }$suffix";
    my $template        = {
        name            => $template_name,
        template        => $template_name,
        description     => "Generated by mib2zabbix",
        apptags         => {},
        applications    => [],
        discovery_rules => [],
        groups          => [{
            name        => $opts->{ group }
        }],
        items           => [],
        macros      => [
            { macro => '{$MIB2ZABBIX_CMD}', value => $cmd },
            { macro => '{$OID}',            value => "$oid_root->{ objectID }" },
            { macro => '{$OID_PATH}',       value => oid_path($oid_root) },
            { macro => '{$OID_MOD}',        value => $oid_root->{ moduleID } },
            { macro => '{$SNMP_PORT}',      value => $opts->{ snmpport } }
        ]
    };

    # Add SNMP connection macros
    if($opts->{ snmpver } < 3) {
        push(@{ $template->{ macros } }, { macro => '{$SNMP_COMMUNITY}', value => $opts->{ snmpcomm } });
    } elsif($opts->{ snmpver } == 3) {
        push(@{ $template->{ macros } }, { macro => '{$SNMP_USER}',      value => $opts->{ v3user } });
        push(@{ $template->{ macros } }, { macro => '{$SNMP_CONTEXT}',   value => $opts->{ v3context } });
        push(@{ $template->{ macros } }, { macro => '{$SNMP_AUTHPASS}',  value => $opts->{ v3auth_pass } });
        push(@{ $template->{ macros } }, { macro => '{$SNMP_PRIVPASS}',  value => $opts->{ v3sec_pass } });
    };
    build_template($template, $oid_root, 0);

    # Convert applications hash to array
    @{ $template->{ applications } } = map { { name => $_ } } keys %{ $template->{ apptags } };
    delete($template->{ apptags });

    # Build XML document
    my $time = time();
    my $output = {
        version     => '3.0',
        date        => time2str("%Y-%m-%dT%H:%M:%SZ", $time),
        groups      => $template->{ groups },
        templates   => [$template],
        triggers    => [],
        graphs      => [],
        value_maps  => [$valuemaps]
    };

    # Output stream
    my $fh = *STDOUT;
    if ($opts->{ filename }) {
        open($fh, ">$opts->{ filename }") or die "$!";
    }

    # Output XML
    XMLout($output,
        OutputFile      => \$fh,
        XMLDecl         => "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
        RootName        => 'zabbix_export',
        NoAttr          => 1,
        SuppressEmpty   => undef,
        GroupTags       => {
            'applications'          => 'application',
            'groups'                => 'group',
            'templates'             => 'template',
            'items'                 => 'item',
            'macros'                => 'macro',
            'discovery_rules'       => 'discovery_rule',
            'item_prototypes'       => 'item_prototype',
            'trigger_prototypes'    => 'trigger_prototype',
            'graph_prototypes'      => 'graph_prototype',
            'host_prototypes'       => 'host_prototype',
            'value_maps'            => %{ $valuemaps } ? 'value_map' : undef,
            'mappings'              => 'mapping'
        }
    );

    if ($opts->{ filename }) {
        close $fh;
    }
}
