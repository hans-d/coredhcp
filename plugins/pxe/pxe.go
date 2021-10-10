// Copyright 2021-present Hans Donner. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package pxe implements handling of a PXE client. For the TFTP part
// use the nbp plugin.

// server4:
//   - plugins:
//     - nbp: tftp://10.0.0.254/nbp
//     - pxe

// Background information:
// dnsmasq
// https://thekelleys.org.uk/gitweb/?p=dnsmasq.git;a=blob;f=src/dhcp-protocol.h;h=6ff3ffa23758e7a37f653df4105e3cc385c438d1;hb=HEAD
// - PXE_PORT                4011
// - SUBOPT_PXE_BOOT_ITEM    71
//   SUBOPT_PXE_DISCOVERY    6
//   SUBOPT_PXE_SERVERS      8
//   SUBOPT_PXE_MENU         9
//   SUBOPT_PXE_MENU_PROMPT  10
// https://thekelleys.org.uk/gitweb/?p=dnsmasq.git;a=blob;f=src/dnsmasq.h;h=3fdc1b0e1d98ec8c22a01d34e2291d9a1431aeb3;hb=HEAD
// - DHOPT_VENDOR_PXE        16384
//   DHCP_PXE_DEF_VENDOR     "PXEClient"

// https://thekelleys.org.uk/gitweb/?p=dnsmasq.git;a=blob;f=src/rfc2131.c;h=c902eb70cae5bf00aa2b3f9e972e3c052eb649fc;hb=HEAD
// - if ((mess_type == DHCPREQUEST || mess_type == DHCPINFORM) &&
//   (opt = option_find(mess, sz, OPTION_VENDOR_CLASS_OPT, 1)) &&
//   (opt = option_find1(option_ptr(opt, 0), option_ptr(opt, option_len(opt)), SUBOPT_PXE_BOOT_ITEM, 4)))
//   - if (layer & 0x8000) my_syslog(MS_DHCP | LOG_ERR, _("PXE BIS not supported"));
//   - memcpy(save71, option_ptr(opt, 0), 4);
//   - for (service = daemon->pxe_services; service; service = service->next) if (service->type == type) break;
//   - if (service->sname) mess->siaddr = a_record_from_hosts(service->sname, now);
// - /* Disable multicast, since we don't support it, and broadcast unless we need it */
//   discovery_control = 3;

// https://datatracker.ietf.org/doc/rfc2119/
// https://www.rfc-editor.org/rfc/rfc2119

// Henry, M. and M. Johnston, "Preboot Execution Environment (PXE) Specification", September 1999
// http://www.pix.net/software/pxeboot/archive/pxespec.pdf
// https://web.archive.org/web/20110524083740/http://download.intel.com/design/archives/wfm/downloads/pxespec.pdf

// Intel Preboot Execution Environment [Expired]
// https://datatracker.ietf.org/doc/draft-henry-remote-boot-protocol/
// - 3.1.1 DHCPDISCOVER
//   The PXE client's DHCPDISCOVER packet MUST include:
//   - Client Machine Identifier - UUID (DHCP Option#61).
//   - PXE Client Class Identifier (DHCP option #60 - "PXEClient:Arch:xxxxx:UNDI:yyyzzz")
// - 3.1.2 DHCPOFFER
//   The DHCPOFFER includes encapsulated PXEW client vendor options in Option $43 that provide:
//   - A ASCII list of available bootservers
//   - A header prompt for the ASCII bootserver list
//   - A timeout value in seconds
//   - A list of bootserver types and their IP addresses.
//   - An option [...] whether bootservers are to be discovered by a broadcast, multicast or a unicast discovery method.
//   - A multicast discovery address [...] if the multicast discovery option is enabled
// - 3.2.1 PXE Class Identifier - Option 60
//   60 | len(1) = 32 | "PXEClient:Arch:" | architecture(5) | ":UNDI:" | major(3) | minor(3)
// - 3.2.3 PXE Vendor specific information - Option 43
// - 3.2.3.1 PXE_DISCOVERY_CONTROL
//   6 | len(1) = 1 | control(1)
//     bit 0 is the least significant bit
//     Bit 0 - If set, broadcast discovery of servers is NOT allowed.
//     Bit 1 - If set, multicast discovery of servers is NOT allowed.
//     Bit 2 - If set, only use and/or accept replies from servers in the list defined by PXE_BOOT_SERVERS tag
// - 3.2.3.2 DISCOVERY_MCAST_ADDR
//   7 | len(1) = 4 | ipv4(4)
// - 3.2.3.3 PXE_BOOT_SERVERS
//   8 | len(1) | repeated[]: type(2) | count(1) | ipv4(4)[count]
// - 3.2.3.4 PXE_BOOT_MENU
//   9 | len(1) | repeated[]: type(2) | len(1) | chars[len]
// - 3.2.3.5 PXE_MENU_PROMPT
//   10 | len(1) | timeout(1) | chars[]
// - 3.2.3.6 PXE_BOOT_ITEM
//   71 | len(1) = 4 | type(2) | layer(2)
//     layer: MSBit  0 = bootfile
//                   1 = credentials
//                     when [...] DHCPREQUEST [...] MUST also include  PXE_CREDENTIAL_TYPES option
// - 3.2.3.7 PXE_CREDENTIAL_TYPES
//   12 | len(1) | type(4) ---- ref7
//
// PXE_END                255  None


// Intel Corp., "Extensible Firmware Interface Specification", December 2002
// http://developer.intel.com/technology/efi/main_specification.htm
// https://www.intel.de/content/dam/doc/product-specification/efi-v1-10-specification.pdf

// TFTP Protocol (revision 2)
// https://datatracker.ietf.org/doc/rfc783/
// https://www.rfc-editor.org/rfc/rfc783

// 951
// rfc1350

// BOOTP Vendor Information Extensions
// https://datatracker.ietf.org/doc/html/rfc1497

// Dynamic Host Configuration Protocol
// https://datatracker.ietf.org/doc/rfc2131/
// https://www.rfc-editor.org/rfc/rfc2131

// DHCP Options and BOOTP Vendor Extensions
// https://datatracker.ietf.org/doc/rfc2132/
// https://www.rfc-editor.org/rfc/rfc2132
// - 8.4. Vendor Specific Information
//   43 | len(1) | encoded(n): code(1) | len(1) | data(n)
//   - the vendor SHOULD encode the option using "Encapsulated vendor-specific options"
//     - SHOULD be encoded as a sequence of code/length/value fields
//     - Code 255 (END), if present, signifies the end of the encapsulated vendor extensions, not the end of the vendor extensions field.
// - 9.4 TFTP server name
//   66 | len(1) | string[len]
// - 9.5 Bootfile name
//   67 | len(1) | string[len]
// - 9.13. Vendor class identifier
//   60 | len(1) | string[len]

// Procedures and IANA Guidelines for Definition of New DHCP Options and Message Types
// https://www.rfc-editor.org/rfc/rfc2939

// Reclassifying Dynamic Host Configuration Protocol version 4 (DHCPv4) Options
// https://www.rfc-editor.org/rfc/rfc3942

// Dynamic Host Configuration Protocol (DHCP) Options for the Intel Preboot eXecution Environment (PXE)
// https://www.rfc-editor.org/rfc/rfc4578
// - Client System Architecture Type Option Definition
//   93 | len(1) = 2 | type(2)
// - Client Network Interface Identifier Option Definition
//   94 | len(1) = 3 | type(1) = 1 | major(1) | minor(1)
// - Client Machine Identifier Option Definition
//   97 | len(1) = 17 | type(1) = 0 | uuid(16)
// - Options Requested by PXE Clients
//   All compliant PXE clients MUST include a request for DHCP options 128 through 135
//   These options MAY be present in the DHCP and PXE boot server replies
//   As options 128-135 are not officially assigned for PXE [...] may conflict with other uses [...]

// Dynamic Host Configuration Protocol (DHCP) and Bootstrap Protocol (BOOTP) Parameters
// https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml

package pxe


import (
	"strings"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
	"github.com/insomniacslk/dhcp/dhcpv4"
)

var log = logger.GetLogger("plugins/pxe")

// Plugin wraps plugin registration information
var Plugin = plugins.Plugin{
	Name:   "pxe",
	Setup4: setup4,
}

var (
	opt43, opt60 *dhcpv4.Option
)


func setup4(args ...string) (handler.Handler4, error) {
	oci := dhcpv4.OptClassIdentifier("PXEClient")
	opt60 = &oci

	pxe_opt6 := []byte{6, 1, 8} // PXE_DISCOVERY
	pxe_opt255 := []byte{255}   // PXE_END

	ovsi := dhcpv4.OptGeneric(dhcpv4.OptionVendorSpecificInformation, append(pxe_opt6[:], pxe_opt255[:]...))
	opt43 = &ovsi

	log.Printf("loaded PXE plugin for DHCPv4.")
	return pxeHandler4, nil
}

func pxeHandler4(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	// needs to be pxe request
	if !(len(req.ClassIdentifier()) == 32 && strings.HasPrefix(req.ClassIdentifier(), "PXEClient")) {
		return resp, false
	}

	// req must have specific options
	cmi := req.GetOneOption(dhcpv4.OptionClientMachineIdentifier)
	if len(cmi) != 17 {
		return resp, false
	}

	resp.Options.Update(*opt60) // PXEClient
	resp.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionClientMachineIdentifier, cmi)) // Duplicate
	resp.UpdateOption(*opt43) // PXE options


	log.Debugf("Added PXE options to request")
	return resp, false
}
