#!/usr/bin/env python
import argparse
import enum
import ipaddress
import logging
import textwrap
from typing import Optional

import pandas
from pybatfish.client.session import Session
from pybatfish.datamodel import BgpRoute, HeaderConstraints
from settings import BOGONS_IPV4

logger = logging.getLogger("ocv")
logging.basicConfig(level=logging.WARN, format="%(levelname)s: %(message)s")
logger.setLevel(logging.DEBUG)


class PolicyAction(enum.Enum):
    DENY = "deny"
    PERMIT = "permit"

    @staticmethod
    def from_answer(bf_answer):
        if bf_answer.empty:
            return None
        if len(bf_answer) > 1:
            raise Exception(f"Retrieving action from bf test resulted in multiple policy matches:\n{bf_answer}")
        action = bf_answer.iloc[0]["Action"]
        return getattr(PolicyAction, action)


def main(debug, config_dir, batfish_host):
    if not debug:
        logger.setLevel(logging.INFO)

    pandas.set_option("display.max_rows", None)
    bf = prepare_batfish_session(config_dir, batfish_host)

    logger.info(f"==== Validating traffic filters on interfaces ====")
    TrafficFilterValidator(bf).validate(BOGONS_IPV4)

    logger.info(f"==== Validating prefix filters on BGP sessions ====")
    BgpFilterValidator(bf).validate(BOGONS_IPV4)


def prepare_batfish_session(config_dir, batfish_host):
    bf = Session(host=batfish_host)

    bf.set_network("ocv")
    bf.init_snapshot(config_dir, name="ocv", overwrite=True)
    # bf.set_snapshot("ocv")
    issues = bf.q.initIssues().answer().frame()
    # TODO: clean this output
    if not issues.empty:
        logger.info(f"==== Issues in parsing coniguration: ====\n{issues}")
    return bf


class TrafficFilterValidator:
    def __init__(self, bf):
        self.bf = bf

    def validate(self, disallowed_prefixes):
        self._build_filter_status(disallowed_prefixes)
        self._check_interface_filters()

    def _build_filter_status(self, disallowed_prefixes):
        logger.info(f"Checking traffic filter status for {len(disallowed_prefixes)} prefixes...")
        bogon_ips = [str(ipaddress.ip_network(prefix)[1]) for prefix in disallowed_prefixes]
        self.filters_status = {}
        for bogon_ip in bogon_ips:
            filter_results = (
                self.bf.q.testFilters(headers=HeaderConstraints(srcIps=bogon_ip, applications=["http"]))
                .answer()
                .frame()
            )
            for filter_result in filter_results.itertuples():
                node, filter_name, vrf, action = (
                    filter_result.Node,
                    filter_result.Filter_Name,
                    filter_result.Flow.ingressVrf,
                    getattr(PolicyAction, filter_result.Action),
                )
                self.filters_status.setdefault(node, {}).setdefault(filter_name, []).append((vrf, bogon_ip, action))

    def _check_interface_filters(self):
        interfaces = self.bf.q.interfaceProperties().answer().frame()
        logger.info(f"Checking {len(interfaces)} interfaces for traffic filters...")

        for intf in interfaces.itertuples():
            node, name, descr, prefixes, admin_up, incoming_filter = (
                intf.Interface.hostname,
                intf.Interface.interface,
                getattr(intf, "Description", ""),
                intf.All_Prefixes,
                intf.Admin_Up,
                getattr(intf, "Incoming_Filter_Name", ""),
            )
            if descr:
                descr = textwrap.shorten(descr, width=20, placeholder="...")
            label = f"Interface {node} {name} {descr}"

            if not prefixes or not admin_up:
                logger.debug(f"{label}: ignoring due to admin down or no prefixes:")
                continue

            if incoming_filter:
                filter_status = self.filters_status.get(node, {}).get(incoming_filter, [])
                permitted_incorrectly = [
                    (ip, vrf) for vrf, ip, action in filter_status if action == PolicyAction.PERMIT
                ]
                if permitted_incorrectly:
                    # For brevity, only print the VRF if any non-default VRF filters were found
                    multiple_vrf = any([vrf != "default" for ip, vrf in permitted_incorrectly])
                    permitted_incorrectly_str = [
                        f"{ip} in VRF {vrf}" if multiple_vrf else ip for ip, vrf in permitted_incorrectly
                    ]
                    logger.error(f'{label}: incorrectly permits {", ".join(permitted_incorrectly_str)}')
                else:
                    logger.info(f"{label}: no issues with traffic filter")
            else:
                logger.error(f"{label}: no traffic filter found")


class BgpFilterValidator:
    def __init__(self, bf):
        self.bf = bf

        self.bgp_peers = bf.q.bgpPeerConfiguration().answer().frame()
        logger.info(f"Checking {len(self.bgp_peers)} BGP peers...")

    def validate(self, disallowed_prefixes):
        # For node Import_Policy's, we only consider them if there is only one
        # as for all other cases Batfish will generate a composite policy.
        nodes_import_policies = {
            peer.Import_Policy[0] for peer in self.bgp_peers.itertuples() if len(peer.Import_Policy) == 1
        }
        self._build_policy_status(disallowed_prefixes, nodes_import_policies)

        for bgp_peer in self.bgp_peers.itertuples():
            node, peer_group, remote_ip, node_import_policy = (
                bgp_peer.Node,
                bgp_peer.Peer_Group,
                bgp_peer.Remote_IP,
                bgp_peer.Import_Policy if len(bgp_peer.Import_Policy) == 1 else None,
            )
            label = f"Peer {node} {peer_group} {remote_ip}"

            prefix_actions = self._test_policy(node, remote_ip, node_import_policy)
            if prefix_actions is None:
                permitted_incorrectly = disallowed_prefixes
            else:
                permitted_incorrectly = [
                    prefix for prefix, action in prefix_actions.items() if action == PolicyAction.PERMIT
                ]

            if permitted_incorrectly:
                logger.error(f'{label}: import policy permits disallowed prefixes {", ".join(permitted_incorrectly)}')
            else:
                logger.info(f"{label}: no issues with prefix filter")

    def _test_policy(self, node, peer_ip, node_policy):
        # Policies may appear in three ways:
        # - Composite policy for Juniper, as ~PEER_IMPORT_POLICY:{peer_ip}/32~
        # - Composite policy for Cisco, as ~BGP_PEER_IMPORT_POLICY:default:{peer_ip}~
        # - From the node's Import_Policy - this is the option of last resort
        possible_keys = [f"~PEER_IMPORT_POLICY:{peer_ip}/32~", f"~BGP_PEER_IMPORT_POLICY:default:{peer_ip}~"]
        if node_policy:
            possible_keys.append(node_policy)

        for key in possible_keys:
            try:
                return self.policies_statuses[node][key]
            except KeyError:
                continue
        return None

    def _build_policy_status(self, disallowed_prefixes, nodes_import_policies):
        logger.info(f"Checking traffic filter status for {len(disallowed_prefixes)} prefixes...")
        self.policies_statuses = {}

        policy_spec = f"/^(~(BGP_)?PEER_IMPORT_POLICY(:default)?:[\d:\.]+(\/32)?~|{'|'.join(nodes_import_policies)})$/"

        for prefix in disallowed_prefixes:
            routes = [
                BgpRoute(
                    network=prefix,
                    originatorIp="192.0.2.0",
                    originType="egp",
                    protocol="bgp",
                )
            ]

            policy_results = (
                self.bf.q.testRoutePolicies(policies=policy_spec, direction="in", inputRoutes=routes).answer().frame()
            )
            for policy_result in policy_results.itertuples():
                node, policy_name, action = (
                    policy_result.Node,
                    policy_result.Policy_Name,
                    getattr(PolicyAction, policy_result.Action),
                )
                action = getattr(PolicyAction, policy_result.Action)
                self.policies_statuses.setdefault(node, {}).setdefault(policy_name, {})[prefix] = action


if __name__ == "__main__":
    description = """Validate interface traffic filters and BGP peers."""
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "config_dir",
        help="path to the config directory - files should be in " 'a subdirectory called "configs" on this path',
    )
    parser.add_argument(
        "--batfish_host",
        default="localhost",
        help="host where the Batish service is listening",
    )
    parser.add_argument("-d", dest="debug", action="store_true", help=f"enable debug logs")
    args = parser.parse_args()

    main(args.debug, args.config_dir, args.batfish_host)
