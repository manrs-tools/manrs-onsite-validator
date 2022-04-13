import enum
from typing import Optional
from pybatfish.client.session import Session
from pybatfish.datamodel import BgpRouteConstraints, HeaderConstraints, BgpRoute
from settings import BOGONS_IPV4
import pandas
import logging
import textwrap

logger = logging.getLogger("ocv")
logging.basicConfig(level=logging.WARN, format="%(levelname)s: %(message)s")
logger.setLevel(logging.INFO)


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


def main():
    pandas.set_option("display.max_rows", None)
    bf = prepare_batfish_session()
    # BgpFilterValidator(bf).validate(BOGONS_IPV4)
    
    logger.info(f"Checking traffic filter status for {len(BOGONS_IPV4)} prefixes...")

    bogon_ips = [prefix.split('/')[0] + '1' for prefix in BOGONS_IPV4]
    filters_status = {}
    for bogon_ip in bogon_ips:
        filter_results = bf.q.testFilters(headers=HeaderConstraints(srcIps=bogon_ip, applications = ['http'])).answer().frame()
        for _, filter_result in filter_results.iterrows():
            node, filter_name, vrf, action = filter_result['Node'], filter_result['Filter_Name'], filter_result['Flow'].ingressVrf, getattr(PolicyAction, filter_result['Action'])
            filters_status.setdefault(node, {}).setdefault(filter_name, []).append((vrf, bogon_ip, action))
            
    interfaces = bf.q.interfaceProperties().answer().frame()
    logger.info(f"Checking {len(interfaces)} interfaces for traffic filters...")
    for _, intf in interfaces.iterrows():
        node, name, descr, incoming_filter = (
            intf['Interface'].hostname,
            intf['Interface'].interface,
            intf.get('Description', ''),
            intf.get('Incoming_Filter_Name'),
        )
        if descr:
            descr = textwrap.shorten(descr, width=15, placeholder='...')
        label = f"Interface {node} {name} {descr}"
        if incoming_filter:
            filter_status = filters_status.get(node, {}).get(incoming_filter, [])
            permitted_incorrectly = [(ip, vrf) for vrf, ip, action in filter_status if action ==PolicyAction.PERMIT]
            if permitted_incorrectly:
                multiple_vrf = any([vrf != 'default' for ip, vrf in permitted_incorrectly])
                permitted_incorrectly_str = [f'{ip} in VRF {vrf}' if multiple_vrf else ip for ip, vrf in permitted_incorrectly]
                logger.error(f'{label}: incorrectly permits {", ".join(permitted_incorrectly_str)}')
            else:
                logger.info(f"{label}: no issues with traffic filter")
        else:
            logger.error(f"{label}: no traffic filter found")


def prepare_batfish_session():
    bf = Session(host="localhost")

    bf.set_network("ocv")
    # TODO: revert to normal init_snapshot
    # bf.init_snapshot("snap", name="ocv", overwrite=True)
    bf.set_snapshot('ocv')
    # issues = bf.q.initIssues().answer().frame()
    # if not issues.empty:
    #     logger.info(f"==== Issues in parsing coniguration: ====\n{issues}")
    return bf


class BgpFilterValidator:
    def __init__(self, bf):
        self.bf = bf

        bgp_peers = bf.q.bgpPeerConfiguration().answer().frame()
        logger.info(f"Checking {len(bgp_peers)} BGP peers...")
        # logger.debug(f"==== BGP PEER LIST ====\n{bgp_peers}")
        # for idx, peer in bgp_peers.iterrows():
        # print(peer)

        # nodes_properties = bf.q.nodeProperties(properties="Routing_Policies").answer().frame()
        # for idx, node_properties in nodes_properties.iterrows():
        #     print(f'Routing policies for node {node_properties["Node"]}: {", ".join(node_properties["Routing_Policies"])}')

    def validate(self, disallowed_prefixes):
        bgp_peers = self.bf.q.bgpPeerConfiguration().answer().frame()

        # TODO: this may not be the nicest way to iterate a DF
        for _, bgp_peer in bgp_peers.iterrows():
            node, peer_group, remote_ip, node_import_policies = (
                bgp_peer["Node"],
                bgp_peer["Peer_Group"],
                bgp_peer["Remote_IP"],
                bgp_peer["Import_Policy"],
            )
            label = f"Peer {node} {peer_group} {remote_ip}"

            # Policies may appear in three ways:
            # - Composite policy for Juniper, as ~PEER_IMPORT_POLICY:{peer_ip}/32~
            # - Composite policy for Cisco, as ~BGP_PEER_IMPORT_POLICY:default:{peer_ip}~
            # - From the node's Import_Policy - this is the option of last resort
            import_policy_spec = f"/^~(BGP_)?PEER_IMPORT_POLICY(:default)?:{remote_ip}(\/32)?~$/"
            node_import_policies_spec = ",".join(node_import_policies)

            logger.debug(
                f"{label} checking with policy spec {import_policy_spec} + {node_import_policies_spec}..."
            )

            # print(f'===== BGP PEER: {node} {peer_group} {remote_ip} =====')
            # print(f'Policy spec {import_policy_spec}, fallback {node_import_policies_spec}')

            # rp = test_policy(bf, node, import_policy_spec, node_import_policies_spec, '10.0.0.0/24')
            # for _, r in rp.iterrows():
            #     print(r)
            #     print(r['Trace'])

            prefix_actions = {
                prefix: PolicyAction.from_answer(
                    self.test_policy(node, import_policy_spec, node_import_policies_spec, prefix)
                )
                for prefix in disallowed_prefixes
            }

            permitted_incorrectly = [
                prefix for prefix, action in prefix_actions.items() if action == PolicyAction.PERMIT
            ]

            if not prefix_actions:
                logger.error(
                    f"{label}: internal parsing issue, unable to determine policy from spec {import_policy_spec} + {node_import_policies_spec}"
                )
            elif permitted_incorrectly:
                logger.error(
                    f'{label}: import policy permits disallowed prefixes {", ".join(permitted_incorrectly)}'
                )
            else:
                logger.info(f"{label}: no issues with prefix filter")

    def test_policy(self, node, policy_spec, node_policy_spec, prefix):
        # TODO: this is a bit slow, probably should load this in bulk and then extract details? Depends on policy questions.
        routes = [
            BgpRoute(
                network=prefix,
                originatorIp="192.0.2.0",
                originType="egp",
                protocol="bgp",
            )
        ]
        answer = (
            self.bf.q.testRoutePolicies(nodes=node, policies=policy_spec, direction="in", inputRoutes=routes)
            .answer()
            .frame()
        )
        if answer.empty and node_policy_spec:
            return (
                self.bf.q.testRoutePolicies(
                    nodes=node,
                    policies=node_policy_spec,
                    direction="in",
                    inputRoutes=routes,
                )
                .answer()
                .frame()
            )
        return answer


if __name__ == "__main__":
    main()
