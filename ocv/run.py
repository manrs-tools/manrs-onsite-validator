import enum
from typing import Optional
from pybatfish.client.session import Session
from pybatfish.datamodel import BgpRouteConstraints, HeaderConstraints, BgpRoute
from settings import BOGONS_IPV4
import pandas
import logging

logger = logging.getLogger("ocv")
logging.basicConfig(level=logging.WARN, format="%(message)s")
logger.setLevel(logging.INFO)


class PolicyAction(enum.Enum):
    DENY = "deny"
    PERMIT = "permit"

    @staticmethod
    def from_answer(bf_answer):
        if bf_answer.empty:
            return None
        if len(bf_answer) > 1:
            raise Exception(f"Retrieving action from bf policy test resulted in multiple policy matches:\n{bf_answer}")
        action = bf_answer.iloc[0]["Action"]
        return getattr(PolicyAction, action)


def main():
    pandas.set_option("display.max_rows", None)
    bf = prepare_batfish_session()

    BgpFilterValidator(bf).validate(BOGONS_IPV4)


def prepare_batfish_session():
    bf = Session(host="localhost")

    bf.set_network("ocv")
    bf.init_snapshot("snap", name="ocv", overwrite=True)
    # bf.set_snapshot('ocv')
    issues = bf.q.initIssues().answer().frame()
    if not issues.empty:
        logger.info(f"==== Issues in parsing coniguration: ====\n{issues}")
    return bf


class BgpFilterValidator:
    def __init__(self, bf):
        self.bf = bf

        bgp_peers = bf.q.bgpPeerConfiguration().answer().frame()
        logger.info(f"Checking {len(bgp_peers)} BGP peers")
        logger.debug(f"==== BGP PEER LIST ====\n{bgp_peers}")
        # for idx, peer in bgp_peers.iterrows():
        # print(peer)

        # nodes_properties = bf.q.nodeProperties(properties="Routing_Policies").answer().frame()
        # for idx, node_properties in nodes_properties.iterrows():
        #     print(f'Routing policies for node {node_properties["Node"]}: {", ".join(node_properties["Routing_Policies"])}')

    def validate(self, disallowed_prefixes):
        bgp_peers = self.bf.q.bgpPeerConfiguration().answer().frame()

        # TODO: this may not be the nicest way to iterate a DF
        for (
            _,
            bgp_peer,
        ) in bgp_peers.iterrows():
            node, peer_group, remote_ip, node_import_policies = (
                bgp_peer["Node"],
                bgp_peer["Peer_Group"],
                bgp_peer["Remote_IP"],
                bgp_peer["Import_Policy"],
            )
            label = f"{node} {peer_group} {remote_ip}"

            # Policies may appear in three ways:
            # - Composite policy for Juniper, as ~PEER_IMPORT_POLICY:{peer_ip}/32~
            # - Composite policy for Cisco, as ~BGP_PEER_IMPORT_POLICY:default:{peer_ip}~
            # - From the node's Import_Policy - this is the option of last resort
            node_import_policies_spec = ",".join(node_import_policies)
            import_policy_spec = f"/^~(BGP_)?PEER_IMPORT_POLICY(:default)?:{remote_ip}(\/32)?~$/"

            logger.debug(
                f"Checking peer {label} with policy spec {import_policy_spec} + {node_import_policies_spec}..."
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
                logger.info(
                    f"Peer {label}: internal parsing issue, unable to determine policy from spec {import_policy_spec} + {node_import_policies_spec}"
                )
            elif permitted_incorrectly:
                logger.error(
                    f'Peer {label}: import policy permits disallowed prefixes {", ".join(permitted_incorrectly)}'
                )
            else:
                logger.debug(f"Peer {label}: no issues with prefix filter")

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
