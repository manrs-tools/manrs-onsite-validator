import enum
from typing import Optional
from pybatfish.client.session import Session
from pybatfish.datamodel import BgpRouteConstraints, HeaderConstraints, BgpRoute
from settings import BOGONS_IPV4
import pandas



class PolicyAction(enum.Enum):
    DENY = 'deny'
    PERMIT = 'permit'


def main():
    pandas.set_option('display.max_rows', None)

    bf = prepare_batfish_session()
    bgp_peers = bf.q.bgpPeerConfiguration().answer().frame()
    print(f'==== BGP PEER LIST ====\n{bgp_peers}')
    # for idx, peer in bgp_peers.iterrows():
    #     print(peer)
        
    # nodes_properties = bf.q.nodeProperties(properties="Routing_Policies").answer().frame()
    # for idx, node_properties in nodes_properties.iterrows():
    #     print(f'Routing policies for node {node_properties["Node"]}: {", ".join(node_properties["Routing_Policies"])}')

    for _, bgp_peer in bgp_peers.iterrows():
        node, peer_group, remote_ip, node_import_policies = bgp_peer['Node'], bgp_peer['Peer_Group'], bgp_peer['Remote_IP'], bgp_peer['Import_Policy']

        # Policies may appear in three ways:
        # - Composite policy for Juniper, as ~PEER_IMPORT_POLICY:{peer_ip}/32~
        # - Composite policy for Cisco, as ~BGP_PEER_IMPORT_POLICY:default:{peer_ip}~
        # - From the node's Import_Policy - this is the option of last resort
        node_import_policies_spec = ','.join(node_import_policies)
        import_policy_spec = f'/^~(BGP_)?PEER_IMPORT_POLICY(:default)?:{remote_ip}(\/32)?~$/'

        # print(f'===== BGP PEER: {node} {peer_group} {remote_ip} =====')
        # print(f'Policy spec {import_policy_spec}, fallback {node_import_policies_spec}')

        # rp_not_bogon = test_policy(bf, node, import_policy_spec, node_import_policies_spec, '3.0.0.0/24')
        # rp_bogon = test_policy(bf, node, import_policy_spec, node_import_policies_spec, '10.0.0.0/24')

        # print('Policy for bogon ->')
        # for _, r in rp_bogon.iterrows():
        #     print(r)
        #     print(r['Trace'])

        # print('Policy for not bogon ->')
        # for _, r in rp_not_bogon.iterrows():
        #     print(r)
        #     print(r['Trace'])
        
        bogon_actions = {
            prefix:
            get_policy_action(test_policy(bf, node, import_policy_spec, node_import_policies_spec, prefix))
            for prefix in BOGONS_IPV4
        }
        
        permitted_bogons = [
            prefix
            for prefix, action in bogon_actions.items()
            if action == PolicyAction.PERMIT
        ]
        
        if not bogon_actions:
            print(f'Peer {node} {peer_group} {remote_ip}: internal parsing issue, unable to determine policy from spec {import_policy_spec} / {node_import_policies_spec}')
        if permitted_bogons:
            print(f'Peer {node} {peer_group} {remote_ip}: import policy permits bogon prefixes {", ".join(permitted_bogons)}')
        # print(f'Policy not bogon {get_policy_action(rp_bogon)}, bogon {get_policy_action(rp_not_bogon)}')


def prepare_batfish_session():
    bf = Session(host="localhost")

    bf.set_network('ocv')
    bf.init_snapshot('snap', name='ocv', overwrite=True)
    # bf.set_snapshot('ocv')
    print(bf.q.initIssues().answer().frame())
    return bf


def test_policy(bf, node, policy_spec, node_policy_spec, prefix):
    # TODO: this is a bit slow, probably should load this in bulk and then extract details? Depends on policy questions.
    routes = [BgpRoute(network=prefix, originatorIp='192.0.2.0', originType='egp', protocol='bgp')]
    policy_answer = bf.q.testRoutePolicies(nodes=node, policies=policy_spec, direction='in', inputRoutes=routes).answer().frame()
    if not policy_answer.empty or not node_policy_spec:
        return policy_answer
    return bf.q.testRoutePolicies(nodes=node, policies=node_policy_spec, direction='in', inputRoutes=routes).answer().frame()

    
def get_policy_action(bf_answer) -> Optional[PolicyAction]:
    if bf_answer.empty:
        return None
    if len(bf_answer) > 1:
        raise Exception(f'Retrieving action from bf policy test resulted in multiple policy matches:\n{bf_answer}')
    action = bf_answer.iloc[0]["Action"]
    return getattr(PolicyAction, action)
    

if __name__ == '__main__':
    main()
