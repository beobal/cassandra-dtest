from dtest import Tester
from time import sleep

import pytest

since = pytest.mark.since

class TestGossiper(Tester):
    """
    Test gossip states
    """

    @since('3.11.2')
    def test_startup_no_live_seeds(self):
        """
        Test that a node won't start with no live seeds.
        @jira_ticket CASSANDRA-13851
        """

        self.fixture_dtest_setup.allow_log_errors = True
        n1 = self.cluster.create_node('node1', True, None, ('127.0.0.1', 7000), '7100',
                                      None, None, binary_interface=('127.0.0.1', 9042))
        self.cluster.add(n1, False)
        node1 = self.cluster.nodelist()[0]
        self.cluster.set_configuration_options({
            'seed_provider': [{'class_name': 'org.apache.cassandra.locator.SimpleSeedProvider',
                               'parameters': [{'seeds': '127.0.0.2'}]  # dummy node doesn't exist
                               }]
            })

        node1.start(wait_other_notice=False)
        self.assert_log_had_msg(node1, "Unable to gossip with any peers", timeout=120)

    @since('3.11.2')
    @pytest.mark.resource_intensive
    def test_startup_non_seed_with_peers(self):
        """
        Test that a node can start if peers are alive, or if a node has been bootstrapped
        but there are no live seeds or peers
        @jira_ticket CASSANDRA-13851
        """

        self.fixture_dtest_setup.allow_log_errors = True
        n1 = self.cluster.create_node('node1', True, None, ('127.0.0.1', 7000), '7100',
                                      None, None, binary_interface=('127.0.0.1', 9042))
        n2 = self.cluster.create_node('node2', True, None, ('127.0.0.2', 7000), '7101',
                                      None, None, binary_interface=('127.0.0.2', 9042))
        n3 = self.cluster.create_node('node3', True, None, ('127.0.0.3', 7000), '7102',
                                      None, None, binary_interface=('127.0.0.3', 9042))
        self.cluster.add(n1, True)
        self.cluster.add(n2, True)
        self.cluster.add(n3, True)

        node1, node2, node3 = self.cluster.nodelist()

        self.cluster.start()
        node3.stop(wait=True)
        node1.stop(wait=True)
        self.cluster.set_configuration_options({
            'seed_provider': [{'class_name': 'org.apache.cassandra.locator.SimpleSeedProvider',
                               'parameters': [{'seeds': '127.0.0.1'}]
                               }]
            })

        # test non seed node can start when peer is started but seed isn't
        node3.start(wait_other_notice=False, wait_for_binary_proto=120)
        self.assert_log_had_msg(node3, "Received an ack from /{}, who isn't a seed. Ensure your seed list includes a live node. Exiting shadow round".format(node2.address()), timeout=60)
        node2.stop(wait=False)
        node3.stop(wait=True)

        # test seed node starts when no other nodes started
        node1.start(wait_other_notice=False, wait_for_binary_proto=120)
        self.assert_log_had_msg(node1, 'Unable to gossip with any peers but continuing anyway since node is in its own seed list', timeout=60)

    @since('3.11.2')
    def test_startup_after_ring_delay(self):
        """
        Tests that if we start a node with no live seeds, then start a seed after RING_DELAY
        we will still join the ring. More broadly tests that starting a seed while a node is in
        shadow round will still allow that node to join the ring.
        @jira_ticket CASSANDRA-13851
        """
        RING_DELAY=15000 #ms
        self.fixture_dtest_setup.allow_log_errors = True
        n1 = self.cluster.create_node('node1', True, None, ('127.0.0.1', 7000), '7100',
                                    None, None, binary_interface=('127.0.0.1', 9042))
        n2 = self.cluster.create_node('node2', True, None, ('127.0.0.2', 7000), '7101',
                                    None, None, binary_interface=('127.0.0.2', 9042))
        self.cluster.add(n1, True)
        self.cluster.add(n2, False)
        node1, node2 = self.cluster.nodelist()

        node2.start(wait_other_notice=False, jvm_args=['-Dcassandra.ring_delay_ms={}'.format(RING_DELAY)])
        node2.watch_log_for('Starting shadow gossip round to check for endpoint collision', filename='debug.log')
        sleep(RING_DELAY / 1000)
        # Start seed, ensure node2 joins before it exits shadow round.
        node1.start(wait_other_notice=True, wait_for_binary_proto=120)
        self.assert_log_had_msg(node2, 'Starting listening for CQL clients', timeout=60)
