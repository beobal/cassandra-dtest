import time
import pytest
import logging

from tools.assertions import (assert_all, assert_invalid, assert_one, assert_none,
                              assert_unauthorized, assert_unauthorized_statement)
from cassandra import ConsistencyLevel, consistency_value_to_name, Unauthorized
from cassandra.protocol import SyntaxException
from cassandra.query import SimpleStatement, BatchStatement, BatchType, TraceUnavailable
from dtest import Tester

since = pytest.mark.since
logger = logging.getLogger(__name__)

logging.getLogger("cassandra").setLevel("WARN")
logging.getLogger("dtest_setup").setLevel("WARN")

def capabilities_as_list(capabilities):
    return ", ".join(["<{c}>".format(c=cap) for cap in capabilities])


def format_resource_name(name):
    return "<{l} {n}>".format(l="table" if "." in name else "keyspace", n=name)


def consistency_as_capability(cl, for_write=False):
    return "system.cl_{c}_{rw}".format(c=consistency_value_to_name(cl), rw="WRITE" if for_write else "READ").lower()


def statement(cql, options=None):
    if options is None: options = {}
    return SimpleStatement(cql, **options)


def error_msg(role, resource, capabilities_list):
    template = "Role {role} or one of its granted roles has restrictions on one " \
               "or more capabilities required for this operation which apply " \
               "to {resource} or one of its parents. Required but restricted " \
               "capabilities : {cap_list}"
    return template.format(role=role, resource=format_resource_name(resource), cap_list=capabilities_list)


def create_role(admin, role):
        admin.execute("CREATE ROLE {role} WITH LOGIN=true AND PASSWORD = 'pass'".format(role=role))


@since('3.10')
class TestCapabilityRestrictions(Tester):

    role_counter = 0

    def next_role(self):
        self.role_counter += 1
        return "role{c}".format(c=self.role_counter)

    def test_permissions_for_list_restrictions(self):
        """
        Assert that a logged in user can only list restrictions for roles which they
        have been granted. Unless they have been granted DESCRIBE permission on all
        roles (or are a superuser) in which case they can list any restrictions
        """
        self.prepare(nodes=1, authorizer='CassandraAuthorizer')
        admin = self.get_session(user='cassandra', password='cassandra')
        role1 = self.next_role()
        role2 = self.next_role()
        create_role(admin, role1)
        create_role(admin, role2)
        admin.execute("CREATE KEYSPACE ks WITH replication = {'class':'SimpleStrategy', 'replication_factor':1}")
        admin.execute("CREATE TABLE ks.t1 (k int PRIMARY KEY, v int)")
        admin.execute("CREATE RESTRICTION ON {role1} USING filtering WITH ks.t1".format(role1=role1))

        # role1 can list its own restrictions
        list_one_statement = "LIST RESTRICTIONS ON {role1}".format(role1=role1)
        session1 = self.get_session(role1)
        assert_one(session1, list_one_statement, list([role1, '<table ks.t1>', 'system.filtering']))
        # role2 cannot see restrictions for role1
        session2 = self.get_session(role2)
        assert_unauthorized(session2, list_one_statement,
                            "User {role2} is not authorized to view capability restrictions on {role1}".format(role1=role1, role2=role2))
        # unless role2 is granted role1
        admin.execute("GRANT {role1} TO {role2}".format(role1=role1, role2=role2))
        all_restrictions = list([role1, '<table ks.t1>', 'system.filtering'])
        assert_one(session2, list_one_statement, all_restrictions)

        # listing all restrictions requires DESCRIBE on ALL ROLES
        msg = "User {role1} is not authorized to view capability restrictions on all roles".format(role1=role1)
        assert_unauthorized(session1, "LIST RESTRICTIONS", msg)
        assert_unauthorized(session1, "LIST RESTRICTIONS ON ANY ROLE USING ANY CAPABILITY WITH ANY RESOURCE", msg)
        assert_unauthorized(session1, "LIST RESTRICTIONS ON ANY ROLE USING ANY CAPABILITY WITH ks.t1", msg)
        assert_unauthorized(session1, "LIST RESTRICTIONS ON ANY ROLE USING filtering WITH ks.t1", msg)

        admin.execute("GRANT DESCRIBE ON ALL ROLES TO {role1}".format(role1=role1))
        assert_one(session1, "LIST RESTRICTIONS", all_restrictions)
        assert_one(session1, "LIST RESTRICTIONS ON ANY ROLE USING ANY CAPABILITY WITH ANY RESOURCE", all_restrictions)
        assert_one(session1, "LIST RESTRICTIONS ON ANY ROLE USING ANY CAPABILITY WITH ks.t1", all_restrictions)
        assert_one(session1, "LIST RESTRICTIONS ON ANY ROLE USING filtering WITH ks.t1", all_restrictions)

    def test_permissions_for_create_and_drop(self):
        """
        Assert that the necessary permissions checks are carried out for CREATE &
        DROP RESTRICTION statements
        """
        self.prepare(nodes=1, authorizer='CassandraAuthorizer')
        role1 = self.next_role()
        role2 = self.next_role()
        role3 = self.next_role()

        admin = self.get_session(user='cassandra', password='cassandra')
        create_role(admin, role1)
        create_role(admin, role2)
        create_role(admin, role3)

        admin.execute("CREATE KEYSPACE ks WITH replication = {'class':'SimpleStrategy', 'replication_factor':1}")
        admin.execute("CREATE TABLE ks.t1 (k int PRIMARY KEY, v int)")

        session1 = self.get_session(role1)
        msg = "User {role} does not have sufficient privileges to perform the requested operation".format(role=role1)
        assert_unauthorized(session1, "CREATE RESTRICTION ON {role2} USING filtering WITH ks.t1".format(role2=role2), msg)
        # To be able to execute CREATE RESTRICTION ON role2 USING filtering WITH ks.t1
        # role1 must have AUTHORIZE permission on both role2 and ks.t1
        assert_unauthorized(session1, "CREATE RESTRICTION ON {role2} USING filtering WITH ks.t1".format(role2=role2), msg)
        admin.execute("GRANT AUTHORIZE ON ROLE {role2} TO {role1}".format(role1=role1, role2=role2))
        assert_unauthorized(session1, "CREATE RESTRICTION ON {role2} USING filtering WITH ks.t1".format(role2=role2), msg)
        admin.execute("GRANT AUTHORIZE ON ks.t1 TO {role1}".format(role1=role1, role2=role2))
        session1.execute("CREATE RESTRICTION ON {role2} USING filtering WITH ks.t1".format(role2=role2))

        # the same applies to DROP RESTRICTION
        msg = "User {role} does not have sufficient privileges to perform the requested operation".format(role=role3)
        session3 = self.get_session(role3)
        assert_unauthorized(session3, "DROP RESTRICTION ON {role2} USING filtering WITH ks.t1".format(role2=role2), msg)
        # as usual, necessary permissions can be acquired through role grants
        admin.execute("GRANT {role1} TO {role3}".format(role1=role1, role3=role3))
        session3.execute("DROP RESTRICTION ON {role2} USING filtering WITH ks.t1".format(role2=role2))

    def test_capabilities_not_valid_with_resource(self):
        """
        Verify that the combination of capability and resource in a CREATE RESTRICTION
        statement is valid. Of the default IResource implementations, only DataResource
        can currently be used in restrictions.
        Custom Capability and IResource implementations are not covered here, but there
        are unit tests which exercise them.
        """
        self.prepare(nodes=1)
        admin = self.get_session(user='cassandra', password='cassandra')
        role = self.next_role()
        other_role = self.next_role()
        create_role(admin, role)
        create_role(admin, other_role)

        assert_invalid(admin,
                       "CREATE RESTRICTION ON {r1} USING system.cl_one_read WITH ROLE {r2}".format(r1=role, r2=other_role),
                       "<system.cl_one_read> cannot be used in restrictions with <role {r2}>".format(r2=other_role))
        assert_invalid(admin,
                       """
                       CREATE RESTRICTION ON {role}
                       USING system.filtering
                       WITH MBEAN 'org.apache.cassandra.net:type=FailureDetector'""".format(role=role),
                       "<system.filtering> cannot be used in restrictions with <mbean org.apache.cassandra.net:type=FailureDetector>")
        assert_invalid(admin,
                       "CREATE RESTRICTION ON {role} USING system.lwt WITH FUNCTION system.avg(int)".format(role=role),
                       "<system.lwt> cannot be used in restrictions with <function system.avg\(int\)>")

    def test_unknown_capabilities(self):
        """
        Verify that only registered capabilities can be used in CREATE/DROP restrictions
        statements. Only system capabilities are included in the build, so unfortunately
        this test is a bit limited in scope. We could bundle a jar containing some custom
        test capabilities with dtests, but we would need to modify ccm to enable us to
        deploy those by copying the jar to the cluster's lib directory before starting it
        """
        self.prepare(nodes=1)
        admin = self.get_session(user='cassandra', password='cassandra')
        role = self.next_role()
        create_role(admin, role)
        admin.execute("CREATE KEYSPACE ks WITH replication = {'class':'SimpleStrategy', 'replication_factor':1}")
        admin.execute("CREATE TABLE ks.t1 (k int PRIMARY KEY, v int)")
        assert_invalid(admin,
                       "CREATE RESTRICTION ON {role} USING custom.non_such_capability WITH ks.t1".format(role=role),
                       "Unknown capability custom.non_such_capability",
                       SyntaxException)
        assert_invalid(admin,
                       "CREATE RESTRICTION ON {role} USING system.foo WITH ks.t1".format(role=role),
                       "Unknown capability system.foo",
                       SyntaxException)
        assert_invalid(admin,
                       "CREATE RESTRICTION ON {role} USING bar WITH ks.t1".format(role=role),
                       "Unknown capability system.bar",
                       SyntaxException)

    def test_conditional_create_and_drop(self):
        """
        Verify that IF EXISTS/IF NOT EXISTS works as expected in the context of
        CREATE/DROP RESTRICTION statements.
        """
        self.prepare(nodes=1)
        admin = self.get_session(user='cassandra', password='cassandra')
        role = self.next_role()
        create_role(admin, role)
        admin.execute("CREATE KEYSPACE ks WITH replication = {'class':'SimpleStrategy', 'replication_factor':1}")
        admin.execute("CREATE TABLE ks.t1 (k int PRIMARY KEY, v int)")
        admin.execute("CREATE RESTRICTION ON {role} USING system.filtering WITH ks.t1".format(role=role))

        assert_one(admin, "LIST RESTRICTIONS", list([role, '<table ks.t1>', 'system.filtering']))
        assert_invalid(admin, "CREATE RESTRICTION ON {role} USING system.filtering WITH ks.t1".format(role=role))
        admin.execute("CREATE RESTRICTION IF NOT EXISTS ON {role} USING system.filtering WITH ks.t1".format(role=role))
        assert_one(admin, "LIST RESTRICTIONS", list([role, '<table ks.t1>', 'system.filtering']))

        admin.execute("DROP RESTRICTION ON {role} USING system.filtering WITH ks.t1".format(role=role))
        assert_none(admin, "LIST RESTRICTIONS")
        assert_invalid(admin, "DROP RESTRICTION ON {role} USING system.filtering WITH ks.t1".format(role=role))
        admin.execute("DROP RESTRICTION IF EXISTS ON {role} USING system.filtering WITH ks.t1".format(role=role))

    def test_restrictions_caching(self):
        """
        Test to show that the caching of restrictions in AuthenticatedUser
        works correctly and revokes the roles from a logged in user
        * Launch a one node cluster with a restrictions cache validity of 2s
        * Create restriction on role
        * Verify that affected operations are rejected
        * Drop restriction and assert that it remains in place until the cache expires
        """
        self.prepare(nodes=1, restrictions_validity=2000)#, authorizer='CassandraAuthorizer')
        admin = self.get_session(user='cassandra', password='cassandra')
        role = self.next_role()
        create_role(admin, role)
        admin.execute("CREATE KEYSPACE ks WITH replication = {'class':'SimpleStrategy', 'replication_factor':1}")
        admin.execute("CREATE TABLE ks.t1 (k int PRIMARY KEY, v int)")
        admin.execute("CREATE RESTRICTION ON {role} USING system.filtering WITH ks.t1".format(role=role))
        # admin.execute("GRANT SELECT ON ks.t1 TO {role}".format(role=role))

        session = self.get_session(role)
        assert_unauthorized(session,
                            "SELECT * FROM ks.t1 WHERE v=0 ALLOW FILTERING",
                            error_msg(role, "ks.t1", "<system.filtering>"))

        admin.execute("DROP RESTRICTION ON {role} USING system.filtering WITH ks.t1".format(role=role))
        # restriction should remain in place until the cache expires
        unauthorized = None
        cnt = 0
        while not unauthorized and cnt < 20:
            try:
                session.execute("SELECT * FROM ks.t1 WHERE v=0 ALLOW FILTERING")
                cnt += 1
                time.sleep(.5)
            except Unauthorized as e:
                unauthorized = e

        assert unauthorized is not None

    def test_restrictions_inheritance(self):
        """
        Verify the inheritence of restrictions through a Roles hierarchy
        """
        self.prepare(nodes=1)
        admin = self.get_session(user='cassandra', password='cassandra')
        role1 = self.next_role()
        role2 = self.next_role()
        create_role(admin, role1)
        create_role(admin, role2)
        admin.execute("CREATE KEYSPACE ks WITH replication = {'class':'SimpleStrategy', 'replication_factor':1}")
        admin.execute("CREATE TABLE ks.t1 (k int PRIMARY KEY, v int)")
        admin.execute("CREATE RESTRICTION ON {role} USING FILTERING WITH ks.t1".format(role=role1))
        select = statement("SELECT * FROM ks.t1 WHERE v=0 ALLOW FILTERING")

        # role1 can't execute the select with filtering
        assert_unauthorized_statement(self.get_session(role1), select, error_msg(role1, "ks.t1", "<system.filtering>"))
        # but role2 can
        self.get_session(role2).execute(select)
        # unless role1 is granted to role2
        admin.execute("GRANT {role1} TO {role2}".format(role1=role1, role2=role2))
        assert_unauthorized_statement(self.get_session(role2), select, error_msg(role2, "ks.t1", "<system.filtering>"))
        # revoking role1 from role2 removes the restriction
        admin.execute("REVOKE {role1} FROM {role2}".format(role1=role1, role2=role2))
        self.get_session(role2).execute(select)

    def test_drop_role_cleans_up_restrictions(self):
        """
        Test to verify that when a role is dropped, all restrictions created on it are cleaned up
        """
        self.prepare(nodes=1)
        admin = self.get_session(user='cassandra', password='cassandra')
        role1 = self.next_role()
        create_role(admin, role1)
        admin.execute("CREATE KEYSPACE ks WITH replication = {'class':'SimpleStrategy', 'replication_factor':1}")
        admin.execute("CREATE TABLE ks.t1 (k int PRIMARY KEY, v int)")
        admin.execute("CREATE RESTRICTION ON {role} USING FILTERING WITH ks.t1".format(role=role1))
        admin.execute("CREATE RESTRICTION ON {role} USING CL_ALL_READ WITH KEYSPACE ks".format(role=role1))
        admin.execute("CREATE RESTRICTION ON {role} USING QUERY_TRACING WITH ALL KEYSPACES".format(role=role1))
        # lookup restrictions by role
        assert_all(admin, "LIST RESTRICTIONS ON {role}".format(role=role1),
                   [[role1, '<all keyspaces>', 'system.query_tracing'],
                    [role1, '<keyspace ks>', 'system.cl_all_read'],
                    [role1, '<table ks.t1>', 'system.filtering']],
                   ignore_order=True)
        # and also by resource/capability
        assert_one(admin, "LIST RESTRICTIONS ON ANY ROLE USING SYSTEM.FILTERING WITH ks.t1",
                   [role1, '<table ks.t1>', 'system.filtering'])

        admin.execute("DROP ROLE {role}".format(role=role1))
        # we can't lookup by role since we dropped it, but we can still lookup by resource/capability
        assert_none(admin, "LIST RESTRICTIONS ON ANY ROLE USING SYSTEM.FILTERING WITH ks.t1")
        # recreate the role & verify that the old restrictions haven't returned
        create_role(admin, role1)
        assert_none(admin, "LIST RESTRICTIONS ON {role}".format(role=role1))

    def test_drop_resource_cleans_up_restrictions(self):
        """
        Test to verify that when a table or keyspace is dropped, all restrictions which reference it are cleaned up
        """
        self.prepare(nodes=1)
        admin = self.get_session(user='cassandra', password='cassandra')
        role1 = self.next_role()
        create_role(admin, role1)
        admin.execute("CREATE KEYSPACE ks WITH replication = {'class':'SimpleStrategy', 'replication_factor':1}")
        admin.execute("CREATE TABLE ks.t1 (k int PRIMARY KEY, v int)")
        admin.execute("CREATE RESTRICTION ON {role} USING FILTERING WITH ks.t1".format(role=role1))
        admin.execute("CREATE RESTRICTION ON {role} USING CL_ALL_READ WITH KEYSPACE ks".format(role=role1))
        # list restrictions by role
        assert_all(admin, "LIST RESTRICTIONS ON {role}".format(role=role1),
                   [[role1, '<keyspace ks>', 'system.cl_all_read'],
                    [role1, '<table ks.t1>', 'system.filtering']],
                   ignore_order=True)
        # drop the table
        admin.execute("DROP TABLE ks.t1")
        assert_one(admin, "LIST RESTRICTIONS ON {role}".format(role=role1),
                   [role1, '<keyspace ks>', 'system.cl_all_read'])
        # drop the keyspace
        admin.execute("DROP KEYSPACE ks")
        assert_none(admin, "LIST RESTRICTIONS ON {role}".format(role=role1))
        # recreate the keyspace and table & verify that the old restrictions don't return
        admin.execute("CREATE KEYSPACE ks WITH replication = {'class':'SimpleStrategy', 'replication_factor':1}")
        admin.execute("CREATE TABLE ks.t1 (k int PRIMARY KEY, v int)")
        assert_none(admin, "LIST RESTRICTIONS ON {role}".format(role=role1))

    def test_restricted_cql_operations(self):
        """
        Really, this test could run on a single node cluster, which would eliminate certain scenarios which
        can cause test failures, but which aren't strictly problems in The Real World. For instance, with DCL
        statements executing on nodeA and queries running nodeB, there's a race between the updated DCL being
        applied on nodeB before the query runs. In reality, this isn't an issue as there isn't an expectation
        of serializability between statements from different clients. In tests though this is problematic,
        exacerbated by the fact that we need to run these tests on a multi node cluster to ensure that restrictions
        on using all consistency levels can be exercised. For this reason, both the admin session - which
        issues all DCL statements - and the client sessions - which verify that the DCL works - are restricted to
        the same single node in the cluster.
        """
        self.prepare(nodes=3)
        admin = self.get_session(user='cassandra', password='cassandra')
        # create test ks with NTS so that we can use LOCAL CLs in tests
        admin.execute("CREATE KEYSPACE ks WITH replication = {'class':'NetworkTopologyStrategy', 'datacenter1':3}")
        admin.execute("CREATE TABLE ks.t1 (k int PRIMARY KEY, v int)")
        admin.execute("CREATE TABLE ks.t2 (k int PRIMARY KEY, v int)")
        admin.execute("CREATE INDEX v_idx ON ks.t2(v)")
        admin.execute("CREATE TABLE ks.t3 (k int PRIMARY KEY, v counter)")
        admin.cluster.control_connection.wait_for_schema_agreement()

        self.check_filtering_restrictions(admin)

        self.check_read_consistency_restrictions(admin)

        self.check_write_consistency_restrictions(admin)

        self.check_truncate_restrictions(admin)

        self.check_lwt_restrictions(admin)

        self.check_non_lwt_restrictions(admin)

        self.check_multipartition_read_restrictions(admin)

        self.check_multipartition_aggregate_restrictions(admin)

        self.check_partition_range_read_restrictions(admin)

        self.check_multiple_restricted_capabilites_reported(admin)

        self.check_lwt_restrictions_with_batches(admin)

        self.check_batch_restrictions_using_legacy_batches(admin)

        self.check_batch_restrictions_using_batch_statements(admin)

        self.check_native_index_restrictions(admin)

        self.check_unprepared_statement_restrictions(admin)

        self.check_query_tracing_restrictions(admin)

    def check_query_tracing_restrictions(self, admin):
        role = self.next_role()
        create_role(admin, role)
        admin.execute("CREATE RESTRICTION ON {role} USING system.query_tracing WITH ALL KEYSPACES".format(role=role))
        session = self.get_session(role)

        def exec_select():
            return session.execute_async("SELECT * FROM ks.t1 WHERE k=0", trace=True)

        def exec_prepared():
            prepared = session.prepare("SELECT * FROM ks.t1 WHERE k=0")
            return session.execute_async(prepared, trace=True)

        def exec_batch():
            batch = BatchStatement()
            batch.add(statement("INSERT INTO ks.t1 (k, v) VALUES (0, 0)"))
            return session.execute_async(batch, trace=True)

        logger.info("Testing CQL operation: Query tracing restriction with simple statement")
        self.do_tracing_restriction_check(role, exec_select)
        logger.info("Testing CQL operation: Query tracing restriction with prepared statement")
        self.do_tracing_restriction_check(role, exec_prepared)
        logger.info("Testing CQL operation: Query tracing restriction with batch statement")
        self.do_tracing_restriction_check(role, exec_batch)

    def do_tracing_restriction_check(self, role, exec_fn):
        future = exec_fn()
        future.result()

        try:
            self.assertIsNone(future.get_query_trace(max_wait=2), "Expected no query trace, but found one")
        except TraceUnavailable:
            pass

        self.assertIsNotNone(future.warnings)
        self.assertEquals(1, len(future.warnings))
        self.assertEquals("Query tracing was triggered either explicitly or probabilistically "
                          "but is restricted for role {role} or one of its granted roles.".format(role=role),
                          future.warnings[0])

    def check_unprepared_statement_restrictions(self, admin):
        role = self.next_role()
        self.assert_cql_restricted(admin,
                                   "Execution of unprepared statements restricted at table level",
                                   [("system.unprepared_statement", "ks.t1")],
                                   ("ks.t1", ["system.unprepared_statement"]),
                                   statement("SELECT * FROM ks.t1 WHERE k=0"),
                                   role=role)
        # prepared statements are still permitted
        session = self.get_session(role)
        logger.warn("PREPARING")
        session.execute(session.prepare("SELECT * FROM ks.t1 WHERE k=0"))

        role = self.next_role()
        self.assert_cql_restricted(admin,
                                   "Execution of unprepared statements restricted at keyspace level",
                                   [("system.unprepared_statement", "keyspace ks")],
                                   ("ks.t1", ["system.unprepared_statement"]),
                                   statement("SELECT * FROM ks.t1 WHERE k=0"),
                                   role=role)
        # prepared statements are still permitted
        session = self.get_session(role)
        session.execute(session.prepare("SELECT * FROM ks.t1 WHERE k=0"))

    def check_native_index_restrictions(self, admin):
        self.assert_cql_restricted(admin,
                                   "Use of native secondary indexes restricted at table level",
                                   [("system.native_secondary_index", "ks.t2")],
                                   ("ks.t2", ["system.native_secondary_index"]),
                                   statement("SELECT * FROM ks.t2 WHERE v=0"))
        self.assert_cql_restricted(admin,
                                   "Use of native secondary indexes restricted at table level",
                                   [("system.native_secondary_index", "ks.t2")],
                                   ("ks.t2", ["system.native_secondary_index"]),
                                   statement("SELECT * FROM ks.t2 WHERE v=0"))

    def check_batch_restrictions_using_legacy_batches(self, admin):
        # verify restrictions on LOGGED/UNLOGGED batches when performed using batches
        # tunnelled over SimpleStatements.
        unlogged_batch = statement("""BEGIN UNLOGGED BATCH
                                      INSERT INTO ks.t1 (k, v) VALUES (0, 0)
                                      APPLY BATCH""")
        logged_batch = statement("""BEGIN BATCH
                                    INSERT INTO ks.t1 (k, v) VALUES (0, 0)
                                    APPLY BATCH""")
        counter_batch = statement("""BEGIN COUNTER BATCH
                                     UPDATE ks.t3 SET v = v + 1 WHERE k = 0
                                     APPLY BATCH""")
        self.check_batch_restrictions(admin, unlogged_batch, logged_batch, counter_batch)

    def check_batch_restrictions_using_batch_statements(self, admin):
        unlogged_batch = BatchStatement(batch_type=BatchType.UNLOGGED)
        unlogged_batch.add(statement("INSERT INTO ks.t1 (k, v) VALUES (0, 0)"))

        logged_batch = BatchStatement(batch_type=BatchType.LOGGED)
        logged_batch.add(statement("INSERT INTO ks.t1 (k, v) VALUES (0, 0)"))

        counter_batch = BatchStatement(batch_type=BatchType.COUNTER)
        counter_batch.add(statement("UPDATE ks.t3 SET v = v + 1 WHERE k = 0"))

        self.check_batch_restrictions(admin, unlogged_batch, logged_batch, counter_batch)

    def check_batch_restrictions(self, admin, unlogged_batch, logged_batch, counter_batch):
        # verify restrictions on LOGGED/UNLOGGED/COUNTER batches.
        # For each LOGGED/UNLOGGED also assert that the un-restricted
        # type is still permitted
        role = self.next_role()
        self.assert_cql_restricted(admin,
                                   "UNLOGGED Batch restricted at table level",
                                   [("system.unlogged_batch", "ks.t1")],
                                   ("ks.t1", ["system.unlogged_batch"]),
                                   unlogged_batch,
                                   role=role)
        self.get_session(role).execute(logged_batch)

        role = self.next_role()
        self.assert_cql_restricted(admin,
                                   "UNLOGGED Batch restricted at keyspace level",
                                   [("system.unlogged_batch", "keyspace ks")],
                                   ("ks.t1", ["system.unlogged_batch"]),
                                   unlogged_batch,
                                   role=role)
        self.get_session(role).execute(logged_batch)

        role = self.next_role()
        self.assert_cql_restricted(admin,
                                   "LOGGED Batch restricted at table level",
                                   [("system.logged_batch", "ks.t1")],
                                   ("ks.t1", ["system.logged_batch"]),
                                   logged_batch,
                                   role=role)
        self.get_session(role).execute(unlogged_batch)

        role = self.next_role()
        self.assert_cql_restricted(admin,
                                   "LOGGED Batch restricted at keyspace level",
                                   [("system.logged_batch", "keyspace ks")],
                                   ("ks.t1", ["system.logged_batch"]),
                                   logged_batch,
                                   role=role)
        self.get_session(role).execute(unlogged_batch)

        role = self.next_role()
        self.assert_cql_restricted(admin,
                                   "COUNTER Batch restricted at table level",
                                   [("system.counter_batch", "ks.t3")],
                                   ("ks.t3", ["system.counter_batch"]),
                                   counter_batch,
                                   role=role)

        role = self.next_role()
        self.assert_cql_restricted(admin,
                                   "COUNTER Batch restricted at keyspace level",
                                   [("system.counter_batch", "keyspace ks")],
                                   ("ks.t3", ["system.counter_batch"]),
                                   counter_batch,
                                   role=role)

    def check_lwt_restrictions_with_batches(self, admin):
        logger.info("Testing CQL operation: Batch statement with some statements restricted")
        # Non-LWT updates are restricted for ks.t2, but not for ks.t1
        # Execute a batch at with updates for both tables and neither should be performed
        batch = BatchStatement(batch_type=BatchType.UNLOGGED)
        batch.add(statement("INSERT INTO ks.t1 (k, v) VALUES (0, 0)"))
        batch.add(statement("INSERT INTO ks.t2 (k, v) VALUES (0, 0)"))

        role = self.next_role()
        create_role(admin, role)
        admin.execute("CREATE RESTRICTION ON {role} USING system.non_lwt_update WITH ks.t2".format(role=role))
        admin.execute("TRUNCATE ks.t1")
        admin.execute("TRUNCATE ks.t2")

        session = self.get_session(role)
        message = error_msg(role, "ks.t2", "<system.non_lwt_update>")
        assert_unauthorized_statement(session, batch, message)

        # assert no rows in ks.t1 or ks.t2
        assert_none(admin, "SELECT * FROM ks.t1")
        assert_none(admin, "SELECT * FROM ks.t2")

    def check_multiple_restricted_capabilites_reported(self, admin):
        self.assert_cql_restricted(admin,
                                   "FILTERING and CL_ALL_READ restricted at table level",
                                   [("system.filtering", "ks.t1"), ("system.cl_all_read", "ks.t1")],
                                   ("ks.t1", ["system.filtering", "system.cl_all_read"]),
                                   statement("SELECT * FROM ks.t1 WHERE v=0 ALLOW FILTERING",
                                             {"consistency_level": ConsistencyLevel.ALL}))

    def check_partition_range_read_restrictions(self, admin):
        self.assert_cql_restricted(admin,
                                   "Partition range read restricted at table level",
                                   [("system.partition_range_read", "ks.t1")],
                                   ("ks.t1", ["system.partition_range_read"]),
                                   statement("SELECT * FROM ks.t1"))
        self.assert_cql_restricted(admin,
                                   "Partition range read restricted at table level",
                                   [("system.partition_range_read", "keyspace ks")],
                                   ("ks.t1", ["system.partition_range_read"]),
                                   statement("SELECT * FROM ks.t1"))

    def check_multipartition_aggregate_restrictions(self, admin):
        self.assert_cql_restricted(admin,
                                   "Aggregate query without partition key restricted at table level",
                                   [("system.multi_partition_aggregation", "ks.t1")],
                                   ("ks.t1", ["system.multi_partition_aggregation"]),
                                   statement("SELECT max(v) FROM ks.t1"))
        self.assert_cql_restricted(admin,
                                   "Aggregate query without partition key restricted at keyspace level",
                                   [("system.multi_partition_aggregation", "keyspace ks")],
                                   ("ks.t1", ["system.multi_partition_aggregation"]),
                                   statement("SELECT max(v) FROM ks.t1"))
        self.assert_cql_restricted(admin,
                                   "Aggregate query with partition key IN restricted at table level",
                                   [("system.multi_partition_aggregation", "ks.t1")],
                                   ("ks.t1", ["system.multi_partition_aggregation"]),
                                   statement("SELECT max(v) FROM ks.t1 WHERE k IN (0, 1)"))
        self.assert_cql_restricted(admin,
                                   "Aggregate query with partition key IN restricted at keyspace level",
                                   [("system.multi_partition_aggregation", "keyspace ks")],
                                   ("ks.t1", ["system.multi_partition_aggregation"]),
                                   statement("SELECT max(v) FROM ks.t1 WHERE k in (0, 1)"))

    def check_multipartition_read_restrictions(self, admin):
        self.assert_cql_restricted(admin,
                                   "Multi partition read restricted at table level",
                                   [("system.multi_partition_read", "ks.t1")],
                                   ("ks.t1", ["system.multi_partition_read"]),
                                   statement("SELECT * FROM ks.t1 WHERE k IN (0, 1, 2)"))
        self.assert_cql_restricted(admin,
                                   "Multi partition read restricted at keyspace level",
                                   [("system.multi_partition_read", "keyspace ks")],
                                   ("ks.t1", ["system.multi_partition_read"]),
                                   statement("SELECT * FROM ks.t1 WHERE k IN (0, 1, 2)"))

    def check_lwt_restrictions(self, admin):
        self.assert_cql_restricted(admin,
                                   "LWT insert restricted at table level",
                                   [("system.lwt", "ks.t1")],
                                   ("ks.t1", ["system.lwt"]),
                                   statement("INSERT INTO ks.t1 (k, v) VALUES (0, 0) IF NOT EXISTS"))
        self.assert_cql_restricted(admin,
                                   "LWT insert restricted at keyspace level",
                                   [("system.lwt", "keyspace ks")],
                                   ("ks.t1", ["system.lwt"]),
                                   statement("INSERT INTO ks.t1 (k, v) VALUES (0, 0) IF NOT EXISTS"))
        self.assert_cql_restricted(admin,
                                   "LWT update restricted at table level",
                                   [("system.lwt", "ks.t1")],
                                   ("ks.t1", ["system.lwt"]),
                                   statement("UPDATE ks.t1 SET v=1 WHERE k=0 IF v=0"))
        self.assert_cql_restricted(admin,
                                   "LWT update restricted at keyspace level",
                                   [("system.lwt", "keyspace ks")],
                                   ("ks.t1", ["system.lwt"]),
                                   statement("UPDATE ks.t1 SET v=1 WHERE k=0 IF v=0"))

    def check_non_lwt_restrictions(self, admin):
        # for each variant, also verify that the same role can still
        # perform LWT updates, i.e. that this can be used to enforce
        # only serial updates to a given table or keyspace
        role = self.next_role()
        self.assert_cql_restricted(admin,
                                   "Non-LWT insert restricted at table level",
                                   [("system.non_lwt_update", "ks.t1")],
                                   ("ks.t1", ["system.non_lwt_update"]),
                                   statement("INSERT INTO ks.t1 (k, v) VALUES (0, 0)"),
                                   role=role)
        session = self.get_session(role)
        session.execute("INSERT INTO ks.t1 (k, v) VALUES (0, 0) IF NOT EXISTS")

        role = self.next_role()
        self.assert_cql_restricted(admin,
                                   "Non-LWT insert restricted at keyspace level",
                                   [("system.non_lwt_update", "keyspace ks")],
                                   ("ks.t1", ["system.non_lwt_update"]),
                                   statement("INSERT INTO ks.t1 (k, v) VALUES (0, 0)"),
                                   role=role)
        session = self.get_session(role)
        session.execute("INSERT INTO ks.t1 (k, v) VALUES (0, 0) IF NOT EXISTS")

        role = self.next_role()
        self.assert_cql_restricted(admin,
                                   "Non-LWT update restricted at table level",
                                   [("system.non_lwt_update", "ks.t1")],
                                   ("ks.t1", ["system.non_lwt_update"]),
                                   statement("UPDATE ks.t1 SET v=1 WHERE k=0"),
                                   role=role)
        session = self.get_session(role)
        session.execute("UPDATE ks.t1 SET v=1 WHERE k=0 IF v=0")

        role = self.next_role()
        self.assert_cql_restricted(admin,
                                   "Non-LWT update restricted at keyspace level",
                                   [("system.non_lwt_update", "keyspace ks")],
                                   ("ks.t1", ["system.non_lwt_update"]),
                                   statement("UPDATE ks.t1 SET v=1 WHERE k=0"),
                                   role=role)
        session = self.get_session(role)
        session.execute("UPDATE ks.t1 SET v=1 WHERE k=0 IF v=0")

        # clean up
        admin.execute("DELETE FROM ks.t1 WHERE k=0")

    def check_truncate_restrictions(self, admin):
        # in the list(tuple) of restrictions to apply, truncate needs
        # quoting as it's a reserved keyword in CQL
        self.assert_cql_restricted(admin,
                                   "TRUNCATE restricted at table level",
                                   [('system."truncate"', "ks.t1")],
                                   ("ks.t1", ["system.truncate"]),
                                   statement("TRUNCATE ks.t1"))
        self.assert_cql_restricted(admin,
                                   "TRUNCATE restricted at keyspace level",
                                   [('system."truncate"', "keyspace ks")],
                                   ("ks.t1", ["system.truncate"]),
                                   statement("TRUNCATE ks.t1"))

    def check_filtering_restrictions(self, admin):
        self.assert_cql_restricted(admin,
                                   "FILTERING restricted at table level",
                                   [("system.filtering", "ks.t1")],
                                   ("ks.t1", ["system.filtering"]),
                                   statement("SELECT * FROM ks.t1 WHERE v=0 ALLOW FILTERING"))
        self.assert_cql_restricted(admin,
                                   "FILTERING restricted at keyspace level",
                                   [("system.filtering", "keyspace ks")],
                                   ("ks.t1", ["system.filtering"]),
                                   statement("SELECT * FROM ks.t1 WHERE v=0 ALLOW FILTERING"))

    def check_read_consistency_restrictions(self, admin):
        # Test restricting reads at each consistency level separately
        all_cls = [ConsistencyLevel.ONE, ConsistencyLevel.TWO, ConsistencyLevel.THREE,
                   ConsistencyLevel.LOCAL_ONE, ConsistencyLevel.LOCAL_QUORUM, ConsistencyLevel.EACH_QUORUM,
                   ConsistencyLevel.QUORUM, ConsistencyLevel.ALL, ConsistencyLevel.LOCAL_SERIAL,
                   ConsistencyLevel.SERIAL]
        for cl in all_cls:
            self.assert_cql_restricted(admin,
                                       "Reading at consistency level {c}".format(c=consistency_value_to_name(cl)),
                                       [(consistency_as_capability(cl), "ks.t1")],
                                       ("ks.t1", [consistency_as_capability(cl)]),
                                       statement("SELECT * FROM ks.t1 WHERE k=0", {"consistency_level": cl}))

        # Leaving only a single CL unrestricted ensures a user can only read at that one CL.
        # Here only CL_ONE is allowed
        logger.info("Testing CQL operation: Only reads with only CL_ONE reads allowed")
        restricted = [consistency_as_capability(cl, False) for cl in all_cls[1:]]
        role = self.next_role()
        create_role(admin, role)
        for capability in restricted:
            admin.execute("CREATE RESTRICTION ON {role} USING {cap} WITH ks.t1".format(role=role, cap=capability))

        session = self.get_session(role)
        # reads at any CL except ONE should be rejected
        for cl in all_cls[1:]:
            stmt = statement("SELECT * FROM ks.t1 WHERE k=0", {"consistency_level":cl})
            message = error_msg(role, "ks.t1", "<{c}>".format(c=consistency_as_capability(cl)))
            assert_unauthorized_statement(session, stmt, message)
        # reading at ONE should be allowed
        session.execute(SimpleStatement("SELECT * FROM ks.t1 WHERE k=0", consistency_level=ConsistencyLevel.ONE))

    def check_write_consistency_restrictions(self, admin):
        # Test restricting modifications at each consistency level separately
        all_cls = [ConsistencyLevel.ONE, ConsistencyLevel.TWO, ConsistencyLevel.THREE,
                   ConsistencyLevel.LOCAL_ONE, ConsistencyLevel.LOCAL_QUORUM, ConsistencyLevel.EACH_QUORUM,
                   ConsistencyLevel.QUORUM, ConsistencyLevel.ALL, ConsistencyLevel.ANY]
        for cl in all_cls:
            self.assert_cql_restricted(admin,
                                       "Inserting at consistency level {c}".format(c=consistency_value_to_name(cl)),
                                       [(consistency_as_capability(cl, for_write=True), "ks.t1")],
                                       ("ks.t1", [consistency_as_capability(cl, for_write=True)]),
                                       statement("INSERT INTO ks.t1 (k, v) VALUES (0, 0)", {"consistency_level": cl}))
            self.assert_cql_restricted(admin,
                                       "Updating at consistency level {c}".format(c=consistency_value_to_name(cl)),
                                       [(consistency_as_capability(cl, for_write=True), "ks.t1")],
                                       ("ks.t1", [consistency_as_capability(cl, for_write=True)]),
                                       statement("UPDATE ks.t1 SET v=0 WHERE k=0", {"consistency_level": cl}))
            self.assert_cql_restricted(admin,
                                       "Deleting at consistency level {c}".format(c=consistency_value_to_name(cl)),
                                       [(consistency_as_capability(cl, for_write=True), "ks.t1")],
                                       ("ks.t1", [consistency_as_capability(cl, for_write=True)]),
                                       statement("DELETE FROM ks.t1 WHERE k=0", {"consistency_level": cl}))
        # Leaving only a single CL unrestricted ensures a user can only write at that one CL.
        # Here only CL_ONE is allowed
        logger.info("Testing CQL operation: Only writes with only CL_ONE reads allowed")
        restricted = [consistency_as_capability(cl, True) for cl in all_cls[1:]]
        role = self.next_role()
        create_role(admin, role)
        for capability in restricted:
            admin.execute("CREATE RESTRICTION ON {role} USING {cap} WITH ks.t1".format(role=role, cap=capability))

        session = self.get_session(role)
        # reads at any CL except ONE should be rejected
        statements = ["INSERT INTO ks.t1 (k, v) VALUES (0, 0)",
                      "UPDATE ks.t1 SET v=0 WHERE k=0",
                      "DELETE FROM ks.t1 WHERE k=0"]
        for cl in all_cls[1:]:
            message = error_msg(role, "ks.t1", "<{c}>".format(c=consistency_as_capability(cl, True)))
            for stmt in statements:
                assert_unauthorized_statement(session, SimpleStatement(stmt, consistency_level=cl), message)

        # updating at ONE should be allowed
        for stmt in statements:
            session.execute(SimpleStatement(stmt, consistency_level=ConsistencyLevel.ONE))

    def assert_cql_restricted(self,
                              admin_session,
                              test_description,
                              restrictions_to_apply,
                              error_message_components,
                              stmt,
                              role=None):
        """
        Perform a series of operations to verify that imposing restrictions on a Role's
        ability to use certain capabilities with specific resources has the desired effect.
        For example, given a CQL statement:
            SELECT * FROM test_ks.test_table WHERE value='foo' ALLOW FILTERING
        The restriction:
            CREATE RESTRICTION ON bill USING system.filtering WITH test_ks.test_table;
        should prevent bill (or any role which has been granted bill) from executing that
        statement. Assuming that bill has the requisite permissions on test_ks and test_table,
        once the restriction is dropped a user with that role should once again be permitted
        to execute the query.
        If no name for the role to which the restrictions are applied is passed, a new one
        will be generated.

        :param admin_session: superuser session for creating & dropping roles & restrictions
        :param test_description: simple description of the test case
        :param restrictions_to_apply: a list of (capability, resource) tuples. The first element
               is the name of the capability to be restricted. The second is the resource to which
               the restrictions are applied (for the role in question).
        :param error_message_components: tuple of (resource, list[capabilities]) that should be
               present in the error message returned by the server. The resource is the resource
               being accessed in the executed statement and does not necessarily match the one
               in the restriction definition. For instance, a restriction on using LWT may be set
               at the keyspace level (and so applies to all tables in that keyspace), but at
               execution time, it is a specific table which the client is attempting to perform
               LWT operations on, and so the table name will appear in the error message.
        :param stmt: CQL statement to be executed. The statement(cql) function can be used to
               make SimpleStatement instances.
        :param role: Name of the role to be the subject of the restiction. If none is supplied,
               a unique role name will be generated
        """
        logger.info("Testing CQL operation: {d}".format(d=test_description))
        logger.warn("Testing CQL operation: {d}".format(d=test_description))

        # Usually, create a new role per-test to ensure isolation but allow a role to be
        # supplied for when we want to perform extra checks outside this function
        role_to_restrict = self.next_role() if role is None else role
        create_role(admin_session, role_to_restrict)

        # establish a connection to a specific node so that queries with LOCAL cl can be executed
        role = self.get_session(role_to_restrict)

        # before creating any restrictions, executing the statement should be allowed
        role.execute(stmt)

        # create the specified restrictions
        for capability, resource in restrictions_to_apply:
            admin_session.execute("CREATE RESTRICTION ON {role} USING {cap} WITH {res}".format(role=role_to_restrict,
                                                                                               cap=capability,
                                                                                               res=resource))
        # Now the execution of the same statement should result in an Unauthorized response. The
        # response message should contain 3 elements:
        #   * The role name
        #   * The target resource of the statement, which may not be the actual resource in
        #     named in any restrictions (e.g. in the case where the restriction is on the
        #     keyspace, the target resource is still the table in the statement)
        #   * The capabiities whose restriction prevents the operation, i.e. the intersection
        #     between those capabilities required to perform it & those for which the role has
        #     restrictions that apply to the resource chain
        restricted_resource = error_message_components[0]
        restricted_capabilities = capabilities_as_list(error_message_components[1])
        message = error_msg(role_to_restrict, restricted_resource, restricted_capabilities)
        assert_unauthorized_statement(role, stmt, message)

    def test_dummy(self):
        self.cluster.populate(1).start(wait_for_binary_proto=True)
        assert True

    def prepare(self, nodes, restrictions_validity=0, authorizer='org.apache.cassandra.auth.AllowAllAuthorizer'):
        """
        Sets up and launches C* cluster. Caching Roles, Permissions and Capability Restrictions are disabled to make
        lookups deterministic
        @param nodes nodes in the cluster, may be an int for a single dc cluster or a list of ints for multi-dc
        @param restrictions_validity The timeout for the capability restrictions cache in ms. Default is 0.
        """
        config = {'authenticator': 'org.apache.cassandra.auth.PasswordAuthenticator',
                  'authorizer': authorizer,
                  'capability_manager': 'org.apache.cassandra.auth.capability.CassandraCapabilityManager',
                  'capability_restrictions_validity_in_ms': restrictions_validity,
                  'roles_validity_in_ms': 0,
                  'permissions_validity_in_ms': 0}

        self.cluster.set_configuration_options(values=config)
        self.cluster.populate(nodes).start(wait_for_binary_proto=True)
        self.cluster.wait_for_any_log('Created default superuser', 25)
        self.wait_for_all_logs(self.cluster.nodelist(), 'CassandraCapabilityManager initialized', 30)

    def get_session(self, user, password='pass', node_idx=0):
        """
        Connect with a set of credentials to node1 in the cluster. Connection is exclusive to that node.
        @param user User to connect as
        @param password Password to use
        @param node_idx node to connect to
        @return Session as user, to specified node
        """
        node = self.cluster.nodelist()[node_idx]
        session = self.patient_cql_connection(node, user=user, password=password)
        return session

    def wait_for_all_logs(self, nodes, pattern, timeout, filename='system.log'):
        """
        Look for a pattern in the system.log of all nodes in a given list.
        @param nodes The list of nodes whose logs to scan
        @param pattern The target pattern
        @param timeout How long to wait for the pattern. Note that
                       strictly speaking, timeout is not really a timeout,
                       but a maximum number of attempts. This implies that
                       the all the grepping takes no time at all, so it is
                       somewhat inaccurate, but probably close enough.
        @param filename name of the log file to inspect, defaults to system.log
        """

        found = {n: False for n in nodes}
        for _ in range(timeout):
            for node in found:
                if not found[node]:
                    found[node] = len(node.grep_log(pattern, filename=filename)) > 0

            results = set(found.values())
            if len(results) == 1 and results.pop():
                return
            time.sleep(1)

        raise TimeoutError(time.strftime("%d %b %Y %H:%M:%S", time.gmtime()) +
                           " Unable to find: " + pattern + " in all node logs within " + str(timeout) + "s")
