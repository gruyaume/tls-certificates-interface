import json
import unittest
from unittest.mock import Mock, call

from charms.tls_certificates_interface.v0.tls_certificates import (
    Cert,
    InsecureCertificatesProvides,
    InsecureCertificatesRequires,
)

PROVIDER_UNIT_NAME = "whatever provider unit name"
REQUIRER_UNIT_NAME = "whatever requirer unit name"


class TestInsecureCertificatesProvides(unittest.TestCase):
    def setUp(self):
        class CharmOnMock:
            certificates = Mock()
            ca_request = Mock()
            certificates_request = Mock()

            def __getitem__(self, key):
                return getattr(self, key)

        relationship_name = "certificates"
        charm = Mock()
        charm.on = CharmOnMock()
        charm.framework.model.unit = PROVIDER_UNIT_NAME
        self.insecure_relation_provides = InsecureCertificatesProvides(
            charm=charm, relationship_name=relationship_name
        )
        self.charm = charm

    def test_given_unit_name_is_missing_from_relation_data_when_relation_changed_then_event_is_deferred(  # noqa: E501
        self,
    ):
        event = Mock()
        event.relation.data = {
            REQUIRER_UNIT_NAME: {
                "common_name": "whatever common name",
            },
            PROVIDER_UNIT_NAME: {},
        }
        event.unit = REQUIRER_UNIT_NAME

        self.insecure_relation_provides._on_relation_changed(event)

        self.assertTrue(event.defer.call_count == 1)

    def test_given_correct_relation_data_when_relation_changed_then_ca_request_event_is_emitted(
        self,
    ):
        common_name = "aaa"
        unit_name = "bla"
        event = Mock()
        event.relation.data = {
            REQUIRER_UNIT_NAME: {
                "unit_name": unit_name,
                "common_name": common_name,
            },
            PROVIDER_UNIT_NAME: {},
        }
        event.unit = REQUIRER_UNIT_NAME

        self.insecure_relation_provides._on_relation_changed(event)

        self.assertEqual(1, self.charm.on.ca_request.emit.call_count)

    def test_given_only_common_name_in_relation_data_when_relation_changed_then_certificate_request_event_is_emitted_for_server(  # noqa: E501
        self,
    ):
        common_name = "aaa"
        unit_name = "bla"
        event = Mock()
        event.relation.data = {
            REQUIRER_UNIT_NAME: {
                "unit_name": unit_name,
                "common_name": common_name,
            },
            PROVIDER_UNIT_NAME: {},
        }
        event.unit = REQUIRER_UNIT_NAME

        self.insecure_relation_provides._on_relation_changed(event)

        self.assertEqual(1, self.charm.on.certificates_request.emit.call_count)
        args, kwargs = self.charm.on.certificates_request.emit.call_args
        self.assertIn("common_name", kwargs)
        self.assertIn("sans", kwargs)
        self.assertIn("cert_type", kwargs)
        self.assertEqual(kwargs["common_name"], common_name)
        self.assertEqual(kwargs["sans"], None)
        self.assertEqual(kwargs["cert_type"], "server")

    def test_given_invalid_cert_requests_in_relation_data_when_relation_changed_then_event_is_deferred(  # noqa: E501
        self,
    ):
        invalid_cert_request_content = "invalid format"
        event = Mock()
        event.relation.data = {
            REQUIRER_UNIT_NAME: {
                "unit_name": "whatever unit name",
                "common_name": "whatever common name",
                "cert_requests": invalid_cert_request_content,
            },
            PROVIDER_UNIT_NAME: {},
        }
        event.unit = REQUIRER_UNIT_NAME

        self.insecure_relation_provides._on_relation_changed(event)

        self.assertTrue(event.defer.call_count == 1)

    def test_given_cert_requests_in_relation_data_when_relation_changed_then_certificate_request_event_is_emitted_for_each_request(  # noqa: E501
        self,
    ):
        general_common_name = "general common name"
        cert_request_1_common_name = "cert request 1 common name"
        cert_request_2_common_name = "cert request 2 common name"
        client_cert_request_1_common_name = "client cert request 1 common name"
        client_cert_request_2_common_name = "client cert request 2 common name"
        cert_requests = [
            {"common_name": cert_request_1_common_name},
            {"common_name": cert_request_2_common_name},
        ]
        client_cert_requests = [
            {"common_name": client_cert_request_1_common_name},
            {"common_name": client_cert_request_2_common_name},
        ]
        event = Mock()
        event.relation.data = {
            REQUIRER_UNIT_NAME: {
                "unit_name": REQUIRER_UNIT_NAME,
                "common_name": general_common_name,
                "cert_requests": json.dumps(cert_requests),
                "client_cert_requests": json.dumps(client_cert_requests),
            },
            PROVIDER_UNIT_NAME: {},
        }
        event.unit = REQUIRER_UNIT_NAME

        self.insecure_relation_provides._on_relation_changed(event)

        calls = [
            call(common_name=general_common_name, sans=None, cert_type="server"),
            call(common_name=cert_request_1_common_name, sans=None, cert_type="server"),
            call(common_name=cert_request_2_common_name, sans=None, cert_type="server"),
            call(common_name=client_cert_request_1_common_name, sans=None, cert_type="client"),
            call(common_name=client_cert_request_2_common_name, sans=None, cert_type="client"),
        ]
        self.charm.on.certificates_request.emit.assert_has_calls(calls, any_order=True)

    def test_given_certificate_when_set_relation_certificate_then_cert_is_added_to_relation_data(
        self,
    ):
        class Relation:
            data: dict = {PROVIDER_UNIT_NAME: dict(), REQUIRER_UNIT_NAME: dict()}

        common_name = "whatever common name"
        certificate = Cert(cert="whatever cert", key="whatever key")
        relation = Relation()
        self.charm.framework.model.get_relation.return_value = relation

        self.insecure_relation_provides.set_relation_certificate(
            common_name=common_name, certificate=certificate
        )

        certificate_data = json.loads(relation.data[PROVIDER_UNIT_NAME][common_name])
        self.assertEqual(certificate_data, certificate)

    def test_given_ca_when_set_relation_ca_then_ca_is_added_to_relation_data(self):
        class Relation:
            data: dict = {PROVIDER_UNIT_NAME: dict(), REQUIRER_UNIT_NAME: dict()}

        ca = "whatever common name"
        relation = Relation()
        self.charm.framework.model.get_relation.return_value = relation

        self.insecure_relation_provides.set_relation_ca(ca=ca)

        self.assertEqual(relation.data[PROVIDER_UNIT_NAME]["ca"], ca)
        self.assertEqual(relation.data[PROVIDER_UNIT_NAME]["chain"], ca)


class TestInsecureCertificatesRequires(unittest.TestCase):
    def setUp(self):
        class CharmOnMock:
            certificates = Mock()
            ca_request = Mock()
            certificates_request = Mock()

            def __getitem__(self, key):
                return getattr(self, key)

        charm = Mock()
        charm.on = CharmOnMock()
        relationship_name = "certificates"
        self.insecure_certificate_requires = InsecureCertificatesRequires(
            charm=charm, relationship_name=relationship_name
        )
        self.charm = charm
        self.charm.framework.model.unit.name = REQUIRER_UNIT_NAME

    def test_given_client_when_request_certificate_then_client_cert_request_is_added_to_relation_data(  # noqa: E501
        self,
    ):
        class Relation:
            data: dict = {PROVIDER_UNIT_NAME: dict(), REQUIRER_UNIT_NAME: dict()}

        common_name = "whatever common name"
        relation = Relation()
        self.charm.framework.model.get_relation.return_value = relation

        self.insecure_certificate_requires.request_certificate(
            cert_type="client",
            common_name=common_name,
        )

        self.assertIn("client_cert_requests", relation.data[REQUIRER_UNIT_NAME])
        client_cert_requests = json.loads(
            relation.data[REQUIRER_UNIT_NAME]["client_cert_requests"]
        )
        expected_client_cert_requests = [{"common_name": common_name, "sans": "null"}]
        self.assertEqual(expected_client_cert_requests, client_cert_requests)
