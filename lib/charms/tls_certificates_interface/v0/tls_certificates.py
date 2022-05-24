# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

""" Library for the tls-certificates relation

This library contains the Requires and Provides classes for handling
the tls-certificates interface.

## Provider charm
Example:
```
from charms.tls_certificates_interface.v0.tls_certificates import (
    Cert,
    CertificatesProviderCharmEvents,
    InsecureCertificatesProvides,
)
from ops.charm import CharmBase


class ExampleProviderCharm(CharmBase):
    on = CertificatesProviderCharmEvents()

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.certificates_request, self._on_certificate_request)
        self.framework.observe(self.on.ca_request, self._on_ca_request)
        self.insecure_certificates = InsecureCertificatesProvides(self, "certificates")

    def _on_certificate_request(self, event):
        common_name = event.common_name
        certificate = Cert(cert="whatever certificate", key="whatever key")
        self.insecure_certificates.set_relation_certificate(
            common_name=common_name, certificate=certificate
        )

    def _on_ca_request(self, event):
        ca = "whatever ca"
        self.insecure_certificates.set_relation_ca(ca=ca)
```

## Requirer charm
Example:

```
from charms.tls_certificates_interface.v0.tls_certificates import (
    CertificatesRequirerCharmEvents,
    InsecureCertificatesRequires,
)
from ops.charm import CharmBase


class ExampleRequirerCharm(CharmBase):
    on = CertificatesRequirerCharmEvents()

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.certificates_available, self._on_certificates_available)
        self.insecure_certificates = InsecureCertificatesRequires(self, "certificates")
        self.insecure_certificates.request_certificate(
            cert_type="client",
            common_name="whatever common name",
        )

    def _on_certificates_available(self, event):
        certificate_data = event.certificate_data
        cert = certificate_data["cert"]
        key = certificate_data["key"]
        print(cert)
        print(key)
```

"""
import json
import logging
from typing import Literal, TypedDict

from jsonschema import exceptions, validate  # type: ignore[import]
from ops.charm import CharmEvents
from ops.framework import EventBase, EventSource, Object

# The unique Charmhub library identifier, never change it
LIBID = "afd8c2bccf834997afce12c2706d2ede"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 2

REQUIRER_JSON_SCHEMA = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "examples": [
        {
            "unit_name": "web-app-0",
            "sans": ["canonical.com"],
            "cert_requests": [{"common_name": "webapp.canonical.com"}],
        }
    ],
    "properties": {
        "common_name": {
            "type": "string",
            "desctiption": "Server common name",
            "examples": ["canonical.com", "ubuntu.com"],
            "description": "Server common name",
        },
        "sans": {
            "type": "array",
            "description": "Server list of server SAN's (subject alternative names)",
            "examples": [
                [
                    "DNS Name=canonical.com",
                    "DNS Name=www.canonical.com",
                    "DNS Name=www.support.canonical.com",
                ],
                [
                    "DNS Name=ubuntu.com",
                    "DNS Name=www.ubuntu.com",
                    "DNS Name=www.support.ubuntu.com",
                ],
            ],
            "items": {"type": "string"},
        },
        "cert_requests": {
            "type": "array",
            "description": "List of server cert requests",
            "examples": [[{"common_name": "abcd.canonical.com"}]],
            "items": {
                "type": "object",
                "properties": {
                    "sans": {"type": "array", "items": {"type": "string"}},
                    "common_name": {"type": "string"},
                },
                "required": ["common_name"],
            },
        },
        "client_cert_requests": {
            "type": "array",
            "description": "List of client cert requests",
            "examples": [[{"common_name": "abcd.canonical.com"}]],
            "items": {
                "type": "object",
                "properties": {
                    "sans": {"type": "array", "items": {"type": "string"}},
                    "common_name": {"type": "string"},
                },
                "required": ["common_name"],
            },
        },
        "application_cert_requests": {
            "type": "array",
            "description": "List of application cert requests",
            "examples": [[{"common_name": "abcd.canonical.com"}]],
            "items": {
                "type": "object",
                "properties": {
                    "sans": {"type": "array", "items": {"type": "string"}},
                    "common_name": {"type": "string"},
                },
                "required": ["common_name"],
            },
        },
        "unit_name": {
            "examples": ["whatever-operator-0", "whatever-operator-1"],
            "type": "string",
        },
    },
    "required": ["unit_name"],
}

PROVIDER_JSON_SCHEMA = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "description": "The root schema comprises the entire JSON document. It contains the data "
    "bucket content and format for the requirer of the tls-certificates relation "
    "to ask TLS certificates to the provider.",
    "examples": [
        {
            "unit_name": "web-app-0",
            "sans": ["canonical.com"],
            "cert_requests": [{"common_name": "webapp.canonical.com"}],
        }
    ],
    "properties": {
        "common_name": {
            "type": "string",
            "description": "Server common name",
            "examples": ["canonical.com", "ubuntu.com"],
        },
        "sans": {
            "type": "array",
            "description": "List of server SAN's (subject alternative names)",
            "examples": [
                [
                    "DNS Name=canonical.com",
                    "DNS Name=www.canonical.com",
                    "DNS Name=www.support.canonical.com",
                ],
                [
                    "DNS Name=ubuntu.com",
                    "DNS Name=www.ubuntu.com",
                    "DNS Name=www.support.ubuntu.com",
                ],
            ],
            "items": {"type": "string"},
        },
        "cert_requests": {
            "type": "array",
            "description": "List of server cert requests",
            "examples": [[{"common_name": "abcd.canonical.com"}]],
            "items": {
                "type": "object",
                "properties": {
                    "sans": {"type": "array", "items": {"type": "string"}},
                    "common_name": {"type": "string"},
                },
                "required": ["common_name"],
            },
        },
        "client_cert_requests": {
            "type": "array",
            "description": "List of client cert requests",
            "examples": [[{"common_name": "abcd.canonical.com"}]],
            "items": {
                "type": "object",
                "properties": {
                    "sans": {"type": "array", "items": {"type": "string"}},
                    "common_name": {"type": "string"},
                },
                "required": ["common_name"],
            },
        },
        "application_cert_requests": {
            "type": "array",
            "description": "List of application cert requests",
            "examples": [[{"common_name": "abcd.canonical.com"}]],
            "items": {
                "type": "object",
                "properties": {
                    "sans": {"type": "array", "items": {"type": "string"}},
                    "common_name": {"type": "string"},
                },
                "required": ["common_name"],
            },
        },
        "unit_name": {
            "description": "Juju Unit name. Explicit set of unit_name needed to support use of "
            "this interface in cross model contexts.",
            "examples": ["whatever-operator-0", "whatever-operator-1"],
            "type": "string",
        },
    },
    "required": ["unit_name"],
}

logger = logging.getLogger(__name__)


class Cert(TypedDict):
    cert: str
    key: str


class CertificatesAvailableEvent(EventBase):
    def __init__(self, handle, certificates_data: Cert = None):
        super().__init__(handle)
        self.certificates_data = certificates_data


class CertificatesRequestEvent(EventBase):
    def __init__(self, handle, common_name: str, sans: str, cert_type: str):
        super().__init__(handle)
        self.common_name = common_name
        self.sans = sans
        self.cert_type = cert_type


class CARequest(EventBase):
    def __init__(self, handle):
        super().__init__(handle)


def _load_relation_data(raw_relation_data: dict) -> dict:
    certificate_data = dict()
    for key in raw_relation_data:
        try:
            certificate_data[key] = json.loads(raw_relation_data[key])
        except json.decoder.JSONDecodeError:
            certificate_data[key] = raw_relation_data[key]
    return certificate_data


class CertificatesProviderCharmEvents(CharmEvents):
    certificates_request = EventSource(CertificatesRequestEvent)
    ca_request = EventSource(CARequest)


class CertificatesRequirerCharmEvents(CharmEvents):
    certificates_available = EventSource(CertificatesAvailableEvent)


class InsecureCertificatesProvides(Object):
    def __init__(self, charm, relationship_name: str):
        super().__init__(charm, relationship_name)
        self.framework.observe(
            charm.on[relationship_name].relation_changed, self._on_relation_changed
        )
        self.charm = charm
        self.relationship_name = relationship_name

    @staticmethod
    def _relation_data_is_valid(certificates_data: dict) -> bool:
        """
        Uses JSON schema validator to validate relation data content.
        :param certificates_data: Certificate data dictionary as retrieved from relation data.
        :return: True/False depending on whether the relation data follows the json schema.
        """
        try:
            validate(instance=certificates_data, schema=REQUIRER_JSON_SCHEMA)
            return True
        except exceptions.ValidationError:
            return False

    def set_relation_ca(self, ca: str):
        """
        Public method that should be used by the provider charm to set relation CA.
        :param ca: Certificate Authority certificate
        """
        logging.info(f"Setting CA to {ca} for {self.model.unit}")
        certificates_relation = self.model.get_relation(self.relationship_name)
        certificates_relation.data[self.model.unit]["ca"] = str(ca)
        certificates_relation.data[self.model.unit]["chain"] = str(ca)

    def set_relation_certificate(self, common_name: str, certificate: Cert):
        logging.info(f"Setting Certificate to {certificate} for {self.model.unit}")
        certificates_relation = self.model.get_relation(self.relationship_name)
        certificates_relation.data[self.model.unit][common_name] = json.dumps(certificate)

    def _on_relation_changed(self, event):
        relation_data = _load_relation_data(event.relation.data[event.unit])
        if not relation_data:
            logger.info("No relation data - Deferring")
            event.defer()
            return
        if not self._relation_data_is_valid(relation_data):
            logger.info("Relation data did not pass JSON Schema validation - Deferring")
            event.defer()
            return
        self.charm.on.ca_request.emit()
        if relation_data.get("common_name"):
            self.charm.on.certificates_request.emit(
                common_name=relation_data.get("common_name"),
                sans=relation_data.get("sans"),
                cert_type="server",
            )
        for server_cert_request in relation_data.get("cert_requests", {}):
            self.charm.on.certificates_request.emit(
                common_name=server_cert_request.get("common_name"),
                sans=server_cert_request.get("sans"),
                cert_type="server",
            )
        for client_cert_requests in relation_data.get("client_cert_requests", {}):
            self.charm.on.certificates_request.emit(
                common_name=client_cert_requests.get("common_name"),
                sans=client_cert_requests.get("sans"),
                cert_type="client",
            )


class InsecureCertificatesRequires(Object):
    def __init__(
        self,
        charm,
        relationship_name: str,
        common_name: str = None,
        sans: list = None,
    ):
        super().__init__(charm, relationship_name)
        self.framework.observe(
            charm.on[relationship_name].relation_changed, self._on_relation_changed
        )
        self.relationship_name = relationship_name
        self.charm = charm
        self.common_name = common_name
        self.sans = sans

    def request_certificate(
        self,
        cert_type: Literal["client", "server"],
        common_name: str,
        sans: list = None,
    ):
        logger.info("Received request to create certificate")
        relation = self.model.get_relation(self.relationship_name)
        relation_data = _load_relation_data(relation.data[self.model.unit.name])
        certificate_key_mapping = {"client": "client_cert_requests", "server": "cert_requests"}
        new_certificate_request = {"common_name": common_name, "sans": json.dumps(sans)}
        if certificate_key_mapping[cert_type] in relation_data:
            certificate_request_list = relation_data[certificate_key_mapping[cert_type]]
            if new_certificate_request in certificate_request_list:
                logger.info("Request was already made - Doing nothing")
                return
            certificate_request_list.append(new_certificate_request)
        else:
            certificate_request_list = [new_certificate_request]
        relation.data[self.model.unit.name][certificate_key_mapping[cert_type]] = json.dumps(
            certificate_request_list
        )
        logger.info("Certificate request sent to provider")

    @staticmethod
    def _relation_data_is_valid(certificates_data: dict) -> bool:
        try:
            validate(instance=certificates_data, schema=PROVIDER_JSON_SCHEMA)
            return True
        except exceptions.ValidationError:
            return False

    def _on_relation_changed(self, event):
        if self.model.unit.is_leader():
            logger.info("relation data: %s", repr(event.relation.data[event.unit]))
            relation_data = _load_relation_data(event.relation.data[event.unit])
            if not self._relation_data_is_valid(relation_data):
                logger.info("Relation data did not pass JSON Schema validation - Deferring")
                event.defer()
                return
            certificates = event.relation.data[event.app].get(self.common_name)
            event.relation.data[self.model.unit]["common_name"] = self.common_name
            event.relation.data[self.model.unit]["unit_name"] = self.model.unit.name
            event.relation.data[self.model.unit]["sans"] = json.dumps(self.sans)
            if certificates:
                self.charm.on.certificates_available.emit(
                    certificates_data=Cert(cert=certificates["cert"], key=certificates["key"])
                )
