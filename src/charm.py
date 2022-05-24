#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.


from charms.tls_certificates_interface.v0.tls_certificates import (
    Cert,
    CertificatesProviderCharmEvents,
    CertificatesRequirerCharmEvents,
    InsecureCertificatesProvides,
    InsecureCertificatesRequires,
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
