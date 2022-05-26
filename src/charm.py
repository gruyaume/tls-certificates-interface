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
        self.insecure_certificates = InsecureCertificatesProvides(self, "certificates")

    def _on_certificate_request(self, event):
        common_name = event.common_name
        sans = event.sans
        cert_type = event.cert_type
        certificate = self._generate_certificate(common_name, sans, cert_type)

        self.insecure_certificates.set_relation_certificate(certificate=certificate)

    def _generate_certificate(self, common_name: str, sans: list, cert_type: str) -> Cert:
        return Cert(
            common_name=common_name, cert="whatever cert", key="whatever key", ca="whatever ca"
        )


class ExampleRequirerCharm(CharmBase):
    on = CertificatesRequirerCharmEvents()

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.certificate_available, self._on_certificate_available)
        self.insecure_certificates = InsecureCertificatesRequires(self, "certificates")
        self.insecure_certificates.request_certificate(
            cert_type="client",
            common_name="whatever common name",
        )

    def _on_certificate_available(self, event):
        certificate_data = event.certificate_data
        print(certificate_data["common_name"])
        print(certificate_data["key"])
        print(certificate_data["ca"])
        print(certificate_data["cert"])
