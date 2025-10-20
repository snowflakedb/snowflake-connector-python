#!/usr/bin/env python
from __future__ import annotations

import logging
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import Mock
from unittest.mock import patch as mock_patch

import pytest
import responses
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from snowflake.connector.crl import (
    CertRevocationCheckMode,
    CRLConfig,
    CRLValidationResult,
    CRLValidator,
)
from snowflake.connector.crl_cache import CRLCacheEntry, CRLCacheManager
from snowflake.connector.session_manager import SessionManager


@pytest.fixture
def session_manager() -> SessionManager | Any:
    """For testing purposes we mock SessionManager instances with `requests` module
    to use `responses` module for mocking HTTP responses.
    """
    import requests

    return requests


@pytest.fixture(scope="module")
def crl_urls():
    @dataclass
    class CRLUrls:
        _base_url = "http://localhost:43210"
        primary_ca = _base_url + "/primary-ca.crl"
        backup_ca = _base_url + "/backup-ca.crl"
        test_ca = _base_url + "/test-ca.crl"
        invalid_ca = _base_url + "/invalid-ca.crl"
        valid_ca = _base_url + "/valid-ca.crl"
        expired_ca = _base_url + "/expired-ca.crl"

    return CRLUrls()


@dataclass
class CertificateChain:
    """Container for certificate chain components"""

    root_cert: x509.Certificate
    intermediate_cert: x509.Certificate
    leaf_cert: x509.Certificate


@dataclass
class CrossSignedCertificateChain:
    #        CA
    #     /     \
    #  rootA   rootB
    #   /            \
    #  A --(AsignB)--> B
    #    <-(BsignA)--
    #     \       /
    #    leafA leafB
    #        \   /
    #       leaf_ca
    #          |
    #       subject

    rootA: x509.Certificate
    rootB: x509.Certificate
    AsignB: x509.Certificate
    BsignA: x509.Certificate
    leafA: x509.Certificate
    leafB: x509.Certificate
    final_cert: x509.Certificate


@pytest.fixture(scope="module")
def cert_gen():
    class CertificateGeneratorUtil:
        """Utility class for generating test certificates - simplified Python version"""

        def __init__(self):
            self.random = random.Random()
            self.ca_private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=default_backend()
            )
            self.ca_certificate = self._create_ca_certificate()
            self.revoked_serial_numbers = set()

        def _create_ca_certificate(self) -> x509.Certificate:
            """Create a CA certificate for signing other certificates"""
            ca_name = x509.Name(
                [
                    x509.NameAttribute(
                        NameOID.COMMON_NAME, f"Test CA {self.random.randint(1, 10000)}"
                    )
                ]
            )

            ca_cert = (
                x509.CertificateBuilder()
                .subject_name(ca_name)
                .issuer_name(ca_name)  # Self-signed
                .public_key(self.ca_private_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.now(timezone.utc))
                .not_valid_after(
                    datetime.now(timezone.utc) + timedelta(days=3650)  # 10 years
                )
                .add_extension(
                    x509.BasicConstraints(ca=True, path_length=None),
                    critical=True,
                )
                .add_extension(
                    x509.KeyUsage(
                        key_cert_sign=True,
                        crl_sign=True,
                        digital_signature=False,
                        key_encipherment=False,
                        key_agreement=False,
                        content_commitment=False,
                        data_encipherment=False,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
                .sign(self.ca_private_key, hashes.SHA256(), backend=default_backend())
            )

            return ca_cert

        def generate_valid_crl(self) -> bytes:
            """Generate a valid CRL"""
            builder = x509.CertificateRevocationListBuilder()
            builder = builder.issuer_name(self.ca_certificate.subject)
            builder = builder.last_update(datetime.now(timezone.utc))
            builder = builder.next_update(
                datetime.now(timezone.utc) + timedelta(days=1)
            )

            # Add any revoked certificates
            for serial_number in self.revoked_serial_numbers:
                revoked_cert = (
                    x509.RevokedCertificateBuilder()
                    .serial_number(serial_number)
                    .revocation_date(datetime.now(timezone.utc))
                    .build()
                )
                builder = builder.add_revoked_certificate(revoked_cert)

            crl = builder.sign(
                self.ca_private_key, hashes.SHA256(), backend=default_backend()
            )
            return crl.public_bytes(serialization.Encoding.DER)

        def generate_expired_crl(self) -> bytes:
            """Generate an expired CRL"""
            builder = x509.CertificateRevocationListBuilder()
            builder = builder.issuer_name(self.ca_certificate.subject)
            # Set dates in the past to make it expired
            past_date = datetime.now(timezone.utc) - timedelta(days=2)
            builder = builder.last_update(past_date - timedelta(days=1))
            builder = builder.next_update(past_date)  # Already expired

            crl = builder.sign(
                self.ca_private_key, hashes.SHA256(), backend=default_backend()
            )
            return crl.public_bytes(serialization.Encoding.DER)

        def create_simple_chain(self) -> CertificateChain:
            """Create a simple certificate chain for testing"""
            # Generate key pairs
            root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            intermediate_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048
            )
            leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

            # Create root certificate (self-signed)
            root_name = x509.Name(
                [
                    x509.NameAttribute(
                        NameOID.COMMON_NAME,
                        f"Test Root CA {self.random.randint(1, 10000)}",
                    )
                ]
            )

            root_cert = (
                x509.CertificateBuilder()
                .subject_name(root_name)
                .issuer_name(root_name)
                .public_key(root_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.now(timezone.utc))
                .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
                .add_extension(
                    x509.BasicConstraints(ca=True, path_length=None),
                    critical=True,
                )
                .sign(root_key, hashes.SHA256())
            )

            # Create intermediate certificate
            intermediate_name = x509.Name(
                [
                    x509.NameAttribute(
                        NameOID.COMMON_NAME,
                        f"Test Intermediate CA {self.random.randint(1, 10000)}",
                    )
                ]
            )

            intermediate_cert = (
                x509.CertificateBuilder()
                .subject_name(intermediate_name)
                .issuer_name(root_name)
                .public_key(intermediate_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.now(timezone.utc))
                .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
                .add_extension(
                    x509.BasicConstraints(ca=True, path_length=0),
                    critical=True,
                )
                .sign(root_key, hashes.SHA256())
            )

            # Create leaf certificate
            leaf_name = x509.Name(
                [
                    x509.NameAttribute(
                        NameOID.COMMON_NAME,
                        f"Test Leaf {self.random.randint(1, 10000)}",
                    )
                ]
            )

            leaf_cert = (
                x509.CertificateBuilder()
                .subject_name(leaf_name)
                .issuer_name(intermediate_name)
                .public_key(leaf_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.now(timezone.utc))
                .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
                .add_extension(
                    x509.BasicConstraints(ca=False, path_length=None),
                    critical=True,
                )
                .sign(intermediate_key, hashes.SHA256())
            )

            return CertificateChain(root_cert, intermediate_cert, leaf_cert)

        def create_cross_signed_chain(self) -> CrossSignedCertificateChain:
            A_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            B_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

            A_name = x509.Name(
                [
                    x509.NameAttribute(
                        NameOID.COMMON_NAME,
                        f"Test CA A {self.random.randint(1, 10000)}",
                    )
                ]
            )
            B_name = x509.Name(
                [
                    x509.NameAttribute(
                        NameOID.COMMON_NAME,
                        f"Test CA B {self.random.randint(1, 10000)}",
                    )
                ]
            )
            leaf_name = x509.Name(
                [
                    x509.NameAttribute(
                        NameOID.COMMON_NAME,
                        f"Test CA Leaf {self.random.randint(1, 10000)}",
                    )
                ]
            )
            subject_name = x509.Name(
                [
                    x509.NameAttribute(
                        NameOID.COMMON_NAME,
                        f"Test Subject {self.random.randint(1, 10000)}",
                    )
                ]
            )
            rootA_cert = (
                x509.CertificateBuilder()
                .subject_name(A_name)
                .issuer_name(self.ca_certificate.subject)
                .public_key(A_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.now(timezone.utc))
                .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
                .add_extension(
                    x509.BasicConstraints(ca=True, path_length=None),
                    critical=True,
                )
                .sign(self.ca_private_key, hashes.SHA256())
            )
            rootB_cert = (
                x509.CertificateBuilder()
                .subject_name(B_name)
                .issuer_name(self.ca_certificate.subject)
                .public_key(B_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.now(timezone.utc))
                .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
                .add_extension(
                    x509.BasicConstraints(ca=True, path_length=None),
                    critical=True,
                )
                .sign(self.ca_private_key, hashes.SHA256())
            )
            BsignA_cert = (
                x509.CertificateBuilder()
                .subject_name(A_name)
                .issuer_name(B_name)
                .public_key(A_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.now(timezone.utc))
                .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
                .add_extension(
                    x509.BasicConstraints(ca=True, path_length=None),
                    critical=True,
                )
                .sign(B_key, hashes.SHA256())
            )
            AsignB_cert = (
                x509.CertificateBuilder()
                .subject_name(B_name)
                .issuer_name(A_name)
                .public_key(B_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.now(timezone.utc))
                .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
                .add_extension(
                    x509.BasicConstraints(ca=True, path_length=None),
                    critical=True,
                )
                .sign(A_key, hashes.SHA256())
            )
            leafA_cert = (
                x509.CertificateBuilder()
                .subject_name(leaf_name)
                .issuer_name(A_name)
                .public_key(leaf_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.now(timezone.utc))
                .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
                .add_extension(
                    x509.BasicConstraints(ca=True, path_length=None),
                    critical=True,
                )
                .sign(A_key, hashes.SHA256())
            )
            leafB_cert = (
                x509.CertificateBuilder()
                .subject_name(leaf_name)
                .issuer_name(B_name)
                .public_key(leaf_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.now(timezone.utc))
                .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
                .add_extension(
                    x509.BasicConstraints(ca=True, path_length=None),
                    critical=True,
                )
                .sign(B_key, hashes.SHA256())
            )
            final_cert = (
                x509.CertificateBuilder()
                .subject_name(subject_name)
                .issuer_name(leaf_name)
                .public_key(subject_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.now(timezone.utc))
                .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
                .add_extension(
                    x509.BasicConstraints(ca=False, path_length=None),
                    critical=True,
                )
                .sign(leaf_key, hashes.SHA256())
            )
            return CrossSignedCertificateChain(
                rootA_cert,
                rootB_cert,
                AsignB_cert,
                BsignA_cert,
                leafA_cert,
                leafB_cert,
                final_cert,
            )

        def create_short_lived_certificate(
            self, validity_days: int, issuance_date: datetime
        ) -> x509.Certificate:
            """Create a short-lived certificate for testing"""
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

            name = x509.Name(
                [
                    x509.NameAttribute(
                        NameOID.COMMON_NAME,
                        f"Test Short-Lived {self.random.randint(1, 10000)}",
                    )
                ]
            )

            not_after = issuance_date + timedelta(days=validity_days)

            cert = (
                x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(self.ca_certificate.subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(issuance_date)
                .not_valid_after(not_after)
                .add_extension(
                    x509.BasicConstraints(ca=False, path_length=None),
                    critical=True,
                )
                .sign(self.ca_private_key, hashes.SHA256(), backend=default_backend())
            )

            return cert

        def create_certificate_with_crl_distribution_points(
            self, subject_dn: str, crl_urls: list[str]
        ) -> x509.Certificate:
            """Create a certificate with CRL distribution points"""

            # Generate a new key pair for this certificate
            cert_private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=default_backend()
            )

            subject_name = x509.Name(
                [x509.NameAttribute(NameOID.COMMON_NAME, subject_dn)]
            )

            # Create certificate builder
            builder = (
                x509.CertificateBuilder()
                .subject_name(subject_name)
                .issuer_name(self.ca_certificate.subject)
                .public_key(cert_private_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.now(timezone.utc))
                .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
                .add_extension(
                    x509.BasicConstraints(ca=False, path_length=None),
                    critical=False,
                )
            )

            # Add CRL distribution points if URLs provided
            if crl_urls:
                distribution_points = []
                for url in crl_urls:
                    distribution_point = x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(url)],
                        relative_name=None,
                        crl_issuer=None,
                        reasons=None,
                    )
                    distribution_points.append(distribution_point)

                crl_distribution_points = x509.CRLDistributionPoints(
                    distribution_points
                )
                builder = builder.add_extension(crl_distribution_points, critical=False)

            # Sign the certificate with CA private key
            certificate = builder.sign(
                self.ca_private_key, hashes.SHA256(), backend=default_backend()
            )

            return certificate

        def generate_crl_with_revoked_certificate(self, serial_number: int) -> bytes:
            """Generate a CRL with a specific certificate marked as revoked"""
            self.revoked_serial_numbers.add(serial_number)
            return self.generate_valid_crl()

    return CertificateGeneratorUtil()


def test_should_allow_connection_when_crl_validation_disabled(
    cert_gen, session_manager
):
    """Test that connections are allowed when CRL validation is disabled"""
    chain = cert_gen.create_simple_chain()
    chains = [[chain.leaf_cert, chain.intermediate_cert, chain.root_cert]]

    validator = CRLValidator(
        session_manager,
        cert_revocation_check_mode=CertRevocationCheckMode.DISABLED,
        trusted_certificates=[chain.root_cert],
    )

    assert validator.validate_certificate_chains(chains)


def test_should_allow_connection_when_crl_validation_disabled_and_no_cert_chain(
    session_manager,
):
    validator = CRLValidator(
        session_manager,
        cert_revocation_check_mode=CertRevocationCheckMode.DISABLED,
        trusted_certificates=[],
    )
    assert validator.validate_certificate_chains([])
    assert validator.validate_certificate_chains(None)


def test_should_fail_with_null_or_empty_certificate_chains(cert_gen, session_manager):
    """Test that validator fails with null or empty certificate chains"""
    validator = CRLValidator(
        session_manager,
        cert_revocation_check_mode=CertRevocationCheckMode.ENABLED,
        trusted_certificates=[],
    )
    assert not validator.validate_certificate_chains([])
    assert not validator.validate_certificate_chains(None)


def test_should_handle_certificates_without_crl_urls_in_enabled_mode(
    cert_gen, session_manager
):
    """Test handling of certificates without CRL URLs in enabled mode"""
    chain = cert_gen.create_simple_chain()
    chains = [[chain.leaf_cert, chain.intermediate_cert, chain.root_cert]]
    validator = CRLValidator(
        session_manager,
        cert_revocation_check_mode=CertRevocationCheckMode.ENABLED,
        allow_certificates_without_crl_url=False,
        trusted_certificates=[chain.root_cert],
    )
    assert not validator.validate_certificate_chains(chains)


def test_should_allow_certificates_without_crl_urls_when_configured(
    cert_gen, session_manager
):
    """Test that certificates without CRL URLs are allowed when configured"""
    chain = cert_gen.create_simple_chain()
    chains = [[chain.leaf_cert, chain.intermediate_cert, chain.root_cert]]

    validator = CRLValidator(
        session_manager,
        cert_revocation_check_mode=CertRevocationCheckMode.ENABLED,
        allow_certificates_without_crl_url=True,
        trusted_certificates=[chain.root_cert],
    )
    assert validator.validate_certificate_chains(chains)


def test_should_pass_in_advisory_mode_even_with_errors(cert_gen, session_manager):
    """Test that validation passes in advisory mode even with errors"""
    chain = cert_gen.create_simple_chain()
    chains = [[chain.leaf_cert, chain.intermediate_cert, chain.root_cert]]

    validator = CRLValidator(
        session_manager,
        cert_revocation_check_mode=CertRevocationCheckMode.ADVISORY,
        trusted_certificates=[chain.root_cert],
    )

    assert validator.validate_certificate_chains(chains)


def test_should_validate_multiple_chains_and_return_first_valid_with_no_crl_urls(
    cert_gen, session_manager
):
    """Test validation of multiple chains and return first valid"""
    # Create a certificate that would be considered invalid (before March 2024)
    before_march_2024 = datetime(2024, 2, 1, tzinfo=timezone.utc)
    invalid_cert = cert_gen.create_short_lived_certificate(5, before_march_2024)

    # Create a valid chain
    valid_chain = cert_gen.create_simple_chain()

    # Create list with invalid chain first, then valid chain
    chains = [
        [invalid_cert, valid_chain.intermediate_cert, valid_chain.root_cert],
        [valid_chain.leaf_cert, valid_chain.intermediate_cert, valid_chain.root_cert],
    ]

    validator = CRLValidator(
        session_manager,
        cert_revocation_check_mode=CertRevocationCheckMode.ENABLED,
        allow_certificates_without_crl_url=True,
        trusted_certificates=[valid_chain.root_cert],
    )

    result = validator.validate_certificate_chains(chains)
    assert result, "Should return true when at least one valid chain is found"


def test_cross_signed_certificate_chain(cert_gen, session_manager):
    """Test validation of cross-signed certificate chain"""
    chain = cert_gen.create_cross_signed_chain()
    validator = CRLValidator(
        session_manager,
        cert_revocation_check_mode=CertRevocationCheckMode.ENABLED,
        allow_certificates_without_crl_url=True,
        trusted_certificates=[cert_gen.ca_certificate],
    )

    # provide full chain in arbitrary order
    chains = [
        [
            chain.final_cert,
            chain.AsignB,
            chain.leafA,
            chain.leafB,
            chain.BsignA,
            chain.rootB,
            chain.rootA,
        ]
    ]
    assert validator.validate_certificate_chains(chains)

    # only A is signed by CA
    chains = [
        [
            chain.final_cert,
            chain.leafA,
            chain.AsignB,
            chain.leafB,
            chain.BsignA,
            # chain.rootB,
            chain.rootA,
        ]
    ]
    assert validator.validate_certificate_chains(chains)

    # nor A nor B is signed by CA
    chains = [
        [
            chain.final_cert,
            chain.leafA,
            chain.AsignB,
            chain.leafB,
            chain.BsignA,
            # chain.rootB,
            # chain.rootA,
        ]
    ]
    assert not validator.validate_certificate_chains(chains)

    # mingled A and B paths passed in one chain - A has no connection to CA, B has
    chains = [
        [
            chain.final_cert,
            chain.leafA,
            chain.AsignB,
            chain.leafB,
            # chain.BsignA,
            chain.rootB,
            # chain.rootA,
        ]
    ]
    assert validator.validate_certificate_chains(chains)


def test_starfield_incident(cert_gen, session_manager):
    # leaf is signed by A, who is signed by CA (revoked) and B, who is also a trusted CA
    chain = cert_gen.create_cross_signed_chain()
    validator = CRLValidator(
        session_manager,
        cert_revocation_check_mode=CertRevocationCheckMode.ENABLED,
        trusted_certificates=[cert_gen.ca_certificate, chain.rootB],
    )

    def mock_validate(cert, _):
        if cert == chain.rootA:
            return CRLValidationResult.REVOKED
        return CRLValidationResult.UNREVOKED

    validator._validate_certificate_is_not_revoked = mock_validate

    assert (
        validator._validate_single_chain([chain.leafA, chain.BsignA, chain.rootA])
        == CRLValidationResult.UNREVOKED
    )


def test_validate_single_chain(cert_gen, session_manager):
    chain = cert_gen.create_cross_signed_chain()
    validator = CRLValidator(
        session_manager,
        cert_revocation_check_mode=CertRevocationCheckMode.ENABLED,
        trusted_certificates=[cert_gen.ca_certificate],
    )

    input_chain = [chain.final_cert, chain.leafA, chain.leafB, chain.rootA, chain.rootB]

    # case 1: at least one valid path
    def mock_validate_with_special_cert(revoked_cert, error_result):
        validator._validate_certificate_is_not_revoked_with_cache = lambda cert, _: (
            error_result if cert == revoked_cert else CRLValidationResult.UNREVOKED
        )

    for error_result in [CRLValidationResult.ERROR, CRLValidationResult.REVOKED]:
        for revoked_cert in [chain.rootA, chain.rootB, chain.leafA, chain.leafB]:
            mock_validate_with_special_cert(revoked_cert, error_result)
            assert (
                validator._validate_single_chain(input_chain)
                == CRLValidationResult.UNREVOKED
            )

    # case 2: all paths revoked
    def mock_validate(cert, _):
        if cert in [chain.rootA, chain.rootB]:
            return CRLValidationResult.REVOKED
        return CRLValidationResult.UNREVOKED

    validator._validate_certificate_is_not_revoked_with_cache = mock_validate
    assert validator._validate_single_chain(input_chain) == CRLValidationResult.REVOKED

    # case 3: revoked + error should result in revoked\
    def mock_validate(cert, _):
        if cert in [chain.rootA, chain.leafB]:
            return CRLValidationResult.REVOKED
        return CRLValidationResult.ERROR

    validator._validate_certificate_is_not_revoked_with_cache = mock_validate
    assert validator._validate_single_chain(input_chain) == CRLValidationResult.REVOKED

    # case 4: no path to trusted certificate
    def mock_validate(cert, _):
        return CRLValidationResult.UNREVOKED

    validator._validate_certificate_is_not_revoked_with_cache = mock_validate
    assert (
        validator._validate_single_chain(
            [chain.final_cert, chain.leafA, chain.leafB, chain.AsignB, chain.BsignA]
        )
        == CRLValidationResult.ERROR
    )

    # case 5: only unrevoked path has an error
    def mock_validate(cert, _):
        if cert in [chain.rootA, chain.leafB]:
            return CRLValidationResult.REVOKED
        if cert == chain.BsignA:
            return CRLValidationResult.ERROR
        return CRLValidationResult.UNREVOKED

    validator._validate_certificate_is_not_revoked_with_cache = mock_validate
    assert (
        validator._validate_single_chain(
            [
                chain.final_cert,
                chain.leafA,
                chain.rootA,
                chain.leafB,
                chain.rootB,
                chain.BsignA,
            ]
        )
        == CRLValidationResult.ERROR
    )


@responses.activate
def test_should_validate_non_revoked_certificate_successfully(
    cert_gen, crl_urls, session_manager
):
    """Test validation of non-revoked certificate"""
    # Setup mock HTTP client
    crl_content = cert_gen.generate_valid_crl()
    resp = responses.add(
        responses.GET,
        crl_urls.test_ca,
        body=crl_content,
        status=200,
        content_type="application/pkcs7-mime",
    )

    # Create certificate with CRL distribution point
    cert = cert_gen.create_certificate_with_crl_distribution_points(
        "CN=Test Server", [crl_urls.test_ca]
    )
    chain = [cert, cert_gen.ca_certificate]

    validator = CRLValidator(
        session_manager,
        cert_revocation_check_mode=CertRevocationCheckMode.ENABLED,
        trusted_certificates=[cert_gen.ca_certificate],
    )

    assert validator.validate_certificate_chains([chain])
    assert resp.call_count


@responses.activate
def test_should_validate_non_revoked_certificate_successfully_if_root_not_provided_on_chain(
    cert_gen, crl_urls, session_manager
):
    """Test validation of non-revoked certificate"""
    # Setup mock HTTP client
    crl_content = cert_gen.generate_valid_crl()
    resp = responses.add(
        responses.GET,
        crl_urls.test_ca,
        body=crl_content,
        status=200,
        content_type="application/pkcs7-mime",
    )

    # Create certificate with CRL distribution point
    cert = cert_gen.create_certificate_with_crl_distribution_points(
        "CN=Test Server", [crl_urls.test_ca]
    )
    chain = [cert]

    validator = CRLValidator(
        session_manager,
        cert_revocation_check_mode=CertRevocationCheckMode.ENABLED,
        trusted_certificates=[cert_gen.ca_certificate],
    )

    assert validator.validate_certificate_chains([chain])
    assert resp.call_count


@responses.activate
def test_should_fail_for_revoked_certificate(cert_gen, crl_urls, session_manager):
    """Test failure for revoked certificate"""
    # Create certificate first
    cert = cert_gen.create_certificate_with_crl_distribution_points(
        "CN=Revoked Server", [crl_urls.test_ca]
    )

    # mock a CRL with the cert as revoked
    resp = responses.add(
        responses.GET,
        crl_urls.test_ca,
        body=cert_gen.generate_crl_with_revoked_certificate(cert.serial_number),
        status=200,
        content_type="application/pkcs7-mime",
    )

    chain = [cert, cert_gen.ca_certificate]

    validator = CRLValidator(
        session_manager,
        cert_revocation_check_mode=CertRevocationCheckMode.ENABLED,
        trusted_certificates=[cert_gen.ca_certificate],
    )

    assert not validator.validate_certificate_chains([chain])
    assert resp.call_count


@responses.activate
def test_should_allow_revoked_certificate_when_crl_validation_disabled(
    cert_gen, crl_urls, session_manager
):
    """Test that revoked certificates are allowed when CRL validation is disabled"""
    # Create certificate first
    revoked_cert = cert_gen.create_certificate_with_crl_distribution_points(
        "CN=Revoked Server (Disabled Mode)", [crl_urls.test_ca]
    )
    # A mock response, which is expected not to be hit
    resp = responses.add(
        responses.GET,
        crl_urls.test_ca,
        body=cert_gen.generate_crl_with_revoked_certificate(revoked_cert.serial_number),
        status=200,
        content_type="application/pkcs7-mime",
    )

    chain = [revoked_cert, cert_gen.ca_certificate]

    validator = CRLValidator(
        session_manager,
        cert_revocation_check_mode=CertRevocationCheckMode.DISABLED,
        trusted_certificates=[cert_gen.ca_certificate],
    )

    assert validator.validate_certificate_chains([chain])
    assert resp.call_count == 0


@responses.activate
def test_should_pass_in_advisory_mode_with_crl_errors(
    cert_gen, crl_urls, session_manager
):
    """Test that advisory mode passes even with CRL errors"""
    # Setup 404 response for CRL
    resp = responses.add(responses.GET, crl_urls.test_ca, status=404)

    cert = cert_gen.create_certificate_with_crl_distribution_points(
        "CN=Test Server", [crl_urls.test_ca]
    )
    chain = [cert, cert_gen.ca_certificate]

    validator = CRLValidator(
        session_manager,
        cert_revocation_check_mode=CertRevocationCheckMode.ADVISORY,
        trusted_certificates=[cert_gen.ca_certificate],
    )

    assert validator.validate_certificate_chains([chain])
    assert resp.call_count


@responses.activate
def test_should_fail_in_enabled_mode_with_crl_errors(
    cert_gen, crl_urls, session_manager
):
    """Test that enabled mode fails with CRL errors"""
    # Setup 404 response for CRL
    resp = responses.add(responses.GET, crl_urls.test_ca, status=404)

    cert = cert_gen.create_certificate_with_crl_distribution_points(
        "CN=Test Server", [crl_urls.test_ca]
    )
    chain = [cert, cert_gen.ca_certificate]

    validator = CRLValidator(
        session_manager,
        cert_revocation_check_mode=CertRevocationCheckMode.ENABLED,
        trusted_certificates=[cert_gen.ca_certificate],
    )

    assert not validator.validate_certificate_chains([chain])
    assert resp.call_count


@responses.activate
def test_should_validate_multiple_chains_and_success_if_just_one_valid(
    cert_gen, crl_urls, session_manager
):
    """Test validation of multiple chains and return first valid"""
    # Create certificates
    invalid_cert = cert_gen.create_certificate_with_crl_distribution_points(
        "CN=Invalid Server", [crl_urls.invalid_ca]
    )
    invalid_chain = [invalid_cert, cert_gen.ca_certificate]

    valid_cert = cert_gen.create_certificate_with_crl_distribution_points(
        "CN=Valid Server", [crl_urls.valid_ca]
    )
    valid_chain = [valid_cert, cert_gen.ca_certificate]

    valid_crl_content = cert_gen.generate_valid_crl()

    resp_200 = responses.add(
        responses.GET,
        crl_urls.valid_ca,
        body=valid_crl_content,
        status=200,
        content_type="application/pkcs7-mime",
    )

    # Setup 404 for invalid certificate CRL
    resp_404 = responses.add(responses.GET, crl_urls.invalid_ca, status=404)

    validator = CRLValidator(
        session_manager,
        cert_revocation_check_mode=CertRevocationCheckMode.ENABLED,
        trusted_certificates=[cert_gen.ca_certificate],
    )

    assert validator.validate_certificate_chains([invalid_chain, valid_chain])
    assert resp_200.call_count
    assert resp_404.call_count


@responses.activate
def test_should_reject_expired_crl(cert_gen, crl_urls, session_manager):
    """Test rejection of expired CRL"""
    # Setup mock HTTP client with expired CRL
    resp = responses.add(
        responses.GET,
        crl_urls.expired_ca,
        body=cert_gen.generate_expired_crl(),
        status=200,
        content_type="application/pkcs7-mime",
    )

    cert = cert_gen.create_certificate_with_crl_distribution_points(
        "CN=Test Server", [crl_urls.expired_ca]
    )
    chain = [cert, cert_gen.ca_certificate]

    validator = CRLValidator(
        session_manager,
        cert_revocation_check_mode=CertRevocationCheckMode.ENABLED,
        trusted_certificates=[cert_gen.ca_certificate],
    )

    assert not validator.validate_certificate_chains([chain])
    assert resp.call_count


def test_should_skip_short_lived_certificates(cert_gen, session_manager):
    """Test that short-lived certificates skip CRL validation"""
    # Create short-lived certificate (5 days validity)
    short_lived_cert = cert_gen.create_short_lived_certificate(
        5, datetime.now(timezone.utc)
    )
    chain = [short_lived_cert, cert_gen.ca_certificate]

    validator = CRLValidator(
        session_manager,
        cert_revocation_check_mode=CertRevocationCheckMode.ENABLED,
        trusted_certificates=[cert_gen.ca_certificate],
    )

    # Should pass without any HTTP calls (no responses setup)
    assert validator.validate_certificate_chains([chain])


@responses.activate
def test_should_handle_multiple_crl_distribution_points(
    cert_gen, crl_urls, session_manager
):
    """Test handling of multiple CRL distribution points"""
    crl_content = cert_gen.generate_valid_crl()
    # Setup mock HTTP that returns valid CRL for both URLs
    resp_primary = responses.add(
        responses.GET,
        crl_urls.primary_ca,
        body=crl_content,
        status=200,
        content_type="application/pkcs7-mime",
    )
    resp_backup = responses.add(
        responses.GET,
        crl_urls.backup_ca,
        body=crl_content,
        status=200,
        content_type="application/pkcs7-mime",
    )

    # Create certificate with multiple CRL URLs
    crl_urls_list = [
        crl_urls.primary_ca,
        crl_urls.backup_ca,
    ]
    cert = cert_gen.create_certificate_with_crl_distribution_points(
        "CN=Multi-CRL Server", crl_urls_list
    )
    chain = [cert, cert_gen.ca_certificate]

    validator = CRLValidator(
        session_manager,
        cert_revocation_check_mode=CertRevocationCheckMode.ENABLED,
        trusted_certificates=[cert_gen.ca_certificate],
    )

    assert validator.validate_certificate_chains([chain])
    assert resp_primary.call_count
    assert resp_backup.call_count


def test_crl_validator_creation(session_manager):
    """Test that CRLValidator can be created properly"""

    # Test basic instantiation
    validator = CRLValidator(session_manager, trusted_certificates=[])
    assert validator is not None
    assert isinstance(validator, CRLValidator)

    # Test that it works with from_config class method
    validator = CRLValidator.from_config(
        CRLConfig(), session_manager, trusted_certificates=[]
    )
    assert validator is not None
    assert isinstance(validator, CRLValidator)


def test_crl_validator_atexit_cleanup(session_manager):
    """Test that CRLValidator properly starts cleanup with atexit handler"""
    from snowflake.connector.crl_cache import CRLCacheFactory

    # Create a config with cleanup enabled
    config = CRLConfig(
        enable_crl_cache=True,
        crl_cache_start_cleanup=True,  # This will start background cleanup
        crl_cache_cleanup_interval_hours=1,
    )

    try:
        # Create validator which should start cleanup
        CRLValidator.from_config(config, session_manager, trusted_certificates=[])

        # Verify cleanup is running through factory
        assert CRLCacheFactory.is_periodic_cleanup_running()

        # Verify atexit handler was registered
        assert CRLCacheFactory._atexit_registered

        # Test the atexit handler directly
        CRLCacheFactory._atexit_cleanup_handler()

        # After calling atexit handler, cleanup should be stopped
        assert not CRLCacheFactory.is_periodic_cleanup_running()
    finally:
        # Ensure cleanup is stopped for other tests
        CRLCacheFactory.reset()


def test_crl_validator_validate_connection(session_manager):
    """Test the validate_connection method"""
    # Create a mock connection
    mock_connection = Mock()

    # Test with no certificate chain
    mock_connection.get_peer_cert_chain.return_value = []
    validator = CRLValidator(session_manager, trusted_certificates=[])

    # Should return True when disabled (default)
    assert validator.validate_connection(mock_connection)

    # Test with enabled mode and no certificates
    validator = CRLValidator(
        session_manager,
        cert_revocation_check_mode=CertRevocationCheckMode.ENABLED,
        trusted_certificates=[],
    )
    assert not validator.validate_connection(mock_connection)


def test_crl_validator_extract_certificate_chains_from_connection(
    cert_gen, session_manager
):
    """Test the _extract_certificate_chains_from_connection method"""
    chain = cert_gen.create_simple_chain()

    validator = CRLValidator(session_manager, trusted_certificates=[chain.root_cert])

    # Test with no certificate chain
    mock_connection = Mock()
    mock_connection.get_peer_cert_chain.return_value = []

    chains = validator._extract_certificate_chains_from_connection(mock_connection)
    assert chains == []

    # Test with mock certificate chain
    mock_certs = []

    # Create mock OpenSSL certificates
    for cert in [chain.leaf_cert, chain.intermediate_cert, chain.root_cert]:
        mock_openssl_cert = Mock()
        # Mock the dump_certificate call to return the DER bytes
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        mock_certs.append((mock_openssl_cert, cert_der))

    mock_connection.get_peer_cert_chain.return_value = [cert[0] for cert in mock_certs]

    # Mock dump_certificate to return the appropriate DER data
    def mock_dump_certificate(file_type, cert_openssl):
        for mock_cert, der_data in mock_certs:
            if mock_cert == cert_openssl:
                return der_data
        raise ValueError("Certificate not found")

    # Patch dump_certificate from OpenSSL.crypto module
    from unittest.mock import patch

    with patch("OpenSSL.crypto.dump_certificate", side_effect=mock_dump_certificate):
        chains = validator._extract_certificate_chains_from_connection(mock_connection)

    assert len(chains) == 1
    assert len(chains[0]) == 3  # leaf, intermediate, root


# New comprehensive tests for CRLConfig.from_connection
def test_crl_config_from_connection_disabled_mode():
    """Test CRLConfig.from_connection with DISABLED mode"""
    # from unittest.mock import Mock

    mock_connection = Mock()
    mock_connection.cert_revocation_check_mode = "DISABLED"
    mock_connection.allow_certificates_without_crl_url = None
    mock_connection.crl_connection_timeout_ms = None
    mock_connection.crl_read_timeout_ms = None
    mock_connection.crl_cache_validity_hours = None
    mock_connection.enable_crl_cache = None
    mock_connection.enable_crl_file_cache = None
    mock_connection.crl_cache_dir = None
    mock_connection.crl_cache_removal_delay_days = None
    mock_connection.crl_cache_cleanup_interval_hours = None
    mock_connection.crl_cache_start_cleanup = None

    config = CRLConfig.from_connection(mock_connection)

    assert config.cert_revocation_check_mode == CertRevocationCheckMode.DISABLED
    # Other parameters should use defaults when mode is disabled


def test_crl_config_from_connection_enabled_mode():
    """Test CRLConfig.from_connection with ENABLED mode and all parameters"""
    from unittest.mock import Mock

    mock_connection = Mock()
    mock_connection.cert_revocation_check_mode = "ENABLED"
    mock_connection.allow_certificates_without_crl_url = True
    mock_connection.crl_connection_timeout_ms = 5000
    mock_connection.crl_read_timeout_ms = 6000
    mock_connection.crl_cache_validity_hours = 12
    mock_connection.enable_crl_cache = False
    mock_connection.enable_crl_file_cache = False
    mock_connection.crl_cache_dir = "/custom/path"
    mock_connection.crl_cache_removal_delay_days = 14
    mock_connection.crl_cache_cleanup_interval_hours = 2
    mock_connection.crl_cache_start_cleanup = True

    config = CRLConfig.from_connection(mock_connection)

    assert config.cert_revocation_check_mode == CertRevocationCheckMode.ENABLED
    assert config.allow_certificates_without_crl_url
    assert config.connection_timeout_ms == 5000
    assert config.read_timeout_ms == 6000
    assert config.cache_validity_time == timedelta(hours=12)
    assert not config.enable_crl_cache
    assert not config.enable_crl_file_cache
    assert config.crl_cache_dir == Path("/custom/path")
    assert config.crl_cache_removal_delay_days == 14
    assert config.crl_cache_cleanup_interval_hours == 2
    assert config.crl_cache_start_cleanup


def test_crl_config_from_connection_none_values():
    """Test CRLConfig.from_connection with None values uses defaults"""
    mock_connection = Mock()
    mock_connection.cert_revocation_check_mode = "ADVISORY"
    mock_connection.allow_certificates_without_crl_url = None
    mock_connection.crl_connection_timeout_ms = None
    mock_connection.crl_read_timeout_ms = None
    mock_connection.crl_cache_validity_hours = None
    mock_connection.enable_crl_cache = None
    mock_connection.enable_crl_file_cache = None
    mock_connection.crl_cache_dir = None
    mock_connection.crl_cache_removal_delay_days = None
    mock_connection.crl_cache_cleanup_interval_hours = None
    mock_connection.crl_cache_start_cleanup = None

    config = CRLConfig.from_connection(mock_connection)

    assert config.cert_revocation_check_mode == CertRevocationCheckMode.ADVISORY
    # All other parameters should use class defaults
    assert (
        config.allow_certificates_without_crl_url
        == CRLConfig.allow_certificates_without_crl_url
    )
    assert config.connection_timeout_ms == CRLConfig.connection_timeout_ms
    assert config.read_timeout_ms == CRLConfig.read_timeout_ms
    assert config.cache_validity_time == CRLConfig.cache_validity_time
    assert config.enable_crl_cache == CRLConfig.enable_crl_cache
    assert config.enable_crl_file_cache == CRLConfig.enable_crl_file_cache
    assert config.crl_cache_dir == CRLConfig.crl_cache_dir
    assert config.crl_cache_removal_delay_days == CRLConfig.crl_cache_removal_delay_days
    assert (
        config.crl_cache_cleanup_interval_hours
        == CRLConfig.crl_cache_cleanup_interval_hours
    )
    assert config.crl_cache_start_cleanup == CRLConfig.crl_cache_start_cleanup


def test_crl_config_from_connection_invalid_mode_string():
    """Test CRLConfig.from_connection with invalid cert_revocation_check_mode string"""
    mock_connection = Mock()
    mock_connection.cert_revocation_check_mode = "INVALID_MODE"
    mock_connection.allow_certificates_without_crl_url = None
    mock_connection.crl_connection_timeout_ms = None
    mock_connection.crl_read_timeout_ms = None
    mock_connection.crl_cache_validity_hours = None
    mock_connection.enable_crl_cache = None
    mock_connection.enable_crl_file_cache = None
    mock_connection.crl_cache_dir = None
    mock_connection.crl_cache_removal_delay_days = None
    mock_connection.crl_cache_cleanup_interval_hours = None
    mock_connection.crl_cache_start_cleanup = None

    # Should default to class default and log warning
    config = CRLConfig.from_connection(mock_connection)
    assert config.cert_revocation_check_mode == CRLConfig.cert_revocation_check_mode


def test_crl_config_from_connection_enum_mode():
    """Test CRLConfig.from_connection with CertRevocationCheckMode enum"""
    mock_connection = Mock()
    mock_connection.cert_revocation_check_mode = CertRevocationCheckMode.ADVISORY
    mock_connection.allow_certificates_without_crl_url = None
    mock_connection.crl_connection_timeout_ms = None
    mock_connection.crl_read_timeout_ms = None
    mock_connection.crl_cache_validity_hours = 1
    mock_connection.enable_crl_cache = None
    mock_connection.enable_crl_file_cache = None
    mock_connection.crl_cache_dir = None
    mock_connection.crl_cache_removal_delay_days = None
    mock_connection.crl_cache_cleanup_interval_hours = None
    mock_connection.crl_cache_start_cleanup = None

    config = CRLConfig.from_connection(mock_connection)
    assert config.cert_revocation_check_mode == CertRevocationCheckMode.ADVISORY


def test_crl_config_from_connection_unsupported_mode_type():
    """Test CRLConfig.from_connection with unsupported cert_revocation_check_mode type"""
    mock_connection = Mock()
    mock_connection.cert_revocation_check_mode = 123  # Invalid type
    mock_connection.allow_certificates_without_crl_url = None
    mock_connection.crl_connection_timeout_ms = None
    mock_connection.crl_read_timeout_ms = None
    mock_connection.crl_cache_validity_hours = None
    mock_connection.enable_crl_cache = None
    mock_connection.enable_crl_file_cache = None
    mock_connection.crl_cache_dir = None
    mock_connection.crl_cache_removal_delay_days = None
    mock_connection.crl_cache_cleanup_interval_hours = None
    mock_connection.crl_cache_start_cleanup = None

    # Should default to class default and log warning
    config = CRLConfig.from_connection(mock_connection)
    assert config.cert_revocation_check_mode == CRLConfig.cert_revocation_check_mode


def test_crl_config_from_connection_none_mode():
    """Test CRLConfig.from_connection with None cert_revocation_check_mode"""
    mock_connection = Mock()
    mock_connection.cert_revocation_check_mode = None
    mock_connection.allow_certificates_without_crl_url = None
    mock_connection.crl_connection_timeout_ms = None
    mock_connection.crl_read_timeout_ms = None
    mock_connection.crl_cache_validity_hours = None
    mock_connection.enable_crl_cache = None
    mock_connection.enable_crl_file_cache = None
    mock_connection.crl_cache_dir = None
    mock_connection.crl_cache_removal_delay_days = None
    mock_connection.crl_cache_cleanup_interval_hours = None
    mock_connection.crl_cache_start_cleanup = None

    config = CRLConfig.from_connection(mock_connection)
    assert config.cert_revocation_check_mode == CRLConfig.cert_revocation_check_mode


# Tests for CRL download and certificate checking functionality
@responses.activate
def test_crl_validator_download_crl_success(cert_gen, session_manager):
    """Test successful CRL download"""
    # Setup mock CRL response with valid CRL data
    crl_url = "http://example.com/test.crl"
    crl_data = cert_gen.generate_valid_crl()  # Use valid CRL data

    responses.add(
        responses.GET,
        crl_url,
        body=crl_data,
        status=200,
        content_type="application/pkcs7-mime",
    )

    validator = CRLValidator(
        session_manager, trusted_certificates=[cert_gen.ca_certificate]
    )

    # Test the download method - it returns a tuple (crl, timestamp)
    crl, timestamp = validator._download_crl(crl_url)
    assert crl is not None  # Should return parsed CRL object
    assert timestamp is not None  # Should return download timestamp
    assert len(responses.calls) == 1


@responses.activate
def test_crl_validator_download_crl_http_error(session_manager):
    """Test CRL download with HTTP error"""
    crl_url = "http://example.com/missing.crl"

    responses.add(responses.GET, crl_url, status=404)

    validator = CRLValidator(session_manager, trusted_certificates=[])

    # Should return (None, None) on HTTP error
    crl, timestamp = validator._download_crl(crl_url)
    assert crl is None
    assert timestamp is None


@responses.activate
def test_crl_validator_download_crl_network_timeout(session_manager):
    """Test CRL download with network timeout"""
    from requests.exceptions import Timeout

    crl_url = "http://example.com/slow.crl"

    validator = CRLValidator(
        session_manager,
        connection_timeout_ms=1000,
        read_timeout_ms=1000,
        trusted_certificates=[],
    )

    # Mock requests to raise timeout
    with mock_patch.object(
        session_manager,
        "get",
        side_effect=Timeout("Connection timeout"),
    ):
        crl, timestamp = validator._download_crl(crl_url)
        assert crl is None
        assert timestamp is None


@responses.activate
def test_crl_validator_download_crl_network_error(session_manager):
    """Test CRL download with network connection error"""
    from requests.exceptions import ConnectionError

    crl_url = "http://example.com/unreachable.crl"

    validator = CRLValidator(session_manager, trusted_certificates=[])

    # Mock requests to raise connection error
    with mock_patch.object(
        session_manager, "get", side_effect=ConnectionError("Connection failed")
    ):
        crl, timestamp = validator._download_crl(crl_url)
        assert crl is None
        assert timestamp is None


def test_crl_validator_extract_crl_distribution_points_success(
    cert_gen, session_manager
):
    """Test successful extraction of CRL distribution points"""
    # Create certificate with CRL distribution points
    crl_urls = ["http://example.com/ca.crl", "http://backup.com/ca.crl"]
    cert = cert_gen.create_certificate_with_crl_distribution_points("CN=Test", crl_urls)

    validator = CRLValidator(session_manager, trusted_certificates=[])

    extracted_urls = validator._extract_crl_distribution_points(cert)

    assert len(extracted_urls) == 2
    assert "http://example.com/ca.crl" in extracted_urls
    assert "http://backup.com/ca.crl" in extracted_urls


def test_crl_validator_extract_crl_distribution_points_no_extension(
    cert_gen, session_manager
):
    """Test extraction when certificate has no CRL distribution points"""
    # Create simple certificate without CRL distribution points
    chain = cert_gen.create_simple_chain()
    cert = chain.leaf_cert

    validator = CRLValidator(session_manager, trusted_certificates=[])

    # Should return empty list when no CRL extension found
    extracted_urls = validator._extract_crl_distribution_points(cert)
    assert extracted_urls == []


def test_crl_validator_check_certificate_against_crl_not_revoked(
    cert_gen, session_manager
):
    """Test certificate checking against CRL - not revoked"""
    from cryptography.x509 import CertificateRevocationList

    # Create test certificate
    chain = cert_gen.create_simple_chain()
    cert = chain.leaf_cert

    # Mock CRL that doesn't contain the certificate
    mock_crl = Mock(spec=CertificateRevocationList)
    mock_crl.get_revoked_certificate_by_serial_number.return_value = None

    validator = CRLValidator(session_manager, trusted_certificates=[])

    # Should return UNREVOKED
    result = validator._check_certificate_against_crl(cert, mock_crl)
    assert result == CRLValidationResult.UNREVOKED


def test_crl_validator_check_certificate_against_crl_revoked(cert_gen, session_manager):
    """Test certificate checking against CRL - revoked"""
    from cryptography.x509 import CertificateRevocationList, RevokedCertificate

    # Create test certificate
    chain = cert_gen.create_simple_chain()
    cert = chain.leaf_cert

    # Mock CRL that contains the certificate as revoked
    mock_revoked_cert = Mock(spec=RevokedCertificate)
    mock_crl = Mock(spec=CertificateRevocationList)
    mock_crl.get_revoked_certificate_by_serial_number.return_value = mock_revoked_cert

    validator = CRLValidator(session_manager, trusted_certificates=[])

    # Should return REVOKED
    result = validator._check_certificate_against_crl(cert, mock_crl)
    assert result == CRLValidationResult.REVOKED


def test_crl_validator_check_certificate_against_crl_expired(
    cert_gen, session_manager, crl_urls
):
    """Test certificate checking against expired CRL"""

    # Create test certificate
    chain = cert_gen.create_simple_chain()
    cert = chain.leaf_cert
    parent = chain.intermediate_cert

    # Mock expired CRL
    mock_crl = Mock(spec=x509.CertificateRevocationList)
    mock_crl.next_update_utc = datetime.now(timezone.utc) - timedelta(days=1)  # Expired
    mock_crl.get_revoked_certificate_by_serial_number.return_value = None
    mock_crl.issuer = parent.subject

    # Cache will return an expired CRL
    mock_cache_mgr = Mock(spec=CRLCacheManager)
    mock_cache_mgr.get.return_value = CRLCacheEntry(mock_crl, datetime.now())

    validator = CRLValidator(
        session_manager, cache_manager=mock_cache_mgr, trusted_certificates=[]
    )
    with mock_patch.object(
        validator, "_download_crl", return_value=(mock_crl, datetime.now())
    ) as mock_download, mock_patch.object(
        validator, "_verify_crl_signature", return_value=True
    ) as mock_verify:
        result = validator._check_certificate_against_crl_url(
            cert, parent, crl_urls.expired_ca
        )
        assert result == CRLValidationResult.UNREVOKED
        mock_cache_mgr.get.assert_called_once()
        mock_download.assert_called_once()
        mock_verify.assert_called_once_with(mock_crl, parent)


def test_crl_validator_validate_certificate_with_cache_hit(
    cert_gen, session_manager, crl_urls
):
    """Test certificate validation with cache hit"""

    # Create certificate with CRL distribution points
    cert = cert_gen.create_certificate_with_crl_distribution_points(
        "CN=Test", [crl_urls.test_ca]
    )
    ca_cert = cert_gen.ca_certificate

    # Mock cache manager with cache hit
    mock_crl = Mock(spec=x509.CertificateRevocationList)
    mock_crl.next_update_utc = datetime.now(timezone.utc) + timedelta(days=7)
    mock_crl.issuer = ca_cert.subject
    mock_cache_manager = Mock()
    cached_entry = CRLCacheEntry(mock_crl, datetime.now(timezone.utc))
    mock_cache_manager.get.return_value = cached_entry

    validator = CRLValidator(session_manager, trusted_certificates=[])
    validator._cache_manager = mock_cache_manager

    # Mock CRL parsing and validation
    with mock_patch.object(
        validator,
        "_check_certificate_against_crl",
        return_value=CRLValidationResult.UNREVOKED,
    ) as mock_check, mock_patch.object(
        validator, "_verify_crl_signature", return_value=True
    ) as mock_verify:
        result = validator._validate_certificate_is_not_revoked(cert, ca_cert)

        # Should use cached CRL
        assert result == CRLValidationResult.UNREVOKED
        mock_cache_manager.get.assert_called_once()
        mock_check.assert_called_once_with(cert, cached_entry.crl)
        mock_verify.assert_called_once_with(cached_entry.crl, ca_cert)


def test_crl_validator_validate_certificate_with_cache_miss(
    cert_gen, session_manager, crl_urls
):
    """Test certificate validation with cache miss and download"""
    # Create certificate with CRL distribution points
    cert = cert_gen.create_certificate_with_crl_distribution_points(
        "CN=Test", [crl_urls.valid_ca]
    )
    ca_cert = cert_gen.ca_certificate

    # Mock cache manager with cache miss
    mock_cache_manager = Mock()
    mock_cache_manager.get.return_value = None

    validator = CRLValidator(
        session_manager,
        cache_manager=mock_cache_manager,
        trusted_certificates=[],
    )

    # Mock successful download and validation
    with mock_patch.object(
        validator, "_fetch_crl_from_url", return_value=b"downloaded_crl"
    ) as mock_fetch, mock_patch(
        "snowflake.connector.crl.x509.load_der_x509_crl"
    ) as mock_load_crl, mock_patch.object(
        validator,
        "_check_certificate_against_crl",
        return_value=CRLValidationResult.UNREVOKED,
    ) as mock_check, mock_patch.object(
        validator, "_verify_crl_signature", return_value=True
    ) as mock_verify:
        mock_crl = Mock()
        mock_crl.next_update_utc = datetime.now(timezone.utc) + timedelta(days=7)
        mock_crl.issuer = ca_cert.subject  # Set the CRL issuer to match CA subject
        mock_load_crl.return_value = mock_crl
        result = validator._validate_certificate_is_not_revoked(cert, ca_cert)

        # Should download CRL and cache it
        assert result == CRLValidationResult.UNREVOKED
        mock_cache_manager.get.assert_called_once()
        mock_fetch.assert_called_once_with(crl_urls.valid_ca)
        mock_cache_manager.put.assert_called_once()
        mock_check.assert_called_once_with(cert, mock_crl)
        mock_verify.assert_called_once_with(mock_crl, ca_cert)


def test_crl_signature_verification_success(cert_gen, session_manager):
    """Test successful CRL signature verification"""
    # Create a valid CRL signed by the test CA
    crl_bytes = cert_gen.generate_valid_crl()
    crl = x509.load_der_x509_crl(crl_bytes, backend=default_backend())

    validator = CRLValidator(session_manager, trusted_certificates=[])

    # Should successfully verify the signature
    result = validator._verify_crl_signature(crl, cert_gen.ca_certificate)
    assert result is True


def test_crl_signature_verification_failure_wrong_ca(cert_gen, session_manager):
    """Test CRL signature verification failure with wrong CA certificate"""
    # Create a CRL signed by the test CA
    crl_bytes = cert_gen.generate_valid_crl()
    crl = x509.load_der_x509_crl(crl_bytes, backend=default_backend())

    # Create a different CA certificate
    different_ca_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    different_ca_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Different CA")]
    )
    different_ca_cert = (
        x509.CertificateBuilder()
        .subject_name(different_ca_name)
        .issuer_name(different_ca_name)
        .public_key(different_ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(different_ca_key, hashes.SHA256(), backend=default_backend())
    )

    validator = CRLValidator(session_manager, trusted_certificates=[])

    # Should fail to verify the signature with wrong CA
    result = validator._verify_crl_signature(crl, different_ca_cert)
    assert result is False


def test_crl_signature_verification_with_ec_key(session_manager):
    """Test CRL signature verification with EC (Elliptic Curve) keys"""
    from cryptography.hazmat.primitives.asymmetric import ec

    # Generate EC key pair for CA
    ec_private_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())

    # Create EC CA certificate
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "EC Test CA")])
    ec_ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ec_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                key_cert_sign=True,
                crl_sign=True,
                digital_signature=False,
                key_encipherment=False,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ec_private_key, hashes.SHA256(), backend=default_backend())
    )

    # Create CRL signed with EC key
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ec_ca_cert.subject)
    builder = builder.last_update(datetime.now(timezone.utc))
    builder = builder.next_update(datetime.now(timezone.utc) + timedelta(days=1))

    ec_crl = builder.sign(ec_private_key, hashes.SHA256(), backend=default_backend())

    validator = CRLValidator(session_manager, trusted_certificates=[])

    # Should successfully verify EC signature
    result = validator._verify_crl_signature(ec_crl, ec_ca_cert)
    assert result is True


def test_crl_signature_verification_with_corrupted_signature(cert_gen, session_manager):
    """Test CRL signature verification with corrupted signature"""
    # Create a valid CRL
    crl_bytes = cert_gen.generate_valid_crl()
    crl = x509.load_der_x509_crl(crl_bytes, backend=default_backend())

    # Mock the CRL to have a corrupted signature
    corrupted_crl = Mock(spec=x509.CertificateRevocationList)
    corrupted_crl.signature_algorithm_oid = crl.signature_algorithm_oid
    corrupted_crl.signature_hash_algorithm = crl.signature_hash_algorithm
    corrupted_crl.signature = b"corrupted_signature_bytes"
    corrupted_crl.tbs_certlist_bytes = crl.tbs_certlist_bytes

    validator = CRLValidator(session_manager, trusted_certificates=[])

    # Should fail to verify corrupted signature
    result = validator._verify_crl_signature(corrupted_crl, cert_gen.ca_certificate)
    assert result is False


def test_crl_signature_verification_exception_handling(cert_gen, session_manager):
    """Test CRL signature verification exception handling"""
    # Create a valid CRL
    crl_bytes = cert_gen.generate_valid_crl()
    crl = x509.load_der_x509_crl(crl_bytes, backend=default_backend())

    # Mock CA certificate that will cause an exception
    mock_public_key = Mock()
    mock_public_key.verify.side_effect = Exception("Test exception")
    mock_ca_cert = Mock(spec=x509.Certificate)
    mock_ca_cert.public_key.return_value = mock_public_key

    validator = CRLValidator(session_manager, trusted_certificates=[])

    # Should handle exception gracefully and return False
    result = validator._verify_crl_signature(crl, mock_ca_cert)
    assert result is False


def test_crl_signature_verification_integration_with_validation_flow(
    cert_gen, crl_urls, session_manager
):
    """Test that signature verification is properly integrated into the validation flow"""
    # Create certificate with CRL distribution point
    cert = cert_gen.create_certificate_with_crl_distribution_points(
        "CN=Test Server", [crl_urls.test_ca]
    )

    # Create a CRL signed by a different CA (should fail signature verification)
    different_ca_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    different_ca_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Different CA")]
    )

    # Create CRL with different CA
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(different_ca_name)
    builder = builder.last_update(datetime.now(timezone.utc))
    builder = builder.next_update(datetime.now(timezone.utc) + timedelta(days=1))

    invalid_crl = builder.sign(
        different_ca_key, hashes.SHA256(), backend=default_backend()
    )
    invalid_crl_bytes = invalid_crl.public_bytes(serialization.Encoding.DER)

    # Test in ENABLED mode - should fail due to signature verification failure
    validator_enabled = CRLValidator(
        session_manager,
        cert_revocation_check_mode=CertRevocationCheckMode.ENABLED,
        trusted_certificates=[],
    )

    with mock_patch.object(
        validator_enabled, "_fetch_crl_from_url", return_value=invalid_crl_bytes
    ):
        result = validator_enabled._validate_certificate_is_not_revoked(
            cert, cert_gen.ca_certificate
        )
        assert result == CRLValidationResult.ERROR

    # Test in ADVISORY mode - should also fail due to signature verification failure
    # CRL signature verification failure always returns ERROR regardless of mode
    validator_advisory = CRLValidator(
        session_manager,
        cert_revocation_check_mode=CertRevocationCheckMode.ADVISORY,
        trusted_certificates=[],
    )

    with mock_patch.object(
        validator_advisory, "_fetch_crl_from_url", return_value=invalid_crl_bytes
    ):
        result = validator_advisory._validate_certificate_is_not_revoked(
            cert, cert_gen.ca_certificate
        )
        # Even in ADVISORY mode, signature verification failure should return ERROR
        # We cannot trust a CRL whose signature cannot be verified
        assert result == CRLValidationResult.ERROR


def test_crl_signature_verification_with_issuer_mismatch_warning(
    cert_gen, session_manager, caplog
):
    """Test that we log a warning when CRL issuer doesn't match CA certificate subject"""
    # Create a valid CRL signed by the test CA
    crl = Mock(spec=x509.CertificateRevocationList)
    crl.issuer = cert_gen.ca_certificate.subject

    # Create a different CA certificate with different subject
    different_ca_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    different_subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Different Subject CA")]
    )
    different_ca_cert = (
        x509.CertificateBuilder()
        .subject_name(different_subject)
        .issuer_name(different_subject)
        .public_key(different_ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(different_ca_key, hashes.SHA256(), backend=default_backend())
    )

    validator = CRLValidator(session_manager, trusted_certificates=[])

    # Mock the _verify_crl_signature to return True to focus on the issuer check
    with mock_patch.object(
        validator, "_verify_crl_signature", return_value=True
    ), mock_patch.object(
        validator,
        "_check_certificate_against_crl",
        return_value=CRLValidationResult.UNREVOKED,
    ), mock_patch.object(
        validator, "_download_crl", return_value=(crl, datetime.now(timezone.utc))
    ), caplog.at_level(
        logging.WARNING
    ):

        # This should log a warning about issuer mismatch but still proceed
        result = validator._check_certificate_against_crl_url(
            cert_gen.ca_certificate,  # dummy cert
            different_ca_cert,  # CA with different subject than CRL issuer
            "http://test.crl",
        )

        # Should return ERROR due to issuer mismatch
        assert result == CRLValidationResult.ERROR

        # Verify that the warning was logged
        assert len(caplog.records) > 0
        warning_found = any(
            "CRL issuer" in record.message
            and "does not match CA certificate subject" in record.message
            for record in caplog.records
            if record.levelno == logging.WARNING
        )
        assert (
            warning_found
        ), f"Expected warning about CRL issuer mismatch not found in logs: {[r.message for r in caplog.records]}"


@pytest.mark.parametrize(
    "issue_date,validity_days,expected",
    [
        (
            # Issued on March 15, 2024, should use 10-day rule
            datetime(2024, 3, 15, tzinfo=timezone.utc),
            10,
            True,
        ),
        (
            # Issued on March 15, 2024, should use 10-day rule
            datetime(2024, 3, 15, tzinfo=timezone.utc),
            11,
            False,
        ),
        (
            # Issued on March 15, 2024, should use 10-day rule
            datetime(2024, 3, 15),
            10,
            True,
        ),
        (
            # Issued on March 15, 2024, should use 10-day rule
            datetime(2024, 3, 15),
            11,
            False,
        ),
        (
            # Issued on March 15, 2026, should use 7-day rule
            datetime(2026, 3, 15, tzinfo=timezone.utc),
            7,
            True,
        ),
        (
            # Issued on March 15, 2026, should use 7-day rule
            datetime(2026, 3, 15, tzinfo=timezone.utc),
            8,
            False,
        ),
        (
            # Issued on March 15, 2026, should use 7-day rule
            datetime(2026, 3, 15),
            7,
            True,
        ),
        (
            # Issued on March 15, 2026, should use 7-day rule
            datetime(2026, 3, 15),
            8,
            False,
        ),
    ],
)
def test_is_short_lived_certificate(cert_gen, issue_date, validity_days, expected):
    cert = cert_gen.create_short_lived_certificate(validity_days, issue_date)
    assert CRLValidator._is_short_lived_certificate(cert) == expected


def test_validate_certificate_signatures(cert_gen, session_manager):
    """Test that certificate validation fails with ERROR when signed by wrong key"""
    # we will replace intermediate cert with one with a wrong signature
    chain = cert_gen.create_simple_chain()
    different_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    different_cert = (
        x509.CertificateBuilder()
        .subject_name(chain.intermediate_cert.subject)
        .issuer_name(chain.intermediate_cert.issuer)
        .public_key(chain.intermediate_cert.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(different_key, hashes.SHA256(), backend=default_backend())
    )
    short_lived_different_cert = (
        x509.CertificateBuilder()
        .subject_name(chain.intermediate_cert.subject)
        .issuer_name(chain.intermediate_cert.issuer)
        .public_key(chain.intermediate_cert.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(different_key, hashes.SHA256(), backend=default_backend())
    )

    validator = CRLValidator(
        session_manager,
        cert_revocation_check_mode=CertRevocationCheckMode.ENABLED,
        allow_certificates_without_crl_url=True,
        trusted_certificates=[chain.root_cert],
    )

    # wrong signature - no path found = ERROR
    assert (
        validator._validate_single_chain(
            [chain.leaf_cert, different_cert, chain.root_cert]
        )
        == CRLValidationResult.ERROR
    )
    # wrong signature - short-lived - no path found = ERROR
    assert (
        validator._validate_single_chain(
            [chain.leaf_cert, short_lived_different_cert, chain.root_cert]
        )
        == CRLValidationResult.ERROR
    )
    # wrong signature does not stop from searching of new path
    assert (
        validator._validate_single_chain(
            [
                chain.leaf_cert,
                different_cert,
                short_lived_different_cert,
                chain.intermediate_cert,
                chain.root_cert,
            ]
        )
        == CRLValidationResult.UNREVOKED
    )


def test_validate_certificate_signatures_in_chain(cert_gen, session_manager):
    """Test that certificate validation fails with ERROR when signed by wrong key"""
    # Create a certificate chain signed by the test CA: leaf -> A -> B -> CA
    # mingle with A -> B
    chain = cert_gen.create_cross_signed_chain()

    valid_cert = chain.BsignA

    # Create a different CA key pair
    different_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    different_cert = (
        x509.CertificateBuilder()
        .subject_name(valid_cert.subject)
        .issuer_name(cert_gen.ca_certificate.subject)
        .public_key(cert_gen.ca_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(different_key, hashes.SHA256(), backend=default_backend())
    )
    short_lived_different_cert = (
        x509.CertificateBuilder()
        .subject_name(valid_cert.subject)
        .issuer_name(cert_gen.ca_certificate.subject)
        .public_key(different_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(different_key, hashes.SHA256(), backend=default_backend())
    )

    validator = CRLValidator(
        session_manager,
        allow_certificates_without_crl_url=True,
        cert_revocation_check_mode=CertRevocationCheckMode.ENABLED,
        trusted_certificates=[cert_gen.ca_certificate],
    )

    # wrong signature - no path found = ERROR
    assert (
        validator._validate_single_chain(
            [chain.final_cert, chain.leafA, different_cert, chain.rootB]
        )
        == CRLValidationResult.ERROR
    )
    # wrong signature - short-lived - no path found = ERROR
    assert (
        validator._validate_single_chain(
            [chain.final_cert, chain.leafA, short_lived_different_cert, chain.rootB]
        )
        == CRLValidationResult.ERROR
    )
    # wrong signature does not stop from searching of new path
    assert (
        validator._validate_single_chain(
            [
                chain.final_cert,
                chain.leafA,
                different_cert,
                short_lived_different_cert,
                valid_cert,
                chain.rootB,
            ]
        )
        == CRLValidationResult.UNREVOKED
    )


def test_trusted_certificates_helpers(cert_gen):
    chain = cert_gen.create_simple_chain()

    validator = CRLValidator(
        session_manager=Mock(), trusted_certificates=[chain.root_cert]
    )

    assert validator._is_certificate_trusted_by_os(chain.root_cert) is True
    assert validator._is_certificate_trusted_by_os(chain.intermediate_cert) is False

    assert validator._get_trusted_ca_issuer(chain.intermediate_cert) is chain.root_cert
    assert validator._get_trusted_ca_issuer(chain.leaf_cert) is None
