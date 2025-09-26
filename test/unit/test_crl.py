#!/usr/bin/env python
from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
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
                .issuer_name(name)  # Self-signed for simplicity
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(issuance_date)
                .not_valid_after(not_after)
                .add_extension(
                    x509.BasicConstraints(ca=False, path_length=None),
                    critical=True,
                )
                .sign(key, hashes.SHA256())
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
    )

    assert validator.validate_certificate_chains(chains)


def test_should_allow_connection_when_crl_validation_disabled_and_no_cert_chain(
    session_manager,
):
    validator = CRLValidator(
        session_manager,
        cert_revocation_check_mode=CertRevocationCheckMode.DISABLED,
    )
    assert validator.validate_certificate_chains([])
    assert validator.validate_certificate_chains(None)


def test_should_fail_with_null_or_empty_certificate_chains(cert_gen, session_manager):
    """Test that validator fails with null or empty certificate chains"""
    validator = CRLValidator(
        session_manager,
        cert_revocation_check_mode=CertRevocationCheckMode.ENABLED,
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
    )
    assert validator.validate_certificate_chains(chains)


def test_should_pass_in_advisory_mode_even_with_errors(cert_gen, session_manager):
    """Test that validation passes in advisory mode even with errors"""
    chain = cert_gen.create_simple_chain()
    chains = [[chain.leaf_cert, chain.intermediate_cert, chain.root_cert]]

    validator = CRLValidator(
        session_manager,
        cert_revocation_check_mode=CertRevocationCheckMode.ADVISORY,
    )

    assert validator.validate_certificate_chains(chains)


def test_should_validate_multiple_chains_and_return_first_valid_with_no_crl_urls(
    cert_gen,
    session_manager,
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
    )

    result = validator.validate_certificate_chains(chains)
    assert result, "Should return true when at least one valid chain is found"


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
    )

    assert validator.validate_certificate_chains([chain])
    assert resp_primary.call_count
    assert resp_backup.call_count


def test_crl_validator_creation(session_manager):
    """Test that CRLValidator can be created properly"""

    # Test basic instantiation
    validator = CRLValidator(session_manager)
    assert validator is not None
    assert isinstance(validator, CRLValidator)

    # Test that it works with from_config class method
    validator = CRLValidator.from_config(CRLConfig(), session_manager)
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
        CRLValidator.from_config(config, session_manager)

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
    validator = CRLValidator(session_manager)

    # Should return True when disabled (default)
    assert validator.validate_connection(mock_connection)

    # Test with enabled mode and no certificates
    validator = CRLValidator(
        session_manager, cert_revocation_check_mode=CertRevocationCheckMode.ENABLED
    )
    assert not validator.validate_connection(mock_connection)


def test_crl_validator_extract_certificate_chains_from_connection(
    cert_gen, session_manager
):
    """Test the _extract_certificate_chains_from_connection method"""
    validator = CRLValidator(session_manager)

    # Test with no certificate chain
    mock_connection = Mock()
    mock_connection.get_peer_cert_chain.return_value = []

    chains = validator._extract_certificate_chains_from_connection(mock_connection)
    assert chains == []

    # Test with mock certificate chain
    chain = cert_gen.create_simple_chain()
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
    assert str(config.crl_cache_dir) == "/custom/path"
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

    validator = CRLValidator(session_manager)

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

    validator = CRLValidator(session_manager)

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
        session_manager, connection_timeout_ms=1000, read_timeout_ms=1000
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

    validator = CRLValidator(session_manager)

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

    validator = CRLValidator(session_manager)

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

    validator = CRLValidator(session_manager)

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

    validator = CRLValidator(session_manager)

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

    validator = CRLValidator(session_manager)

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

    # Cache will return an expired CRL
    mock_cache_mgr = Mock(spec=CRLCacheManager)
    mock_cache_mgr.get.return_value = CRLCacheEntry(mock_crl, datetime.now())

    validator = CRLValidator(session_manager, cache_manager=mock_cache_mgr)
    with mock_patch.object(
        validator, "_download_crl", return_value=(mock_crl, datetime.now())
    ) as mock_download:
        result = validator._check_certificate_against_crl_url(
            cert, parent, crl_urls.expired_ca
        )
        assert result == CRLValidationResult.UNREVOKED
        mock_cache_mgr.get.assert_called_once()
        mock_download.assert_called_once()


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
    mock_cache_manager = Mock()
    cached_entry = CRLCacheEntry(mock_crl, datetime.now(timezone.utc))
    mock_cache_manager.get.return_value = cached_entry

    validator = CRLValidator(session_manager)
    validator._cache_manager = mock_cache_manager

    # Mock CRL parsing and validation
    with mock_patch.object(
        validator, "_check_certificate_against_crl", return_value=True
    ) as mock_check:
        result = validator._validate_certificate(cert, ca_cert)

        # Should use cached CRL
        assert result == CRLValidationResult.UNREVOKED
        mock_cache_manager.get.assert_called_once()
        mock_check.assert_called_once_with(cert, cached_entry.crl)


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

    validator = CRLValidator(session_manager, cache_manager=mock_cache_manager)

    # Mock successful download and validation
    with mock_patch.object(
        validator, "_fetch_crl_from_url", return_value=b"downloaded_crl"
    ) as mock_fetch, mock_patch(
        "snowflake.connector.crl.x509.load_der_x509_crl"
    ) as mock_load_crl, mock_patch.object(
        validator,
        "_check_certificate_against_crl",
        return_value=CRLValidationResult.UNREVOKED,
    ) as mock_check:

        mock_crl = Mock()
        mock_crl.next_update_utc = datetime.now(timezone.utc) + timedelta(days=7)
        mock_load_crl.return_value = mock_crl

        result = validator._validate_certificate(cert, ca_cert)

        # Should download CRL and cache it
        assert result == CRLValidationResult.UNREVOKED
        mock_cache_manager.get.assert_called_once()
        mock_fetch.assert_called_once_with(crl_urls.valid_ca)
        mock_cache_manager.put.assert_called_once()
        mock_check.assert_called_once_with(cert, mock_crl)
