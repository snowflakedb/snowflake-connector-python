#!/usr/bin/env python
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum, unique
from logging import getLogger
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat._oid import ExtensionOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from OpenSSL.SSL import Connection as SSLConnection

from .crl_cache import CRLCacheEntry, CRLCacheManager
from .session_manager import SessionManager

logger = getLogger(__name__)


@unique
class CertRevocationCheckMode(Enum):
    """Certificate revocation check modes based on revocation lists (CRL)

    CRL mode descriptions:
        DISABLED: No revocation check is done.
        ENABLED: Revocation check is done in the strictest way. The endpoint must expose at least one fully valid
            certificate chain. Any check error invalidate the chain.
        ADVISORY: Revocation check is done in a more relaxed way. Only a revocated certificate can invalidate
            the chain. An error is treated positively (as a successful check).
    """

    DISABLED = "DISABLED"
    ENABLED = "ENABLED"
    ADVISORY = "ADVISORY"


class CRLValidationResult(Enum):
    """Certificate revocation validation result statuses"""

    REVOKED = "REVOKED"
    UNREVOKED = "UNREVOKED"
    ERROR = "ERROR"


@dataclass
class CRLConfig:
    """Configuration class for CRL validation settings."""

    cert_revocation_check_mode: CertRevocationCheckMode = (
        CertRevocationCheckMode.DISABLED
    )
    allow_certificates_without_crl_url: bool = False
    connection_timeout_ms: int = 3000
    read_timeout_ms: int = 3000
    cache_validity_time: timedelta = timedelta(hours=24)
    enable_crl_cache: bool = True
    enable_crl_file_cache: bool = True
    crl_cache_dir: Path | str | None = None
    crl_cache_removal_delay_days: int = 7
    crl_cache_cleanup_interval_hours: int = 1
    crl_cache_start_cleanup: bool = False

    @classmethod
    def from_connection(cls, sf_connection) -> CRLConfig:
        """
        Create a CRLConfig instance from a SnowflakeConnection instance.

        This method extracts CRL configuration parameters from the connection's
        read-only properties and creates a CRLConfig instance.

        Args:
            sf_connection: SnowflakeConnection instance containing CRL configuration

        Returns:
            CRLConfig: Configured CRLConfig instance

        Raises:
            ValueError: If session_manager is not available in the connection
        """
        # Extract CRL-specific configuration parameters from connection properties
        if sf_connection.cert_revocation_check_mode is None:
            cert_revocation_check_mode = cls.cert_revocation_check_mode
        elif isinstance(sf_connection.cert_revocation_check_mode, str):
            try:
                cert_revocation_check_mode = CertRevocationCheckMode(
                    sf_connection.cert_revocation_check_mode
                )
            except ValueError:
                logger.warning(
                    f"Invalid cert_revocation_check_mode: {sf_connection.cert_revocation_check_mode}, "
                    f"defaulting to {cls.cert_revocation_check_mode}"
                )
                cert_revocation_check_mode = cls.cert_revocation_check_mode
        elif isinstance(
            sf_connection.cert_revocation_check_mode, CertRevocationCheckMode
        ):
            cert_revocation_check_mode = sf_connection.cert_revocation_check_mode
        else:
            logger.warning(
                f"Unsupported value for cert_revocation_check_mode: {sf_connection.cert_revocation_check_mode}, "
                f"defaulting to {cls.cert_revocation_check_mode}"
            )
            cert_revocation_check_mode = cls.cert_revocation_check_mode

        if cert_revocation_check_mode == CertRevocationCheckMode.DISABLED:
            # The rest of the parameters don't matter if CRL checking is disabled
            return cls(cert_revocation_check_mode=cert_revocation_check_mode)

        # Apply default value logic for all other parameters when connection attribute is None
        cache_validity_time = (
            cls.cache_validity_time
            if sf_connection.crl_cache_validity_hours is None
            else timedelta(hours=int(sf_connection.crl_cache_validity_hours))
        )
        crl_cache_dir = (
            cls.crl_cache_dir
            if sf_connection.crl_cache_dir is None
            else Path(sf_connection.crl_cache_dir)
        )
        allow_certificates_without_crl_url = (
            cls.allow_certificates_without_crl_url
            if sf_connection.allow_certificates_without_crl_url is None
            else bool(sf_connection.allow_certificates_without_crl_url)
        )
        connection_timeout_ms = (
            cls.connection_timeout_ms
            if sf_connection.crl_connection_timeout_ms is None
            else int(sf_connection.crl_connection_timeout_ms)
        )
        read_timeout_ms = (
            cls.read_timeout_ms
            if sf_connection.crl_read_timeout_ms is None
            else int(sf_connection.crl_read_timeout_ms)
        )
        enable_crl_cache = (
            cls.enable_crl_cache
            if sf_connection.enable_crl_cache is None
            else bool(sf_connection.enable_crl_cache)
        )
        enable_crl_file_cache = (
            cls.enable_crl_file_cache
            if sf_connection.enable_crl_file_cache is None
            else bool(sf_connection.enable_crl_file_cache)
        )
        crl_cache_removal_delay_days = (
            cls.crl_cache_removal_delay_days
            if sf_connection.crl_cache_removal_delay_days is None
            else int(sf_connection.crl_cache_removal_delay_days)
        )
        crl_cache_cleanup_interval_hours = (
            cls.crl_cache_cleanup_interval_hours
            if sf_connection.crl_cache_cleanup_interval_hours is None
            else int(sf_connection.crl_cache_cleanup_interval_hours)
        )
        crl_cache_start_cleanup = (
            cls.crl_cache_start_cleanup
            if sf_connection.crl_cache_start_cleanup is None
            else bool(sf_connection.crl_cache_start_cleanup)
        )

        return cls(
            cert_revocation_check_mode=cert_revocation_check_mode,
            allow_certificates_without_crl_url=allow_certificates_without_crl_url,
            connection_timeout_ms=connection_timeout_ms,
            read_timeout_ms=read_timeout_ms,
            cache_validity_time=cache_validity_time,
            enable_crl_cache=enable_crl_cache,
            enable_crl_file_cache=enable_crl_file_cache,
            crl_cache_dir=crl_cache_dir,
            crl_cache_removal_delay_days=crl_cache_removal_delay_days,
            crl_cache_cleanup_interval_hours=crl_cache_cleanup_interval_hours,
            crl_cache_start_cleanup=crl_cache_start_cleanup,
        )


class CRLValidator:
    def __init__(
        self,
        session_manager: SessionManager | Any,
        cert_revocation_check_mode: CertRevocationCheckMode = CRLConfig.cert_revocation_check_mode,
        allow_certificates_without_crl_url: bool = CRLConfig.allow_certificates_without_crl_url,
        connection_timeout_ms: int = CRLConfig.connection_timeout_ms,
        read_timeout_ms: int = CRLConfig.read_timeout_ms,
        cache_validity_time: timedelta = CRLConfig.cache_validity_time,
        cache_manager: CRLCacheManager | None = None,
    ):
        self._session_manager = session_manager
        self._cert_revocation_check_mode = cert_revocation_check_mode
        self._allow_certificates_without_crl_url = allow_certificates_without_crl_url
        self._connection_timeout_ms = connection_timeout_ms
        self._read_timeout_ms = read_timeout_ms
        self._cache_validity_time = cache_validity_time
        self._cache_manager = cache_manager or CRLCacheManager.noop()

    @classmethod
    def from_config(
        cls, config: CRLConfig, session_manager: SessionManager
    ) -> CRLValidator:
        """
        Create a CRLValidator instance from a CRLConfig.

        This method creates a CRLValidator and its underlying objects (except session_manager)
        from configuration parameters found in the CRLConfig.

        Args:
            config: CRLConfig instance containing CRL-related parameters
            session_manager: SessionManager instance

        Returns:
            CRLValidator: Configured CRLValidator instance
        """
        # Create cache manager if caching is enabled
        cache_manager = None
        if config.enable_crl_cache:
            from snowflake.connector.crl_cache import CRLCacheFactory

            # Create memory cache using factory
            memory_cache = CRLCacheFactory.get_memory_cache(config.cache_validity_time)

            # Create file cache if enabled
            if config.enable_crl_file_cache:
                removal_delay = timedelta(days=config.crl_cache_removal_delay_days)
                file_cache = CRLCacheFactory.get_file_cache(
                    cache_dir=config.crl_cache_dir, removal_delay=removal_delay
                )
            else:
                from snowflake.connector.crl_cache import NoopCRLCache

                file_cache = NoopCRLCache()

            # Create cache manager
            cache_manager = CRLCacheManager(
                memory_cache=memory_cache,
                file_cache=file_cache,
            )

            # Start cleanup through factory if requested
            if config.crl_cache_start_cleanup:
                cleanup_interval = timedelta(
                    hours=config.crl_cache_cleanup_interval_hours
                )
                CRLCacheFactory.start_periodic_cleanup(cleanup_interval)
        else:
            cache_manager = CRLCacheManager.noop()

        return cls(
            session_manager=session_manager,
            cert_revocation_check_mode=config.cert_revocation_check_mode,
            allow_certificates_without_crl_url=config.allow_certificates_without_crl_url,
            connection_timeout_ms=config.connection_timeout_ms,
            read_timeout_ms=config.read_timeout_ms,
            cache_validity_time=config.cache_validity_time,
            cache_manager=cache_manager,
        )

    def validate_certificate_chains(
        self, certificate_chains: list[list[x509.Certificate]]
    ) -> bool:
        """
        Validate certificate chains against CRLs with actual HTTP requests

        Args:
            certificate_chains: List of certificate chains to validate

        Returns:
            True if validation passes, False otherwise

        Raises:
            ValueError: If certificate_chains is None or empty
        """
        if self._cert_revocation_check_mode == CertRevocationCheckMode.DISABLED:
            return True

        if certificate_chains is None or len(certificate_chains) == 0:
            logger.warning("Certificate chains are empty")
            if self._cert_revocation_check_mode == CertRevocationCheckMode.ADVISORY:
                return True
            return False

        results = []
        for chain in certificate_chains:
            result = self._validate_single_chain(chain)
            # If any of the chains is valid, the whole check is considered positive
            if result == CRLValidationResult.UNREVOKED:
                return True
            results.append(result)

        # In non-advisory mode we require at least one chain get a clear UNREVOKED status
        if self._cert_revocation_check_mode != CertRevocationCheckMode.ADVISORY:
            return False

        # We're in advisory mode, so any error is treated positively
        return any(result == CRLValidationResult.ERROR for result in results)

    def _validate_single_chain(
        self, chain: list[x509.Certificate]
    ) -> CRLValidationResult:
        """Validate a single certificate chain"""
        # An empty chain is considered an error
        if len(chain) == 0:
            return CRLValidationResult.ERROR
        # the last certificate of the chain is considered the root and isn't validated
        results = []
        for i in range(len(chain) - 1):
            result = self._validate_certificate(chain[i], chain[i + 1])
            if result == CRLValidationResult.REVOKED:
                return CRLValidationResult.REVOKED
            results.append(result)

        if CRLValidationResult.ERROR in results:
            return CRLValidationResult.ERROR

        return CRLValidationResult.UNREVOKED

    def _validate_certificate(
        self, cert: x509.Certificate, ca_cert: x509.Certificate
    ) -> CRLValidationResult:
        """Validate a single certificate against CRL"""
        # Check if certificate is short-lived (skip CRL check)
        if self._is_short_lived_certificate(cert):
            return CRLValidationResult.UNREVOKED

        # Extract CRL distribution points
        crl_urls = self._extract_crl_distribution_points(cert)

        if not crl_urls:
            # No CRL URLs found
            if self._allow_certificates_without_crl_url:
                return CRLValidationResult.UNREVOKED
            return CRLValidationResult.ERROR

        results: list[CRLValidationResult] = []
        # Check against each CRL URL
        for crl_url in crl_urls:
            result = self._check_certificate_against_crl_url(cert, ca_cert, crl_url)
            if result == CRLValidationResult.REVOKED:
                return result
            results.append(result)

        if all(result == CRLValidationResult.ERROR for result in results):
            return CRLValidationResult.ERROR

        return CRLValidationResult.UNREVOKED

    @staticmethod
    def _is_short_lived_certificate(cert: x509.Certificate) -> bool:
        """Check if certificate is short-lived (validity <= 5 days)"""
        try:
            # Use timezone.utc versions to avoid deprecation warnings
            validity_period = cert.not_valid_after_utc - cert.not_valid_before_utc
        except AttributeError:
            # Fallback for older versions
            validity_period = cert.not_valid_after - cert.not_valid_before
        return validity_period.days <= 5

    @staticmethod
    def _extract_crl_distribution_points(cert: x509.Certificate) -> list[str]:
        """Extract CRL distribution point URLs from certificate"""
        try:
            crl_dist_points = cert.extensions.get_extension_for_oid(
                ExtensionOID.CRL_DISTRIBUTION_POINTS
            ).value

            urls = []
            for point in crl_dist_points:
                if point.full_name:
                    for name in point.full_name:
                        if isinstance(name, x509.UniformResourceIdentifier):
                            urls.append(name.value)
            return urls
        except x509.ExtensionNotFound:
            return []

    def _get_crl_from_cache(self, crl_url: str) -> CRLCacheEntry | None:
        return self._cache_manager.get(crl_url)

    def _put_crl_to_cache(
        self, crl_url: str, crl: x509.CertificateRevocationList, ts: datetime
    ) -> None:
        self._cache_manager.put(crl_url, crl, ts)

    def _fetch_crl_from_url(self, crl_url: str) -> bytes | None:
        try:
            logger.debug("Trying to download CRL from: %s", crl_url)
            response = self._session_manager.get(
                crl_url, timeout=(self._connection_timeout_ms, self._read_timeout_ms)
            )
            response.raise_for_status()
            return response.content
        except Exception:
            # CRL fetch or parsing failed
            logger.exception("Failed to download CRL from %s", crl_url)
            return None

    def _download_crl(
        self, crl_url: str
    ) -> tuple[x509.CertificateRevocationList | None, datetime | None]:
        crl_bytes, now = self._fetch_crl_from_url(crl_url), datetime.now(timezone.utc)
        try:
            logger.debug("Trying to parse CRL from: %s", crl_url)
            crl = x509.load_der_x509_crl(crl_bytes, backend=default_backend())
            # Check if CRL is expired
            try:
                next_update = crl.next_update_utc
            except AttributeError:
                next_update = crl.next_update

            if next_update and now > next_update:
                logger.warning(
                    "The CRL from %s was expired on %s", crl_url, next_update
                )
                return None, None

            return crl, now
        except Exception:
            logger.exception("Failed to parse CRL from %s", crl_url)
            return None, None

    def _check_certificate_against_crl_url(
        self, cert: x509.Certificate, ca_cert: x509.Certificate, crl_url: str
    ) -> CRLValidationResult:
        """Check if certificate is revoked according to CRL by the provided URL"""
        now = datetime.now(timezone.utc)
        logger.debug("Trying to get cached CRL for %s", crl_url)
        cached_crl = self._get_crl_from_cache(crl_url)
        if (
            cached_crl is None
            or cached_crl.is_crl_expired_by(now)
            or cached_crl.is_evicted_by(now, self._cache_validity_time)
        ):
            crl, ts = self._download_crl(crl_url)
            if crl and ts:
                self._put_crl_to_cache(crl_url, crl, ts)
        else:
            crl = cached_crl.crl

        # If by some reason we didn't get a valid CRL we consider it a check error
        if crl is None:
            return CRLValidationResult.ERROR

        # Verify CRL signature with CA public key
        # Check if the CA certificate is the expected CRL issuer
        if crl.issuer != ca_cert.subject:
            logger.warning(
                "CRL issuer (%s) does not match CA certificate subject (%s) for URL: %s",
                crl.issuer,
                ca_cert.subject,
                crl_url,
            )
            # In most cases this indicates a configuration issue, but we'll still try verification

        if not self._verify_crl_signature(crl, ca_cert):
            logger.warning("CRL signature verification failed for URL: %s", crl_url)
            # Always return ERROR when signature verification fails
            # We cannot trust a CRL whose signature cannot be verified
            return CRLValidationResult.ERROR

        # Check if certificate is revoked
        return self._check_certificate_against_crl(cert, crl)

    def _verify_crl_signature(
        self, crl: x509.CertificateRevocationList, ca_cert: x509.Certificate
    ) -> bool:
        """Verify CRL signature with CA's public key"""
        try:
            # Get the signature algorithm from the CRL
            signature_algorithm = crl.signature_algorithm_oid
            hash_algorithm = crl.signature_hash_algorithm

            logger.debug(
                "Verifying CRL signature with algorithm: %s, hash: %s",
                signature_algorithm,
                hash_algorithm,
            )

            # Determine the appropriate padding based on the signature algorithm
            public_key = ca_cert.public_key()

            # Handle different key types with appropriate signature verification
            if isinstance(public_key, rsa.RSAPublicKey):
                # For RSA signatures, we need to use PKCS1v15 padding
                public_key.verify(
                    crl.signature,
                    crl.tbs_certlist_bytes,
                    padding.PKCS1v15(),
                    hash_algorithm,
                )
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                # For EC signatures, use ECDSA algorithm
                public_key.verify(
                    crl.signature,
                    crl.tbs_certlist_bytes,
                    ec.ECDSA(hash_algorithm),
                )
            else:
                # For other key types (DSA, etc.), try without padding
                public_key.verify(
                    crl.signature,
                    crl.tbs_certlist_bytes,
                    hash_algorithm,
                )

            logger.debug("CRL signature verification successful")
            return True
        except Exception as e:
            logger.warning("CRL signature verification failed: %s", e)
            return False

    def _check_certificate_against_crl(
        self, cert: x509.Certificate, crl: x509.CertificateRevocationList
    ) -> CRLValidationResult:
        """Check if certificate is revoked according to CRL"""
        revoked_cert = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
        return (
            CRLValidationResult.REVOKED
            if revoked_cert
            else CRLValidationResult.UNREVOKED
        )

    def validate_connection(self, connection: SSLConnection) -> bool:
        """
        Validate an OpenSSL connection against CRLs.

        This method extracts certificate chains from the connection and validates them
        against Certificate Revocation Lists (CRLs).

        Args:
            connection: OpenSSL connection object

        Returns:
            True if validation passes, False otherwise
        """
        certificate_chains = self._extract_certificate_chains_from_connection(
            connection
        )
        return self.validate_certificate_chains(certificate_chains)

    def _extract_certificate_chains_from_connection(
        self, connection
    ) -> list[list[x509.Certificate]]:
        """Extract certificate chains from OpenSSL connection for CRL validation.

        Args:
            connection: OpenSSL connection object

        Returns:
            List of certificate chains, where each chain is a list of x509.Certificate objects
        """
        from OpenSSL.crypto import FILETYPE_ASN1, dump_certificate

        try:
            cert_chain = connection.get_peer_cert_chain()
            if not cert_chain:
                logger.debug("No certificate chain found in connection")
                return []

            # Convert OpenSSL certificates to cryptography x509 certificates
            x509_chain = []
            for cert_openssl in cert_chain:
                cert_der = dump_certificate(FILETYPE_ASN1, cert_openssl)
                cert_x509 = x509.load_der_x509_certificate(cert_der, default_backend())
                x509_chain.append(cert_x509)

            logger.debug(
                "Extracted %d certificates for CRL validation", len(x509_chain)
            )
            return [x509_chain]  # Return as a single chain

        except Exception as e:
            logger.warning(
                "Failed to extract certificate chain for CRL validation: %s", e
            )
            return []
