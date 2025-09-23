#!/usr/bin/env python
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum, unique
from logging import getLogger
from pathlib import Path
from types import TracebackType
from typing import Any

from cryptography import x509
from cryptography.hazmat._oid import ExtensionOID
from cryptography.hazmat.backends import default_backend
from typing_extensions import Self

from .crl_cache import CRLCacheEntry, CRLCacheManager, CRLFileCache, CRLInMemoryCache
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


class _CRLValidationResult(Enum):
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
    def from_connection(cls, connection) -> CRLConfig:
        """
        Create a CRLConfig instance from a SnowflakeConnection instance.

        This method extracts CRL configuration parameters from the connection's
        read-only properties and creates a CRLConfig instance.

        Args:
            connection: SnowflakeConnection instance containing CRL configuration

        Returns:
            CRLConfig: Configured CRLConfig instance

        Raises:
            ValueError: If session_manager is not available in the connection
        """
        # Extract CRL-specific configuration parameters from connection properties
        cert_revocation_check_mode_str = connection.cert_revocation_check_mode
        if isinstance(cert_revocation_check_mode_str, str):
            try:
                cert_revocation_check_mode = CertRevocationCheckMode(
                    cert_revocation_check_mode_str
                )
            except ValueError:
                logger.warning(
                    f"Invalid cert_revocation_check_mode: {cert_revocation_check_mode_str}, "
                    "defaulting to DISABLED"
                )
                cert_revocation_check_mode = CertRevocationCheckMode.DISABLED
        else:
            cert_revocation_check_mode = cert_revocation_check_mode_str

        # Handle cache validity time from hours to timedelta
        cache_validity_time = timedelta(hours=connection.crl_cache_validity_hours)

        # Handle cache directory path
        crl_cache_dir = connection.crl_cache_dir
        if crl_cache_dir is not None and not isinstance(crl_cache_dir, Path):
            crl_cache_dir = Path(crl_cache_dir)

        return cls(
            cert_revocation_check_mode=cert_revocation_check_mode,
            allow_certificates_without_crl_url=connection.allow_certificates_without_crl_url,
            connection_timeout_ms=connection.crl_connection_timeout_ms,
            read_timeout_ms=connection.crl_read_timeout_ms,
            cache_validity_time=cache_validity_time,
            enable_crl_cache=connection.enable_crl_cache,
            enable_crl_file_cache=connection.enable_crl_file_cache,
            crl_cache_dir=crl_cache_dir,
            crl_cache_removal_delay_days=connection.crl_cache_removal_delay_days,
            crl_cache_cleanup_interval_hours=connection.crl_cache_cleanup_interval_hours,
            crl_cache_start_cleanup=connection.crl_cache_start_cleanup,
        )


class CRLValidator:
    def __init__(
        self,
        session_manager: SessionManager | Any,
        cert_revocation_check_mode: CertRevocationCheckMode = CertRevocationCheckMode.DISABLED,
        allow_certificates_without_crl_url: bool = False,
        connection_timeout_ms: int | None = None,
        read_timeout_ms: int | None = None,
        cache_validity_time: timedelta | None = None,
        cache_manager: CRLCacheManager | None = None,
    ):
        self._session_manager = session_manager
        self._cert_revocation_check_mode = cert_revocation_check_mode
        self._allow_certificates_without_crl_url = allow_certificates_without_crl_url
        self._connection_timeout_ms = connection_timeout_ms or 3000
        self._read_timeout_ms = read_timeout_ms or 3000
        self._cache_validity_time = cache_validity_time or timedelta(hours=24)
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
            # Create memory cache
            memory_cache = CRLInMemoryCache(config.cache_validity_time)

            # Create file cache if enabled
            if config.enable_crl_file_cache:
                removal_delay = timedelta(days=config.crl_cache_removal_delay_days)
                file_cache = CRLFileCache(
                    cache_dir=config.crl_cache_dir, removal_delay=removal_delay
                )
            else:
                from snowflake.connector.crl_cache import NoopCRLCache

                file_cache = NoopCRLCache()

            # Create cache manager with cleanup
            cleanup_interval = timedelta(hours=config.crl_cache_cleanup_interval_hours)

            cache_manager = CRLCacheManager(
                memory_cache=memory_cache,
                file_cache=file_cache,
                cleanup_interval=cleanup_interval,
                start_cleanup=config.crl_cache_start_cleanup,
            )
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
            if result == _CRLValidationResult.UNREVOKED:
                return True
            results.append(result)

        # In non-advisory mode we require at least one chain get a clear UNREVOKED status
        if self._cert_revocation_check_mode != CertRevocationCheckMode.ADVISORY:
            return False

        # We're in advisory mode, so any error is treated positively
        return any(result == _CRLValidationResult.ERROR for result in results)

    def _validate_single_chain(
        self, chain: list[x509.Certificate]
    ) -> _CRLValidationResult:
        """Validate a single certificate chain"""
        # An empty chain is considered an error
        if len(chain) == 0:
            return _CRLValidationResult.ERROR
        # the last certificate of the chain is considered the root and isn't validated
        results = []
        for i in range(len(chain) - 1):
            result = self._validate_certificate(chain[i], chain[i + 1])
            if result == _CRLValidationResult.REVOKED:
                return _CRLValidationResult.REVOKED
            results.append(result)

        if _CRLValidationResult.ERROR in results:
            return _CRLValidationResult.ERROR

        return _CRLValidationResult.UNREVOKED

    def _validate_certificate(
        self, cert: x509.Certificate, parent: x509.Certificate
    ) -> _CRLValidationResult:
        """Validate a single certificate against CRL"""
        # Check if certificate is short-lived (skip CRL check)
        if self._is_short_lived_certificate(cert):
            return _CRLValidationResult.UNREVOKED

        # Extract CRL distribution points
        crl_urls = self._extract_crl_distribution_points(cert)

        if not crl_urls:
            # No CRL URLs found
            if self._allow_certificates_without_crl_url:
                return _CRLValidationResult.UNREVOKED
            return _CRLValidationResult.ERROR

        results: list[_CRLValidationResult] = []
        # Check against each CRL URL
        for crl_url in crl_urls:
            result = self._check_certificate_against_crl(cert, parent, crl_url)
            if result == _CRLValidationResult.REVOKED:
                return result
            results.append(result)

        if all(result == _CRLValidationResult.ERROR for result in results):
            return _CRLValidationResult.ERROR

        return _CRLValidationResult.UNREVOKED

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

    def _download_crl(
        self, crl_url: str
    ) -> tuple[x509.CertificateRevocationList | None, datetime | None]:
        now = datetime.now(timezone.utc)
        try:
            logger.debug("Trying to download CRL from: %s", crl_url)
            response = self._session_manager.get(crl_url, timeout=30)
            response.raise_for_status()

        except Exception:
            # CRL fetch or parsing failed
            logger.exception("Failed to download CRL from %s", crl_url)
            return None, None

        try:
            logger.debug("Trying to parse CRL from: %s", crl_url)
            crl = x509.load_der_x509_crl(response.content, backend=default_backend())

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

    def _check_certificate_against_crl(
        self, cert: x509.Certificate, parent: x509.Certificate, crl_url: str
    ) -> _CRLValidationResult:
        """Check if certificate is revoked according to CRL"""
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
            return _CRLValidationResult.ERROR

        # Check if certificate is revoked
        revoked_cert = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
        return (
            _CRLValidationResult.REVOKED
            if revoked_cert
            else _CRLValidationResult.UNREVOKED
        )

    def __enter__(self) -> Self:
        """Enter the runtime context for the CRLValidator.

        Returns:
            Self: The CRLValidator instance
        """
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Exit the runtime context for the CRLValidator.

        Ensures proper cleanup of resources, particularly the cache manager
        and any background cleanup tasks.

        Args:
            exc_type: The exception type if raised
            exc_value: The exception value if raised
            traceback: The exception traceback if raised
        """
        # Stop any periodic cleanup tasks in the cache manager
        if self._cache_manager is not None:
            self._cache_manager.stop_periodic_cleanup()

    def validate_connection(self, connection) -> bool:
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
