from __future__ import annotations

from datetime import datetime, timezone
from logging import getLogger

from cryptography import x509

from snowflake.connector.crl import CRLValidationResult
from snowflake.connector.crl import CRLValidator as CRLValidatorSync

logger = getLogger(__name__)


class CRLValidator(CRLValidatorSync):
    async def _fetch_crl_from_url(self, crl_url: str) -> bytes | None:
        """Async version of CRL fetching"""
        try:
            logger.debug("Trying to download CRL from: %s", crl_url)
            response = await self._session_manager.get(
                crl_url, timeout=(self._connection_timeout_ms, self._read_timeout_ms)
            )
            response.raise_for_status()
            return response.content
        except Exception:
            # CRL fetch or parsing failed
            logger.exception("Failed to download CRL from %s", crl_url)
            return None

    async def _download_crl(
        self, crl_url: str
    ) -> tuple[x509.CertificateRevocationList | None, datetime | None]:
        """Async version of CRL download"""
        from cryptography.hazmat.backends import default_backend

        crl_bytes = await self._fetch_crl_from_url(crl_url)
        now = datetime.now(timezone.utc)
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

    async def _check_certificate_against_crl_url(
        self, cert: x509.Certificate, ca_cert: x509.Certificate, crl_url: str
    ) -> CRLValidationResult:
        """Async version of checking certificate against CRL URL"""
        now = datetime.now(timezone.utc)
        logger.debug("Trying to get cached CRL for %s", crl_url)
        cached_crl = self._get_crl_from_cache(crl_url)
        if (
            cached_crl is None
            or cached_crl.is_crl_expired_by(now)
            or cached_crl.is_evicted_by(now, self._cache_validity_time)
        ):
            crl, ts = await self._download_crl(crl_url)
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
            return CRLValidationResult.ERROR

        if not self._verify_crl_signature(crl, ca_cert):
            logger.warning("CRL signature verification failed for URL: %s", crl_url)
            # Always return ERROR when signature verification fails
            # We cannot trust a CRL whose signature cannot be verified
            return CRLValidationResult.ERROR

        # Verify that the CRL URL matches the IDP extension
        if not self._verify_against_idp_extension(crl, crl_url):
            logger.warning("CRL URL does not match IDP extension for URL: %s", crl_url)
            return CRLValidationResult.ERROR

        # Check if certificate is revoked
        return self._check_certificate_against_crl(cert, crl)

    async def _validate_certificate_is_not_revoked(
        self, cert: x509.Certificate, ca_cert: x509.Certificate
    ) -> CRLValidationResult:
        """Async version of certificate validation"""
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
            result = await self._check_certificate_against_crl_url(
                cert, ca_cert, crl_url
            )
            if result == CRLValidationResult.REVOKED:
                return result
            results.append(result)

        if all(result == CRLValidationResult.ERROR for result in results):
            return CRLValidationResult.ERROR

        return CRLValidationResult.UNREVOKED

    async def _validate_certificate_is_not_revoked_with_cache(
        self, cert: x509.Certificate, ca_cert: x509.Certificate
    ) -> CRLValidationResult:
        """Async version with caching"""
        # validate certificate can be called multiple times with the same certificate
        if cert not in self._cache_for__validate_certificate_is_not_revoked:
            self._cache_for__validate_certificate_is_not_revoked[cert] = (
                await self._validate_certificate_is_not_revoked(cert, ca_cert)
            )
        return self._cache_for__validate_certificate_is_not_revoked[cert]

    async def _validate_chain(
        self, start_cert: x509.Certificate, chain: list[x509.Certificate]
    ) -> CRLValidationResult:
        """Async version of chain validation"""
        from collections import defaultdict

        # Check if start certificate is expired
        if not self._is_within_validity_dates(start_cert):
            logger.warning(
                "Start certificate is expired or not yet valid: %s", start_cert.subject
            )
            return CRLValidationResult.ERROR

        subject_certificates: dict[x509.Name, list[x509.Certificate]] = defaultdict(
            list
        )
        for cert in chain:
            if not self._is_ca_certificate(cert):
                logger.warning("Ignoring non-CA certificate: %s", cert)
                continue
            if not self._is_within_validity_dates(cert):
                logger.warning(
                    "Ignoring certificate not within validity dates: %s", cert
                )
                continue
            subject_certificates[cert.subject].append(cert)
        currently_visited_subjects: set[x509.Name] = set()

        async def traverse_chain(cert: x509.Certificate) -> CRLValidationResult | None:
            # UNREVOKED - unrevoked path to a trusted certificate found
            # REVOKED - all paths are revoked
            # ERROR - some certificates on potentially unrevoked paths can't be verified, or no path to a trusted CA is detected
            # None - ignore this path (cycle detected)
            if self._is_certificate_trusted_by_os(cert):
                logger.debug("Found trusted certificate: %s", cert.subject)
                return CRLValidationResult.UNREVOKED

            if trusted_ca_issuer := self._get_trusted_ca_issuer(cert):
                logger.debug("Certificate signed by trusted CA: %s", cert.subject)
                return await self._validate_certificate_is_not_revoked_with_cache(
                    cert, trusted_ca_issuer
                )

            if cert.issuer in currently_visited_subjects:
                # cycle detected - invalid path
                return None

            valid_results: list[tuple[CRLValidationResult, x509.Certificate]] = []
            for ca_cert in subject_certificates[cert.issuer]:
                if not self._verify_certificate_signature(cert, ca_cert):
                    logger.debug(
                        "Certificate signature verification failed for %s, looking for other paths",
                        cert,
                    )
                    continue

                currently_visited_subjects.add(cert.issuer)
                ca_result = await traverse_chain(ca_cert)
                currently_visited_subjects.remove(cert.issuer)
                if ca_result is None:
                    # ignore invalid path result
                    continue
                if ca_result == CRLValidationResult.UNREVOKED:
                    # good path found
                    return await self._validate_certificate_is_not_revoked_with_cache(
                        cert, ca_cert
                    )
                valid_results.append((ca_result, ca_cert))

            if len(valid_results) == 0:
                # "root" certificate not cought by "is_trusted_by_os" check
                logger.debug("No path towards trusted anchor: %s", cert.subject)
                return CRLValidationResult.ERROR

            # check if there exists an ERROR path
            for ca_result, ca_cert in valid_results:
                if ca_result == CRLValidationResult.ERROR:
                    cert_result = (
                        await self._validate_certificate_is_not_revoked_with_cache(
                            cert, ca_cert
                        )
                    )
                    if cert_result == CRLValidationResult.REVOKED:
                        return CRLValidationResult.REVOKED
                    return CRLValidationResult.ERROR

            # no ERROR result found, all paths are REVOKED
            return CRLValidationResult.REVOKED

        return await traverse_chain(start_cert)

    async def validate_certificate_chain(
        self, peer_cert: x509.Certificate, chain: list[x509.Certificate] | None
    ) -> bool:
        """Async version of certificate chain validation"""
        from snowflake.connector.crl import CertRevocationCheckMode

        if self._cert_revocation_check_mode == CertRevocationCheckMode.DISABLED:
            return True

        chain = chain if chain is not None else []
        result = await self._validate_chain(peer_cert, chain)

        if result == CRLValidationResult.UNREVOKED:
            return True
        if result == CRLValidationResult.REVOKED:
            return False
        # In advisory mode, errors are treated positively
        return self._cert_revocation_check_mode == CertRevocationCheckMode.ADVISORY

    async def validate_connection(self, connection) -> bool:
        """Async version of connection validation"""
        from snowflake.connector.crl import CertRevocationCheckMode

        try:
            # Get the peer certificate (the start certificate)
            peer_cert = self._get_peer_certificate(connection)
            if peer_cert is None:
                logger.warning("No peer certificate found in connection")
                return (
                    self._cert_revocation_check_mode == CertRevocationCheckMode.ADVISORY
                )

            # Extract the certificate chain
            cert_chain = self._extract_certificate_chain_from_connection(connection)

            return await self.validate_certificate_chain(peer_cert, cert_chain)
        except Exception as e:
            logger.warning("Failed to validate connection: %s", e)
            return self._cert_revocation_check_mode == CertRevocationCheckMode.ADVISORY
