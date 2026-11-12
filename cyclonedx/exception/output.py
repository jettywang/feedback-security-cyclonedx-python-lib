# This file is part of CycloneDX Python Library
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OWASP Foundation. All Rights Reserved.


"""
Exceptions that are for specific error scenarios during the output of a Model to a SBOM.
"""

from typing import TYPE_CHECKING

from . import CycloneDxException

if TYPE_CHECKING:  # pragma: no cover
    from ..output.compatibility import CompatibilityReport


class BomGenerationErrorException(CycloneDxException):
    """
    Raised if there is an unknown error.
    """
    pass


class FormatNotSupportedException(CycloneDxException):
    """
    Exception raised when attempting to output a BOM to a format not supported in the requested version.

    For example, JSON is not supported prior to 1.2.
    """
    pass


class DowngradeSecurityLossException(CycloneDxException):
    """
    Exception raised in strict mode when downgrading a BOM to an older schema version
    would silently drop security-relevant content
    (e.g. cryptographic assets, component evidence, hashes, vulnerabilities).

    Carries the full :class:`cyclonedx.output.compatibility.CompatibilityReport`
    in the ``report`` attribute, so callers can locate every lost object and field.
    """

    def __init__(self, report: 'CompatibilityReport') -> None:
        self._report = report
        losses = '\n'.join(f'  - {loss.path}' for loss in report.security_losses)
        super().__init__(
            f'Downgrading from CycloneDX {report.source_version.to_version()}'
            f' to {report.target_version.to_version()}'
            f' loses security-relevant content:\n{losses}'
        )

    @property
    def report(self) -> 'CompatibilityReport':
        """The report describing all content lost by the downgrade."""
        return self._report
