# Third-party notices

VPPDetector 1.1.0 is licensed under the GNU Affero General Public License,
version 3 only (AGPL-3.0-only). The complete license text is in LICENSE.

## Scope

This notice covers third-party components in the VPPDetector 1.1.0 wheel and
source distribution. VPPDetector does not vendor or bundle PCResolve.
PCResolve is a runtime dependency installed separately by pip.

The project source checkout also contains historical and local-only material,
including the legacy research scanner (legacy_vppdetector.py), dataset
snapshots, local evaluation fixtures, tests, and development documentation.
That material is not part of the wheel or source distribution and is outside
the scope of this notice.

## Runtime dependency

| Component | Version tested | License | Distribution |
| --- | --- | --- | --- |
| PCResolve | 1.0.8 | MIT | Separate package; not bundled |

VPPDetector requires `pcresolve>=1.0.8` and was tested with PCResolve 1.0.8.
PCResolve 1.0.8 declares no runtime dependencies of its own. A newer PCResolve
installed under that requirement carries its own license and notices.

### PCResolve

- Project: https://github.com/PCART-tools/PCResolve
- PyPI: https://pypi.org/project/pcresolve/1.0.8/
- Copyright: Copyright (c) 2026 Guanping Xiao
- License: MIT

The MIT License text follows.

MIT License

Copyright (c) 2026 Guanping Xiao

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## No other distributed third-party components

The VPPDetector 1.1.0 wheel contains only the `vppdetector` package, its
metadata, LICENSE, and this notice. The source distribution contains the same
project sources and license files. No other third-party source code is
included.

Build and verification tools (for example setuptools, build, pytest, psutil,
Ruff, and twine) are used to produce and check the release but are not part of
the wheel or source distribution. Their own licenses apply to those tools.
