# FIPS boundary and limitations

This Zig wrapper is not a cryptographic module validation and makes no claim
that an application is FIPS validated.

Where FIPS validation is required, prefer an official Microsoft dynamic
SymCrypt module whose certificate, platform, configuration, installation, and
security policy cover the actual deployment. The validated module—not this
wrapper—is the intended cryptographic boundary.

The source-built CI fixtures, successful algorithm tests, module self-tests,
integrity postprocessing, and ABI checks do not establish validation. Static
linkage and custom/source builds are not claimed to be FIPS validated or
FIPS-capable. Consumers are responsible for selecting and operating an
applicable upstream validated module and for satisfying all policy requirements.

Windows CI renames its DLL to prevent accidental loading of the inbox module and
disables Spectre-library linkage because the public hosted images do not install
those optional libraries. This test-only hardening difference is recorded in
the provenance manifest and is another reason the fixture is not distributable
or a validation boundary.
