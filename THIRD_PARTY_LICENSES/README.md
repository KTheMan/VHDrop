# Third-party license notices

This directory contains the license/notice files available for the resolved Windows GNU Cargo dependency graph and the two Python wheels bundled with the host helper. See `manifest.json` for package names, versions, license declarations, file paths and provenance. Published crate archive notices are used where available; otherwise the notice is obtained from the exact upstream commit identified by `.cargo_vcs_info.json`.

Font notices include epaint default fonts, Iosevka bundled by Ouroboros UI, and the Phosphor icon font. The Phosphor font identifies itself as version 2.1 under MIT, but its crate does not record an exact upstream icon-font revision. Its included upstream license text was fetched from the upstream URL embedded in the font, and that exact-revision provenance remains unverified.

The copy-helper installer downloads Dissect and its dependencies separately at setup time. Their installed versions and licenses are not covered by this directory; Dissect target declares AGPL-3.0-or-later. Consult the installed package metadata and upstream license terms for those additional packages.
