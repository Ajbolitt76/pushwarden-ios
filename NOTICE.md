# PushWarden

PushWarden is a modified version of Bitwarden's open-source iOS client. It adds a second
encryption level ("level 2") whose passwords are only released after approval on your phone
or with a separate password.

**PushWarden is not affiliated with, endorsed by, or supported by Bitwarden, Inc.**
"Bitwarden" is a trademark of Bitwarden, Inc.; it is used here only to describe compatibility
and the origin of the code. Report PushWarden problems to PushWarden, not to Bitwarden.

## License

This fork is licensed under the GNU General Public License v3.0 (see `LICENSE.txt`).

## Changes from upstream

Modified 2026 by PushWarden contributors:
- level 2 encryption and PC fill approvals (`PushWardenL2/` package, wired into
  `BitwardenShared`);
- app name, bundle ID (`com.corex.pushwarden`) and icon;
- associated domains removed from the entitlements (they claim Bitwarden's domains).
