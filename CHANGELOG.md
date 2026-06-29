# Changelog

## Unreleased

_(Nothing yet.)_

## 0.0.2 — 2026-06-30

- **In-app update check** (App menu → Check for Updates…): queries GitHub for a newer release, downloads the notarized DMG, opens it for install.
- **Finder drag-and-drop**: dropping multiple files now uploads all of them (not just the first); the drop target is auto-detected from the cursor (no need to click the pane first).
- **Overwrite safety (Finder → server)**: asks before overwriting an existing file; handles several conflicts one at a time, each named in the dialog.
- **Local timezone**: "Date modified" now shows local time instead of UTC.
- **About panel**: fixed mojibake (ASCII-only credits); cleaner layout.
- **iCloud sync toggle** in the menu now shows its current ON/OFF state.
- Polish README mirrors English; softer, natural wording.

## 0.0.1 — 2026-06-30

- Renamed the application to gmacFTP.
- Added a native macOS menu bar (App / File / Edit / View / Window / Help) with a real About panel.
- Added optional iCloud Keychain sync of saved servers across Macs, toggled from the app menu.
- Hardened the menu so the app runs as a proper foreground app (the app-name menu and iCloud item now appear reliably).
- Prepared public GitHub documentation and open-source project files.
- Added sanitized documentation screenshots (light + dark + connection manager + editor + transfers).
- Removed private/internal design audit documents and dev-only scaffolding from the public tree.
