# Python Source Files

This directory contains the Python backend and UI logic for CipherAuth.

## File Descriptions

- **[aes.py](aes.py):** Implements the `Crypto` class using `AES-GCM` for secure encryption and decryption of sensitive data.
- **[config.py](config.py):** Manages global configuration settings, platform-specific directory paths, and shared UI state.
- **[creds_handler.py](creds_handler.py):** Contains logic for adding new credentials, including manual entry and QR code processing.
- **[export_handler.py](export_handler.py):** Handles the secure export of credentials to a CSV format for user backups.
- **[main.py](main.py):** The main entry point for the application. It initializes the `CustomTkinter` window and handles the high-level UI flow (Lock screen, Main dashboard).
- **[reset_handler.py](reset_handler.py):** Manages the master password reset process and ensures all saved data is re-encrypted with the new key.
- **[sync_connection.py](sync_connection.py):** Handles the syncing of credentials between devices on the `same local network`.
- **[utils.py](utils.py):** A utility module providing helper functions for QR code decoding, clipboard operations, file handling, and UI interactions.
- **[icon.ico](icon.ico):** The application icon asset used for the window and taskbar.

## Note
These files are designed to be cross-platform and rely on the dependencies listed in the root `requirements.txt`.
