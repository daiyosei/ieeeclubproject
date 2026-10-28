"""Secure Messenger — a single-page KivyMD demo of AES-GCM + RSA-OAEP.

The app is entirely local: the only "communication channel" is the encrypted
JSON file written to disk.  There is no networking code anywhere.

Run with::

    python main.py
"""

from __future__ import annotations

import os
import textwrap
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from kivy.lang import Builder
from kivy.metrics import dp
from kivymd.app import MDApp
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.button import MDRaisedButton
from kivymd.uix.card import MDCard
from kivymd.uix.label import MDLabel
from kivymd.uix.screen import MDScreen
from kivymd.uix.scrollview import MDScrollView
from kivymd.uix.textfield import MDTextField

import file_dialogs

# The KivyMD widget imports above are not all referenced in Python: importing
# them registers the classes with Kivy's Factory, which is what lets main.kv
# resolve them when it is parsed.

import crypto_utils
from crypto_utils import CryptoError


class ResponsiveButtonRow(MDBoxLayout):
    """A row of buttons that stacks vertically when it no longer fits.

    This is still an ``MDBoxLayout``; it only switches its ``orientation`` so
    that button labels are never clipped when the window is made narrow.
    """

    def __init__(self, **kwargs: Any) -> None:
        kwargs.setdefault("adaptive_height", True)
        kwargs.setdefault("spacing", dp(8))
        super().__init__(**kwargs)
        self.orientation = "horizontal"
        self.bind(width=self._update_orientation)

    def add_widget(self, widget, *args: Any, **kwargs: Any) -> None:
        super().add_widget(widget, *args, **kwargs)
        # A button's natural width is exposed through size_hint_min_x.
        widget.bind(size_hint_min_x=self._update_orientation)
        self._update_orientation()

    def _update_orientation(self, *_args: Any) -> None:
        needed = sum(
            (child.size_hint_min_x or child.width or 0)
            for child in self.children
        ) + self.spacing * max(0, len(self.children) - 1)
        orientation = "vertical" if needed > self.width else "horizontal"
        if self.orientation != orientation:
            self.orientation = orientation


class PressableButton(MDRaisedButton):
    """Raised button with press feedback that never leaves its bounds.

    KivyMD's default ripple and elevation shadow allocate GPU buffers lazily.
    On some drivers the very first press paints that buffer outside the
    button (over the card background and the gaps between buttons).  A plain
    colour change is always clipped to the button and behaves identically on
    every click, so it is used instead of the ripple/shadow effects.
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._no_ripple_effect = True  # no stencil-based ripple
        self.elevation = 0  # no shadow buffer / elevation animation
        self._normal_bg_color: Optional[list] = None
        self.bind(state=self._update_pressed_color)

    def _update_pressed_color(self, _instance: Any, state: str) -> None:
        if state == "down":
            if self._normal_bg_color is None:
                self._normal_bg_color = list(self._md_bg_color)
            red, green, blue, alpha = self._normal_bg_color
            self.md_bg_color = [
                red * 0.8,
                green * 0.8,
                blue * 0.8,
                alpha,
            ]
        elif self._normal_bg_color is not None:
            self.md_bg_color = self._normal_bg_color
            self._normal_bg_color = None


class SecureApp(MDApp):
    """Single-page secure messaging demonstration."""

    title = "Secure Messenger"

    #: Kivy layout file, resolved relative to this module (not the cwd).
    KV_PATH = Path(__file__).with_name("main.kv")

    #: Paths used by the "Save Keys" / "Save Message" buttons.
    KEYS_DIR = "keys"
    PUB_KEY_PATH = os.path.join(KEYS_DIR, "public_key.pem")
    PRIV_KEY_PATH = os.path.join(KEYS_DIR, "private_key.pem")

    #: Encrypted messages live in this folder (created in the current
    #: working directory).  New saves default to "<timestamp>.txt" there.
    MSG_DIR = "msg"
    MSG_EXTENSION = ".txt"
    MSG_FILTERS = [
        ["Encrypted messages", "*.txt", "*.json"],
        ["All files", "*"],
    ]

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.public_key = None
        self.private_key = None
        self.public_pem: Optional[bytes] = None
        self.private_pem: Optional[bytes] = None
        self.current_bundle: Optional[Dict[str, str]] = None

    # ------------------------------------------------------------------
    # UI helpers
    # ------------------------------------------------------------------

    def build(self) -> MDScreen:
        self.theme_cls.theme_style = "Light"
        self.theme_cls.primary_palette = "Teal"
        try:
            self._ensure_msg_dir()
        except OSError:
            # Reported with a friendly message the first time the user
            # tries to save or load a message.
            pass
        return Builder.load_file(str(self.KV_PATH))

    # ------------------------------------------------------------------
    # File dialog helpers
    # ------------------------------------------------------------------

    @classmethod
    def default_message_name(cls) -> str:
        """Return the default file name for a new message, e.g.
        ``2026-10-28_14-30-05.txt``."""

        stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        return stamp + cls.MSG_EXTENSION

    def _ensure_msg_dir(self) -> None:
        """Create ``msg/`` in the current working directory if missing."""

        os.makedirs(self.MSG_DIR, exist_ok=True)

    @staticmethod
    def _display_path(path: str) -> str:
        """Shorten ``path`` for the status line when it is under the cwd."""

        try:
            relative = os.path.relpath(path)
        except ValueError:  # e.g. a different drive on Windows
            return path
        return path if relative.startswith("..") else relative

    def _ask_save_path(self) -> Optional[str]:
        """Show the native "save as" dialog and return the chosen path."""

        default_path = os.path.join(
            os.path.abspath(self.MSG_DIR), self.default_message_name()
        )
        return file_dialogs.save_file(
            path=default_path,
            filters=self.MSG_FILTERS,
            title="Save encrypted message",
        )

    def _ask_open_path(self) -> Optional[str]:
        """Show the native "open" dialog and return the chosen path."""

        return file_dialogs.open_file(
            path=os.path.abspath(self.MSG_DIR),
            filters=self.MSG_FILTERS,
            title="Open encrypted message",
        )

    def _set_status(self, message: str, error: bool = False) -> None:
        """Show a message in the status line (red for errors)."""

        label = self.root.ids.lbl_status
        label.text = message
        label.theme_text_color = "Error" if error else "Primary"

    def _set_output(self, message: str) -> None:
        self.root.ids.lbl_output.text = message

    def _set_keys_label(self, message: str) -> None:
        self.root.ids.lbl_keys.text = message

    @staticmethod
    def _wrap(value: str, width: int = 64) -> str:
        """Break long base64 strings so they wrap inside the label."""

        return "\n".join(textwrap.wrap(value, width=width)) or value

    def _format_bundle(self, bundle: Dict[str, str]) -> str:
        return (
            "Ciphertext (base64):\n"
            f"{self._wrap(bundle.get('ciphertext', ''))}\n\n"
            "RSA-wrapped AES key (base64):\n"
            f"{self._wrap(bundle.get('wrapped_key', ''))}\n\n"
            "AES-GCM nonce (base64):\n"
            f"{self._wrap(bundle.get('nonce', ''))}"
        )

    # ------------------------------------------------------------------
    # Key management
    # ------------------------------------------------------------------

    def generate_keys(self) -> None:
        try:
            public_pem, private_pem = crypto_utils.generate_rsa_keys()
            self.public_pem = public_pem
            self.private_pem = private_pem
            self.public_key = crypto_utils.public_key_from_pem(public_pem)
            self.private_key = crypto_utils.private_key_from_pem(private_pem)
            self._set_keys_label("RSA keys: generated (2048-bit)")
            self._set_status("RSA key pair generated.")
        except CryptoError as exc:
            self._set_status(f"Could not generate keys: {exc}", error=True)
        except Exception as exc:
            self._set_status(f"Could not generate keys: {exc}", error=True)

    def save_keys(self) -> None:
        try:
            if self.public_key is None or self.private_key is None:
                self._set_status("Generate keys first.", error=True)
                return

            os.makedirs(self.KEYS_DIR, exist_ok=True)
            public_pem = self.public_pem or crypto_utils.public_pem_from_key(
                self.public_key
            )
            private_pem = self.private_pem or crypto_utils.private_pem_from_key(
                self.private_key
            )
            crypto_utils.save_keys(
                public_pem, private_pem, self.PUB_KEY_PATH, self.PRIV_KEY_PATH
            )
            self._set_status(
                f"Keys saved to {self.PUB_KEY_PATH} and {self.PRIV_KEY_PATH}."
            )
        except CryptoError as exc:
            self._set_status(f"Could not save keys: {exc}", error=True)
        except Exception as exc:
            self._set_status(f"Could not save keys: {exc}", error=True)

    def load_keys(self) -> None:
        try:
            public_key = crypto_utils.load_public_key(self.PUB_KEY_PATH)
            private_key = crypto_utils.load_private_key(self.PRIV_KEY_PATH)
            self.public_key = public_key
            self.private_key = private_key
            self.public_pem = crypto_utils.public_pem_from_key(public_key)
            self.private_pem = crypto_utils.private_pem_from_key(private_key)
            self._set_keys_label("RSA keys: loaded from files")
            self._set_status("Keys loaded from files.")
        except CryptoError as exc:
            self._set_status(f"Could not load keys: {exc}", error=True)
        except Exception as exc:
            self._set_status(f"Could not load keys: {exc}", error=True)

    # ------------------------------------------------------------------
    # Message actions
    # ------------------------------------------------------------------

    def encrypt(self) -> None:
        try:
            text = self.root.ids.txt_input.text or ""
            if not text.strip():
                self._set_status("Enter a message first.", error=True)
                return
            if self.public_key is None:
                self._set_status(
                    "Generate or load keys first.", error=True
                )
                return

            bundle = crypto_utils.encrypt_message(self.public_key, text)
            self.current_bundle = bundle
            self._set_output(self._format_bundle(bundle))
            self._set_status("Message encrypted.")
        except CryptoError as exc:
            self._set_output("—")
            self._set_status(str(exc), error=True)
        except Exception as exc:
            self._set_output("—")
            self._set_status(f"Encryption failed: {exc}", error=True)

    def decrypt(self) -> None:
        try:
            if self.current_bundle is None:
                self._set_status(
                    "Nothing to decrypt — encrypt or load a message first.",
                    error=True,
                )
                return
            if self.private_key is None:
                self._set_status(
                    "Generate or load keys first.", error=True
                )
                return

            plaintext = crypto_utils.decrypt_message(
                self.private_key, self.current_bundle
            )
            self._set_output(f"Plaintext:\n{plaintext}")
            self.root.ids.txt_input.text = plaintext
            self._set_status("Message decrypted.")
        except CryptoError as exc:
            self._set_output("—")
            self._set_status(str(exc), error=True)
        except Exception as exc:
            self._set_output("—")
            self._set_status(f"Decryption failed: {exc}", error=True)

    # ------------------------------------------------------------------
    # File persistence
    # ------------------------------------------------------------------

    def save_message(self) -> None:
        if self.current_bundle is None:
            self._set_status(
                "Nothing to save — encrypt a message first.", error=True
            )
            return

        try:
            self._ensure_msg_dir()
        except OSError as exc:
            self._set_status(
                f"Could not create the {self.MSG_DIR}/ folder: {exc}", error=True
            )
            return

        try:
            path = self._ask_save_path()
        except file_dialogs.DialogError as exc:
            self._set_status(str(exc), error=True)
            return
        except Exception as exc:
            self._set_status(f"Could not open the save dialog: {exc}", error=True)
            return

        if path is None:
            self._set_status("Save cancelled.")
            return
        if not os.path.splitext(path)[1]:
            path += self.MSG_EXTENSION

        try:
            crypto_utils.save_encrypted(path, self.current_bundle)
            self._set_status(f"Saved to {self._display_path(path)}.")
        except CryptoError as exc:
            self._set_status(f"Could not save message: {exc}", error=True)
        except Exception as exc:
            self._set_status(f"Could not save message: {exc}", error=True)

    def load_message(self) -> None:
        try:
            self._ensure_msg_dir()
        except OSError as exc:
            self._set_status(
                f"Could not create the {self.MSG_DIR}/ folder: {exc}", error=True
            )
            return

        try:
            path = self._ask_open_path()
        except file_dialogs.DialogError as exc:
            self._set_status(str(exc), error=True)
            return
        except Exception as exc:
            self._set_status(f"Could not open the load dialog: {exc}", error=True)
            return

        if path is None:
            self._set_status("Load cancelled.")
            return

        try:
            bundle = crypto_utils.load_encrypted(path)
            self.current_bundle = bundle
            self._set_output(self._format_bundle(bundle))
            self._set_status(
                f"Loaded encrypted message from {self._display_path(path)}."
            )
        except CryptoError as exc:
            self._set_output("—")
            self._set_status(f"Could not load message: {exc}", error=True)
        except Exception as exc:
            self._set_output("—")
            self._set_status(f"Could not load message: {exc}", error=True)


if __name__ == "__main__":
    SecureApp().run()
