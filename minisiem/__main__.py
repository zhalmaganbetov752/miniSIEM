from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from minisiem.app import MiniSIEMApp
from minisiem.theme import apply_application_theme


def main() -> int:
    app = QApplication(sys.argv)
    apply_application_theme(app)
    win = MiniSIEMApp().create_main_window()
    win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())

